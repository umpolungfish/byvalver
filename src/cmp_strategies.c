#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Helper to check if instruction is CMP
static int is_cmp_instruction(cs_insn *insn) {
    return insn->id == X86_INS_CMP;
}

// Helper to check if immediate value contains null bytes
static int has_null_in_immediate(int64_t imm) {
    uint32_t val = (uint32_t)imm;
    return ((val & 0xFF) == 0) ||
           ((val & 0xFF00) == 0) ||
           ((val & 0xFF0000) == 0) ||
           ((val & 0xFF000000) == 0);
}

// Helper to check if displacement contains null bytes when encoded as 32-bit
static int has_null_in_displacement(int32_t disp) {
    if (disp == 0) return 1; // Zero displacement is null
    uint32_t val = (uint32_t)disp;
    return ((val & 0xFF) == 0) ||
           (((val >> 8) & 0xFF) == 0) ||
           (((val >> 16) & 0xFF) == 0) ||
           (((val >> 24) & 0xFF) == 0);
}

// Helper to check if a byte value is null (for disp8 encoding)
static int is_disp8_null(int32_t disp) {
    return ((uint8_t)disp == 0);
}

// Strategy 1: CMP reg, imm with null bytes in immediate
// Transform to: PUSH reg; XOR reg, reg (or load null-free value); CMP; POP reg
int can_handle_cmp_reg_imm_null(cs_insn *insn) {
    if (!is_cmp_instruction(insn)) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    // First operand must be register
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }

    // Second operand must be immediate with null bytes
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    int64_t imm = insn->detail->x86.operands[1].imm;

    // Check if immediate is zero or has null bytes
    if (imm == 0 || has_null_in_immediate(imm)) {
        return 1;
    }

    return 0;
}

size_t get_size_cmp_reg_imm_null(cs_insn *insn) {
    int64_t imm = insn->detail->x86.operands[1].imm;

    // For comparing with zero: PUSH reg; XOR reg, reg; CMP dest, reg; POP reg
    // PUSH (1) + XOR reg,reg (2) + CMP (2) + POP (1) = 6 bytes
    if (imm == 0) {
        return 6;
    }

    // For other null-containing immediates, we'll use similar approach
    // PUSH temp; MOV temp, imm (null-free); CMP dest, temp; POP temp
    // PUSH (1) + MOV reg,imm (2-5) + CMP (2) + POP (1) = 6-9 bytes
    // Estimate conservatively
    return 9;
}

void generate_cmp_reg_imm_null(struct buffer *b, cs_insn *insn) {
    x86_reg dest_reg = insn->detail->x86.operands[0].reg;
    int64_t imm = insn->detail->x86.operands[1].imm;

    // Choose a temporary register (prefer EAX if not the destination)
    x86_reg temp_reg = (dest_reg == X86_REG_EAX) ? X86_REG_ECX : X86_REG_EAX;

    if (imm == 0) {
        // CMP reg, 0 => PUSH temp; XOR temp, temp; CMP dest, temp; POP temp
        // This preserves all flags correctly

        // PUSH temp_reg
        buffer_write_byte(b, 0x50 + get_reg_index(temp_reg));

        // XOR temp_reg, temp_reg (sets temp to 0)
        buffer_write_byte(b, 0x31);
        buffer_write_byte(b, 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(temp_reg));

        // CMP dest_reg, temp_reg
        buffer_write_byte(b, 0x39);
        uint8_t modrm = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(dest_reg);
        buffer_write_byte(b, modrm);

        // POP temp_reg
        buffer_write_byte(b, 0x58 + get_reg_index(temp_reg));
    } else {
        // For non-zero null-containing immediates
        // PUSH temp; construct value in temp; CMP dest, temp; POP temp

        // PUSH temp_reg
        buffer_write_byte(b, 0x50 + get_reg_index(temp_reg));

        // MOV temp_reg, imm (construct null-free)
        uint32_t val = (uint32_t)imm;

        if (!is_null_free(val)) {
            // Try arithmetic equivalent first
            uint32_t base, offset;
            int operation;
            if (find_arithmetic_equivalent(val, &base, &offset, &operation)) {
                if (operation == 0) {
                    // Addition: MOV temp, base; ADD temp, offset
                    if (temp_reg == X86_REG_EAX) {
                        generate_mov_eax_imm(b, base);
                    } else {
                        buffer_write_byte(b, 0x50); // PUSH EAX to save
                        generate_mov_eax_imm(b, base);
                        // MOV temp_reg, EAX
                        uint8_t mov_code[] = {0x89, 0xC0};
                        mov_code[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(temp_reg);
                        buffer_append(b, mov_code, 2);
                        buffer_write_byte(b, 0x58); // POP EAX
                    }

                    buffer_write_byte(b, 0x81);
                    buffer_write_byte(b, 0xC0 + get_reg_index(temp_reg));
                    buffer_write_dword(b, offset);
                } else {
                    // Subtraction: MOV temp, base; SUB temp, offset
                    if (temp_reg == X86_REG_EAX) {
                        generate_mov_eax_imm(b, base);
                    } else {
                        buffer_write_byte(b, 0x50); // PUSH EAX to save
                        generate_mov_eax_imm(b, base);
                        // MOV temp_reg, EAX
                        uint8_t mov_code[] = {0x89, 0xC0};
                        mov_code[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(temp_reg);
                        buffer_append(b, mov_code, 2);
                        buffer_write_byte(b, 0x58); // POP EAX
                    }

                    buffer_write_byte(b, 0x81);
                    buffer_write_byte(b, 0xE8 + get_reg_index(temp_reg));
                    buffer_write_dword(b, offset);
                }
            } else {
                // Fallback: Try NEG equivalent
                uint32_t negated_val;
                if (find_neg_equivalent(val, &negated_val)) {
                    // MOV temp, -val; NEG temp
                    if (temp_reg == X86_REG_EAX) {
                        generate_mov_eax_imm(b, negated_val);
                    } else {
                        buffer_write_byte(b, 0x50); // PUSH EAX to save
                        generate_mov_eax_imm(b, negated_val);
                        // MOV temp_reg, EAX
                        uint8_t mov_code[] = {0x89, 0xC0};
                        mov_code[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(temp_reg);
                        buffer_append(b, mov_code, 2);
                        buffer_write_byte(b, 0x58); // POP EAX
                    }

                    buffer_write_byte(b, 0xF7);
                    buffer_write_byte(b, 0xD8 + get_reg_index(temp_reg));
                } else {
                    // Last resort: byte-by-byte construction
                    // XOR temp, temp
                    buffer_write_byte(b, 0x31);
                    buffer_write_byte(b, 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(temp_reg));

                    // Build value byte by byte using SHL + OR
                    for (int i = 0; i < 4; i++) {
                        uint8_t byte = (val >> (i * 8)) & 0xFF;
                        if (byte != 0) {
                            if (i > 0) {
                                // SHL temp, 8
                                buffer_write_byte(b, 0xC1);
                                buffer_write_byte(b, 0xE0 + get_reg_index(temp_reg));
                                buffer_write_byte(b, 8);
                            }
                            // OR temp_low, byte
                            buffer_write_byte(b, 0x80);
                            buffer_write_byte(b, 0xC8 + get_reg_index(temp_reg));
                            buffer_write_byte(b, byte);
                        } else if (i > 0) {
                            // Shift for null bytes too
                            buffer_write_byte(b, 0xC1);
                            buffer_write_byte(b, 0xE0 + get_reg_index(temp_reg));
                            buffer_write_byte(b, 8);
                        }
                    }
                }
            }
        } else {
            // Value is null-free, use direct MOV
            if (temp_reg == X86_REG_EAX) {
                generate_mov_eax_imm(b, val);
            } else {
                buffer_write_byte(b, 0x50); // PUSH EAX to save
                generate_mov_eax_imm(b, val);
                // MOV temp_reg, EAX
                uint8_t mov_code[] = {0x89, 0xC0};
                mov_code[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(temp_reg);
                buffer_append(b, mov_code, 2);
                buffer_write_byte(b, 0x58); // POP EAX
            }
        }

        // CMP dest_reg, temp_reg
        buffer_write_byte(b, 0x39);
        uint8_t modrm = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(dest_reg);
        buffer_write_byte(b, modrm);

        // POP temp_reg
        buffer_write_byte(b, 0x58 + get_reg_index(temp_reg));
    }
}

strategy_t cmp_reg_imm_null_strategy = {
    .name = "cmp_reg_imm_null",
    .can_handle = can_handle_cmp_reg_imm_null,
    .get_size = get_size_cmp_reg_imm_null,
    .generate = generate_cmp_reg_imm_null,
    .priority = 85
};

// Strategy 2: CMP BYTE [reg], imm with null in immediate
int can_handle_cmp_byte_mem_imm_null(cs_insn *insn) {
    if (!is_cmp_instruction(insn)) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    // First operand must be memory (byte-sized)
    if (insn->detail->x86.operands[0].type != X86_OP_MEM) {
        return 0;
    }

    // Check if it's byte-sized operation
    if (insn->detail->x86.operands[0].size != 1) {
        return 0;
    }

    // Must have a base register (like [ESI], [EBP+disp])
    if (insn->detail->x86.operands[0].mem.base == X86_REG_INVALID) {
        return 0; // Already handled by memory_strategies.c
    }

    // Second operand must be immediate
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    // Check if has null bytes in encoding
    if (has_null_bytes(insn)) {
        return 1;
    }

    return 0;
}

size_t get_size_cmp_byte_mem_imm_null(__attribute__((unused)) cs_insn *insn) {
    // PUSH temp; XOR temp, temp; CMP [mem], temp_8bit; POP temp
    // PUSH (1) + XOR (2) + CMP byte [reg], reg8 (2-6) + POP (1) = 6-10 bytes
    return 10;
}

void generate_cmp_byte_mem_imm_null(struct buffer *b, cs_insn *insn) {
    int64_t imm = insn->detail->x86.operands[1].imm;
    x86_reg base_reg = insn->detail->x86.operands[0].mem.base;
    int32_t disp = insn->detail->x86.operands[0].mem.disp;

    // Choose temp register
    x86_reg temp_reg = (base_reg == X86_REG_EAX) ? X86_REG_ECX : X86_REG_EAX;

    if (imm == 0) {
        // CMP BYTE [reg+disp], 0
        // Transform: PUSH temp; XOR temp, temp; CMP [reg+disp], temp_low; POP temp

        // PUSH temp_reg
        buffer_write_byte(b, 0x50 + get_reg_index(temp_reg));

        // XOR temp_reg, temp_reg
        buffer_write_byte(b, 0x31);
        buffer_write_byte(b, 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(temp_reg));

        // CMP BYTE [base_reg+disp], temp_reg_low (AL, CL, DL, BL)
        buffer_write_byte(b, 0x38); // CMP r/m8, r8

        // Build ModR/M byte
        uint8_t base_idx = get_reg_index(base_reg);
        uint8_t temp_idx = get_reg_index(temp_reg);

        if (disp == 0 && base_reg != X86_REG_EBP) {
            // [reg] mode
            uint8_t modrm = 0x00 + (temp_idx << 3) + base_idx;
            buffer_write_byte(b, modrm);
        } else if (disp >= -128 && disp <= 127 && !is_disp8_null(disp)) {
            // [reg+disp8] mode (displacement fits in 8 bits and isn't null)
            uint8_t modrm = 0x40 + (temp_idx << 3) + base_idx;
            buffer_write_byte(b, modrm);
            buffer_write_byte(b, (uint8_t)disp);
        } else {
            // [reg+disp32] mode - may need null-free displacement
            uint8_t modrm = 0x80 + (temp_idx << 3) + base_idx;
            buffer_write_byte(b, modrm);

            // Try to use null-free displacement
            if (has_null_in_displacement(disp)) {
                // Use [reg] and adjust base temporarily - complex, for now use disp32
                buffer_write_dword(b, (uint32_t)disp);
            } else {
                buffer_write_dword(b, (uint32_t)disp);
            }
        }

        // POP temp_reg
        buffer_write_byte(b, 0x58 + get_reg_index(temp_reg));
    } else {
        // Non-zero immediate - similar approach
        // For simplicity, use same pattern
        buffer_write_byte(b, 0x50 + get_reg_index(temp_reg));

        // Get indices
        uint8_t base_idx = get_reg_index(base_reg);
        uint8_t temp_idx = get_reg_index(temp_reg);

        // MOV temp_reg_low, imm8
        buffer_write_byte(b, 0xB0 + temp_idx); // MOV AL/CL/DL/BL, imm8
        buffer_write_byte(b, (uint8_t)imm);

        // CMP BYTE [base_reg+disp], temp_reg_low
        buffer_write_byte(b, 0x38);

        if (disp == 0 && base_reg != X86_REG_EBP) {
            uint8_t modrm = 0x00 + (temp_idx << 3) + base_idx;
            buffer_write_byte(b, modrm);
        } else if (disp >= -128 && disp <= 127 && !is_disp8_null(disp)) {
            uint8_t modrm = 0x40 + (temp_idx << 3) + base_idx;
            buffer_write_byte(b, modrm);
            buffer_write_byte(b, (uint8_t)disp);
        } else {
            uint8_t modrm = 0x80 + (temp_idx << 3) + base_idx;
            buffer_write_byte(b, modrm);
            buffer_write_dword(b, (uint32_t)disp);
        }

        buffer_write_byte(b, 0x58 + get_reg_index(temp_reg));
    }
}

strategy_t cmp_byte_mem_imm_null_strategy = {
    .name = "cmp_byte_mem_imm_null",
    .can_handle = can_handle_cmp_byte_mem_imm_null,
    .get_size = get_size_cmp_byte_mem_imm_null,
    .generate = generate_cmp_byte_mem_imm_null,
    .priority = 88
};

// Strategy 3: CMP [reg+disp], reg with null in displacement
int can_handle_cmp_mem_reg_null(cs_insn *insn) {
    if (!is_cmp_instruction(insn)) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    // First operand must be memory
    if (insn->detail->x86.operands[0].type != X86_OP_MEM) {
        return 0;
    }

    // Must have a base register
    if (insn->detail->x86.operands[0].mem.base == X86_REG_INVALID) {
        return 0; // Already handled by memory_strategies.c
    }

    // Second operand must be register
    if (insn->detail->x86.operands[1].type != X86_OP_REG) {
        return 0;
    }

    // Check if has null bytes in encoding
    if (has_null_bytes(insn)) {
        return 1;
    }

    return 0;
}

size_t get_size_cmp_mem_reg_null(__attribute__((unused)) cs_insn *insn) {
    // PUSH temp; LEA temp, [reg+disp]; CMP [temp], reg2; POP temp
    // Or simpler: PUSH temp; MOV temp, base; ADD temp, disp; CMP [temp], reg2; POP temp
    // Conservative estimate: 12 bytes
    return 12;
}

void generate_cmp_mem_reg_null(struct buffer *b, cs_insn *insn) {
    x86_reg cmp_reg = insn->detail->x86.operands[1].reg;
    x86_reg base_reg = insn->detail->x86.operands[0].mem.base;
    int32_t disp = insn->detail->x86.operands[0].mem.disp;
    uint8_t size = insn->detail->x86.operands[0].size;

    // Choose temp register (avoid cmp_reg and base_reg)
    x86_reg temp_reg = X86_REG_EAX;
    if (temp_reg == cmp_reg || temp_reg == base_reg) temp_reg = X86_REG_ECX;
    if (temp_reg == cmp_reg || temp_reg == base_reg) temp_reg = X86_REG_EDX;

    // PUSH temp
    buffer_write_byte(b, 0x50 + get_reg_index(temp_reg));

    // MOV temp, base
    buffer_write_byte(b, 0x89);
    uint8_t modrm = 0xC0 + (get_reg_index(base_reg) << 3) + get_reg_index(temp_reg);
    buffer_write_byte(b, modrm);

    // ADD temp, disp (if disp != 0)
    if (disp != 0) {
        if (disp >= -128 && disp <= 127 && !is_disp8_null(disp)) {
            // ADD temp, imm8 (displacement fits in 8 bits and isn't null)
            buffer_write_byte(b, 0x83);
            buffer_write_byte(b, 0xC0 + get_reg_index(temp_reg));
            buffer_write_byte(b, (uint8_t)disp);
        } else if (!has_null_in_displacement(disp)) {
            // ADD temp, imm32 (displacement is null-free as 32-bit)
            buffer_write_byte(b, 0x81);
            buffer_write_byte(b, 0xC0 + get_reg_index(temp_reg));
            buffer_write_dword(b, (uint32_t)disp);
        } else {
            // Try to break into multiple smaller displacements to avoid nulls
            // Find arithmetic equivalent: base ± offset = disp (both null-free)
            uint32_t base, offset;
            int operation;
            if (find_arithmetic_equivalent((uint32_t)disp, &base, &offset, &operation)) {
                if (operation == 0) {
                    // Addition: ADD temp, base; ADD temp, offset
                    buffer_write_byte(b, 0x81);
                    buffer_write_byte(b, 0xC0 + get_reg_index(temp_reg));
                    buffer_write_dword(b, base);

                    buffer_write_byte(b, 0x81);
                    buffer_write_byte(b, 0xC0 + get_reg_index(temp_reg));
                    buffer_write_dword(b, offset);
                } else {
                    // Subtraction: ADD temp, base; SUB temp, offset
                    buffer_write_byte(b, 0x81);
                    buffer_write_byte(b, 0xC0 + get_reg_index(temp_reg));
                    buffer_write_dword(b, base);

                    buffer_write_byte(b, 0x81);
                    buffer_write_byte(b, 0xE8 + get_reg_index(temp_reg));  // SUB
                    buffer_write_dword(b, offset);
                }
            } else {
                // Fallback: use displacement as-is (may have nulls but rare)
                buffer_write_byte(b, 0x81);
                buffer_write_byte(b, 0xC0 + get_reg_index(temp_reg));
                buffer_write_dword(b, (uint32_t)disp);
            }
        }
    }

    // CMP [temp], cmp_reg
    if (size == 1) {
        // Byte comparison
        buffer_write_byte(b, 0x38);
    } else {
        // Dword comparison
        buffer_write_byte(b, 0x39);
    }

    modrm = 0x00 + (get_reg_index(cmp_reg) << 3) + get_reg_index(temp_reg);
    buffer_write_byte(b, modrm);

    // POP temp
    buffer_write_byte(b, 0x58 + get_reg_index(temp_reg));
}

strategy_t cmp_mem_reg_null_strategy = {
    .name = "cmp_mem_reg_null",
    .can_handle = can_handle_cmp_mem_reg_null,
    .get_size = get_size_cmp_mem_reg_null,
    .generate = generate_cmp_mem_reg_null,
    .priority = 86
};

// Registration function
void register_cmp_strategies() {
    register_strategy(&cmp_reg_imm_null_strategy);
    register_strategy(&cmp_byte_mem_imm_null_strategy);
    register_strategy(&cmp_mem_reg_null_strategy);
}
