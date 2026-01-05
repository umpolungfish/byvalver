#include "strategy.h"
#include "utils.h"
#include "profile_aware_sib.h"
#include <stdio.h>
#include <string.h>

/*
 * Strategy: Byte-by-byte construction for immediate values that can't be handled by other methods
 * This strategy constructs the target value byte-by-byte, starting with clearing a register
 * and then setting each non-zero byte individually.
 */

int can_handle_byte_construct(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Must be register destination
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }

    // Must be immediate source
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    // Only handle if it has null bytes (this is for null byte removal)
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Check if other strategies can handle this first
    // We only want to use this as a fallback when other strategies fail
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t negated_val, not_val;
    uint32_t val1, val2;
    int is_add;

    // Check if NEG strategy can handle it
    if (find_neg_equivalent(target, &negated_val)) {
        return 0;
    }

    // Check if NOT strategy can handle it
    if (find_not_equivalent(target, &not_val)) {
        return 0;
    }

    // Check if ADD/SUB strategy can handle it
    if (find_addsub_key(target, &val1, &val2, &is_add)) {
        return 0;
    }

    // Check if XOR strategy can handle it
    uint32_t xor_key;
    if (find_xor_key(target, &xor_key)) {
        return 0;
    }

    // Check if arithmetic equivalent strategy can handle it
    uint32_t base, offset;
    int operation;
    if (find_arithmetic_equivalent(target, &base, &offset, &operation)) {
        return 0;
    }

    // If none of the other strategies can handle it, use byte construction
    return 1;
}

size_t get_size_byte_construct(cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t reg = insn->detail->x86.operands[0].reg;

    // Size calculation:
    // - Clear register: XOR reg, reg (2 bytes if not EAX, 1 if EAX with 31 C0 pattern)
    // - For each non-zero byte: MOV reg+offs, imm8 (2-4 bytes depending on addressing)
    size_t size = 2; // Initial clear operation

    // Add size for each non-zero byte
    for (int i = 0; i < 4; i++) {
        uint8_t byte_val = (target >> (i * 8)) & 0xFF;
        if (byte_val != 0) {
            // MOV to specific byte in register
            if (reg == X86_REG_EAX && i == 0) {
                size += 2; // MOV AL, imm8 (0xB0 + imm8)
            } else if (reg == X86_REG_ECX && i == 0) {
                size += 2; // MOV CL, imm8 (0xB1 + imm8)
            } else if (reg == X86_REG_EDX && i == 0) {
                size += 2; // MOV DL, imm8 (0xB2 + imm8)
            } else if (reg == X86_REG_EBX && i == 0) {
                size += 2; // MOV BL, imm8 (0xB3 + imm8)
            } else {
                // Use MOV [reg+offs], imm8 pattern
                size += 3; // MOV [reg], imm8 with appropriate addressing
            }

            // Need to shift if not the lowest byte
            if (i > 0) {
                size += 4; // SHL reg, 8 (for each position shift)
            }
        }
    }

    // Conservative estimate - actual size may vary based on implementation
    return 15; // Conservative upper bound
}

void generate_byte_construct(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t reg = insn->detail->x86.operands[0].reg;

    // For true byte-by-byte construction:
    if (reg == X86_REG_EAX) {
        // Clear EAX first (XOR EAX, EAX)
        uint8_t xor_eax[] = {0x31, 0xC0};
        buffer_append(b, xor_eax, 2);

        // Build value byte by byte using safe addressing to avoid nulls
        // Process bytes from least significant to most significant
        for (int i = 0; i < 4; i++) {
            uint8_t byte_val = (target >> (i * 8)) & 0xFF;
            if (byte_val != 0) {
                if (i == 0) {
                    // Set AL directly
                    uint8_t mov_al[] = {0xB0, byte_val};
                    buffer_append(b, mov_al, 2);
                } else if (i == 1) {
                    // Set AH directly
                    uint8_t mov_ah[] = {0xB4, byte_val};
                    buffer_append(b, mov_ah, 2);
                } else {
                    // For higher bytes, use shift and OR approach
                    uint8_t push_ecx[] = {0x51};
                    buffer_append(b, push_ecx, 1);

                    // MOV ECX, byte_val
                    generate_mov_eax_imm(b, byte_val);

                    // SHL EAX, i*8
                    for (int j = 0; j < i * 8; j++) {
                        uint8_t shl_eax[] = {0xD1, 0xE0};
                        buffer_append(b, shl_eax, 2);
                    }

                    // OR EAX, ECX shifted
                    uint8_t or_eax_ecx[] = {0x0B, 0xC1  /* Changed from 0x09 (TAB) to 0x0B (OR alternative encoding) */};
                    buffer_append(b, or_eax_ecx, 2);

                    uint8_t pop_ecx[] = {0x59};
                    buffer_append(b, pop_ecx, 1);
                }
            }
        }
    } else {
        // For other registers, save EAX, use it to build the value, then move result
        uint8_t push_eax[] = {0x50};  // PUSH EAX to save original value
        buffer_append(b, push_eax, 1);

        // Build the target value in EAX using the byte-by-byte method above
        // Clear EAX first (XOR EAX, EAX)
        uint8_t xor_eax[] = {0x31, 0xC0};
        buffer_append(b, xor_eax, 2);

        // Build value byte by byte
        for (int i = 0; i < 4; i++) {
            uint8_t byte_val = (target >> (i * 8)) & 0xFF;
            if (byte_val != 0) {
                if (i == 0) {
                    // Set AL directly
                    uint8_t mov_al[] = {0xB0, byte_val};
                    buffer_append(b, mov_al, 2);
                } else if (i == 1) {
                    // Set AH directly
                    uint8_t mov_ah[] = {0xB4, byte_val};
                    buffer_append(b, mov_ah, 2);
                } else {
                    // For higher bytes, use shift and OR approach
                    uint8_t push_temp[] = {0x51};  // Use ECX as temp
                    buffer_append(b, push_temp, 1);

                    // MOV ECX, byte_val
                    generate_mov_eax_imm(b, byte_val);

                    // SHL EAX, i*8
                    for (int j = 0; j < i * 8; j++) {
                        uint8_t shl_eax[] = {0xD1, 0xE0};
                        buffer_append(b, shl_eax, 2);
                    }

                    // OR EAX, ECX shifted
                    uint8_t or_eax_ecx[] = {0x0B, 0xC1  /* Changed from 0x09 (TAB) to 0x0B (OR alternative encoding) */};
                    buffer_append(b, or_eax_ecx, 2);

                    uint8_t pop_temp[] = {0x59};
                    buffer_append(b, pop_temp, 1);
                }
            }
        }

        // FIXED: Use profile-safe encoding
        if (generate_safe_mov_mem_reg(b, reg, X86_REG_EAX) != 0) {
            // Fallback
            uint8_t push[] = {0x50};  // PUSH EAX
            buffer_append(b, push, 1);
            uint8_t pop[] = {(uint8_t)(0x58 | get_reg_index(reg))};  // POP reg (gets value from [reg])
            buffer_append(b, pop, 1);
        }

        // Restore original EAX
        uint8_t pop_eax[] = {0x58};  // POP EAX
        buffer_append(b, pop_eax, 1);
    }
}

strategy_t byte_construct_strategy = {
    .name = "BYTE_CONSTRUCT_MOV",
    .can_handle = can_handle_byte_construct,
    .get_size = get_size_byte_construct,
    .generate = generate_byte_construct,
    .priority = 5  // Lower priority - this is a fallback strategy
};

void register_byte_construct_strategy() {
    register_strategy(&byte_construct_strategy);
}