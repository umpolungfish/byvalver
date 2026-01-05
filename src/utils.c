#define _POSIX_C_SOURCE 200809L
#include "utils.h"
#include "core.h"
#include "profile_aware_sib.h"  // For profile-safe SIB generation
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#include <errno.h>

// Initialize random seed
__attribute__((constructor))
static void initialize_rand() {
    srand(time(NULL));
}


// Helper functions for buffer manipulation
void buffer_write_byte(struct buffer *b, uint8_t byte) {
    buffer_append(b, &byte, 1);
}

void buffer_write_word(struct buffer *b, uint16_t word) {
    buffer_append(b, (uint8_t*)&word, 2);
}

void buffer_write_dword(struct buffer *b, uint32_t dword) {
    buffer_append(b, (uint8_t*)&dword, 4);
}

void buffer_resize(struct buffer *b, size_t new_size) {
    if (new_size <= b->capacity) {
        b->size = new_size;
    }
}

size_t get_mov_eax_imm_size(uint32_t imm) {
    // Check if the immediate value is already null-byte-free
    int has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((imm >> (i * 8)) & 0xFF) == 0x00) {
            has_null = 1;
            break;
        }
    }

    if (!has_null) {
        return 5; // MOV EAX, imm32 (B8 + imm32)
    } else {
        // Try NEG-based approach
        uint32_t negated_val;
        if (find_neg_equivalent(imm, &negated_val)) {
            return 5 + 2; // MOV EAX, negated_val (5 bytes) + NEG EAX (2 bytes)
        } else {
            return 5; // Fallback to direct MOV EAX, imm32 (will contain nulls)
        }
    }
}

void _generate_mov_eax_imm_direct(struct buffer *b, uint32_t imm) {
    uint8_t mov_eax_imm[] = {0xB8, 0, 0, 0, 0};
    memcpy(mov_eax_imm + 1, &imm, 4);
    buffer_append(b, mov_eax_imm, 5);
}

void generate_mov_eax_imm(struct buffer *b, uint32_t imm) {
    // Check if the immediate value is already bad-byte-free (profile-aware, v3.0+)
    // Use is_bad_byte_free() to check ALL configured bad bytes, not just 0x00
    if (is_bad_byte_free(imm)) {
        // If no bad bytes, use the direct MOV EAX, imm32
        _generate_mov_eax_imm_direct(b, imm);
    } else {
        // Try NEG-based approach
        uint32_t negated_val;
        if (find_neg_equivalent(imm, &negated_val)) {
            _generate_mov_eax_imm_direct(b, negated_val);
            uint8_t neg_eax[] = {0xF7, 0xD8}; // NEG EAX
            buffer_append(b, neg_eax, 2);
        } else {
            // Try NOT-based approach
            uint32_t not_val;
            if (find_not_equivalent(imm, &not_val)) {
                _generate_mov_eax_imm_direct(b, not_val);
                uint8_t not_eax[] = {0xF7, 0xD0}; // NOT EAX
                buffer_append(b, not_eax, 2);
            } else {
                // Try XOR encoding approach
                uint32_t xor_key;
                if (find_xor_key(imm, &xor_key)) {
                    uint32_t encoded_val = imm ^ xor_key;
                    
                    // MOV EAX, encoded_val (using null-free construction)
                    generate_mov_eax_imm(b, encoded_val);
                    
                    // XOR EAX, xor_key
                    uint8_t xor_eax_key[] = {0x35, 0, 0, 0, 0};  // XOR EAX, imm32
                    memcpy(xor_eax_key + 1, &xor_key, 4);
                    buffer_append(b, xor_eax_key, 5);
                } else {
                    // Try arithmetic equivalent approach
                    uint32_t base, offset;
                    int operation; // 0 for addition, 1 for subtraction
                    if (find_arithmetic_equivalent(imm, &base, &offset, &operation)) {
                        // MOV EAX, base
                        _generate_mov_eax_imm_direct(b, base);
                        
                        // Perform the arithmetic operation
                        if (operation == 0) { // Addition
                            uint8_t add_eax_offset[] = {0x05, 0, 0, 0, 0};  // ADD EAX, offset
                            memcpy(add_eax_offset + 1, &offset, 4);
                            buffer_append(b, add_eax_offset, 5);
                        } else { // Subtraction
                            uint8_t sub_eax_offset[] = {0x2D, 0, 0, 0, 0};  // SUB EAX, offset  
                            memcpy(sub_eax_offset + 1, &offset, 4);
                            buffer_append(b, sub_eax_offset, 5);
                        }
                    } else {
                        // ============================================================
                        // FIXED: Improved byte-by-byte construction
                        // ============================================================
                        // Clear EAX first using XOR EAX, EAX
                        uint8_t xor_eax_eax[] = {0x31, 0xC0};  // XOR EAX, EAX
                        buffer_append(b, xor_eax_eax, 2);

                        // Find first non-zero byte from MSB to LSB
                        int first_nonzero = -1;
                        for (int i = 3; i >= 0; i--) {
                            if (((imm >> (i * 8)) & 0xFF) != 0) {
                                first_nonzero = i;
                                break;
                            }
                        }

                        if (first_nonzero == -1) {
                            // Value is 0x00000000, already done with XOR EAX, EAX
                            return;
                        }

                        // Load first non-zero byte into AL using safe construction
                        uint8_t first_byte = (imm >> (first_nonzero * 8)) & 0xFF;

                        if (is_bad_byte_free_byte(first_byte)) {
                            // Safe byte - use direct MOV
                            uint8_t mov_al[] = {0xB0, first_byte};  // MOV AL, imm8
                            buffer_append(b, mov_al, 2);
                        } else {
                            // Bad byte - construct using arithmetic from safe values
                            // Find two safe bytes that add/sub/xor to target
                            int found = 0;
                            for (uint8_t base = 1; base < 0xFF && !found; base++) {
                                if (!is_bad_byte_free_byte(base)) continue;

                                uint8_t offset = first_byte - base;
                                if (is_bad_byte_free_byte(offset)) {
                                    // Use ADD: MOV AL, base; ADD AL, offset
                                    uint8_t mov_al[] = {0xB0, base};
                                    buffer_append(b, mov_al, 2);
                                    uint8_t add_al[] = {0x04, offset};  // ADD AL, imm8
                                    buffer_append(b, add_al, 2);
                                    found = 1;
                                }
                            }
                            if (!found) {
                                // Fallback: use larger value and subtract
                                for (uint8_t base = first_byte + 1; base != 0 && !found; base++) {
                                    if (!is_bad_byte_free_byte(base)) continue;

                                    uint8_t offset = base - first_byte;
                                    if (is_bad_byte_free_byte(offset)) {
                                        // Use SUB: MOV AL, base; SUB AL, offset
                                        uint8_t mov_al[] = {0xB0, base};
                                        buffer_append(b, mov_al, 2);
                                        uint8_t sub_al[] = {0x2C, offset};  // SUB AL, imm8
                                        buffer_append(b, sub_al, 2);
                                        found = 1;
                                    }
                                }
                            }
                        }

                        // Process remaining bytes (including zeros)
                        for (int i = first_nonzero - 1; i >= 0; i--) {
                            // Shift left by 8 bits to make room for next byte
                            uint8_t shl_eax_8[] = {0xC1, 0xE0, 0x08};  // SHL EAX, 8
                            buffer_append(b, shl_eax_8, 3);

                            uint8_t byte_val = (imm >> (i * 8)) & 0xFF;
                            if (byte_val != 0) {
                                if (is_bad_byte_free_byte(byte_val)) {
                                    // Safe byte - use direct OR
                                    uint8_t or_al[] = {0x0C, byte_val};  // OR AL, imm8
                                    buffer_append(b, or_al, 2);
                                } else {
                                    // Bad byte - construct using ADD from safe values
                                    int found = 0;
                                    for (uint8_t base = 1; base < byte_val && !found; base++) {
                                        if (!is_bad_byte_free_byte(base)) continue;

                                        uint8_t offset = byte_val - base;
                                        if (is_bad_byte_free_byte(offset)) {
                                            // ADD AL, base; ADD AL, offset
                                            uint8_t add_al_base[] = {0x04, base};
                                            buffer_append(b, add_al_base, 2);
                                            uint8_t add_al_offset[] = {0x04, offset};
                                            buffer_append(b, add_al_offset, 2);
                                            found = 1;
                                        }
                                    }
                                }
                            }
                            // Zero bytes don't need OR - the shift already placed 0x00 in AL
                        }
                    }
                }
            }
        }
    }
}

size_t get_mov_reg_imm_size(cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

    if (reg == X86_REG_EAX) {
        // Use the comprehensive size calculator for EAX
        return get_mov_eax_imm_size(imm);
    } else {
        // Check if direct encoding would have nulls
        uint8_t test_code[] = {0xC7, 0xC0 + get_reg_index(reg), 0, 0, 0, 0};
        memcpy(test_code + 2, &imm, 4);

        int has_null = 0;
        for (int i = 0; i < 6; i++) {
            if (test_code[i] == 0x00) {
                has_null = 1;
                break;
            }
        }

        if (!has_null) {
            return 6; // Direct C7 /0 + imm32
        } else {
            // Use EAX as intermediary: MOV EAX, imm + MOV reg, EAX
            return get_mov_eax_imm_size(imm) + 2;
        }
    }
}

void generate_mov_reg_imm(struct buffer *b, cs_insn *insn) {
    if (!b || !insn || !insn->detail) {
        fprintf(stderr, "[ERROR] Invalid parameters in generate_mov_reg_imm\n");
        return;
    }

    // Check that we have the expected number of operands
    if (insn->detail->x86.op_count < 2) {
        fprintf(stderr, "[ERROR] Not enough operands in generate_mov_reg_imm\n");
        return;
    }

    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

    if (reg == X86_REG_EAX) {
        // For EAX, use the comprehensive null-free generator
        generate_mov_eax_imm(b, imm);
    } else {
        // For other registers: Check if direct encoding would have nulls
        uint8_t test_code[] = {0xC7, 0xC0 + get_reg_index(reg), 0, 0, 0, 0};
        memcpy(test_code + 2, &imm, 4);

        // Check the encoding for null bytes
        int has_null = 0;
        for (int i = 0; i < 6; i++) {
            if (test_code[i] == 0x00) {
                has_null = 1;
                break;
            }
        }

        if (!has_null) {
            // Safe to use direct encoding
            buffer_append(b, test_code, 6);
        } else {
            // Use EAX as intermediary with comprehensive null-free handling
            generate_mov_eax_imm(b, imm);
            // MOV reg, EAX
            uint8_t mov_reg_eax[] = {0x89, 0xC0 + get_reg_index(reg)};
            buffer_append(b, mov_reg_eax, 2);
        }
    }
}

size_t get_op_reg_imm_size(cs_insn *insn) {
    // Generic size for operations like ADD reg, imm32, SUB reg, imm32, etc.
    // Format: op reg, imm32 (83 /0 id for 8-bit, 83 /0 id for 32-bit)
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    
    // Check if immediate can be represented as 8-bit sign-extended
    if ((int32_t)(int8_t)imm == (int32_t)imm) {
        return 3; // 83 /0 ib format
    } else {
        return 6; // 83 /0 id format
    }
}

void generate_op_reg_imm(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    
    // Get opcode based on instruction type
    uint8_t base_opcode;
    switch(insn->id) {
        case X86_INS_ADD: base_opcode = 0x83; break;  // For 8-bit immediate
        case X86_INS_SUB: base_opcode = 0x83; break; 
        case X86_INS_AND: base_opcode = 0x83; break;
        case X86_INS_OR:  base_opcode = 0x83; break;
        case X86_INS_XOR: base_opcode = 0x83; break;
        case X86_INS_CMP: base_opcode = 0x83; break;
        default: base_opcode = 0x83; break;
    }
    
    // Check if immediate can be represented as 8-bit sign-extended
    if ((int32_t)(int8_t)imm == (int32_t)imm) {
        uint8_t code[] = {base_opcode, 0xC0 + get_reg_index(reg), (uint8_t)imm};
        buffer_append(b, code, 3);
    } else {
        uint8_t code[] = {0x83, 0xC0 + get_reg_index(reg), 0, 0, 0, 0};
        code[0] = base_opcode + 0x01; // Switch from 83 to 81 for 32-bit immediate
        memcpy(code + 2, &imm, 4);
        buffer_append(b, code, 6);
    }
}

size_t get_push_imm32_size(__attribute__((unused)) uint32_t imm) {
    return 5; // 68 + imm32 for PUSH imm32 (using 68 for 32-bit push)
}

void generate_push_imm32(struct buffer *b, uint32_t imm) {
    // Check if the immediate value has null bytes
    int has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((imm >> (i * 8)) & 0xFF) == 0x00) {
            has_null = 1;
            break;
        }
    }

    if (!has_null) {
        // Direct encoding - no null bytes
        uint8_t code[] = {0x68, 0, 0, 0, 0};  // PUSH imm32
        memcpy(code + 1, &imm, 4);
        buffer_append(b, code, 5);
    } else {
        // Use alternative: construct value in EAX then PUSH EAX
        // Save original EAX value first
        uint8_t push_eax[] = {0x50};  // PUSH EAX
        buffer_append(b, push_eax, 1);

        // Load the value into EAX (this handles nulls)
        generate_mov_eax_imm(b, imm);

        // Exchange with stack top: XCHG [ESP], EAX
        // This puts our value on stack and restores EAX
        uint8_t xchg_esp_eax[] = {0x87, 0x04, 0x24};  // XCHG [ESP], EAX
        buffer_append(b, xchg_esp_eax, 3);
    }
}

size_t get_push_imm8_size() {
    return 2; // 6A + imm8 for PUSH imm8
}

void generate_push_imm8(struct buffer *b, int8_t imm) {
    uint8_t code[] = {0x6A, (uint8_t)imm};
    buffer_append(b, code, 2);
}

size_t get_mov_reg_mem_imm_size(cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[1].mem.disp;
    // MOV reg, [imm32] -> MOV EAX, imm32 + MOV reg, [EAX]
    return get_mov_eax_imm_size(addr) + 2;  // 2 for MOV reg, [EAX] instruction
}

void generate_mov_reg_mem_imm(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t addr = (uint32_t)insn->detail->x86.operands[1].mem.disp;
    
    // MOV EAX, addr
    generate_mov_eax_imm(b, addr);
    
    // MOV reg, [EAX]
    // FIXED: Use profile-safe SIB generation instead of hardcoded 0x20
    if (generate_safe_mov_reg_mem(b, reg, X86_REG_EAX) != 0) {
        // Fallback
        uint8_t push[] = {0xFF, 0x30};  // PUSH [EAX]
        buffer_append(b, push, 2);
        uint8_t pop[] = {(uint8_t)(0x58 | get_reg_index(reg))};  // POP reg
        buffer_append(b, pop, 1);
    }
}

size_t get_lea_reg_mem_disp32_size(cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[1].mem.disp;
    // LEA reg, [disp32] -> MOV EAX, disp32 + LEA reg, [EAX]
    return get_mov_eax_imm_size(addr) + 2;  // 2 for LEA reg, [EAX] instruction
}

void generate_lea_reg_mem_disp32(struct buffer *b, cs_insn *insn) {
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;
    uint32_t addr = (uint32_t)insn->detail->x86.operands[1].mem.disp;
    
    // MOV EAX, addr
    generate_mov_eax_imm(b, addr);
    
    // LEA dst_reg, [EAX]
    // FIXED: Use profile-safe SIB generation instead of hardcoded 0x20
    if (generate_safe_lea_reg_mem(b, dst_reg, X86_REG_EAX) != 0) {
        // Fallback - LEA is just MOV for [reg] with no displacement
        uint8_t mov[] = {0x89, (uint8_t)(0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(dst_reg))};
        buffer_append(b, mov, 2);
    }
}

size_t get_mov_disp32_reg_size(cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;
    // MOV EAX, addr (null-free) + MOV [EAX], reg
    return get_mov_eax_imm_size(addr) + 2;  // 2 for MOV [EAX], reg instruction
}

void generate_mov_disp32_reg(struct buffer *b, cs_insn *insn) {
    uint8_t src_reg = insn->detail->x86.operands[1].reg;
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;
    
    // MOV EAX, addr
    generate_mov_eax_imm(b, addr);
    
    // MOV [EAX], src_reg
    // FIXED: Use profile-safe SIB generation instead of hardcoded 0x20
    if (generate_safe_mov_mem_reg(b, X86_REG_EAX, src_reg) != 0) {
        // Fallback
        uint8_t push[] = {(uint8_t)(0x50 | get_reg_index(src_reg))};  // PUSH src_reg
        buffer_append(b, push, 1);
        uint8_t pop[] = {0x8F, 0x00};  // POP [EAX]
        buffer_append(b, pop, 2);
    }
}

size_t get_cmp_mem32_reg_size(cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;
    // CMP [disp32], reg -> MOV EAX, disp32 + CMP [EAX], reg
    return get_mov_eax_imm_size(addr) + 2;  // 2 for CMP [EAX], reg instruction
}

void generate_cmp_mem32_reg(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[1].reg;
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;
    
    // MOV EAX, addr
    generate_mov_eax_imm(b, addr);
    
    // CMP [EAX], reg
    // FIXED: Use profile-safe SIB generation for CMP instruction
    sib_encoding_result_t enc = select_sib_encoding_for_eax(reg);
    if (enc.strategy == SIB_ENCODING_STANDARD) {
        uint8_t code[3] = {0x39, enc.modrm_byte, enc.sib_byte};
        buffer_append(b, code, ((enc.modrm_byte & 0x07) == 0x04) ? 3 : 2);
    } else {
        // Complex fallback for CMP
        uint8_t push[] = {0xFF, 0x30};  // PUSH [EAX]
        buffer_append(b, push, 2);
        uint8_t pop_temp[] = {0x5A};  // POP EDX (temp)
        buffer_append(b, pop_temp, 1);
        uint8_t cmp[] = {0x39, (uint8_t)(0xC0 | (get_reg_index(reg) << 3) | 2)};  // CMP EDX, reg
        buffer_append(b, cmp, 2);
    }
}

size_t get_arith_mem32_imm32_size(__attribute__((unused)) cs_insn *insn) {
    // This would involve loading address to EAX, then performing the arithmetic operation
    return 9;  // Conservative estimate: MOV EAX, addr (5) + arithmetic (4)
}

void generate_arith_mem32_imm32(struct buffer *b, cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    
    // MOV EAX, addr
    generate_mov_eax_imm(b, addr);
    
    // Perform arithmetic operation on [EAX] with immediate
    // This is a simplified implementation - actual opcodes would vary by instruction type
    uint8_t base_opcode;
    switch(insn->id) {
        case X86_INS_ADD: base_opcode = 0x83; break;  // For 8-bit immediate
        case X86_INS_SUB: base_opcode = 0x83; break; 
        case X86_INS_AND: base_opcode = 0x83; break;
        case X86_INS_OR:  base_opcode = 0x83; break;
        case X86_INS_XOR: base_opcode = 0x83; break;
        case X86_INS_CMP: base_opcode = 0x83; break;
        default: base_opcode = 0x83; break;
    }
    
    // For now, using a 32-bit immediate for memory operations
    // FIXED: Use profile-safe SIB generation
    uint8_t opcode = base_opcode + 0x01;  // Switch from 83 to 81 for 32-bit immediate
    sib_encoding_result_t enc = select_sib_encoding_for_eax(X86_REG_EAX);

    if (enc.strategy == SIB_ENCODING_STANDARD) {
        uint8_t fixed_code[] = {opcode, enc.modrm_byte, enc.sib_byte, 0, 0, 0, 0};
        memcpy(fixed_code + 3, &imm, 4);
        buffer_append(b, fixed_code, ((enc.modrm_byte & 0x07) == 0x04) ? 7 : 6);
    } else {
        // Complex fallback - load value, perform operation, store back
        uint8_t push[] = {0xFF, 0x30};  // PUSH [EAX]
        buffer_append(b, push, 2);
        uint8_t pop[] = {0x5A};  // POP EDX
        buffer_append(b, pop, 1);

        // Perform operation on EDX
        uint8_t op_imm[] = {opcode, 0xC2, 0, 0, 0, 0};  // OP EDX, imm32
        memcpy(op_imm + 2, &imm, 4);
        buffer_append(b, op_imm, 6);

        // Store result back
        uint8_t push_edx[] = {0x52};  // PUSH EDX
        buffer_append(b, push_edx, 1);
        uint8_t pop_mem[] = {0x8F, 0x00};  // POP [EAX]
        buffer_append(b, pop_mem, 2);
    }
}

size_t get_xor_reg_reg_size(__attribute__((unused)) cs_insn *insn) {
    return 2; // 31 /r format for XOR reg, reg
}

void generate_xor_reg_reg(struct buffer *b, cs_insn *insn) {
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;
    uint8_t src_reg = insn->detail->x86.operands[1].reg;
    
    uint8_t code[] = {0x31, 0xC0};
    code[1] = (get_reg_index(dst_reg) << 3) + get_reg_index(src_reg);
    buffer_append(b, code, 2);
}

size_t get_cdq_size() {
    return 1; // CDQ is 1 byte (99)
}

void generate_cdq(struct buffer *b) {
    uint8_t cdq[] = {0x99};
    buffer_append(b, cdq, 1);
}

size_t get_mul_reg_size(__attribute__((unused)) uint8_t reg) {
    return 2; // 0FA6 + reg for MUL reg
}

void generate_mul_reg(struct buffer *b, uint8_t reg) {
    uint8_t code[] = {0xF7, 0xE0};
    code[1] = 0xE0 + get_reg_index(reg);
    buffer_append(b, code, 2);
}

size_t get_push_pop_size(__attribute__((unused)) cs_insn *insn) {
    return 4; // Approximate size for PUSH/POP sequences
}

void generate_push_pop(struct buffer *b, cs_insn *insn) {
    // Implementation would depend on the specific instruction
    // For now, just use the original instruction as a placeholder
    buffer_append(b, insn->bytes, insn->size);
}

size_t get_get_pc_size() {
    return 5; // CALL next instruction + POP reg
}

void generate_get_pc(struct buffer *b, uint8_t reg) {
    // CALL next instruction (5 bytes) + POP reg (1 byte)
    uint8_t call_next[] = {0xE8, 0x00, 0x00, 0x00, 0x00};
    uint8_t pop_reg[] = {0x58 + get_reg_index(reg)};
    
    buffer_append(b, call_next, 5);
    buffer_append(b, pop_reg, 1);
}

size_t get_mov_reg_imm_get_pc_size(__attribute__((unused)) cs_insn *insn, __attribute__((unused)) struct instruction_node *current) {
    return 10; // Approximate for GET PC technique
}

void generate_mov_reg_imm_get_pc(struct buffer *b, cs_insn *insn) {
    // Implementation for GET PC technique
    // This is a simplified version - in practice would need to calculate offset correctly
    uint8_t reg = insn->detail->x86.operands[0].reg;
    
    // CALL next + POP reg to get PC
    generate_get_pc(b, reg);
    
    // Then add offset to get the desired value
    // This is a placeholder implementation
}

size_t get_find_kernel32_base_size() {
    return 10; // Placeholder size
}

void generate_find_kernel32_base(__attribute__((unused)) struct buffer *b) {
    // Placeholder implementation
}

size_t get_find_get_proc_address_size() {
    return 10; // Placeholder size
}

void generate_find_get_proc_address(__attribute__((unused)) struct buffer *b) {
    // Placeholder implementation
}

size_t get_call_imm_dynamic_size() {
    // CALL via register instead of immediate
    return 7; // MOV EAX, imm32 + CALL EAX
}

void generate_call_imm_dynamic(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[0].imm;
    
    // MOV EAX, target
    generate_mov_eax_imm(b, target);
    
    // CALL EAX
    uint8_t call_eax[] = {0xFF, 0xD0};
    buffer_append(b, call_eax, 2);
}

size_t get_call_imm_size(__attribute__((unused)) cs_insn *insn) {
    // CALL via register instead of immediate when immediate contains nulls
    return 7; // MOV EAX, imm32 + CALL EAX
}

void generate_call_imm(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[0].imm;
    
    // MOV EAX, target
    generate_mov_eax_imm(b, target);
    
    // CALL EAX
    uint8_t call_eax[] = {0xFF, 0xD0};
    buffer_append(b, call_eax, 2);
}

size_t get_mov_reg_imm_shift_size(__attribute__((unused)) cs_insn *insn) {
    // MOV reg, imm32 (5 bytes) + SHR/SHL reg, imm8 (3 bytes) = 8 bytes
    return 8;
}

void generate_mov_reg_imm_shift(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;

    // Try left shifts (SHL) - useful when low bytes are zero
    for (int shift_amount = 1; shift_amount <= 24; shift_amount++) {
        uint32_t shifted = target << shift_amount;
        if (is_bad_byte_free(shifted)) {
            // MOV reg, shifted_value
            cs_insn temp_insn = *insn;
            temp_insn.detail->x86.operands[1].imm = shifted;
            generate_mov_reg_imm(b, &temp_insn);

            // SHR reg, shift_amount
            uint8_t code[] = {0xC1, 0xE8, 0};
            code[1] = 0xE8 + get_reg_index(reg);
            code[2] = shift_amount;
            buffer_append(b, code, 3);
            return;
        }
    }

    // Try right shifts (SHR) - useful when high bytes are zero
    for (int shift_amount = 1; shift_amount <= 24; shift_amount++) {
        uint32_t shifted = target >> shift_amount;
        if (shifted != 0 && is_bad_byte_free(shifted)) {
            // MOV reg, shifted_value
            cs_insn temp_insn = *insn;
            temp_insn.detail->x86.operands[1].imm = shifted;
            generate_mov_reg_imm(b, &temp_insn);

            // SHL reg, shift_amount
            uint8_t code[] = {0xC1, 0xE0, 0};
            code[1] = 0xE0 + get_reg_index(reg);
            code[2] = shift_amount;
            buffer_append(b, code, 3);
            return;
        }
    }

    // Fallback if no suitable shift found
    generate_mov_reg_imm(b, insn);
}

int find_neg_equivalent(uint32_t target, uint32_t *negated_val) {
    // Calculate the two's complement negative of the target value
    *negated_val = (~target) + 1;
    
    // Check if the negated value has no null bytes
    int has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((*negated_val >> (i * 8)) & 0xFF) == 0) {
            has_null = 1;
            break;
        }
    }
    return !has_null;  // Return 1 if no null bytes in negated value
}

size_t get_mov_reg_imm_neg_size(__attribute__((unused)) cs_insn *insn) {
    return 7; // MOV reg, imm (no nulls) + NEG reg = ~6-7 bytes
}

void generate_mov_reg_imm_neg(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    
    // Find the negated value that has no null bytes
    uint32_t negated_val;
    if (find_neg_equivalent(imm, &negated_val)) {
        // MOV reg, negated_val (that has no nulls)
        cs_insn temp_insn = *insn;
        temp_insn.detail->x86.operands[1].imm = negated_val;
        generate_mov_reg_imm(b, &temp_insn);
        
        // NEG reg
        uint8_t neg_code[] = {0xF7, 0xD8};
        neg_code[1] = neg_code[1] + get_reg_index(reg);
        buffer_append(b, neg_code, 2);
    } else {
        // Fallback to original implementation
        generate_mov_reg_imm(b, insn);
    }
}

size_t get_op_reg_imm_neg_size(__attribute__((unused)) cs_insn *insn) {
    return 9; // MOV EAX, negated_imm + op reg, EAX + cleanup = ~9 bytes
}

void generate_op_reg_imm_neg(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    
    // Find the negated value that has no null bytes
    uint32_t negated_val;
    if (find_neg_equivalent(imm, &negated_val)) {
        // MOV EAX, negated_val
        generate_mov_eax_imm(b, negated_val);
        
        // Apply the operation: op reg, EAX
        uint8_t op_code;
        switch(insn->id) {
            case X86_INS_ADD: op_code = 0x01; break;
            case X86_INS_SUB: op_code = 0x29; break;
            case X86_INS_AND: op_code = 0x21; break;
            case X86_INS_OR:  op_code = 0x09; break;
            case X86_INS_XOR: op_code = 0x31; break;
            case X86_INS_CMP: op_code = 0x39; break;
            default: op_code = 0x01; break;  // default to ADD
        }
        
        uint8_t code[] = {op_code, 0xC0};
        code[1] = code[1] + (get_reg_index(reg) << 3) + get_reg_index(X86_REG_EAX);
        buffer_append(b, code, 2);
    } else {
        // Fallback to original implementation
        generate_op_reg_imm(b, insn);
    }
}

size_t get_xor_encoded_mov_size(cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    // MOV reg, encoded_imm32 (5 bytes) + XOR reg, key (5 for EAX, 6 for others)
    return (reg == X86_REG_EAX) ? 10 : 11;
}

void generate_xor_encoded_mov(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;

    // Try to find a null-free XOR key
    uint32_t xor_keys[] = {
        0x01010101, 0x11111111, 0x22222222, 0x33333333,
        0x44444444, 0x55555555, 0x66666666, 0x77777777,
        0x88888888, 0x99999999, 0xAAAAAAAA, 0xBBBBBBBB,
        0xCCCCCCCC, 0xDDDDDDDD, 0xEEEEEEEE, 0xFFFFFFFF
    };

    for (size_t i = 0; i < sizeof(xor_keys)/sizeof(xor_keys[0]); i++) {
        uint32_t encoded = target ^ xor_keys[i];
        if (is_bad_byte_free(encoded) && is_bad_byte_free(xor_keys[i])) {
            // MOV reg, encoded_value
            cs_insn temp_insn = *insn;
            temp_insn.detail->x86.operands[1].imm = encoded;
            generate_mov_reg_imm(b, &temp_insn);

            // XOR reg, key
            if (reg == X86_REG_EAX) {
                // XOR EAX, imm32
                uint8_t code[] = {0x35, 0, 0, 0, 0};
                memcpy(code + 1, &xor_keys[i], 4);
                buffer_append(b, code, 5);
            } else {
                // XOR reg, imm32
                uint8_t code[] = {0x81, 0xF0, 0, 0, 0, 0};
                code[1] = 0xF0 + get_reg_index(reg);
                memcpy(code + 2, &xor_keys[i], 4);
                buffer_append(b, code, 6);
            }
            return;
        }
    }

    // Fallback if no suitable key found
    generate_mov_reg_imm(b, insn);
}

size_t get_xor_encoded_arithmetic_size(__attribute__((unused)) cs_insn *insn) {
    return 12; // Placeholder
}

void generate_xor_encoded_arithmetic(struct buffer *b, cs_insn *insn) {
    // Implementation would use XOR encoding technique for arithmetic operations
    // For now, use original implementation as fallback
    generate_op_reg_imm(b, insn);
}

// ADD/SUB Encoding functions
// Find a suitable add/sub operation that when applied to the target doesn't produce null bytes in the encoded value
int find_addsub_key(uint32_t target, uint32_t *val1, uint32_t *val2, int *is_add) {
    // Try systematic offsets first (more likely to succeed)
    uint32_t offsets[] = {
        0x01010101, 0x11111111, 0x22222222, 0x33333333,
        0x44444444, 0x55555555, 0x66666666, 0x77777777,
        0x88888888, 0x99999999, 0xAAAAAAAA, 0xBBBBBBBB,
        0xCCCCCCCC, 0xDDDDDDDD, 0xEEEEEEEE, 0xFFFFFFFF,
        0x12345678, 0x87654321, 0xABCDEF01, 0xFEDCBA98
    };

    for (size_t i = 0; i < sizeof(offsets)/sizeof(offsets[0]); i++) {
        // Try SUB: val1 - offset = target  =>  val1 = target + offset
        uint32_t temp_val1 = target + offsets[i];
        if (is_bad_byte_free(temp_val1) && is_bad_byte_free(offsets[i])) {
            *val1 = temp_val1;
            *val2 = offsets[i];
            *is_add = 0; // SUB
            return 1;
        }

        // Try ADD: val1 + offset = target  =>  val1 = target - offset
        temp_val1 = target - offsets[i];
        if (is_bad_byte_free(temp_val1) && is_bad_byte_free(offsets[i])) {
            *val1 = temp_val1;
            *val2 = offsets[i];
            *is_add = 1; // ADD
            return 1;
        }
    }

    // Fall back to random search for remaining cases
    for (int i = 0; i < 5000; i++) {  // Increased from 1000
        // Use a local random approach to avoid global state issues
        uint32_t temp_val2 = (uint32_t)rand() | 0x01010101; // Ensure no zero bytes by ORing with pattern
        if (!is_bad_byte_free(temp_val2)) continue;

        uint32_t temp_val1 = target + temp_val2;
        if (is_bad_byte_free(temp_val1)) {
            *val1 = temp_val1;
            *val2 = temp_val2;
            *is_add = 0;
            return 1;
        }

        temp_val1 = target - temp_val2;
        if (is_bad_byte_free(temp_val1)) {
            *val1 = temp_val1;
            *val2 = temp_val2;
            *is_add = 1;
            return 1;
        }
    }

    return 0; // No suitable key found
}

size_t get_addsub_encoded_mov_size(__attribute__((unused)) cs_insn *insn) {
    // MOV EAX, encoded_val (5 bytes) + ADD/SUB EAX, key (6 bytes) = 11 bytes
    return 11;
}

void generate_addsub_encoded_mov(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t target_reg = insn->detail->x86.operands[0].reg;
    
    uint32_t val1, val2;
    int is_add;
    if (!find_addsub_key(target, &val1, &val2, &is_add)) {
        // If we can't find a good ADD/SUB key, this strategy can't handle it
        // The system will fall back to other strategies
        generate_mov_reg_imm(b, insn);
        return;
    }
    
    // If target register is EAX, we can work directly
    if (target_reg == X86_REG_EAX) {
        uint32_t encoded_val = is_add ? (target + val2) : (target - val2);
        
        // MOV EAX, encoded_val (using null-free construction)
        generate_mov_eax_imm(b, encoded_val);
        
        // ADD/SUB EAX, key
        if (is_add) {
            uint8_t add_eax_key[] = {0x05, 0, 0, 0, 0};  // ADD EAX, imm32
            memcpy(add_eax_key + 1, &val2, 4);
            buffer_append(b, add_eax_key, 5);
        } else {
            uint8_t sub_eax_key[] = {0x2D, 0, 0, 0, 0};  // SUB EAX, imm32
            memcpy(sub_eax_key + 1, &val2, 4);
            buffer_append(b, sub_eax_key, 5);
        }
    } else {
        // For other registers, use a save/restore approach
        uint32_t encoded_val = is_add ? (target + val2) : (target - val2);
        
        // PUSH EAX
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);
        
        // MOV EAX, encoded_val
        generate_mov_eax_imm(b, encoded_val);
        
        // ADD/SUB EAX, key
        if (is_add) {
            uint8_t add_eax_key[] = {0x05, 0, 0, 0, 0};  // ADD EAX, imm32
            memcpy(add_eax_key + 1, &val2, 4);
            buffer_append(b, add_eax_key, 5);
        } else {
            uint8_t sub_eax_key[] = {0x2D, 0, 0, 0, 0};  // SUB EAX, imm32
            memcpy(sub_eax_key + 1, &val2, 4);
            buffer_append(b, sub_eax_key, 5);
        }
        
        // MOV target_reg, EAX
        uint8_t mov_reg_eax[] = {0x89, 0xC0};  // MOV reg, EAX
        mov_reg_eax[1] = mov_reg_eax[1] + get_reg_index(target_reg);
        buffer_append(b, mov_reg_eax, 2);
        
        // POP EAX
        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
    }
}

size_t get_addsub_encoded_arithmetic_size(__attribute__((unused)) cs_insn *insn) {
    // MOV EAX, encoded_val (5 bytes) + ADD/SUB EAX, key (6 bytes) + OP reg, EAX (2 bytes)
    return 13;
}

void generate_addsub_encoded_arithmetic(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t target_reg = insn->detail->x86.operands[0].reg;
    
    uint32_t val1, val2;
    int is_add;
    if (!find_addsub_key(target, &val1, &val2, &is_add)) {
        // If we can't find a good ADD/SUB key, this strategy can't handle it
        // The system will fall back to other strategies
        generate_op_reg_imm(b, insn);
        return;
    }
    
    // We'll use a temporary register approach similar to XOR encoding
    // PUSH target_reg
    uint8_t push_reg = 0x50 + get_reg_index(target_reg);
    buffer_append(b, &push_reg, 1);
    
    // MOV EAX, encoded_val (using null-free construction)
    uint32_t encoded_val = is_add ? (target + val2) : (target - val2);
    generate_mov_eax_imm(b, encoded_val);
    
    // ADD/SUB EAX, key
    if (is_add) {
        uint8_t add_eax_key[] = {0x05, 0, 0, 0, 0};  // ADD EAX, imm32
        memcpy(add_eax_key + 1, &val2, 4);
        buffer_append(b, add_eax_key, 5);
    } else {
        uint8_t sub_eax_key[] = {0x2D, 0, 0, 0, 0};  // SUB EAX, imm32
        memcpy(sub_eax_key + 1, &val2, 4);
        buffer_append(b, sub_eax_key, 5);
    }
    
    // Now perform the original operation with EAX
    // For example: if original was ADD EBX, imm32 -> we do ADD EBX, EAX
    uint8_t op_code[2];
    switch(insn->id) {
        case X86_INS_ADD: op_code[0] = 0x01; op_code[1] = 0xC0 + get_reg_index(target_reg); break;  // ADD reg, EAX
        case X86_INS_SUB: op_code[0] = 0x29; op_code[1] = 0xC0 + get_reg_index(target_reg); break;  // SUB reg, EAX
        case X86_INS_AND: op_code[0] = 0x21; op_code[1] = 0xC0 + get_reg_index(target_reg); break;  // AND reg, EAX
        case X86_INS_OR:  op_code[0] = 0x09; op_code[1] = 0xC0 + get_reg_index(target_reg); break;  // OR reg, EAX
        case X86_INS_XOR: op_code[0] = 0x31; op_code[1] = 0xC0 + get_reg_index(target_reg); break;  // XOR reg, EAX
        case X86_INS_CMP: op_code[0] = 0x39; op_code[1] = 0xC0 + get_reg_index(target_reg); break;  // CMP reg, EAX
        default: {
            // POP target_reg to undo the push
            uint8_t pop_reg = 0x58 + get_reg_index(target_reg);
            buffer_append(b, &pop_reg, 1);
            generate_op_reg_imm(b, insn);  // Use original implementation
            return;
        }
    }
    
    buffer_append(b, op_code, 2);
    
    // POP target_reg (restores original value)
    uint8_t pop_reg = 0x58 + get_reg_index(target_reg);
    buffer_append(b, &pop_reg, 1);
}

// Missing functions for arithmetic strategies
size_t get_mov_reg_imm_arithmetic_size(__attribute__((unused)) cs_insn *insn) {
    // Using arithmetic to construct the value: MOV EAX, base_val + arithmetic to get target
    return 10; // Placeholder for arithmetic value construction
}

void generate_mov_reg_imm_arithmetic(struct buffer *b, cs_insn *insn) {
    // Using arithmetic to construct the value
    // For example: MOV EAX, 0x00200404; SUB EAX, 0x404 (if target is 0x00200000)
    
    // This is a complex implementation that would find arithmetic equivalents
    // For now, use a simpler approach
    generate_mov_reg_imm(b, insn);
}

int find_not_equivalent(uint32_t target, uint32_t *not_val) {
    *not_val = ~target;
    
    int has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((*not_val >> (i * 8)) & 0xFF) == 0) {
            has_null = 1;
            break;
        }
    }
    return !has_null;
}

size_t get_mov_reg_imm_not_size(__attribute__((unused)) cs_insn *insn) {
    return 7; // MOV reg, imm (no nulls) + NOT reg = ~6-7 bytes
}

void generate_mov_reg_imm_not(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    
    uint32_t not_val;
    if (find_not_equivalent(imm, &not_val)) {
        cs_insn temp_insn = *insn;
        temp_insn.detail->x86.operands[1].imm = not_val;
        generate_mov_reg_imm(b, &temp_insn);
        
        uint8_t not_code[] = {0xF7, 0xD0};
        not_code[1] = not_code[1] + get_reg_index(reg);
        buffer_append(b, not_code, 2);
    } else {
        generate_mov_reg_imm(b, insn);
    }
}

size_t get_op_reg_imm_not_size(__attribute__((unused)) cs_insn *insn) {
    // PUSH + MOV + NOT + XOR + POP
    return 12; // Conservative estimate
}

void generate_op_reg_imm_not(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t not_val;

    if (find_not_equivalent(imm, &not_val)) {
        uint8_t temp_reg = X86_REG_EAX;
        if (reg == X86_REG_EAX) {
            temp_reg = X86_REG_ECX; // Use ECX if EAX is the destination
        }

        // PUSH temp_reg
        uint8_t push_op = 0x50 + get_reg_index(temp_reg);
        buffer_append(b, &push_op, 1);

        // MOV temp_reg, not_val
        cs_insn temp_mov_insn = *insn;
        temp_mov_insn.detail->x86.operands[0].reg = temp_reg;
        temp_mov_insn.detail->x86.operands[1].imm = not_val;
        generate_mov_reg_imm(b, &temp_mov_insn);

        // NOT temp_reg
        uint8_t not_code[] = {0xF7, 0xD0 + get_reg_index(temp_reg)};
        buffer_append(b, not_code, 2);

        // XOR reg, temp_reg
        uint8_t xor_code[] = {0x31, 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(reg)};
        buffer_append(b, xor_code, 2);

        // POP temp_reg
        uint8_t pop_op = 0x58 + get_reg_index(temp_reg);
        buffer_append(b, &pop_op, 1);

    } else {
        generate_op_reg_imm(b, insn);
    }
}

// ============================================================================
// Generic Bad Character Checking Functions (v3.0)
// ============================================================================

/**
 * Check if a single byte is free of bad bytes
 * Uses global bad byte context for O(1) lookup
 * @param byte: Byte to check
 * @return: 1 if ok, 0 if bad
 */
int is_bad_byte_free_byte(uint8_t byte) {
    // If context uninitialized, default to null-byte checking only
    if (!g_bad_byte_context.initialized) {
        return byte != 0x00;
    }
    // O(1) bitmap lookup
    return g_bad_byte_context.config.bad_bytes[byte] == 0;
}

/**
 * Check if a 32-bit value is free of bad bytes
 * @param val: 32-bit value to check
 * @return: 1 if all 4 bytes ok, 0 if any byte is bad
 */
int is_bad_byte_free(uint32_t val) {
    // Check each byte
    for (int i = 0; i < 4; i++) {
        uint8_t byte = (val >> (i * 8)) & 0xFF;
        if (!is_bad_byte_free_byte(byte)) {
            return 0;  // Found a bad byte
        }
    }
    return 1;  // All bytes ok
}

/**
 * Check if a buffer is free of bad bytes
 * @param data: Buffer to check
 * @param size: Buffer size
 * @return: 1 if all bytes ok, 0 if any byte is bad
 */
int is_bad_byte_free_buffer(const uint8_t *data, size_t size) {
    if (!data) {
        return 1;  // NULL buffer is considered ok
    }
    for (size_t i = 0; i < size; i++) {
        if (!is_bad_byte_free_byte(data[i])) {
            return 0;  // Found a bad byte
        }
    }
    return 1;  // All bytes ok
}

// ============================================================================
// Backward Compatibility Wrappers (DEPRECATED in v3.0)
// ============================================================================

/**
 * DEPRECATED: Use is_bad_byte_free_byte() instead
 * Maintained for backward compatibility
 */
int is_null_free_byte(uint8_t byte) {
    return is_bad_byte_free_byte(byte);
}

/**
 * DEPRECATED: Use is_bad_byte_free() instead
 * Maintained for backward compatibility
 */
int is_null_free(uint32_t val) {
    return is_bad_byte_free(val);
}

// Find a XOR key to construct the target value without null bytes
int find_xor_key(uint32_t target, uint32_t *xor_key) {
    // Simple approach: try some common XOR keys that don't have null bytes
    uint32_t test_keys[] = {0x41414141, 0x42424242, 0x43434343, 0x55555555, 0xAAAAAAAA, 0x12345678, 0x87654321};
    int num_keys = sizeof(test_keys) / sizeof(test_keys[0]);
    
    for (int i = 0; i < num_keys; i++) {
        uint32_t encoded = target ^ test_keys[i];
        if (is_bad_byte_free(test_keys[i]) && is_bad_byte_free(encoded)) {
            *xor_key = test_keys[i];
            return 1; // Found a valid key
        }
    }
    return 0; // No valid key found
}

// Find arithmetic equivalent (base +/- offset) to construct the target value without null bytes
int find_arithmetic_equivalent(uint32_t target, uint32_t *base, uint32_t *offset, int *operation) {
    // Prioritize offsets that won't create null bytes when encoded as 32-bit immediates
    // Small values like 1, 2, 5, 10 encode as 0x00000001, 0x00000002, etc. which have nulls
    // Prioritize: null-free 32-bit patterns, sign-extended 8-bit values (0x7F, etc.), then small values
    uint32_t test_offsets[] = {
        0x01010101, 0x02020202, 0x05050505, 0x0A0A0A0A,  // Null-free repeating patterns
        0x7F7F7F7F, 0x7E7E7E7E, 0x7D7D7D7D,              // Sign-extendable patterns
        0x7F, 0x7E, 0x7D, 0x50, 0x40, 0x30, 0x20, 0x10,  // 8-bit sign-extendable values
        0x100, 0x1000, 0x10000,                           // Powers of 2
        1, 2, 5, 10  // Small values (last resort - will be caught by validation)
    };
    int num_offsets = sizeof(test_offsets) / sizeof(test_offsets[0]);

    for (int i = 0; i < num_offsets; i++) {
        if (target >= test_offsets[i]) {  // For addition, target must be >= offset
            uint32_t test_base = target - test_offsets[i];
            if (is_bad_byte_free(test_base) && is_bad_byte_free(test_offsets[i])) {
                *base = test_base;
                *offset = test_offsets[i];
                *operation = 0;  // Addition
                return 1;
            }
        }

        // Also try subtraction: base - offset = target
        uint32_t test_base = target + test_offsets[i];
        if (is_bad_byte_free(test_base) && is_bad_byte_free(test_offsets[i])) {
            *base = test_base;
            *offset = test_offsets[i];
            *operation = 1;  // Subtraction
            return 1;
        }
    }

    return 0;  // No valid combination found
}

// Helper function to validate no null bytes in buffer region
static inline void verify_no_nulls(struct buffer *b, size_t start, const char* func_name) {
    for (size_t i = start; i < b->size; i++) {
        if (b->data[i] == 0x00) {
            fprintf(stderr, "ERROR: Null byte detected at offset %zu (function: %s)\n", i - start, func_name);
        }
    }
}

// Create parent directories for a file path if they don't exist
int create_parent_dirs(const char *filepath) {
    if (!filepath || filepath[0] == '\0') {
        return -1;
    }

    // Make a copy of the path since dirname may modify it
    char *path_copy = strdup(filepath);
    if (!path_copy) {
        return -1;
    }

    // Get the directory part
    char *dir = dirname(path_copy);

    // If directory is "." or "/", no need to create
    if (strcmp(dir, ".") == 0 || strcmp(dir, "/") == 0) {
        free(path_copy);
        return 0;
    }

    // Check if directory exists
    struct stat st;
    if (stat(dir, &st) == 0) {
        // Directory exists
        free(path_copy);
        return S_ISDIR(st.st_mode) ? 0 : -1;
    }

    // Directory doesn't exist, create parent directories recursively
    char *path_for_recursion = strdup(dir);
    if (!path_for_recursion) {
        free(path_copy);
        return -1;
    }

    int result = create_parent_dirs(path_for_recursion);
    free(path_for_recursion);

    if (result != 0) {
        free(path_copy);
        return -1;
    }

    // Create this directory
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        free(path_copy);
        return -1;
    }

    free(path_copy);
    return 0;
}

/*
 * Generate PUSH with automatic selection of 8-bit or 32-bit immediate
 * based on the value to avoid null bytes when possible
 */
void generate_push_imm(struct buffer *b, uint32_t imm) {
    // Check if the immediate can be represented as a sign-extended 8-bit value
    // and the sign-extended 8-bit form doesn't contain null bytes
    if ((int32_t)imm >= -128 && (int32_t)imm <= 127) {
        int8_t imm8 = (int8_t)imm;
        // Only use 8-bit push if the immediate value itself is not zero (which would generate a null byte in the instruction)
        if (imm8 != 0) {
            generate_push_imm8(b, imm8);
        } else {
            // For zero, we need to use 32-bit push since PUSH 0x00 contains a null
            generate_push_imm32(b, imm);
        }
    } else {
        // Use 32-bit push for values outside 8-bit range
        generate_push_imm32(b, imm);
    }
}

/*
 * Generate MOV AL, immediate_byte without null bytes in instruction encoding
 */
void generate_mov_eax_imm_byte(struct buffer *b, uint8_t imm) {
    // If the immediate is 0, we can't use MOV AL, 0x00 as it would create a null
    if (imm == 0) {
        // XOR EAX, EAX to zero out, then we'll have AL=0
        uint8_t xor_eax_eax[] = {0x31, 0xC0};  // XOR EAX, EAX (no nulls)
        buffer_append(b, xor_eax_eax, 2);
    } else {
        // For non-zero bytes, we can safely use MOV AL, imm8
        uint8_t mov_al[] = {0xB0, imm};  // MOV AL, imm8
        buffer_append(b, mov_al, 2);
    }
}

