#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

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
    // Check if the immediate value is already null-byte-free
    int has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((imm >> (i * 8)) & 0xFF) == 0x00) {
            has_null = 1;
            break;
        }
    }

    if (!has_null) {
        // If no null bytes, use the direct MOV EAX, imm32
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
                        
                        // Load first non-zero byte into AL using MOV AL, imm8
                        uint8_t first_byte = (imm >> (first_nonzero * 8)) & 0xFF;
                        uint8_t mov_al[] = {0xB0, first_byte};  // MOV AL, imm8
                        buffer_append(b, mov_al, 2);
                        
                        // Process remaining bytes (including zeros)
                        for (int i = first_nonzero - 1; i >= 0; i--) {
                            // Shift left by 8 bits to make room for next byte
                            uint8_t shl_eax_8[] = {0xC1, 0xE0, 0x08};  // SHL EAX, 8
                            buffer_append(b, shl_eax_8, 3);
                            
                            uint8_t byte_val = (imm >> (i * 8)) & 0xFF;
                            if (byte_val != 0) {
                                // OR in the non-zero byte using OR AL, imm8 (0x0C)
                                uint8_t or_al[] = {0x0C, byte_val};  // OR AL, imm8
                                buffer_append(b, or_al, 2);
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
    // For MOV reg32, imm32: 1 + 1 + 4 = 6 bytes (B8 for EAX, B9 for ECX, etc.)
    // But for other registers it's different: C7 /0 + imm32 = 6 bytes
    uint8_t reg = insn->detail->x86.operands[0].reg;
    
    if (reg == X86_REG_EAX) {
        return 5;  // B8 + imm32
    }
    return 6; // C7 /0 + imm32
}

void generate_mov_reg_imm(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    
    if (reg == X86_REG_EAX) {
        uint8_t code[] = {0xB8, 0, 0, 0, 0};
        memcpy(code + 1, &imm, 4);
        buffer_append(b, code, 5);
    } else {
        uint8_t code[] = {0xC7, 0xC0 + get_reg_index(reg), 0, 0, 0, 0};
        memcpy(code + 2, &imm, 4);
        buffer_append(b, code, 6);
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
        // Use 32-bit immediate format
        uint8_t code[] = {0x83, 0xC0 + get_reg_index(reg), 0, 0, 0, 0};
        code[0] = base_opcode + 1; // Switch to 8-bit immediate
        code[1] = 0x00; // Encoding for [EAX]
        memcpy(code + 2, &imm, 4);
        buffer_append(b, code, 6);
    }
}

size_t get_push_imm32_size(__attribute__((unused)) uint32_t imm) {
    return 5; // 68 + imm32 for PUSH imm32 (using 68 for 32-bit push)
}

void generate_push_imm32(struct buffer *b, uint32_t imm) {
    uint8_t code[] = {0x68, 0, 0, 0, 0};  // PUSH imm32
    memcpy(code + 1, &imm, 4);
    buffer_append(b, code, 5);
}

size_t get_push_imm8_size() {
    return 2; // 6A + imm8 for PUSH imm8
}

void generate_push_imm8(struct buffer *b, int8_t imm) {
    uint8_t code[] = {0x6A, (uint8_t)imm};
    buffer_append(b, code, 2);
}

size_t get_mov_reg_mem_imm_size(__attribute__((unused)) cs_insn *insn) {
    // MOV reg, [imm32] -> MOV EAX, imm32 + MOV reg, [EAX]
    // Size: 5 (MOV EAX, imm32) + 2 (MOV reg, [EAX] for EAX) = 7 bytes (simplified)
    return 7;  // Conservative estimate
}

void generate_mov_reg_mem_imm(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t addr = (uint32_t)insn->detail->x86.operands[1].mem.disp;
    
    // MOV EAX, addr
    generate_mov_eax_imm(b, addr);
    
    // MOV reg, [EAX]
    uint8_t code[] = {0x8B, 0x00}; // MOV reg, [EAX] format
    code[1] = 0x00 + (get_reg_index(reg) << 3);  // Encode destination register
    buffer_append(b, code, 2);
}

size_t get_lea_reg_mem_disp32_size(__attribute__((unused)) cs_insn *insn) {
    // LEA reg, [disp32] -> MOV EAX, disp32 + LEA reg, [EAX]
    return 7;  // Conservative estimate
}

void generate_lea_reg_mem_disp32(struct buffer *b, cs_insn *insn) {
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;
    uint32_t addr = (uint32_t)insn->detail->x86.operands[1].mem.disp;
    
    // MOV EAX, addr
    generate_mov_eax_imm(b, addr);
    
    // LEA dst_reg, [EAX]
    uint8_t code[] = {0x8D, 0x00}; // LEA reg, [EAX] format
    code[1] = 0x00 + (get_reg_index(dst_reg) << 3);  // Encode destination register
    buffer_append(b, code, 2);
}

size_t get_mov_disp32_reg_size(__attribute__((unused)) cs_insn *insn) {
    // MOV [disp32], reg -> MOV EAX, disp32 + MOV [EAX], reg
    return 7;  // Conservative estimate
}

void generate_mov_disp32_reg(struct buffer *b, cs_insn *insn) {
    uint8_t src_reg = insn->detail->x86.operands[1].reg;
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;
    
    // MOV EAX, addr
    generate_mov_eax_imm(b, addr);
    
    // MOV [EAX], src_reg
    uint8_t code[] = {0x89, 0x00}; // MOV [EAX], reg format
    code[1] = 0x00 + get_reg_index(src_reg);  // Encode source register
    buffer_append(b, code, 2);
}

size_t get_cmp_mem32_reg_size(__attribute__((unused)) cs_insn *insn) {
    // CMP [disp32], reg -> MOV EAX, disp32 + CMP [EAX], reg
    return 7;  // Conservative estimate
}

void generate_cmp_mem32_reg(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[1].reg;
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;
    
    // MOV EAX, addr
    generate_mov_eax_imm(b, addr);
    
    // CMP [EAX], reg
    uint8_t code[] = {0x39, 0x00}; // CMP [EAX], reg format
    code[1] = 0x00 + get_reg_index(reg);  // Encode source register
    buffer_append(b, code, 2);
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
    uint8_t code[] = {0x83, 0x00, 0, 0, 0, 0};
    code[0] = base_opcode + 1; // Switch to 32-bit immediate
    code[1] = 0x00; // Encoding for [EAX]
    memcpy(code + 2, &imm, 4);
    buffer_append(b, code, 6);
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
    return 10; // Placeholder for shift-based construction
}

void generate_mov_reg_imm_shift(struct buffer *b, cs_insn *insn) {
    // Placeholder for shift-based immediate construction
    // This would involve using SHL/SHR operations to build the value
    
    // For now, just use the regular MOV
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

size_t get_xor_encoded_mov_size(__attribute__((unused)) cs_insn *insn) {
    // XOR encoding would depend on the specific encoding used
    return 10; // Placeholder
}

void generate_xor_encoded_mov(struct buffer *b, cs_insn *insn) {
    // Implementation would use XOR encoding technique
    // For now, use original implementation as fallback
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
// FIXED: Use deterministic approach first