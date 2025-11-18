/*
 * Advanced shellcode strategies for BYVALVER
 *
 * This file contains sophisticated replacement strategies inspired by real-world
 * hand-crafted shellcode. These strategies implement elegant transformations
 * similar to those found in the exploit-db shellcode collection.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/capstone.h>
#include <inttypes.h>
#include "utils.h"
#include "core.h"
#include "strategy.h"
#include "advanced_transformations.h"

/*
 * Strategy: Arithmetic equivalent replacement
 * Example: Instead of MOV EAX, 0x00200000, use MOV EAX, 0x00200404; SUB EAX, 0x404
 * This avoids null bytes by using arithmetic to reach the desired value
 */
size_t get_mov_reg_imm_arithmetic_size(cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    
    // Try to find arithmetic equivalents (ADD/SUB)
    uint32_t base_val, offset_val;
    int operation; // 0 for addition, 1 for subtraction
    
    if (find_arithmetic_equivalent(target, &base_val, &offset_val, &operation)) {
        // Size: MOV reg, base_val + arithmetic instruction
        size_t mov_size = (dest_reg == X86_REG_EAX) ? 5 : 6;  // MOV EAX, imm32 vs MOV reg, imm32
        return mov_size + 6; // Additional arithmetic instruction (6 bytes for 32-bit immediate)
    }
    
    // Try NEG-based approach
    uint32_t negated_val;
    if (find_neg_equivalent(target, &negated_val)) {
        // MOV reg, negated_val + NEG reg
        size_t mov_size = (dest_reg == X86_REG_EAX) ? 5 : 6;
        return mov_size + 2; // NEG reg is 2 bytes
    }
    
    // Try NOT-based approach
    uint32_t not_val;
    if (find_not_equivalent(target, &not_val)) {
        // MOV reg, not_val + NOT reg
        size_t mov_size = (dest_reg == X86_REG_EAX) ? 5 : 6;
        return mov_size + 2; // NOT reg is 2 bytes
    }
    
    // If no arithmetic equivalent found, return original MOV size
    return (dest_reg == X86_REG_EAX) ? 5 : 6;
}

void generate_mov_reg_imm_arithmetic(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    
    // Try to find arithmetic equivalents (ADD/SUB)
    uint32_t base_val, offset_val;
    int operation; // 0 for addition, 1 for subtraction
    
    if (find_arithmetic_equivalent(target, &base_val, &offset_val, &operation)) {
        // MOV dest_reg, base_val
        if (dest_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, base_val);
        } else {
            // Create a temporary instruction to use our existing function
            cs_insn temp_insn = *insn;
            temp_insn.detail->x86.operands[0].reg = dest_reg;
            temp_insn.detail->x86.operands[1].imm = base_val;
            generate_mov_reg_imm(b, &temp_insn);
        }
        
        // Perform the arithmetic operation
        if (operation == 0) { // Addition
            if (dest_reg == X86_REG_EAX) {
                uint8_t add_eax_offset[] = {0x05, 0, 0, 0, 0};  // ADD EAX, offset
                memcpy(add_eax_offset + 1, &offset_val, 4);
                buffer_append(b, add_eax_offset, 5);
            } else {
                // Use ADD reg, imm32 format
                uint8_t add_reg_offset[] = {0x83, 0xC0 + get_reg_index(dest_reg), (uint8_t)offset_val}; // ADD reg, imm8
                if ((int32_t)(int8_t)offset_val == (int32_t)offset_val) {
                    buffer_append(b, add_reg_offset, 3);
                } else {
                    // For 32-bit immediate, use full format
                    uint8_t add_reg_offset32[] = {0x83, 0xC0 + get_reg_index(dest_reg), 0, 0, 0, 0}; // Need to adjust this
                    add_reg_offset32[0] = 0x83 + 1; // Switch to 81 for 32-bit immediate
                    add_reg_offset32[1] = 0xC0 + get_reg_index(dest_reg);
                    memcpy(add_reg_offset32 + 2, &offset_val, 4);
                    buffer_append(b, add_reg_offset32, 6);
                }
            }
        } else { // Subtraction
            if (dest_reg == X86_REG_EAX) {
                uint8_t sub_eax_offset[] = {0x2D, 0, 0, 0, 0};  // SUB EAX, offset
                memcpy(sub_eax_offset + 1, &offset_val, 4);
                buffer_append(b, sub_eax_offset, 5);
            } else {
                // Use SUB reg, imm32 format
                uint8_t sub_reg_offset[] = {0x83, 0xE8 + get_reg_index(dest_reg), (uint8_t)offset_val}; // SUB reg, imm8
                if ((int32_t)(int8_t)offset_val == (int32_t)offset_val) {
                    buffer_append(b, sub_reg_offset, 3);
                } else {
                    // For 32-bit immediate, use full format
                    uint8_t sub_reg_offset32[] = {0x83, 0xE8 + get_reg_index(dest_reg), 0, 0, 0, 0}; // Need to adjust this
                    sub_reg_offset32[0] = 0x83 + 1; // Switch to 81 for 32-bit immediate
                    sub_reg_offset32[1] = 0xE8 + get_reg_index(dest_reg);
                    memcpy(sub_reg_offset32 + 2, &offset_val, 4);
                    buffer_append(b, sub_reg_offset32, 6);
                }
            }
        }
        return;
    }
    
    // Try NEG-based approach
    uint32_t negated_val;
    if (find_neg_equivalent(target, &negated_val)) {
        // MOV dest_reg, negated_val
        if (dest_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, negated_val);
        } else {
            cs_insn temp_insn = *insn;
            temp_insn.detail->x86.operands[0].reg = dest_reg;
            temp_insn.detail->x86.operands[1].imm = negated_val;
            generate_mov_reg_imm(b, &temp_insn);
        }
        
        // NEG dest_reg
        uint8_t neg_code[] = {0xF7, 0xD8};
        neg_code[1] = neg_code[1] + get_reg_index(dest_reg);
        buffer_append(b, neg_code, 2);
        return;
    }
    
    // Try NOT-based approach
    uint32_t not_val;
    if (find_not_equivalent(target, &not_val)) {
        // MOV dest_reg, not_val
        if (dest_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, not_val);
        } else {
            cs_insn temp_insn = *insn;
            temp_insn.detail->x86.operands[0].reg = dest_reg;
            temp_insn.detail->x86.operands[1].imm = not_val;
            generate_mov_reg_imm(b, &temp_insn);
        }
        
        // NOT dest_reg
        uint8_t not_code[] = {0xF7, 0xD0};
        not_code[1] = not_code[1] + get_reg_index(dest_reg);
        buffer_append(b, not_code, 2);
        return;
    }
    
    // Fallback to original implementation
    generate_mov_reg_imm(b, insn);
}

/*
 * Strategy: Decoder stub for complex immediate values
 * For very complex immediate values, implement a decoder pattern:
 * push 0xXXXX; pop reg; add reg, 0xYYYY; (repeat operations as needed)
 * This is similar to the approach seen in sophisticated shellcodes
 */
size_t get_decoder_stub_size(cs_insn *insn) {
    // For complex immediate values, create a decoder stub approach
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    
    // Find XOR key that can be used to encode the target
    uint32_t xor_key;
    if (find_xor_key(target, &xor_key)) {
        // Size: MOV reg, encoded_val (5/6 bytes) + XOR reg, key (6 bytes)
        size_t mov_size = (dest_reg == X86_REG_EAX) ? 5 : 6;
        return mov_size + 5; // XOR EAX, imm32 is 5 bytes
    }
    
    return (dest_reg == X86_REG_EAX) ? 5 : 6; // Fallback to original
}

void generate_decoder_stub(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    
    // Find XOR key that can be used to encode the target
    uint32_t xor_key;
    if (find_xor_key(target, &xor_key)) {
        // Calculate encoded value: target XOR key
        uint32_t encoded_val = target ^ xor_key;
        
        // MOV dest_reg, encoded_val (using null-free construction)
        if (dest_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, encoded_val);
        } else {
            cs_insn temp_insn = *insn;
            temp_insn.detail->x86.operands[0].reg = dest_reg;
            temp_insn.detail->x86.operands[1].imm = encoded_val;
            generate_mov_reg_imm(b, &temp_insn);
        }
        
        // XOR dest_reg, key
        if (dest_reg == X86_REG_EAX) {
            uint8_t xor_eax_key[] = {0x35, 0, 0, 0, 0};  // XOR EAX, imm32
            memcpy(xor_eax_key + 1, &xor_key, 4);
            buffer_append(b, xor_eax_key, 5);
        } else {
            // For non-EAX registers, need to use different approach
            // PUSH EAX (save current EAX)
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);
            
            // MOV EAX, key (null-free construction)
            generate_mov_eax_imm(b, xor_key);
            
            // XOR dest_reg, EAX
            uint8_t xor_reg_eax[] = {0x31, 0xC0};
            xor_reg_eax[1] = xor_reg_eax[1] + (get_reg_index(dest_reg) << 3) + get_reg_index(X86_REG_EAX);
            buffer_append(b, xor_reg_eax, 2);
            
            // POP EAX (restore original EAX)
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }
        return;
    }
    
    // Fallback to original implementation
    generate_mov_reg_imm(b, insn);
}

/*
 * Strategy: Register reuse optimization
 * Instead of always using PUSH/POP EAX, consider which registers are
 * already safe to modify in the current context
 */
size_t get_mov_reg_imm_optimized_size(cs_insn *insn) {
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    
    // If destination is EAX, use direct MOV EAX, imm32
    if (dest_reg == X86_REG_EAX) {
        return get_mov_eax_imm_size(target);
    } else {
        // For other registers, use optimized approach based on target value
        return get_mov_reg_imm_size(insn);
    }
}

void generate_mov_reg_imm_optimized(struct buffer *b, cs_insn *insn) {
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    
    // If destination is EAX, use direct MOV EAX, imm32 with null-byte handling
    if (dest_reg == X86_REG_EAX) {
        generate_mov_eax_imm(b, target);
        return;
    }
    
    // For other registers, first load the value into EAX using optimized approach
    generate_mov_eax_imm(b, target);
    
    // Then move from EAX to the destination register
    uint8_t mov_reg_eax[] = {0x89, 0xC0};
    mov_reg_eax[1] = mov_reg_eax[1] + (get_reg_index(dest_reg) << 3) + get_reg_index(X86_REG_EAX);
    buffer_append(b, mov_reg_eax, 2);
}

/*
 * Strategy: Byte-by-byte construction with context awareness
 * For MOV operations, consider if we can construct the value
 * using smaller, non-null-byte operations
 */
size_t get_construct_from_parts_size(cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    
    // Check if immediate value has null bytes
    int has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((target >> (i * 8)) & 0xFF) == 0x00) {
            has_null = 1;
            break;
        }
    }
    
    if (!has_null) {
        return (dest_reg == X86_REG_EAX) ? 5 : 6;  // Direct MOV
    }
    
    // For null-byte containing values, use byte-by-byte construction
    // Clear register + multiple shifts and ORs
    size_t base_size = 2;  // XOR reg, reg instruction
    
    // Count non-zero bytes to determine additional operations
    for (int i = 0; i < 4; i++) {
        uint8_t byte_val = (target >> (i * 8)) & 0xFF;
        if (byte_val != 0) {
            base_size += 4;  // SHL reg, 8 + OR AL, byte_val
        } else {
            base_size += 3;  // SHL reg, 8
        }
    }
    
    return base_size;
}

void generate_construct_from_parts(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    
    // Check if immediate value has null bytes
    int has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((target >> (i * 8)) & 0xFF) == 0x00) {
            has_null = 1;
            break;
        }
    }
    
    if (!has_null) {
        // If no null bytes, use direct MOV
        if (dest_reg == X86_REG_EAX) {
            _generate_mov_eax_imm_direct(b, target);
        } else {
            generate_mov_reg_imm(b, insn);
        }
        return;
    }
    
    // Use byte-by-byte construction for null-byte containing values
    // Choose the destination register for construction
    uint8_t work_reg = dest_reg;
    
    // If destination is EAX, we can work directly
    if (work_reg == X86_REG_EAX) {
        // Clear EAX first using XOR EAX, EAX
        uint8_t xor_eax_eax[] = {0x31, 0xC0};  // XOR EAX, EAX
        buffer_append(b, xor_eax_eax, 2);
        
        // Find first non-zero byte from MSB to LSB
        int first_nonzero = -1;
        for (int i = 3; i >= 0; i--) {
            if (((target >> (i * 8)) & 0xFF) != 0) {
                first_nonzero = i;
                break;
            }
        }

        if (first_nonzero == -1) {
            // Value is 0x00000000, already done with XOR EAX, EAX
            return;
        }

        // Load first non-zero byte into AL using MOV AL, imm8
        uint8_t first_byte = (target >> (first_nonzero * 8)) & 0xFF;
        uint8_t mov_al[] = {0xB0, first_byte};  // MOV AL, imm8
        buffer_append(b, mov_al, 2);

        // Process remaining bytes (including zeros)
        for (int i = first_nonzero - 1; i >= 0; i--) {
            // Shift left by 8 bits to make room for next byte
            uint8_t shl_eax_8[] = {0xC1, 0xE0, 0x08};  // SHL EAX, 8
            buffer_append(b, shl_eax_8, 3);

            uint8_t byte_val = (target >> (i * 8)) & 0xFF;
            if (byte_val != 0) {
                // OR in the non-zero byte using OR AL, imm8 (0x0C)
                uint8_t or_al[] = {0x0C, byte_val};  // OR AL, imm8
                buffer_append(b, or_al, 2);
            }
            // Zero bytes don't need OR - the shift already placed 0x00 in AL
        }
    } else {
        // For non-EAX registers, we need to save/restore EAX
        // PUSH EAX to save original value
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);
        
        // Use EAX to build the target value
        // Clear EAX first using XOR EAX, EAX
        uint8_t xor_eax_eax[] = {0x31, 0xC0};  // XOR EAX, EAX
        buffer_append(b, xor_eax_eax, 2);
        
        // Find first non-zero byte from MSB to LSB
        int first_nonzero = -1;
        for (int i = 3; i >= 0; i--) {
            if (((target >> (i * 8)) & 0xFF) != 0) {
                first_nonzero = i;
                break;
            }
        }

        if (first_nonzero != -1) {
            // Load first non-zero byte into AL using MOV AL, imm8
            uint8_t first_byte = (target >> (first_nonzero * 8)) & 0xFF;
            uint8_t mov_al[] = {0xB0, first_byte};  // MOV AL, imm8
            buffer_append(b, mov_al, 2);

            // Process remaining bytes (including zeros)
            for (int i = first_nonzero - 1; i >= 0; i--) {
                // Shift left by 8 bits to make room for next byte
                uint8_t shl_eax_8[] = {0xC1, 0xE0, 0x08};  // SHL EAX, 8
                buffer_append(b, shl_eax_8, 3);

                uint8_t byte_val = (target >> (i * 8)) & 0xFF;
                if (byte_val != 0) {
                    // OR in the non-zero byte using OR AL, imm8 (0x0C)
                    uint8_t or_al[] = {0x0C, byte_val};  // OR AL, imm8
                    buffer_append(b, or_al, 2);
                }
            }
        }
        
        // Move the constructed value from EAX to the destination register
        uint8_t mov_dst_eax[] = {0x89, 0xC0};
        mov_dst_eax[1] = mov_dst_eax[1] + (get_reg_index(work_reg) << 3) + get_reg_index(X86_REG_EAX);
        buffer_append(b, mov_dst_eax, 2);
        
        // POP EAX to restore original value
        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
    }
}

/*
 * Strategy: Conditional instruction selection
 * Choose optimal replacement based on the immediate value pattern
 */
void generate_mov_reg_imm_smart(struct buffer *b, cs_insn *insn) {
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    
    // Check for zero immediate
    if (imm == 0) {
        // MOV reg, 0 -> XOR reg, reg
        uint8_t xor_reg_reg[] = {0x31, 0xC0};
        xor_reg_reg[1] = xor_reg_reg[1] + (get_reg_index(dest_reg) << 3) + get_reg_index(dest_reg);
        buffer_append(b, xor_reg_reg, 2);
        return;
    }
    
    // Check for small immediate that can be optimized
    if ((int32_t)(int8_t)imm == (int32_t)imm && dest_reg == X86_REG_EAX) {
        // For small signed 8-bit immediate values in EAX, we might have specific optimizations
        // Use the standard mov eax, imm32 for now
    }
    
    // Check if immediate has null bytes
    int has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((imm >> (i * 8)) & 0xFF) == 0x00) {
            has_null = 1;
            break;
        }
    }
    
    if (!has_null) {
        // No null bytes, use direct MOV
        if (dest_reg == X86_REG_EAX) {
            _generate_mov_eax_imm_direct(b, imm);
        } else {
            generate_mov_reg_imm(b, insn);
        }
        return;
    }
    
    // For immediate values with null bytes, use the smart construction approach
    // Try various encoding methods in order of efficiency:
    
    // 1. Try arithmetic encoding
    uint32_t base_val, offset_val;
    int operation; // 0 for addition, 1 for subtraction
    if (find_arithmetic_equivalent(imm, &base_val, &offset_val, &operation)) {
        generate_addsub_encoded_mov(b, insn);
        return;
    }
    
    // 2. Try NEG encoding
    uint32_t negated_val;
    if (find_neg_equivalent(imm, &negated_val)) {
        generate_mov_reg_imm_neg(b, insn);
        return;
    }
    
    // 3. Try NOT encoding
    uint32_t not_val;
    if (find_not_equivalent(imm, &not_val)) {
        generate_mov_reg_imm_not(b, insn);
        return;
    }
    
    // 4. Try XOR encoding
    uint32_t xor_key;
    if (find_xor_key(imm, &xor_key)) {
        generate_xor_encoded_mov(b, insn);
        return;
    }
    
    // 5. Use byte-by-byte construction
    generate_construct_from_parts(b, insn);
}

/*
 * Strategy: Shift-based construction
 * For certain immediate values, use shifting operations to construct the value
 */
size_t get_mov_reg_imm_shift_size(__attribute__((unused)) cs_insn *insn) {
    return 10; // Placeholder for shift-based construction
}

void generate_mov_reg_imm_shift(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    
    // For shift-based construction, find a value that can be transformed using shifts
    // to reach the target value. This can be useful for values like 0x001FF000
    
    // Look for values that can be constructed with shifts and simple operations
    // For example: MOV EAX, 0x00001FF0; SHL EAX, 12
    
    // Find a simpler value that when shifted gives us the target
    for (int shift_amount = 1; shift_amount <= 16; shift_amount++) {
        uint32_t shifted_val = target >> shift_amount;
        uint32_t reconstructed = shifted_val << shift_amount;
        
        if (reconstructed == target) {
            // We can achieve target by shifting 'shifted_val' left by 'shift_amount'
            // First check if shifted_val has null bytes
            int shifted_has_null = 0;
            for (int i = 0; i < 4; i++) {
                if (((shifted_val >> (i * 8)) & 0xFF) == 0x00) {
                    shifted_has_null = 1;
                    break;
                }
            }
            
            if (!shifted_has_null) {
                // MOV dest_reg, shifted_val
                if (dest_reg == X86_REG_EAX) {
                    _generate_mov_eax_imm_direct(b, shifted_val);
                } else {
                    cs_insn temp_insn = *insn;
                    temp_insn.detail->x86.operands[0].reg = dest_reg;
                    temp_insn.detail->x86.operands[1].imm = shifted_val;
                    generate_mov_reg_imm(b, &temp_insn);
                }
                
                // SHL dest_reg, shift_amount (if shift_amount <= 31)
                if (shift_amount <= 31) {
                    if (shift_amount <= 1) {
                        // Use single shift instruction
                        uint8_t shl_code[] = {0xD1, 0xE0};
                        shl_code[1] = shl_code[1] + get_reg_index(dest_reg);
                        buffer_append(b, shl_code, 2);
                        
                        // Apply additional shifts if needed
                        for (int extra = 1; extra < shift_amount; extra++) {
                            buffer_append(b, shl_code, 2);
                        }
                    } else {
                        // Use SHL reg, imm8
                        uint8_t shl_imm8[] = {0xC1, 0xE0, (uint8_t)shift_amount};
                        shl_imm8[1] = shl_imm8[1] + get_reg_index(dest_reg);
                        buffer_append(b, shl_imm8, 3);
                    }
                }
                return;
            }
        }
    }
    
    // If no simple shift pattern found, use the arithmetic approach
    generate_mov_reg_imm_arithmetic(b, insn);
}

/*
 * Strategy: JMP-CALL-POP technique for immediate value construction
 * This is a classic shellcode technique for getting the current address
 */
size_t get_jmp_call_pop_size(cs_insn *insn) {
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    // CALL + POP + additional operations (if needed)
    size_t base_size = 5 + 1; // CALL rel32 + POP reg
    
    if (dest_reg != X86_REG_EAX) {
        base_size += 2; // MOV reg, EAX if not using EAX
    }
    
    return base_size;
}

void generate_jmp_call_pop(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    
    // This technique is primarily for getting the current instruction pointer
    // For immediate value construction, we use it differently
    // JMP forward to CALL instruction
    uint8_t jmp_forward[] = {0xEB, 0x05};  // JMP short +5 bytes
    buffer_append(b, jmp_forward, 2);
    
    // This is where we would store our immediate value
    // For now, we'll use other strategies for immediate values
    generate_mov_reg_imm_arithmetic(b, insn);
}

/*
 * Summary of Advanced Strategies Implemented:
 *
 * 1. Arithmetic equivalency: MOV EAX, 0x200000 -> MOV EAX, 0x200404; SUB EAX, 0x404
 * 2. XOR decoder stubs: For complex values, use XOR encoding with immediate
 * 3. Register optimization: Use available registers efficiently to avoid EAX conflicts
 * 4. Byte-position aware construction: Build values based on which bytes are zero
 * 5. Shift-based construction: Use shifting operations for specific value patterns
 * 6. Pattern recognition: Try different encoding methods (NEG, NOT, XOR, ADD/SUB)
 */