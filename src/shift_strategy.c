/*
 * Shift-Based Immediate Value Construction Strategy for BYVALVER
 *
 * This strategy uses shift operations (SHL/SHR) to construct immediate values 
 * when direct immediate values contain null bytes. This technique is more 
 * sophisticated than simple arithmetic equivalents.
 *
 * Example from exploit-db: `push 0x1ff9090; shr $0x10, %ecx` to load 
 * 0x1ff into ecx without null bytes in the intermediate representation.
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>
#include <inttypes.h>

// Helper function to check if a 32-bit value has no null bytes
int has_no_null_bytes(uint32_t value) {
    for (int i = 0; i < 4; i++) {
        if (((value >> (i * 8)) & 0xFF) == 0) {
            return 0; // Has null byte
        }
    }
    return 1; // No null bytes
}

// Helper function to check if a 32-bit value has null bytes
int has_null_bytes_in_value(uint32_t value) {
    for (int i = 0; i < 4; i++) {
        if (((value >> (i * 8)) & 0xFF) == 0) {
            return 1; // Has null byte
        }
    }
    return 0; // No null bytes
}

// Function to find suitable shift combinations for a target value
// Returns 1 if solution found, 0 otherwise
int find_shift_substitution(uint32_t target, uint32_t *shifted_val, uint8_t *shift_amount, int *shift_direction) {
    // Try left shifts: shifted_val << shift_amount = target
    for (uint8_t amount = 1; amount < 32; amount++) {
        uint32_t original = target >> amount;  // If target = original << amount, then original = target >> amount
        uint32_t result = original << amount;
        
        if (result == target && has_no_null_bytes(original)) {
            *shifted_val = original;
            *shift_amount = amount;
            *shift_direction = 0; // 0 for left shift
            return 1;
        }
    }
    
    // Try right shifts: shifted_val >> shift_amount = target
    for (uint8_t amount = 1; amount < 32; amount++) {
        // For right shift, we need to be more careful about the original value
        // If shifted_val >> amount = target, then shifted_val = target << amount
        // But we also need to consider that the upper bits might have been lost
        for (int i = 0; i < (1 << amount); i++) {
            uint32_t original = (target << amount) | (i & ((1 << amount) - 1));
            uint32_t result = original >> amount;
            
            if (result == target && has_no_null_bytes(original)) {
                *shifted_val = original;
                *shift_amount = amount;
                *shift_direction = 1; // 1 for right shift
                return 1;
            }
        }
    }
    
    // Try more complex patterns that might work for specific cases
    // Like the example: shift to get a value that when shifted gives target
    for (uint8_t amount = 1; amount < 16; amount++) {
        // Try with different bit patterns
        uint32_t shifted = target << amount;
        if (has_no_null_bytes(shifted)) {
            // This works for left shift: we load the shifted value and then shift right
            *shifted_val = shifted;
            *shift_amount = amount;
            *shift_direction = 1; // To get target, we shift this value right
            return 1;
        }
    }
    
    // Try the other direction
    for (uint8_t amount = 1; amount < 16; amount++) {
        uint32_t shifted = target >> amount;
        if (shifted != 0 && has_no_null_bytes(shifted)) {
            // This works for right shift: we load the shifted value and then shift left
            *shifted_val = shifted;
            *shift_amount = amount;
            *shift_direction = 0; // To get target, we shift this value left
            return 1;
        }
    }
    
    return 0; // No suitable combination found
}

// Check if an instruction is a MOV with immediate that contains null bytes
int shift_based_can_handle(cs_insn *insn) {
    // Only handle MOV reg, imm32 instructions that contain null bytes
    if (insn->id != X86_INS_MOV) {
        return 0;
    }
    
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }
    
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }
    
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }
    
    uint32_t immediate = (uint32_t)insn->detail->x86.operands[1].imm;
    
    // Only handle if the immediate contains null bytes
    if (!has_null_bytes_in_value(immediate)) {
        return 0;
    }
    
    // Check if we can find a shift substitution
    uint32_t shifted_val;
    uint8_t shift_amount;
    int shift_direction;
    
    return find_shift_substitution(immediate, &shifted_val, &shift_amount, &shift_direction);
}

// Calculate the size of the generated code
size_t shift_based_get_size(cs_insn *insn) {
    uint32_t immediate = (uint32_t)insn->detail->x86.operands[1].imm;
    
    // Try to find shift substitution
    uint32_t shifted_val;
    uint8_t shift_amount;
    int shift_direction;
    
    if (find_shift_substitution(immediate, &shifted_val, &shift_amount, &shift_direction)) {
        // MOV reg, shifted_val (5-6 bytes for 32-bit immediate)
        // SHL/SHR reg, shift_amount (3 bytes for immediate shift)
        return 8; // Approximate size
    }
    
    return 0; // Can't handle this case
}

// Generate the shift-based construction code
void shift_based_generate(struct buffer *b, cs_insn *insn) {
    uint32_t immediate = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    
    // Try to find shift substitution
    uint32_t shifted_val;
    uint8_t shift_amount;
    int shift_direction;  // 0 for left shift, 1 for right shift
    
    if (!find_shift_substitution(immediate, &shifted_val, &shift_amount, &shift_direction)) {
        // If no shift substitution found, fall back to default strategy
        generate_mov_reg_imm(b, insn);
        return;
    }
    
    // MOV instruction to load the shifted value
    // First, let's determine the target register position
    uint8_t reg_num;
    
    switch (dest_reg) {
        case X86_REG_EAX: reg_num = 0; break;
        case X86_REG_ECX: reg_num = 1; break;
        case X86_REG_EDX: reg_num = 2; break;
        case X86_REG_EBX: reg_num = 3; break;
        case X86_REG_ESP: reg_num = 4; break;
        case X86_REG_EBP: reg_num = 5; break;
        case X86_REG_ESI: reg_num = 6; break;
        case X86_REG_EDI: reg_num = 7; break;
        default: 
            // For registers not in the standard set, use general MOV encoding that supports all registers
            {
                // MOV EAX, shifted_val first
                uint8_t temp_code[] = {
                    0xB8, 
                    (shifted_val & 0xFF), 
                    ((shifted_val >> 8) & 0xFF), 
                    ((shifted_val >> 16) & 0xFF), 
                    ((shifted_val >> 24) & 0xFF)
                };
                buffer_append(b, temp_code, 5);
                
                // Apply shift operation on EAX
                if (shift_direction == 0) { // Left shift: SHL
                    if (shift_amount == 1) {
                        // Use D1 E0: SHL EAX, 1
                        uint8_t shift_code[] = {0xD1, 0xE0};
                        buffer_append(b, shift_code, 2);
                    } else {
                        // Use C1 E0 xx: SHL EAX, imm8
                        uint8_t shift_code[] = {0xC1, 0xE0, shift_amount};
                        buffer_append(b, shift_code, 3);
                    }
                } else { // Right shift: SHR
                    if (shift_amount == 1) {
                        // Use D1 E8: SHR EAX, 1
                        uint8_t shift_code[] = {0xD1, 0xE8};
                        buffer_append(b, shift_code, 2);
                    } else {
                        // Use C1 E8 xx: SHR EAX, imm8
                        uint8_t shift_code[] = {0xC1, 0xE8, shift_amount};
                        buffer_append(b, shift_code, 3);
                    }
                }
                
                // MOV dest_reg, EAX (for register to register move)
                uint8_t mov_reg_to_reg[] = {
                    0x89, 0xC0 | get_reg_index(dest_reg)  // MOV dest_reg, EAX
                };
                buffer_append(b, mov_reg_to_reg, 2);
                
                return;
            }
    }
    
    // Direct approach for standard registers
    // MOV reg, shifted_val
    uint8_t mov_opcode = 0xB8 + reg_num;  // MOV reg32, imm32
    uint8_t mov_code[] = {
        mov_opcode,
        (shifted_val & 0xFF), 
        ((shifted_val >> 8) & 0xFF), 
        ((shifted_val >> 16) & 0xFF), 
        ((shifted_val >> 24) & 0xFF)
    };
    buffer_append(b, mov_code, 5);
    
    // Apply shift operation to the register
    if (shift_direction == 0) { // Left shift (SHL)
        if (shift_amount == 1) {
            // Use D1 E0-07: SHL reg, 1
            uint8_t shift_code[] = {0xD1, 0xE0 + reg_num};
            buffer_append(b, shift_code, 2);
        } else {
            // Use C1 E0-07: SHL reg, imm8
            uint8_t shift_code[] = {0xC1, 0xE0 + reg_num, shift_amount};
            buffer_append(b, shift_code, 3);
        }
    } else { // Right shift (SHR)
        if (shift_amount == 1) {
            // Use D1 E8-0F: SHR reg, 1
            uint8_t shift_code[] = {0xD1, 0xE8 + reg_num};
            buffer_append(b, shift_code, 2);
        } else {
            // Use C1 E8-0F: SHR reg, imm8
            uint8_t shift_code[] = {0xC1, 0xE8 + reg_num, shift_amount};
            buffer_append(b, shift_code, 3);
        }
    }
}

// Define the strategy structure
strategy_t shift_based_strategy = {
    .name = "Shift-Based Immediate Value Construction Strategy",
    .can_handle = shift_based_can_handle,
    .get_size = shift_based_get_size,
    .generate = shift_based_generate,
    .priority = 5  // Lower priority - use this as last resort when other strategies can't handle
};