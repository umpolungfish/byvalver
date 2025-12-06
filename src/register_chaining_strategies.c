#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// [Windows/Linux] Register Chaining Strategy
// Using multiple registers in sequence to construct values without creating null bytes

// Strategy A: Multi-Register Assembly for immediate values with nulls
int can_handle_register_chaining_immediate(cs_insn *insn) {
    // Look for MOV instructions with immediate values containing nulls
    if (insn->id == X86_INS_MOV && insn->detail->x86.op_count == 2) {
        if (insn->detail->x86.operands[0].type == X86_OP_REG && 
            insn->detail->x86.operands[1].type == X86_OP_IMM) {
            
            uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
            // Check if the immediate value contains null bytes
            if ((imm & 0xFF) == 0 || ((imm >> 8) & 0xFF) == 0 || 
                ((imm >> 16) & 0xFF) == 0 || ((imm >> 24) & 0xFF) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

size_t get_size_register_chaining_immediate(cs_insn *insn) {
    // Size for multi-register construction (typically multiple instructions)
    // Use the insn parameter to make it meaningful
    if (insn->detail->x86.operands[1].type == X86_OP_IMM) {
        uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
        if ((imm & 0xFF) == 0 || ((imm >> 8) & 0xFF) == 0 ||
            ((imm >> 16) & 0xFF) == 0 || ((imm >> 24) & 0xFF) == 0) {
            return 25; // Increased size for multi-register construction with more complex encoding
        }
    }
    return 25; // Increased fallback size
}

void generate_register_chaining_immediate(struct buffer *b, cs_insn *insn) {
    uint32_t target_val = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t target_reg = insn->detail->x86.operands[0].reg;

    // Strategy: Use multiple registers to build complex values with null-free encoding
    // Try alternative encoding methods first before falling back to complex construction

    // Method 1: Try NOT encoding
    uint32_t not_val;
    if (find_not_equivalent(target_val, &not_val)) {
        if (target_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, not_val);
            uint8_t not_code[] = {0xF7, 0xD0}; // NOT EAX
            not_code[1] = 0xD0 + get_reg_index(X86_REG_EAX);
            buffer_append(b, not_code, 2);
        } else {
            // Save original target register value
            uint8_t push_target = 0x50 + get_reg_index(target_reg);
            buffer_append(b, &push_target, 1);

            generate_mov_eax_imm(b, not_val);
            uint8_t not_code[] = {0xF7, 0xD0}; // NOT EAX
            not_code[1] = 0xD0 + get_reg_index(X86_REG_EAX);
            buffer_append(b, not_code, 2);

            // Move result to target register
            uint8_t mov_to_target[] = {0x89, 0xC0}; // MOV target_reg, EAX
            mov_to_target[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(target_reg);
            buffer_append(b, mov_to_target, 2);

            // Restore original target register value
            uint8_t pop_target = 0x58 + get_reg_index(target_reg);
            buffer_append(b, &pop_target, 1);
        }
        return;
    }

    // Method 2: Try NEG encoding
    uint32_t negated_val;
    if (find_neg_equivalent(target_val, &negated_val)) {
        if (target_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, negated_val);
            uint8_t neg_code[] = {0xF7, 0xD8}; // NEG EAX
            neg_code[1] = 0xD8 + get_reg_index(X86_REG_EAX);
            buffer_append(b, neg_code, 2);
        } else {
            // Save original target register value
            uint8_t push_target = 0x50 + get_reg_index(target_reg);
            buffer_append(b, &push_target, 1);

            generate_mov_eax_imm(b, negated_val);
            uint8_t neg_code[] = {0xF7, 0xD8}; // NEG EAX
            neg_code[1] = 0xD8 + get_reg_index(X86_REG_EAX);
            buffer_append(b, neg_code, 2);

            // Move result to target register
            uint8_t mov_to_target[] = {0x89, 0xC0}; // MOV target_reg, EAX
            mov_to_target[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(target_reg);
            buffer_append(b, mov_to_target, 2);

            // Restore original target register value
            uint8_t pop_target = 0x58 + get_reg_index(target_reg);
            buffer_append(b, &pop_target, 1);
        }
        return;
    }

    // Method 3: Try ADD/SUB encoding
    uint32_t val1, val2;
    int is_add;
    if (find_addsub_key(target_val, &val1, &val2, &is_add)) {
        if (target_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, val1);
            uint8_t op_code = is_add ? 0x05 : 0x2D; // ADD EAX, imm32 or SUB EAX, imm32
            uint8_t addsub_code[] = {op_code, 0, 0, 0, 0};
            memcpy(addsub_code + 1, &val2, 4);
            buffer_append(b, addsub_code, 5);
        } else {
            // Save original target register value
            uint8_t push_target = 0x50 + get_reg_index(target_reg);
            buffer_append(b, &push_target, 1);

            generate_mov_eax_imm(b, val1);
            uint8_t op_code = is_add ? 0x05 : 0x2D; // ADD EAX, imm32 or SUB EAX, imm32
            uint8_t addsub_code[] = {op_code, 0, 0, 0, 0};
            memcpy(addsub_code + 1, &val2, 4);
            buffer_append(b, addsub_code, 5);

            // Move result to target register
            uint8_t mov_to_target[] = {0x89, 0xC0}; // MOV target_reg, EAX
            mov_to_target[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(target_reg);
            buffer_append(b, mov_to_target, 2);

            // Restore original target register value
            uint8_t pop_target = 0x58 + get_reg_index(target_reg);
            buffer_append(b, &pop_target, 1);
        }
        return;
    }

    // If no good encoding method found, use byte-by-byte construction
    // Strategy: Use multiple registers to build complex values
    // Example: Build value across multiple registers then combine

    // Clear target register first
    uint8_t target_idx = get_reg_index(target_reg);

    // Clear EAX and build value there first
    uint8_t xor_eax[] = {0x31, 0xC0}; // XOR EAX, EAX
    buffer_append(b, xor_eax, 2);

    // Build the value byte by byte
    // Start with the lowest byte (making sure it's not 0)
    uint8_t low_byte = target_val & 0xFF;
    if (low_byte != 0) {
        uint8_t mov_al[] = {0xB0, low_byte}; // MOV AL, low_byte
        buffer_append(b, mov_al, 2);
    } else {
        // Handle zero byte by using XOR
        uint8_t xor_al[] = {0x30, 0xC0}; // XOR AL, AL
        buffer_append(b, xor_al, 2);
    }

    // Shift to position if needed
    if (((target_val >> 8) & 0xFF) != 0) {
        uint8_t mov_ah[] = {0xB4, (uint8_t)((target_val >> 8) & 0xFF)}; // MOV AH, byte
        buffer_append(b, mov_ah, 2);
    }

    // For higher bytes, we'll need more complex construction
    // Use shift and OR operations to construct full value
    uint16_t high_word = (target_val >> 16) & 0xFFFF;
    if (high_word != 0) {
        // Push current value and work with higher bytes
        uint8_t push_eax[] = {0x50}; // PUSH EAX
        buffer_append(b, push_eax, 1);

        // Build high part - load the value then shift it to upper position
        generate_mov_eax_imm(b, high_word); // Load high word value (null-free)

        // Shift left by 16 to move to upper word position
        uint8_t shl_eax_16[] = {0xC1, 0xE0, 0x10}; // SHL EAX, 16
        buffer_append(b, shl_eax_16, 3);

        // Pop original low part
        uint8_t pop_edx[] = {0x5A}; // POP EDX
        buffer_append(b, pop_edx, 1);

        // OR together
        uint8_t or_eax_edx[] = {0x09, 0xD0}; // OR EAX, EDX
        buffer_append(b, or_eax_edx, 2);
    }

    // Move to target register if not EAX
    if (target_reg != X86_REG_EAX) {
        uint8_t mov_reg_eax[] = {0x89, 0xC0 + target_idx}; // MOV target_reg, EAX
        buffer_append(b, mov_reg_eax, 2);
    }
}

strategy_t register_chaining_immediate_strategy = {
    .name = "register_chaining_immediate",
    .can_handle = can_handle_register_chaining_immediate,
    .get_size = get_size_register_chaining_immediate,
    .generate = generate_register_chaining_immediate,
    .priority = 65  // Medium-high priority
};

// Strategy B: Cross-Register Operations
int can_handle_cross_register_operation(cs_insn *insn) {
    // This strategy handles operations that need to work with values containing nulls
    // For now, we'll focus on MOV instructions with immediate nulls
    if (insn->id == X86_INS_MOV && insn->detail->x86.op_count == 2) {
        if (insn->detail->x86.operands[0].type == X86_OP_REG &&
            insn->detail->x86.operands[1].type == X86_OP_IMM) {

            uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
            // Check if the immediate value contains null bytes
            if ((imm & 0xFF) == 0 || ((imm >> 8) & 0xFF) == 0 ||
                ((imm >> 16) & 0xFF) == 0 || ((imm >> 24) & 0xFF) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

size_t get_size_cross_register_operation(cs_insn *insn) {
    // Use the insn parameter to make it meaningful
    if (insn->detail->x86.operands[1].type == X86_OP_IMM) {
        uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
        if ((imm & 0xFF) == 0 || ((imm >> 8) & 0xFF) == 0 ||
            ((imm >> 16) & 0xFF) == 0 || ((imm >> 24) & 0xFF) == 0) {
            return 18; // Size for cross-register operations
        }
    }
    return 18; // Fallback size
}

void generate_cross_register_operation(struct buffer *b, cs_insn *insn) {
    uint32_t target_val = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t target_reg = insn->detail->x86.operands[0].reg;

    // Build value using cross-register operations
    // First, try alternative encoding methods that don't introduce nulls

    // Method 1: Try NOT encoding
    uint32_t not_val;
    if (find_not_equivalent(target_val, &not_val)) {
        // MOV target_reg, ~target_val then NOT target_reg
        // MOV using null-safe construction
        if (target_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, not_val);
        } else {
            // Use EAX temporarily
            generate_mov_eax_imm(b, not_val);
            // Move from EAX to target register
            uint8_t mov_code[] = {0x89, 0xC0};
            mov_code[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(target_reg);
            buffer_append(b, mov_code, 2);
        }

        // NOT target_reg
        uint8_t not_code[] = {0xF7, 0xD0};
        not_code[1] = not_code[1] | get_reg_index(target_reg);
        buffer_append(b, not_code, 2);
        return;
    }

    // Method 2: Try NEG encoding
    uint32_t negated_val;
    if (find_neg_equivalent(target_val, &negated_val)) {
        // MOV target_reg, -target_val then NEG target_reg
        if (target_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, negated_val);
        } else {
            // Use EAX temporarily
            generate_mov_eax_imm(b, negated_val);
            // Move from EAX to target register
            uint8_t mov_code[] = {0x89, 0xC0};
            mov_code[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(target_reg);
            buffer_append(b, mov_code, 2);
        }

        // NEG target_reg
        uint8_t neg_code[] = {0xF7, 0xD8};
        neg_code[1] = neg_code[1] | get_reg_index(target_reg);
        buffer_append(b, neg_code, 2);
        return;
    }

    // Method 3: Try ADD/SUB encoding
    uint32_t val1, val2;
    int is_add;
    if (find_addsub_key(target_val, &val1, &val2, &is_add)) {
        if (target_reg == X86_REG_EAX) {
            // Direct approach: MOV EAX, val1 + operation with val2
            generate_mov_eax_imm(b, val1);

            uint8_t op_code = is_add ? 0x05 : 0x2D; // ADD EAX, imm32 or SUB EAX, imm32
            uint8_t addsub_code[] = {op_code, 0, 0, 0, 0};
            memcpy(addsub_code + 1, &val2, 4);
            buffer_append(b, addsub_code, 5);
        } else {
            // Indirect approach: use EAX as temporary
            // Save original target register value
            uint8_t push_target = 0x50 + get_reg_index(target_reg);
            buffer_append(b, &push_target, 1);

            // Load val1 into EAX
            generate_mov_eax_imm(b, val1);

            // Perform operation with val2
            uint8_t op_code = is_add ? 0x05 : 0x2D; // ADD EAX, imm32 or SUB EAX, imm32
            uint8_t addsub_code[] = {op_code, 0, 0, 0, 0};
            memcpy(addsub_code + 1, &val2, 4);
            buffer_append(b, addsub_code, 5);

            // Move result to target register
            uint8_t mov_result[] = {0x89, 0xC0};
            mov_result[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(target_reg);
            buffer_append(b, mov_result, 2);

            // Restore original target register value
            uint8_t pop_target = 0x58 + get_reg_index(target_reg);
            buffer_append(b, &pop_target, 1);
        }
        return;
    }

    // If no good encoding method found, use byte-by-byte construction
    // Clear target register first
    if (target_reg == X86_REG_EAX) {
        uint8_t xor_code[] = {0x31, 0xC0}; // XOR EAX, EAX
        buffer_append(b, xor_code, 2);
    } else {
        // Use EAX to clear target
        uint8_t xor_eax[] = {0x31, 0xC0}; // XOR EAX, EAX
        buffer_append(b, xor_eax, 2);

        uint8_t mov_to_target[] = {0x89, 0xC0};
        mov_to_target[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(target_reg);
        buffer_append(b, mov_to_target, 2);
    }

    // Build the value byte by byte
    uint8_t bytes[4];
    memcpy(bytes, &target_val, 4);

    // For each non-zero byte, construct it in the appropriate position
    for (int i = 0; i < 4; i++) {
        if (bytes[i] != 0) {
            // Use shift and OR operations to set the byte at position i*8
            if (i == 0) {
                // Direct assignment to low byte is fine
                if (target_reg == X86_REG_EAX) {
                    uint8_t mov_al[] = {0xB0, bytes[i]}; // MOV AL, low_byte
                    buffer_append(b, mov_al, 2);
                } else {
                    // Load into EAX then move to target
                    uint8_t mov_al[] = {0xB0, bytes[i]}; // MOV AL, low_byte
                    buffer_append(b, mov_al, 2);

                    // Clear high bytes of EAX
                    uint8_t mov_eax_ax[] = {0x0F, 0xB6, 0xC0}; // MOVZX EAX, AX
                    mov_eax_ax[2] = 0xC0 | get_reg_index(target_reg);
                    buffer_append(b, mov_eax_ax, 3);

                    // Move to target
                    uint8_t mov_target[] = {0x89, 0xC0};
                    mov_target[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(target_reg);
                    buffer_append(b, mov_target, 2);
                }
            } else {
                // For higher bytes, use a different approach
                uint8_t temp_val = bytes[i];
                if (target_reg == X86_REG_EAX) {
                    // Use shift approach
                    // First construct the byte value shifted to correct position
                    uint32_t shifted_val = temp_val << (i * 8);
                    generate_mov_eax_imm(b, shifted_val);
                } else {
                    // Use EAX temporarily
                    generate_mov_eax_imm(b, temp_val);

                    // Shift EAX left by i*8
                    for (int j = 0; j < i * 8; j++) {
                        uint8_t shl_eax[] = {0xD1, 0xE0}; // SHL EAX, 1
                        buffer_append(b, shl_eax, 2);
                    }

                    // OR with target register
                    uint8_t or_target[] = {0x09, 0xC0};
                    or_target[1] = 0xC0 | (get_reg_index(target_reg) << 3) | get_reg_index(X86_REG_EAX);
                    buffer_append(b, or_target, 2);
                }
            }
        }
    }
}

strategy_t cross_register_operation_strategy = {
    .name = "cross_register_operation",
    .can_handle = can_handle_cross_register_operation,
    .get_size = get_size_cross_register_operation,
    .generate = generate_cross_register_operation,
    .priority = 60  // Medium priority
};