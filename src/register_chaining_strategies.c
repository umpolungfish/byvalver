#include "strategy.h"
#include "utils.h"
#include "profile_aware_sib.h"
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
            if (!is_bad_byte_free(imm)) {
                // Additionally confirm the original instruction has null bytes
                if (has_null_bytes(insn)) {
                    return 1;
                }
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

    // Method 1: Try NOT encoding (with null-free check)
    uint32_t not_val;
    if (find_not_equivalent(target_val, &not_val) && is_bad_byte_free(not_val)) {
        if (target_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, not_val);
            uint8_t not_code[] = {0xF7, 0xD0}; // NOT EAX
            not_code[1] = 0xD0 + get_reg_index(X86_REG_EAX);
            buffer_append(b, not_code, 2);
        } else {
            // Save original EAX
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, not_val);
            uint8_t not_code[] = {0xF7, 0xD0}; // NOT EAX
            not_code[1] = 0xD0 + get_reg_index(X86_REG_EAX);
            buffer_append(b, not_code, 2);

            // Move result to target register (register-to-register MOV)
            uint8_t mov_to_target[] = {0x89, 0xC0};
            mov_to_target[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(target_reg);
            buffer_append(b, mov_to_target, 2);

            // Restore original EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }
        return;
    }

    // Method 2: Try NEG encoding (with null-free check)
    uint32_t negated_val;
    if (find_neg_equivalent(target_val, &negated_val) && is_bad_byte_free(negated_val)) {
        if (target_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, negated_val);
            uint8_t neg_code[] = {0xF7, 0xD8}; // NEG EAX
            neg_code[1] = 0xD8 + get_reg_index(X86_REG_EAX);
            buffer_append(b, neg_code, 2);
        } else {
            // Save original EAX
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, negated_val);
            uint8_t neg_code[] = {0xF7, 0xD8}; // NEG EAX
            neg_code[1] = 0xD8 + get_reg_index(X86_REG_EAX);
            buffer_append(b, neg_code, 2);

            // Move result to target register (register-to-register MOV)
            uint8_t mov_to_target[] = {0x89, 0xC0};
            mov_to_target[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(target_reg);
            buffer_append(b, mov_to_target, 2);

            // Restore original EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }
        return;
    }

    // Method 3: Try ADD/SUB encoding (with null-free check)
    uint32_t val1, val2;
    int is_add;
    if (find_addsub_key(target_val, &val1, &val2, &is_add) && is_bad_byte_free(val1) && is_bad_byte_free(val2)) {
        if (target_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, val1);
            uint8_t op_code = is_add ? 0x05 : 0x2D; // ADD EAX, imm32 or SUB EAX, imm32
            uint8_t addsub_code[] = {op_code, 0, 0, 0, 0};
            memcpy(addsub_code + 1, &val2, 4);
            buffer_append(b, addsub_code, 5);
        } else {
            // Save original EAX
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, val1);
            uint8_t op_code = is_add ? 0x05 : 0x2D; // ADD EAX, imm32 or SUB EAX, imm32
            uint8_t addsub_code[] = {op_code, 0, 0, 0, 0};
            memcpy(addsub_code + 1, &val2, 4);
            buffer_append(b, addsub_code, 5);

            // Move result to target register (register-to-register MOV)
            uint8_t mov_to_target[] = {0x89, 0xC0};
            mov_to_target[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(target_reg);
            buffer_append(b, mov_to_target, 2);

            // Restore original EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }
        return;
    }

    // If no good encoding method found, fall back to reliable null-free construction
    // Use EAX as temporary register for construction
    if (target_reg == X86_REG_EAX) {
        generate_mov_eax_imm(b, target_val);
    } else {
        // Save original EAX
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);

        // Build target value in EAX using reliable null-free construction
        generate_mov_eax_imm(b, target_val);

        // Move result to target register (register-to-register MOV)
        uint8_t mov_to_target[] = {0x89, 0xC0};
        mov_to_target[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(target_reg);
        buffer_append(b, mov_to_target, 2);

        // Restore original EAX
        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
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
            if (!is_bad_byte_free(imm)) {
                // Additionally confirm the original instruction has null bytes
                if (has_null_bytes(insn)) {
                    return 1;
                }
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

    // Method 1: Try NOT encoding (with null-free check)
    uint32_t not_val;
    if (find_not_equivalent(target_val, &not_val) && is_bad_byte_free(not_val)) {
        // MOV target_reg, ~target_val then NOT target_reg
        // MOV using null-safe construction
        if (target_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, not_val);
        } else {
            // Save original EAX first
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, not_val);
            // Move from EAX to target register
            uint8_t mov_code[] = {0x89, 0xC0};
            mov_code[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(target_reg);
            buffer_append(b, mov_code, 2);

            // Restore original EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }

        // NOT target_reg
        uint8_t not_code[] = {0xF7, 0xD0};
        not_code[1] = not_code[1] | get_reg_index(target_reg);
        buffer_append(b, not_code, 2);
        return;
    }

    // Method 2: Try NEG encoding (with null-free check)
    uint32_t negated_val;
    if (find_neg_equivalent(target_val, &negated_val) && is_bad_byte_free(negated_val)) {
        // MOV target_reg, -target_val then NEG target_reg
        if (target_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, negated_val);
        } else {
            // Save original EAX first
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, negated_val);
            // Move from EAX to target register
            uint8_t mov_code[] = {0x89, 0xC0};
            mov_code[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(target_reg);
            buffer_append(b, mov_code, 2);

            // Restore original EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }

        // NEG target_reg
        uint8_t neg_code[] = {0xF7, 0xD8};
        neg_code[1] = neg_code[1] | get_reg_index(target_reg);
        buffer_append(b, neg_code, 2);
        return;
    }

    // Method 3: Try ADD/SUB encoding (with null-free check)
    uint32_t val1, val2;
    int is_add;
    if (find_addsub_key(target_val, &val1, &val2, &is_add) && is_bad_byte_free(val1) && is_bad_byte_free(val2)) {
        if (target_reg == X86_REG_EAX) {
            // Direct approach: MOV EAX, val1 + operation with val2
            generate_mov_eax_imm(b, val1);

            uint8_t op_code = is_add ? 0x05 : 0x2D; // ADD EAX, imm32 or SUB EAX, imm32
            uint8_t addsub_code[] = {op_code, 0, 0, 0, 0};
            memcpy(addsub_code + 1, &val2, 4);
            buffer_append(b, addsub_code, 5);
        } else {
            // Save original EAX first
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);

            // Load val1 into EAX
            generate_mov_eax_imm(b, val1);

            // Perform operation with val2 (which is null-free per check)
            uint8_t op_code = is_add ? 0x05 : 0x2D; // ADD EAX, imm32 or SUB EAX, imm32
            uint8_t addsub_code[] = {op_code, 0, 0, 0, 0};
            memcpy(addsub_code + 1, &val2, 4);
            buffer_append(b, addsub_code, 5);

            // Move result to target register
            uint8_t mov_result[] = {0x89, 0xC0};
            mov_result[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(target_reg);
            buffer_append(b, mov_result, 2);

            // Restore original EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }
        return;
    }

    // If no good encoding method found, fall back to reliable null-free construction
    if (target_reg == X86_REG_EAX) {
        generate_mov_eax_imm(b, target_val);
    } else {
        // Save original EAX first
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);

        // Use reliable null-free construction
        generate_mov_eax_imm(b, target_val);

        // Move to target register
        uint8_t mov_to_target[] = {0x89, 0xC0};
        mov_to_target[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(target_reg);
        buffer_append(b, mov_to_target, 2);

        // Restore original EAX
        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
    }
}

strategy_t cross_register_operation_strategy = {
    .name = "cross_register_operation",
    .can_handle = can_handle_cross_register_operation,
    .get_size = get_size_cross_register_operation,
    .generate = generate_cross_register_operation,
    .priority = 60  // Medium priority
};

void register_register_chaining_strategies() {
    register_strategy(&register_chaining_immediate_strategy);
    register_strategy(&cross_register_operation_strategy);
}