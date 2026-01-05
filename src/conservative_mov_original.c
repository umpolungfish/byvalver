/*
 * Enhanced Conservative MOV Strategy
 *
 * This strategy prioritizes preserving original instruction patterns while
 * still removing null bytes. It tries the most conservative transformations
 * first that maintain the original instruction semantics as closely as possible.
 */

#include "strategy.h"
#include "profile_aware_sib.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// Enhanced conservative MOV strategy - tries most preservation-focused approaches first
int can_handle_conservative_mov_original(cs_insn *insn) {
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
    return has_null_bytes(insn);
}

size_t get_size_conservative_mov_original(cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

    // Try various conservative approaches in order of preservation

    // Method 1: NOT encoding
    uint32_t not_val;
    if (find_not_equivalent(imm, &not_val)) {
        // MOV reg, ~imm then NOT reg
        cs_insn temp_insn = *insn;
        temp_insn.detail->x86.operands[1].imm = not_val;
        return get_mov_reg_imm_size(&temp_insn) + 2;  // +2 for NOT instruction
    }

    // Method 2: NEG encoding
    uint32_t negated_val;
    if (find_neg_equivalent(imm, &negated_val)) {
        // MOV reg, -imm then NEG reg
        cs_insn temp_insn = *insn;
        temp_insn.detail->x86.operands[1].imm = negated_val;
        return get_mov_reg_imm_size(&temp_insn) + 2;  // +2 for NEG instruction
    }

    // Method 3: Try ADD/SUB encoding with smallest possible values
    uint32_t val1, val2;
    int is_add;
    if (find_addsub_key(imm, &val1, &val2, &is_add)) {
        if (reg == X86_REG_EAX) {
            // Direct approach: MOV EAX, val1 + operation with val2
            cs_insn temp_insn = *insn;
            temp_insn.detail->x86.operands[1].imm = is_add ? (imm - val2) : (imm + val2);
            return get_mov_reg_imm_size(&temp_insn) + 5;  // +5 for ADD/SUB EAX, imm32
        } else {
            // Indirect approach with PUSH/POP
            cs_insn temp_insn = *insn;
            temp_insn.detail->x86.operands[1].imm = is_add ? (imm - val2) : (imm + val2);
            return 1 + get_mov_eax_imm_size(val1) + 5 + 2 + 1;  // PUSH + MOV + OP + MOV + POP
        }
    }

    // If no conservative approach works, return a fallback size
    return 10; // Conservative estimate
}

void generate_conservative_mov_original(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

    // Try various conservative approaches in order of preservation

    // Method 1: NOT encoding (most conservative for values that are just bitwise inversions)
    uint32_t not_val;
    if (find_not_equivalent(imm, &not_val)) {
        // MOV reg, ~imm then NOT reg
        cs_insn temp_insn = *insn;
        temp_insn.detail->x86.operands[1].imm = not_val;
        generate_mov_reg_imm(b, &temp_insn);  // This function handles nulls in target value

        // NOT reg
        uint8_t not_code[] = {0xF7, 0xD0};
        not_code[1] = not_code[1] + get_reg_index(reg);
        buffer_append(b, not_code, 2);
        return;
    }

    // Method 2: NEG encoding (conservative for negative values)
    uint32_t negated_val;
    if (find_neg_equivalent(imm, &negated_val)) {
        // MOV reg, -imm then NEG reg
        cs_insn temp_insn = *insn;
        temp_insn.detail->x86.operands[1].imm = negated_val;
        generate_mov_reg_imm(b, &temp_insn);

        // NEG reg
        uint8_t neg_code[] = {0xF7, 0xD8};
        neg_code[1] = neg_code[1] + get_reg_index(reg);
        buffer_append(b, neg_code, 2);
        return;
    }

    // Method 3: ADD/SUB encoding (conservative for values that are arithmetic combinations)
    uint32_t val1, val2;
    int is_add;
    if (find_addsub_key(imm, &val1, &val2, &is_add)) {
        if (reg == X86_REG_EAX) {
            // For EAX, work directly: MOV EAX, val1; ADD/SUB EAX, val2
            generate_mov_eax_imm(b, val1);
            if (is_add) {
                uint8_t add_eax_key[] = {0x05, 0, 0, 0, 0};
                memcpy(add_eax_key + 1, &val2, 4);
                buffer_append(b, add_eax_key, 5);
            } else {
                uint8_t sub_eax_key[] = {0x2D, 0, 0, 0, 0};
                memcpy(sub_eax_key + 1, &val2, 4);
                buffer_append(b, sub_eax_key, 5);
            }
        } else {
            // For other registers, use a temporary approach
            // PUSH original reg to preserve it
            uint8_t push_reg = 0x50 + get_reg_index(reg);
            buffer_append(b, &push_reg, 1);

            // MOV EAX, val1 (use null-free construction)
            generate_mov_eax_imm(b, val1);

            // ADD/SUB EAX, val2 (use null-free construction if needed)
            if (is_add) {
                generate_mov_eax_imm(b, val2);  // Load val2 into EAX
                uint8_t push_temp = 0x50;  // PUSH EAX to save val2
                buffer_append(b, &push_temp, 1);

                generate_mov_eax_imm(b, val1);  // Reload val1 into EAX
                uint8_t add_eax_esp[] = {0x03, 0x04, 0x24};  // ADD EAX, [ESP] (SIB addressing to avoid nulls)
                buffer_append(b, add_eax_esp, 3);
            } else {
                generate_mov_eax_imm(b, val2);  // Load val2 into EAX
                uint8_t push_temp = 0x50;  // PUSH EAX to save val2
                buffer_append(b, &push_temp, 1);

                generate_mov_eax_imm(b, val1);  // Reload val1 into EAX
                uint8_t sub_eax_esp[] = {0x2B, 0x04, 0x24};  // SUB EAX, [ESP] (SIB addressing to avoid nulls)
                buffer_append(b, sub_eax_esp, 3);
            }

            // MOV [reg], EAX to get the result back to original register
            if (reg == X86_REG_EAX) {
                // Already done
            } else {
                // FIXED: Use profile-aware SIB generation instead of hardcoded 0x20
                if (generate_safe_mov_mem_reg(b, reg, X86_REG_EAX) != 0) {
                    // Fallback: use direct MOV reg, EAX encoding (no SIB)
                    uint8_t modrm = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(reg);
                    uint8_t mov_direct[] = {0x89, modrm};
                    buffer_append(b, mov_direct, 2);
                }
            }

            // POP EAX to clean up the stack
            uint8_t pop_temp = 0x58;
            buffer_append(b, &pop_temp, 1);

            // POP original reg to restore original value that was pushed
            uint8_t pop_reg = 0x58 + get_reg_index(reg);
            buffer_append(b, &pop_reg, 1);
        }
        return;
    }

    // If all conservative methods fail, fall back to a safe method
    // Use the utility function that handles null byte construction properly
    generate_mov_reg_imm(b, insn);
}

strategy_t conservative_mov_original_strategy = {
    .name = "conservative_mov_original",
    .can_handle = can_handle_conservative_mov_original,
    .get_size = get_size_conservative_mov_original,
    .generate = generate_conservative_mov_original,
    .priority = 16  // Highest priority among conservative strategies
};

// Register the enhanced conservative strategy
void register_enhanced_conservative_mov_strategy() {
    register_strategy(&conservative_mov_original_strategy);
}