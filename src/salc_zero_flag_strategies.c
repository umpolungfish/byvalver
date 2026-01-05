/*
 * SALC-based Zero Flag Strategy
 *
 * PROBLEM: Comparing values to zero can involve instructions with null bytes.
 * 
 * SOLUTION: Use SALC (Set AL on Carry) instruction to manipulate flags and 
 * detect zero values without direct comparison operations that might contain nulls.
 *
 * FREQUENCY: Useful in shellcode for zero-value detection without CMP instructions
 * PRIORITY: 75 (Medium-High - good for flag manipulation without nulls)
 *
 * Example transformations:
 *   Original: CMP EAX, 0 (contains null in immediate, may have null encoding)
 *   Strategy: Use arithmetic to detect zero without explicit comparison
 */

#include "salc_zero_flag_strategies.h"
#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Detection function for CMP operations comparing with zero that contain null bytes
 */
int can_handle_salc_zero_comparison(cs_insn *insn) {
    if (insn->id != X86_INS_CMP ||
        insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *src_op = &insn->detail->x86.operands[1];

    // Must be CMP register/value, immediate
    if (src_op->type != X86_OP_IMM) {
        return 0;
    }

    // Check if immediate is zero (comparing against zero)
    uint32_t imm = (uint32_t)src_op->imm;
    if (imm != 0) {
        return 0;
    }

    // Check if the original instruction encoding contains null bytes
    for (size_t j = 0; j < insn->size; j++) {
        if (insn->bytes[j] == 0x00) {
            return 1;
        }
    }

    return 0;
}

/*
 * Size calculation for SALC-based zero comparison
 * Uses OR reg,reg or TEST reg,reg to set flags (2 bytes each)
 */
size_t get_size_salc_zero_comparison(cs_insn *insn) {
    (void)insn; // Unused parameter
    return 3; // OR reg,reg (2 bytes) + optional manipulation (1 byte)
}

/*
 * Generate SALC-based zero comparison
 * 
 * For CMP reg, 0:
 *   OR EAX, EAX (or TEST EAX, EAX) - sets flags appropriately to detect zero
 *   This sets ZF=1 if register is zero, ZF=0 if register is non-zero
 *   No null bytes in the encoding
 */
void generate_salc_zero_comparison(struct buffer *b, cs_insn *insn) {
    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    x86_reg cmp_reg = dst_op->reg;

    // Use OR reg, reg to test for zero (preserves reg value, sets flags)
    // Changed from 0x09 (TAB) to 0x0B (OR alternative encoding)
    uint8_t or_reg_reg[] = {0x0B, 0x00};
    or_reg_reg[1] = 0xC0 | (get_reg_index(cmp_reg) << 3) | get_reg_index(cmp_reg);
    buffer_append(b, or_reg_reg, 2);
}

/*
 * Alternative approach: Using SALC with specific flag setup
 */
int can_handle_salc_with_flag_setup(cs_insn *insn) {
    if (insn->id != X86_INS_CMP ||
        insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *src_op = &insn->detail->x86.operands[1];

    // Must be CMP register/value, immediate
    if (src_op->type != X86_OP_IMM) {
        return 0;
    }

    // Check if immediate is zero (comparing against zero)
    uint32_t imm = (uint32_t)src_op->imm;
    if (imm != 0) {
        return 0;
    }

    // Check if the original instruction encoding contains null bytes
    for (size_t j = 0; j < insn->size; j++) {
        if (insn->bytes[j] == 0x00) {
            return 1;
        }
    }

    return 0;
}

size_t get_size_salc_with_flag_setup(cs_insn *insn) {
    (void)insn; // Unused parameter
    return 4; // CLC + SALC + comparison (if needed)
}

void generate_salc_with_flag_setup(struct buffer *b, cs_insn *insn) {
    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    x86_reg cmp_reg = dst_op->reg;

    // Use the same approach as above since SALC by itself doesn't compare
    // OR reg, reg is more appropriate for zero-checking
    // Changed from 0x09 (TAB) to 0x0B (OR alternative encoding)
    uint8_t or_reg_reg[] = {0x0B, 0x00};
    or_reg_reg[1] = 0xC0 | (get_reg_index(cmp_reg) << 3) | get_reg_index(cmp_reg);
    buffer_append(b, or_reg_reg, 2);
}

strategy_t salc_zero_comparison_strategy = {
    .name = "SALC-based Zero Comparison",
    .can_handle = can_handle_salc_zero_comparison,
    .get_size = get_size_salc_zero_comparison,
    .generate = generate_salc_zero_comparison,
    .priority = 75  // Medium-High priority
};

strategy_t salc_with_flag_setup_strategy = {
    .name = "SALC with Flag Setup",
    .can_handle = can_handle_salc_with_flag_setup,
    .get_size = get_size_salc_with_flag_setup,
    .generate = generate_salc_with_flag_setup,
    .priority = 73  // Slightly lower priority
};

void register_salc_zero_flag_strategies() {
    register_strategy(&salc_zero_comparison_strategy);
    register_strategy(&salc_with_flag_setup_strategy);
}