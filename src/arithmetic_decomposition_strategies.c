/*
 * MOV Immediate via Arithmetic Decomposition Strategy
 *
 * PROBLEM: MOV with immediate values often contains null bytes:
 * - MOV EAX, 0x12003400 → B8 00 34 00 12 (contains 2 nulls)
 * - MOV EBX, 0x00000001 → BB 01 00 00 00 (contains 3 nulls)
 *
 * SOLUTION: Decompose immediate values into arithmetic operations:
 * - Find two null-free values that when combined (ADD/SUB/XOR) produce target
 * - Use multiple decomposition strategies and select most efficient
 *
 * FREQUENCY: General-purpose fallback for immediate values with nulls
 * PRIORITY: 70 (Medium-High - sophisticated fallback before byte construction)
 *
 * Example transformations:
 *   Original: MOV EAX, 0x12003400 (contains nulls)
 *   Strategy: MOV EAX, base; ADD EAX, offset (where both are null-free)
 *
 *   Original: MOV EBX, 0x00000001 (contains nulls)
 *   Strategy: XOR EBX, EBX; INC EBX (handled by other strategies, but fallback available)
 */

#include "arithmetic_decomposition_strategies.h"
#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Detection function for MOV reg, imm that can benefit from arithmetic decomposition
 */
int can_handle_mov_arith_decomp(cs_insn *insn) {
    if (insn->id != X86_INS_MOV ||
        insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    cs_x86_op *src_op = &insn->detail->x86.operands[1];

    // Must be MOV register, immediate
    if (dst_op->type != X86_OP_REG || src_op->type != X86_OP_IMM) {
        return 0;
    }

    // Only handle 32-bit registers for now
    if (dst_op->size != 4) {
        return 0;
    }

    uint32_t imm = (uint32_t)src_op->imm;

    // Check if immediate contains null bytes
    if (is_null_free(imm)) {
        return 0;
    }

    // Check if we can find a good arithmetic decomposition
    uint32_t base, offset, xor_key, neg_val;
    int operation;

    // Try arithmetic decomposition (ADD/SUB)
    if (find_arithmetic_equivalent(imm, &base, &offset, &operation)) {
        return 1;
    }

    // Try XOR decomposition
    if (find_xor_key(imm, &xor_key)) {
        return 1;
    }

    // Try NEG decomposition
    if (find_neg_equivalent(imm, &neg_val)) {
        return 1;
    }

    // No suitable decomposition found
    return 0;
}

/*
 * Size calculation for arithmetic decomposition
 *
 * Tries different decomposition methods and returns size of most efficient one
 */
size_t get_size_mov_arith_decomp(cs_insn *insn) {
    cs_x86_op *src_op = &insn->detail->x86.operands[1];
    uint32_t imm = (uint32_t)src_op->imm;

    uint32_t base, offset, xor_key, neg_val;
    int operation;
    size_t min_size = 100; // Start with large value

    // Try arithmetic decomposition (ADD/SUB)
    if (find_arithmetic_equivalent(imm, &base, &offset, &operation)) {
        size_t arith_size = get_mov_eax_imm_size(base) +
                           get_mov_eax_imm_size(offset) + 2; // +2 for ADD/SUB
        if (arith_size < min_size) {
            min_size = arith_size;
        }
    }

    // Try XOR decomposition
    if (find_xor_key(imm, &xor_key)) {
        size_t xor_size = get_mov_eax_imm_size(~imm) +
                         get_mov_eax_imm_size(xor_key) + 2; // +2 for XOR
        if (xor_size < min_size) {
            min_size = xor_size;
        }
    }

    // Try NEG decomposition
    if (find_neg_equivalent(imm, &neg_val)) {
        size_t neg_size = get_mov_eax_imm_size(neg_val) + 2; // +2 for NEG
        if (neg_size < min_size) {
            min_size = neg_size;
        }
    }

    return min_size;
}

/*
 * Generate MOV using arithmetic decomposition
 *
 * Selects the most efficient decomposition method and generates code
 */
void generate_mov_arith_decomp(struct buffer *b, cs_insn *insn) {
    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    cs_x86_op *src_op = &insn->detail->x86.operands[1];

    uint32_t imm = (uint32_t)src_op->imm;
    uint8_t dst_reg = dst_op->reg;
    uint8_t reg_idx = dst_reg - X86_REG_EAX; // 0 for EAX, 1 for ECX, etc.

    uint32_t base, offset, xor_key, neg_val;
    int operation;

    // Calculate sizes for each method
    size_t arith_size = 1000, xor_size = 1000, neg_size = 1000;
    int has_arith = 0, has_xor = 0, has_neg = 0;

    if (find_arithmetic_equivalent(imm, &base, &offset, &operation)) {
        arith_size = get_mov_eax_imm_size(base) + get_mov_eax_imm_size(offset) + 2;
        has_arith = 1;
    }

    if (find_xor_key(imm, &xor_key)) {
        xor_size = get_mov_eax_imm_size(~imm) + get_mov_eax_imm_size(xor_key) + 2;
        has_xor = 1;
    }

    if (find_neg_equivalent(imm, &neg_val)) {
        neg_size = get_mov_eax_imm_size(neg_val) + 2;
        has_neg = 1;
    }

    // Select most efficient method
    if (has_neg && neg_size <= arith_size && neg_size <= xor_size) {
        // Use NEG decomposition: MOV reg, -target; NEG reg
        generate_mov_eax_imm(b, neg_val);

        // If target register is not EAX, move it
        if (dst_reg != X86_REG_EAX) {
            // MOV dst_reg, EAX
            buffer_write_byte(b, 0x89);
            buffer_write_byte(b, 0xC0 + reg_idx); // ModR/M for MOV reg, EAX
        }

        // NEG dst_reg
        buffer_write_byte(b, 0xF7);
        buffer_write_byte(b, 0xD8 + reg_idx); // ModR/M for NEG reg

    } else if (has_xor && xor_size <= arith_size) {
        // Use XOR decomposition: MOV reg, ~target; XOR reg, key
        generate_mov_eax_imm(b, ~imm);

        if (dst_reg != X86_REG_EAX) {
            buffer_write_byte(b, 0x89);
            buffer_write_byte(b, 0xC0 + reg_idx);
        }

        // XOR dst_reg, xor_key (need to generate null-free)
        // For simplicity, use immediate XOR if key is small
        if (is_null_free(xor_key)) {
            buffer_write_byte(b, 0x81); // XOR r/m32, imm32
            buffer_write_byte(b, 0xF0 + reg_idx); // ModR/M
            buffer_write_byte(b, (uint8_t)(xor_key & 0xFF));
            buffer_write_byte(b, (uint8_t)((xor_key >> 8) & 0xFF));
            buffer_write_byte(b, (uint8_t)((xor_key >> 16) & 0xFF));
            buffer_write_byte(b, (uint8_t)((xor_key >> 24) & 0xFF));
        }

    } else if (has_arith) {
        // Use ADD/SUB decomposition: MOV reg, base; ADD/SUB reg, offset
        generate_mov_eax_imm(b, base);

        if (dst_reg != X86_REG_EAX) {
            buffer_write_byte(b, 0x89);
            buffer_write_byte(b, 0xC0 + reg_idx);
        }

        // ADD or SUB dst_reg, offset
        if (operation == X86_INS_ADD) {
            buffer_write_byte(b, 0x81); // ADD r/m32, imm32
            buffer_write_byte(b, 0xC0 + reg_idx); // ModR/M
        } else { // SUB
            buffer_write_byte(b, 0x81); // SUB r/m32, imm32
            buffer_write_byte(b, 0xE8 + reg_idx); // ModR/M
        }

        buffer_write_byte(b, (uint8_t)(offset & 0xFF));
        buffer_write_byte(b, (uint8_t)((offset >> 8) & 0xFF));
        buffer_write_byte(b, (uint8_t)((offset >> 16) & 0xFF));
        buffer_write_byte(b, (uint8_t)((offset >> 24) & 0xFF));
    }
}

/*
 * Strategy definition
 */
strategy_t mov_arith_decomp_strategy = {
    .name = "MOV Arithmetic Decomposition",
    .can_handle = can_handle_mov_arith_decomp,
    .get_size = get_size_mov_arith_decomp,
    .generate = generate_mov_arith_decomp,
    .priority = 70  // Medium-high - sophisticated fallback before byte construction
};
