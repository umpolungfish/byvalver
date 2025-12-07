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

    // Additional check: make sure the instruction itself has null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Check if we can find a good arithmetic decomposition
    uint32_t base, offset, xor_key, neg_val;
    int operation;

    // Try arithmetic decomposition (ADD/SUB) and ensure both values are null-free
    if (find_arithmetic_equivalent(imm, &base, &offset, &operation)) {
        if (is_null_free(base) && is_null_free(offset)) {
            return 1;
        }
    }

    // Try XOR decomposition and ensure both values are null-free
    if (find_xor_key(imm, &xor_key)) {
        uint32_t val1 = ~imm;
        if (is_null_free(val1) && is_null_free(xor_key)) {
            return 1;
        }
    }

    // Try NEG decomposition and ensure the negated value is null-free
    if (find_neg_equivalent(imm, &neg_val)) {
        if (is_null_free(neg_val)) {
            return 1;
        }
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
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t dst_reg = dst_op->reg;

    uint32_t base, offset, xor_key, neg_val;
    int operation;

    // This should only be called if can_handle found a valid decomposition
    // so we need to find a working decomposition
    // Check each method and use the first one that has null-free components

    // Method 1: Try NEG decomposition
    if (find_neg_equivalent(imm, &neg_val) && is_null_free(neg_val)) {
        // Use NEG decomposition: MOV reg, -target; NEG reg
        if (dst_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, neg_val);
        } else {
            // Save EAX first
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, neg_val);

            // MOV dst_reg, EAX
            uint8_t mov_dst_eax[] = {0x89, 0xC0};
            mov_dst_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(dst_reg);
            buffer_append(b, mov_dst_eax, 2);

            // Restore EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }

        // NEG dst_reg
        uint8_t neg_code[] = {0xF7, 0xD8};
        neg_code[1] = 0xD8 + get_reg_index(dst_reg);
        buffer_append(b, neg_code, 2);
        return;
    }

    // Method 2: Try XOR decomposition
    if (find_xor_key(imm, &xor_key) && is_null_free(~imm) && is_null_free(xor_key)) {
        // Use XOR decomposition: MOV reg, ~target; XOR reg, key
        if (dst_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, ~imm);
        } else {
            // Save EAX first
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, ~imm);

            // MOV dst_reg, EAX
            uint8_t mov_dst_eax[] = {0x89, 0xC0};
            mov_dst_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(dst_reg);
            buffer_append(b, mov_dst_eax, 2);

            // Restore EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }

        // XOR with the key value (which is null-free per check above)
        uint8_t xor_code[] = {0x83, 0x00, 0x00}; // XOR reg, imm8 (if possible) or 0x81 for 32-bit
        // Try to use 8-bit immediate if the key fits
        if (xor_key <= 0xFF) {
            xor_code[0] = 0x83;
            xor_code[1] = 0xF0 + get_reg_index(dst_reg);  // F0-F7 for XOR
            xor_code[2] = (uint8_t)xor_key;
            buffer_append(b, xor_code, 3);
        } else {
            // Use 32-bit immediate
            uint8_t xor32_code[] = {0x81, 0x00, 0x00, 0x00, 0x00, 0x00};
            xor32_code[1] = 0xF0 + get_reg_index(dst_reg);  // F0-F7 for XOR
            memcpy(xor32_code + 2, &xor_key, 4);
            buffer_append(b, xor32_code, 6);
        }
        return;
    }

    // Method 3: Try ADD/SUB decomposition
    if (find_arithmetic_equivalent(imm, &base, &offset, &operation) &&
        is_null_free(base) && is_null_free(offset)) {
        // Use ADD/SUB decomposition: MOV reg, base; ADD/SUB reg, offset
        if (dst_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, base);
        } else {
            // Save EAX first
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, base);

            // MOV dst_reg, EAX
            uint8_t mov_dst_eax[] = {0x89, 0xC0};
            mov_dst_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(dst_reg);
            buffer_append(b, mov_dst_eax, 2);

            // Restore EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }

        // ADD or SUB with the offset (which is null-free per check above)
        if (operation == X86_INS_ADD) {
            // ADD reg, offset
            if (offset <= 0x7F || (offset >= 0xFFFFFF80)) {  // 8-bit signed immediate
                uint8_t add8_code[] = {0x83, 0x00, 0x00};
                add8_code[1] = 0xC0 + get_reg_index(dst_reg); // C0-C7 for ADD
                add8_code[2] = (uint8_t)offset;
                buffer_append(b, add8_code, 3);
            } else {
                // Use 32-bit immediate
                uint8_t add32_code[] = {0x81, 0x00, 0x00, 0x00, 0x00, 0x00};
                add32_code[1] = 0xC0 + get_reg_index(dst_reg); // C0-C7 for ADD
                memcpy(add32_code + 2, &offset, 4);
                buffer_append(b, add32_code, 6);
            }
        } else { // SUB
            // SUB reg, offset
            if (offset <= 0x7F || (offset >= 0xFFFFFF80)) {  // 8-bit signed immediate
                uint8_t sub8_code[] = {0x83, 0x00, 0x00};
                sub8_code[1] = 0xE8 + get_reg_index(dst_reg); // E8-EF for SUB
                sub8_code[2] = (uint8_t)offset;
                buffer_append(b, sub8_code, 3);
            } else {
                // Use 32-bit immediate
                uint8_t sub32_code[] = {0x81, 0x00, 0x00, 0x00, 0x00, 0x00};
                sub32_code[1] = 0xE8 + get_reg_index(dst_reg); // E8-EF for SUB
                memcpy(sub32_code + 2, &offset, 4);
                buffer_append(b, sub32_code, 6);
            }
        }
        return;
    }

    // If no valid decomposition is found (shouldn't happen if can_handle worked properly),
    // fall back to reliable construction
    if (dst_reg == X86_REG_EAX) {
        generate_mov_eax_imm(b, imm);
    } else {
        // Save EAX first
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);

        generate_mov_eax_imm(b, imm);

        // MOV dst_reg, EAX
        uint8_t mov_dst_eax[] = {0x89, 0xC0};
        mov_dst_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(dst_reg);
        buffer_append(b, mov_dst_eax, 2);

        // Restore EAX
        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
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
