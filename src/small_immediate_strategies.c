/*
 * Small Immediate Value Encoding Optimization Strategy
 *
 * PROBLEM: Direct MOV with immediate values can contain null bytes:
 * - MOV ECX, 0x300 → B9 00 03 00 00 (contains 3 nulls)
 * - MOV DWORD PTR [EAX], 1 → C7 00 01 00 00 00 (contains 3 nulls)
 *
 * SOLUTION: Use alternative encodings like setting up values through
 * arithmetic or by constructing them byte-by-byte to avoid nulls.
 *
 * FREQUENCY: Common in shellcode for setting up flags, counters, and API parameters
 * PRIORITY: 75 (High)
 *
 * Example transformations:
 *   Original: MOV ECX, 0x300 (B9 00 03 00 00 - contains nulls)
 *   Strategy: XOR ECX,ECX; MOV CL,0x00; MOV CH,0x03 (null-free construction)
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Detection function for MOV instructions with immediate values that contain null bytes
 */
int can_handle_small_immediate_optimization(cs_insn *insn) {
    if (insn->id != X86_INS_MOV ||
        insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Check if second operand is an immediate value
    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    cs_x86_op *src_op = &insn->detail->x86.operands[1];

    if (src_op->type != X86_OP_IMM) {
        return 0;
    }

    // Only work with register destinations
    if (dst_op->type != X86_OP_REG) {
        return 0;
    }

    // Only handle 32-bit registers
    if (dst_op->size != 4) {
        return 0;
    }

    uint32_t imm = (uint32_t)src_op->imm;

    // Check if immediate contains null bytes
    if (is_null_free(imm)) {
        // If immediate is already null-free, we don't need to optimize
        return 0;
    }

    // Additional check: make sure the instruction itself has null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // For now, focus on values that could benefit from high-byte/low-byte techniques
    // e.g. 0x00000300, 0x00000001 that have problematic encodings
    // We'll specifically look for values where high-byte method is beneficial

    return 1; // We can handle any MOV reg, imm that has nulls
}

/*
 * Size calculation function for small immediate optimization
 */
size_t get_size_small_immediate_optimization(cs_insn *insn) {
    // This approach varies, but often involves multiple instructions
    // Conservative estimate accounting for complex construction methods
    (void)insn; // Unused parameter
    return 15; // Increased conservative estimate for complex encoding methods
}

/*
 * Generation function for null-free immediate encoding using alternative methods
 */
void generate_small_immediate_optimization(struct buffer *b, cs_insn *insn) {
    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t dst_reg = dst_op->reg;

    // Try alternative encoding methods first before falling back to complex construction
    // Method 1: NOT encoding (with null-free check)
    uint32_t not_val;
    if (find_not_equivalent(imm, &not_val) && is_null_free(not_val)) {
        // MOV dst_reg, ~imm then NOT dst_reg
        if (dst_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, not_val);
        } else {
            // Save EAX first
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, not_val);
            uint8_t mov_to_dst[] = {0x89, 0xC0};
            uint8_t dst_idx = get_reg_index(dst_reg);
            mov_to_dst[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | dst_idx;
            buffer_append(b, mov_to_dst, 2);

            // Restore EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }

        // NOT dst_reg
        uint8_t not_code[] = {0xF7, 0xD0};
        uint8_t dst_idx = get_reg_index(dst_reg);
        not_code[1] = 0xD0 | dst_idx;
        buffer_append(b, not_code, 2);
        return;
    }

    // Method 2: NEG encoding (with null-free check)
    uint32_t negated_val;
    if (find_neg_equivalent(imm, &negated_val) && is_null_free(negated_val)) {
        // MOV dst_reg, -imm then NEG dst_reg
        if (dst_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, negated_val);
        } else {
            // Save EAX first
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, negated_val);
            uint8_t mov_to_dst[] = {0x89, 0xC0};
            uint8_t dst_idx = get_reg_index(dst_reg);
            mov_to_dst[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | dst_idx;
            buffer_append(b, mov_to_dst, 2);

            // Restore EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }

        // NEG dst_reg
        uint8_t neg_code[] = {0xF7, 0xD8};
        uint8_t dst_idx = get_reg_index(dst_reg);
        neg_code[1] = 0xD8 | dst_idx;
        buffer_append(b, neg_code, 2);
        return;
    }

    // Method 3: ADD/SUB encoding (with null-free check)
    uint32_t val1, val2;
    int is_add;
    if (find_addsub_key(imm, &val1, &val2, &is_add) && is_null_free(val1) && is_null_free(val2)) {
        if (dst_reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, val1);
            uint8_t op_code = is_add ? 0x05 : 0x2D; // ADD EAX, imm32 or SUB EAX, imm32
            uint8_t addsub_code[] = {op_code, 0, 0, 0, 0};
            memcpy(addsub_code + 1, &val2, 4);
            buffer_append(b, addsub_code, 5);
        } else {
            // Save EAX first
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, val1);
            uint8_t op_code = is_add ? 0x05 : 0x2D; // ADD EAX, imm32 or SUB EAX, imm32
            uint8_t addsub_code[] = {op_code, 0, 0, 0, 0};
            memcpy(addsub_code + 1, &val2, 4);
            buffer_append(b, addsub_code, 5);

            // Move result to destination register
            uint8_t mov_to_dst[] = {0x89, 0xC0};
            uint8_t dst_idx = get_reg_index(dst_reg);
            mov_to_dst[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | dst_idx;
            buffer_append(b, mov_to_dst, 2);

            // Restore EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }
        return;
    }

    // If no good encoding method found, fall back to reliable null-free construction
    if (dst_reg == X86_REG_EAX) {
        generate_mov_eax_imm(b, imm);
    } else {
        // Save EAX first
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);

        generate_mov_eax_imm(b, imm);

        // Move to destination register
        uint8_t mov_to_dst[] = {0x89, 0xC0};
        uint8_t dst_idx = get_reg_index(dst_reg);
        mov_to_dst[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | dst_idx;
        buffer_append(b, mov_to_dst, 2);

        // Restore EAX
        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
    }
}

// Define the strategy structure
strategy_t small_immediate_strategy = {
    .name = "Small Immediate Value Encoding Optimization",
    .can_handle = can_handle_small_immediate_optimization,
    .get_size = get_size_small_immediate_optimization,
    .generate = generate_small_immediate_optimization,
    .priority = 75  // High priority for size optimization
};