/*
 * Register Preservation via XCHG / PUSH Immediate Optimization
 *
 * PROBLEM: PUSH immediate values often contain null bytes:
 * - PUSH 0x100 → 68 00 01 00 00 (contains 3 nulls)
 * - PUSH 0x01 → 68 01 00 00 00 (contains 3 nulls) when using push imm32 encoding
 *
 * SOLUTION: Use alternative encodings to avoid nulls:
 * - For small values: Use PUSH imm8 (sign-extended)
 * - For null-containing values: MOV to register + PUSH register
 * - For register preservation: Optimize PUSH/POP sequences
 *
 * FREQUENCY: Very common in shellcode for stack setup and argument passing
 * PRIORITY: 86 (High - common pattern in function call setup)
 *
 * Example transformations:
 *   Original: PUSH 0x100 (68 00 01 00 00 - contains nulls)
 *   Strategy: MOV EAX, 0x100; PUSH EAX (null-free construction)
 *
 *   Original: PUSH 0x01 (68 01 00 00 00 - contains nulls)
 *   Strategy: PUSH 0x01 as imm8 (6A 01 - no nulls, 2 bytes!)
 */

#include "xchg_preservation_strategies.h"
#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Detection function for PUSH imm32 that contains null bytes
 */
int can_handle_push_imm_preservation(cs_insn *insn) {
    if (insn->id != X86_INS_PUSH ||
        insn->detail->x86.op_count != 1) {
        return 0;
    }

    cs_x86_op *op = &insn->detail->x86.operands[0];

    // Must be PUSH immediate
    if (op->type != X86_OP_IMM) {
        return 0;
    }

    int64_t imm = op->imm;

    // Convert to 32-bit for null byte checking
    uint32_t imm32 = (uint32_t)imm;

    // Check if immediate is already null-free
    if (is_null_free(imm32)) {
        return 0;
    }

    // Check if it's a small immediate that fits in imm8 (signed)
    // Values from -128 to 127 can use PUSH imm8
    if (imm >= -128 && imm <= 127) {
        // Could be optimized to PUSH imm8, but check if current encoding has nulls
        // PUSH imm8 encoding: 6A XX (never has nulls in imm8 range)
        // The original might be encoded as PUSH imm32, so we can optimize
        return 1;
    }

    // For larger values with nulls, we'll need MOV + PUSH
    return 1;
}

/*
 * Size calculation for PUSH imm optimization
 */
size_t get_size_push_imm_preservation(cs_insn *insn) {
    cs_x86_op *op = &insn->detail->x86.operands[0];
    int64_t imm = op->imm;

    // Check if it fits in imm8 (signed -128 to 127)
    // IMPORTANT: Exclude 0 because PUSH 0 encodes as 6A 00 which contains a null byte!
    if (imm >= -128 && imm <= 127 && imm != 0) {
        // PUSH imm8: 6A XX (2 bytes)
        return 2;
    }

    // For larger values: MOV EAX, imm32 (null-free) + PUSH EAX
    // MOV EAX size depends on the immediate value
    size_t mov_size = get_mov_eax_imm_size((uint32_t)imm);
    // PUSH EAX: 1 byte (0x50)
    return mov_size + 1;
}

/*
 * Generate null-free PUSH immediate
 *
 * Strategy A: For small immediates (-128 to 127), use PUSH imm8
 * Strategy B: For larger immediates, use MOV EAX + PUSH EAX
 */
void generate_push_imm_preservation(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op = &insn->detail->x86.operands[0];
    int64_t imm = op->imm;

    // Strategy A: Use PUSH imm8 for small values
    // IMPORTANT: Exclude 0 because PUSH 0 encodes as 6A 00 which contains a null byte!
    if (imm >= -128 && imm <= 127 && imm != 0) {
        // PUSH imm8: 6A XX
        buffer_write_byte(b, 0x6A);
        buffer_write_byte(b, (uint8_t)(imm & 0xFF));
        return;
    }

    // Strategy B: Use MOV EAX, imm32 (null-free) + PUSH EAX
    uint32_t imm32 = (uint32_t)imm;

    // Generate null-free MOV EAX, imm32
    generate_mov_eax_imm(b, imm32);

    // PUSH EAX: 0x50
    buffer_write_byte(b, 0x50);
}

/*
 * Strategy definition
 */
strategy_t push_imm_preservation_strategy = {
    .name = "PUSH Immediate Null-Byte Elimination",
    .can_handle = can_handle_push_imm_preservation,
    .get_size = get_size_push_imm_preservation,
    .generate = generate_push_imm_preservation,
    .priority = 86  // High priority - common pattern in function call setup
};
