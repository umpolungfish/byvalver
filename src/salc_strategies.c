/*
 * SALC Instruction for Zero Register Strategy
 *
 * PROBLEM: Setting AL register to zero or specific values can contain null bytes:
 * - MOV AL, 0x00 → B0 00 (contains 1 null)
 *
 * SOLUTION: Use SALC (Set AL on Carry), a legacy x86 instruction that sets AL based on CF:
 * - SALC sets AL to 0xFF if CF=1, or 0x00 if CF=0
 * - Combined with CLC (Clear Carry) or STC (Set Carry) for specific values
 *
 * FREQUENCY: Common in 32-bit shellcode for register initialization
 * PRIORITY: 91 (Very High - more efficient than ROR13 for AL=0, stealth benefit)
 *
 * Example transformations:
 *   Original: MOV AL, 0x00 (B0 00 - contains null)
 *   Strategy: CLC; SALC (F8 D6 - no nulls, 2 bytes)
 *
 *   Original: MOV AL, 0xFF (B0 FF - null-free but detectable)
 *   Strategy: STC; SALC (F9 D6 - no nulls, 2 bytes, stealthier)
 *
 * NOTE: SALC is only available in 32-bit mode. In x64, it's treated as REX prefix.
 */

#include "salc_strategies.h"
#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Detection function for MOV AL instructions that can be replaced with SALC
 */
int can_handle_salc_zero_al(cs_insn *insn) {
    // Only handle 32-bit mode (SALC is not valid in x64)
    if (insn->detail->x86.encoding.modrm_offset != 0 ||
        insn->detail->x86.rex != 0) {
        // Skip x64 instructions
        // Note: This is a heuristic; proper mode detection would be better
    }

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

    // Must be moving to AL register specifically
    if (dst_op->reg != X86_REG_AL) {
        return 0;
    }

    uint8_t imm = (uint8_t)src_op->imm;

    // SALC can only produce 0x00 (CF=0) or 0xFF (CF=1)
    if (imm != 0x00 && imm != 0xFF) {
        return 0;
    }

    // Check if the immediate contains null bytes when encoded
    // MOV AL, 0x00 → B0 00 (has null)
    // MOV AL, 0xFF → B0 FF (no null, but we can still optimize for stealth)
    if (imm == 0x00) {
        // Always handle zero case (has null byte)
        return 1;
    }

    // For 0xFF, we could optionally handle it for stealth,
    // but let's be conservative and only handle null-containing cases
    return 0;
}

/*
 * Size calculation for SALC-based AL zeroing
 *
 * Transformation uses:
 * - CLC (1 byte: F8) or STC (1 byte: F9)
 * - SALC (1 byte: D6)
 * Total: 2 bytes
 */
size_t get_size_salc_zero_al(cs_insn *insn) {
    (void)insn; // Unused parameter

    // CLC/STC (1) + SALC (1) = 2 bytes
    return 2;
}

/*
 * Generate SALC-based AL initialization
 *
 * For AL = 0x00:
 *   CLC   ; Clear carry flag (F8)
 *   SALC  ; Set AL based on carry (D6) → AL = 0x00
 *
 * For AL = 0xFF:
 *   STC   ; Set carry flag (F9)
 *   SALC  ; Set AL based on carry (D6) → AL = 0xFF
 */
void generate_salc_zero_al(struct buffer *b, cs_insn *insn) {
    cs_x86_op *src_op = &insn->detail->x86.operands[1];
    uint8_t target_value = (uint8_t)src_op->imm;

    if (target_value == 0x00) {
        // CLC - Clear carry flag
        buffer_write_byte(b, 0xF8);
        // SALC - Set AL based on carry (AL = 0x00 when CF=0)
        buffer_write_byte(b, 0xD6);
    } else if (target_value == 0xFF) {
        // STC - Set carry flag
        buffer_write_byte(b, 0xF9);
        // SALC - Set AL based on carry (AL = 0xFF when CF=1)
        buffer_write_byte(b, 0xD6);
    }
}

/*
 * Strategy definition
 */
strategy_t salc_zero_al_strategy = {
    .name = "SALC AL Zeroing Optimization",
    .can_handle = can_handle_salc_zero_al,
    .get_size = get_size_salc_zero_al,
    .generate = generate_salc_zero_al,
    .priority = 91  // Very high priority - more efficient than ROR13 for AL=0
};
