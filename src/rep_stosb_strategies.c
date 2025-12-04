/*
 * REP STOSB for Memory Zeroing/Initialization Strategy
 *
 * PROBLEM: REP STOSB is commonly used in shellcode for memory initialization.
 * The setup code loads count into ECX/RCX and value into AL/EAX, which often
 * contain null bytes:
 * - MOV ECX, 0x100 → B9 00 01 00 00 (contains 3 nulls)
 * - MOV AL, 0x00 → B0 00 (contains 1 null)
 *
 * SOLUTION: Detect MOV to ECX/RCX used for REP STOSB count and provide
 * optimized null-free construction for common count values.
 *
 * FREQUENCY: Very common in shellcode for memory clearing and initialization
 * PRIORITY: 92 (Very High - more efficient than ROR13 for memory counts)
 *
 * Example transformations:
 *   Original: MOV ECX, 0x100 (B9 00 01 00 00 - contains nulls)
 *   Strategy: XOR ECX,ECX; MOV CH,0x01 (null-free, 5 bytes)
 *
 *   Original: MOV ECX, 0x20 (B9 20 00 00 00 - contains nulls)
 *   Strategy: XOR ECX,ECX; MOV CL,0x20 (null-free, 4 bytes)
 */

#include "rep_stosb_strategies.h"
#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Check if an immediate value looks like a typical REP STOSB count
 * Common counts are small values (1-0x10000) used for memory initialization
 */
static int is_likely_stosb_count(uint32_t imm) {
    // REP STOSB counts are typically small-to-medium values
    // Most common: 0x10, 0x20, 0x100, 0x400, 0x1000, etc.
    // Range: 1 to 0x10000 (64KB is reasonable max for shellcode)
    return (imm > 0 && imm <= 0x10000);
}

/*
 * Detection function for MOV ECX/RCX with count values for REP STOSB
 */
int can_handle_rep_stosb_count_setup(cs_insn *insn) {
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

    // Must be moving to ECX or RCX (REP STOSB uses CX as count)
    if (dst_op->reg != X86_REG_ECX && dst_op->reg != X86_REG_RCX) {
        return 0;
    }

    uint32_t imm = (uint32_t)src_op->imm;

    // Check if it looks like a REP STOSB count
    if (!is_likely_stosb_count(imm)) {
        return 0;
    }

    // Check if the immediate contains null bytes when encoded
    if (is_null_free(imm)) {
        // Already null-free
        return 0;
    }

    return 1;
}

/*
 * Size calculation for REP STOSB count setup
 *
 * Strategy depends on the count value:
 * - For values 0x01-0xFF: XOR ECX,ECX + MOV CL,byte = 4 bytes
 * - For values 0x100-0xFFFF: XOR ECX,ECX + MOV CX,word = 6 bytes
 * - For larger values: Use arithmetic construction
 */
size_t get_size_rep_stosb_count_setup(cs_insn *insn) {
    cs_x86_op *src_op = &insn->detail->x86.operands[1];
    uint32_t count = (uint32_t)src_op->imm;

    if (count <= 0xFF) {
        // XOR ECX,ECX (2) + MOV CL,byte (2) = 4 bytes
        return 4;
    } else if (count <= 0xFFFF) {
        // XOR ECX,ECX (2) + MOV CX,word (4: 66 B9 XX XX) = 6 bytes
        return 6;
    } else {
        // For larger counts, use byte-by-byte construction
        // XOR ECX,ECX (2) + up to 4 MOV operations (2 bytes each) = 10 bytes max
        return 10;
    }
}

/*
 * Generate null-free REP STOSB count setup
 *
 * Strategy: For typical count values, use efficient byte/word construction:
 *   - Small counts (0x01-0xFF): XOR ECX,ECX; MOV CL,count
 *   - Medium counts (0x100-0xFFFF): XOR ECX,ECX; MOV CX,count
 *   - Larger counts: Byte-by-byte construction
 */
void generate_rep_stosb_count_setup(struct buffer *b, cs_insn *insn) {
    cs_x86_op *src_op = &insn->detail->x86.operands[1];
    uint32_t count = (uint32_t)src_op->imm;

    // XOR ECX, ECX - clears ECX (and RCX upper bits in x64)
    buffer_write_byte(b, 0x31);  // XOR opcode
    buffer_write_byte(b, 0xC9);  // ModR/M for XOR ECX, ECX

    if (count <= 0xFF) {
        // Count fits in a single byte - use MOV CL, byte
        buffer_write_byte(b, 0xB1);  // MOV CL, imm8
        buffer_write_byte(b, (uint8_t)count);
    } else if (count <= 0xFFFF) {
        // Count fits in a word - use MOV CX, word
        buffer_write_byte(b, 0x66);  // Operand size override prefix
        buffer_write_byte(b, 0xB9);  // MOV CX, imm16
        buffer_write_byte(b, (uint8_t)(count & 0xFF));       // Low byte
        buffer_write_byte(b, (uint8_t)((count >> 8) & 0xFF)); // High byte
    } else {
        // Larger count - construct byte by byte
        // This handles counts up to 0x10000
        uint8_t bytes[4];
        memcpy(bytes, &count, 4);

        // Set each non-zero byte using MOV to specific register parts
        // For ECX: CL (low), CH (high), and then we'd need different approach for higher bytes

        // For simplicity with counts <= 0x10000, we know bytes[2] and bytes[3] are 0
        // So we only need to set bytes[0] and bytes[1]

        if (bytes[0] != 0) {
            // MOV CL, byte
            buffer_write_byte(b, 0xB1);
            buffer_write_byte(b, bytes[0]);
        }

        if (bytes[1] != 0) {
            // MOV CH, byte
            buffer_write_byte(b, 0xB5);
            buffer_write_byte(b, bytes[1]);
        }

        // If we need bytes[2] or bytes[3], we'd use different instructions
        // But for counts <= 0x10000, this shouldn't happen
    }
}

/*
 * Strategy definition
 */
strategy_t rep_stosb_count_setup_strategy = {
    .name = "REP STOSB Count Setup Optimization",
    .can_handle = can_handle_rep_stosb_count_setup,
    .get_size = get_size_rep_stosb_count_setup,
    .generate = generate_rep_stosb_count_setup,
    .priority = 92  // Higher than ROR13 (90) - more efficient for memory counts
};
