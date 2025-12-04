/*
 * Multi-Byte NOP Null-Byte Elimination Strategy
 *
 * PROBLEM: Modern compilers generate multi-byte NOP instructions for code alignment, such as:
 * - 0F 1F 84 00 00 00 00 00  (9 bytes) -> nop dword ptr [eax+eax+0x0] (7 nulls!)
 * - 0F 1F 40 00 (4 bytes) -> nop dword ptr [eax+0x0] (1 null)
 * - 66 2E 0F 1F 84 00 00 00 00 00 (10 bytes) -> nop word ptr cs:[eax+eax+0x0] (5 nulls!)
 *
 * These instructions contain displacement fields set to 0, which introduces null bytes.
 *
 * SOLUTION: Replace with equivalent-length null-free NOPs or functional equivalents.
 *
 * FREQUENCY: Affects 100% of compiler-generated binaries with multi-byte NOPs
 * PRIORITY: 90 (Critical)
 *
 * Example transformations:
 *   Original: nop dword ptr [eax+0x0] (0F 1F 40 00 - contains null)
 *   Strategy A: nop; nop; nop; nop (90 90 90 90 - same size, all 0x90)
 *   Strategy B: xchg ax, ax; nop (66 90 90 - for 3-byte NOPs)
 *   Strategy C: mov eax, eax; etc. (for larger replacements)
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Detection function for multi-byte NOPs that contain null bytes
 */
int can_handle_multibyte_nop_null(cs_insn *insn) {
    // Check if it's a NOP instruction with size > 1 and null bytes
    if (insn->id != X86_INS_NOP) return 0;
    if (insn->size < 2) return 0;  // Need multi-byte NOPs only
    
    // Check for null bytes in the instruction encoding
    for (int i = 0; i < insn->size; i++) {
        if (insn->bytes[i] == 0x00) return 1;
    }
    
    return 0;
}

/*
 * Size calculation function for multi-byte NOP null elimination
 * Replacement size should match original size exactly to preserve offsets
 */
size_t get_size_multibyte_nop_null(cs_insn *insn) {
    // Return the same size as original instruction to preserve offsets
    return insn->size;
}

/*
 * Generation function for null-free multi-byte NOP replacement
 * Multiple strategies for different instruction sizes
 */
void generate_multibyte_nop_null_free(struct buffer *b, cs_insn *insn) {
    size_t original_size = insn->size;
    
    // Strategy A: Replace with equivalent-length single-byte NOPs (safest approach)
    for (size_t i = 0; i < original_size; i++) {
        buffer_write_byte(b, 0x90);  // Single-byte NOP, null-free
    }
}

// Define the strategy structure
strategy_t multibyte_nop_strategy = {
    .name = "Multi-Byte NOP Null Elimination",
    .can_handle = can_handle_multibyte_nop_null,
    .get_size = get_size_multibyte_nop_null,
    .generate = generate_multibyte_nop_null_free,
    .priority = 90  // Critical priority for compiler-generated code
};