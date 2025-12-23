#ifndef LOOP_COMPREHENSIVE_STRATEGIES_H
#define LOOP_COMPREHENSIVE_STRATEGIES_H

#include "strategy.h"
#include "utils.h"

/*
 * LOOP Comprehensive Variants Strategy for Bad Character Elimination
 *
 * PURPOSE: Detect LOOP/LOOPE/LOOPNE/LOOPZ/LOOPNZ instructions with bad
 * character displacements and transform them to equivalent instruction sequences.
 *
 * TECHNIQUE:
 * LOOP instructions decrement ECX and jump if ECX != 0
 * LOOPE/LOOPZ jumps if ECX != 0 AND ZF = 1
 * LOOPNE/LOOPNZ jumps if ECX != 0 AND ZF = 0
 *
 * Transformations:
 * 1. LOOP target → DEC ECX; JNZ target
 * 2. LOOPE target → DEC ECX; JZ end; JE target; end:
 * 3. LOOPNE target → DEC ECX; JZ end; JNE target; end:
 *
 * All LOOP variants use 8-bit displacement which may contain bad characters.
 * The transformation uses standard conditional jumps which we can further
 * transform if needed.
 *
 * PRIORITY: 79 (Medium-High - LOOP common in shellcode iterations)
 */

// Strategy interface functions
int can_handle_loop_comprehensive(cs_insn *insn);
size_t get_size_loop_comprehensive(cs_insn *insn);
void generate_loop_comprehensive(struct buffer *b, cs_insn *insn);

#endif /* LOOP_COMPREHENSIVE_STRATEGIES_H */
