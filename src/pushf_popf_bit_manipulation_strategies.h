#ifndef PUSHF_POPF_BIT_MANIPULATION_STRATEGIES_H
#define PUSHF_POPF_BIT_MANIPULATION_STRATEGIES_H

#include "strategy.h"
#include "utils.h"

/*
 * PUSHF/POPF Bit Manipulation Strategy for Bad Character Elimination
 *
 * PURPOSE: Detect flag-setting instructions that may encode with bad characters.
 * Transform using PUSHF/POPF to manipulate EFLAGS register bits directly.
 *
 * TECHNIQUE: Instead of flag-setting instructions that may have bad char encodings,
 * use PUSHF; POP reg; OR/AND/XOR reg, mask; PUSH reg; POPF
 *
 * This allows setting/clearing specific flags:
 * - CF (Carry Flag) - bit 0
 * - PF (Parity Flag) - bit 2
 * - AF (Auxiliary Flag) - bit 4
 * - ZF (Zero Flag) - bit 6
 * - SF (Sign Flag) - bit 7
 * - DF (Direction Flag) - bit 10
 * - OF (Overflow Flag) - bit 11
 *
 * PRIORITY: 81 (Medium-High - useful for anti-debugging and flag manipulation)
 */

// EFLAGS bit positions
#define EFLAGS_CF  (1 << 0)   // Carry Flag
#define EFLAGS_PF  (1 << 2)   // Parity Flag
#define EFLAGS_AF  (1 << 4)   // Auxiliary Carry Flag
#define EFLAGS_ZF  (1 << 6)   // Zero Flag
#define EFLAGS_SF  (1 << 7)   // Sign Flag
#define EFLAGS_DF  (1 << 10)  // Direction Flag
#define EFLAGS_OF  (1 << 11)  // Overflow Flag

// Strategy interface functions
int can_handle_pushf_popf_flag_manipulation(cs_insn *insn);
size_t get_size_pushf_popf_flag_manipulation(cs_insn *insn);
void generate_pushf_popf_flag_manipulation(struct buffer *b, cs_insn *insn);

// Helper functions
int get_flag_mask_for_instruction(cs_insn *insn, uint32_t *set_mask, uint32_t *clear_mask);

#endif /* PUSHF_POPF_BIT_MANIPULATION_STRATEGIES_H */
