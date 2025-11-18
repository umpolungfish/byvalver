/*
 * Header file for MOVZX/MOVSX Null-Byte Elimination Strategy
 *
 * This strategy handles MOVZX (Move with Zero-Extend) and MOVSX (Move with
 * Sign-Extend) instructions that produce null bytes due to ModR/M encoding
 * or displacement values.
 *
 * These instructions are critical for Windows shellcode that reads PE export
 * table ordinals (16-bit values) during API resolution.
 *
 * Example problematic patterns:
 *   movzx eax, byte [eax]  -> 0F B6 00 (contains \x00)
 *   movzx eax, byte [ebp]  -> 0F B6 45 00 (contains \x00)
 *
 * Strategy: Use temporary register substitution to avoid null-producing
 * ModR/M bytes while preserving zero/sign-extension semantics.
 */

#ifndef MOVZX_STRATEGIES_H
#define MOVZX_STRATEGIES_H

#include "strategy.h"

// Function to register the MOVZX/MOVSX strategies
void register_movzx_strategies();

// Strategy implementation functions
int movzx_null_elimination_can_handle(cs_insn *insn);
size_t movzx_null_elimination_get_size(cs_insn *insn);
void movzx_null_elimination_generate(struct buffer *b, cs_insn *insn);

extern strategy_t movzx_null_elimination_strategy;

#endif
