#ifndef IMMEDIATE_SPLIT_STRATEGIES_H
#define IMMEDIATE_SPLIT_STRATEGIES_H

#include <stdint.h>
#include <stddef.h>
#include <capstone/capstone.h>
#include "core.h"

/*
 * Immediate Value Splitting Strategy
 *
 * This module provides strategies for handling instructions with immediate values
 * that contain null bytes. It decomposes problematic immediates into null-free
 * components using either arithmetic splitting or bit manipulation techniques.
 *
 * Supported instructions:
 * - PUSH imm32 (with null-containing immediate)
 * - MOV reg, imm32 (with null-containing immediate)
 * - Arithmetic operations (ADD, SUB, AND, OR, XOR) reg, imm32
 * - CMP reg, imm32 (with null-containing immediate)
 *
 * Priority: 77 (High - runs before lower-priority fallback strategies)
 */

/* Strategy detection function */
int can_handle_immediate_split(cs_insn *insn);

/* Size calculation function */
size_t get_size_immediate_split(cs_insn *insn);

/* Code generation function */
void generate_immediate_split(struct buffer *b, cs_insn *insn);

/* Strategy registration function */
void register_immediate_split_strategies(void);

#endif /* IMMEDIATE_SPLIT_STRATEGIES_H */
