/*
 * Header file for Shift-Based Immediate Value Construction Strategy
 * 
 * This strategy uses shift operations (SHL/SHR) to construct immediate values 
 * when direct immediate values contain null bytes. This technique is more 
 * sophisticated than simple arithmetic equivalents.
 */

#ifndef SHIFT_STRATEGY_H
#define SHIFT_STRATEGY_H

#include "strategy.h"

// Function to register the shift-based strategy
void register_shift_strategy();

// Strategy implementation functions
int shift_based_can_handle(cs_insn *insn);
size_t shift_based_get_size(cs_insn *insn);
void shift_based_generate(struct buffer *b, cs_insn *insn);

extern strategy_t shift_based_strategy;

#endif