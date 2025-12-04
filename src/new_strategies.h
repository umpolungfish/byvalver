#ifndef NEW_STRATEGIES_H
#define NEW_STRATEGIES_H

#include <capstone/capstone.h>
#include "strategy.h"

// Transformation strategy for MOV reg32, [reg32] instructions that contain null bytes
// Example: mov eax, [eax] (0x8B 0x00) -> transformed to null-byte-free sequence
extern strategy_t transform_mov_reg_mem_self;

// Transformation strategy for ADD [mem], reg8 instructions that contain null bytes
// Example: add [eax], al (0x00 0x00) -> transformed to null-byte-free sequence
extern strategy_t transform_add_mem_reg8;

#endif // NEW_STRATEGIES_H