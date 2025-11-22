#ifndef STRATEGY_H
#define STRATEGY_H

#include <stdint.h>
#include <stddef.h>
#include <capstone/capstone.h>

// Forward declaration to avoid circular dependency
struct buffer;

// Strategy interface structure
typedef struct {
    const char* name;                           // Strategy name for identification
    int (*can_handle)(cs_insn *insn);          // Function to check if strategy can handle instruction
    size_t (*get_size)(cs_insn *insn);         // Function to calculate new size
    void (*generate)(struct buffer *b, cs_insn *insn);  // Function to generate new code
    int priority;                              // Priority for strategy selection (higher = more preferred)
} strategy_t;

#include "core.h"  // Now we can include core.h after strategy_t is defined

// Registry management functions
void register_strategy(strategy_t *strategy);
strategy_t** get_strategies_for_instruction(cs_insn *insn, int *count);
void init_strategies();

// Strategy registration functions for different instruction types
void register_mov_strategies();
void register_arithmetic_strategies();
void register_memory_strategies();
void register_jump_strategies();
void register_general_strategies();
void register_anti_debug_strategies();
void register_peb_strategies();
void register_conservative_strategies();
void register_lea_strategies();
void register_byte_construct_strategy();
void register_conditional_jump_offset_strategies();
void register_cmp_memory_disp_null_strategy();

// Core strategy functions that will be implemented with the new pattern
int is_mov_instruction(cs_insn *insn);
int is_arithmetic_instruction(cs_insn *insn);
int has_null_bytes(cs_insn *insn);

// Additional utility functions for arithmetic substitution
int find_arithmetic_equivalent(uint32_t target, uint32_t *base, uint32_t *offset, int *operation);

#endif