#ifndef SYSCALL_NUMBER_STRATEGIES_H
#define SYSCALL_NUMBER_STRATEGIES_H

#include "strategy.h"
#include <capstone/capstone.h>

// Strategy A: Byte-Based Construction for Linux syscall numbers with null bytes (range 1-1024)
// Priority 78 - Handles larger syscall numbers by constructing them with byte operations
extern strategy_t syscall_number_byte_based_strategy;

// Strategy B: Push/Pop Technique for small syscall numbers (1-127) for size optimization
// Priority 77 - Optimized for smaller syscall numbers
extern strategy_t syscall_number_push_pop_strategy;

#endif /* SYSCALL_NUMBER_STRATEGIES_H */