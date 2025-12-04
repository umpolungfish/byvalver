/*
 * BYVALVER - Pass 1: Obfuscation Strategy Registry Header
 */

#ifndef OBFUSCATION_STRATEGY_REGISTRY_H
#define OBFUSCATION_STRATEGY_REGISTRY_H

#include "strategy.h"
#include <capstone/capstone.h>

// Register an obfuscation strategy
void register_obfuscation_strategy(strategy_t *strategy);

// Initialize all obfuscation strategies
void init_obfuscation_strategies();

// Find best matching obfuscation strategy for an instruction
strategy_t* find_obfuscation_strategy(cs_insn *insn);

// Get count of registered strategies
int get_obfuscation_strategy_count();

// List all strategies (debugging)
void list_obfuscation_strategies();

#endif // OBFUSCATION_STRATEGY_REGISTRY_H
