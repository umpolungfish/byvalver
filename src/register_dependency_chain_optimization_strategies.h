/**
 * register_dependency_chain_optimization_strategies.h
 *
 * Header file for register dependency chain optimization strategies.
 * Priority: 91 (Tier 1 - Multi-instruction)
 * Applicability: Universal (60% of shellcode has dependency chains)
 */

#ifndef REGISTER_DEPENDENCY_CHAIN_OPTIMIZATION_STRATEGIES_H
#define REGISTER_DEPENDENCY_CHAIN_OPTIMIZATION_STRATEGIES_H

#include "strategy.h"

/**
 * Register all register dependency chain optimization strategies.
 * These strategies analyze multi-instruction patterns and optimize
 * them together for better bad-character elimination.
 *
 * Strategies included:
 * 1. Value Accumulation Optimization (Priority 91)
 * 2. Arithmetic Sequence Recognition (Priority 88)
 *
 * NOTE: Full multi-instruction optimization requires lookahead buffer.
 * Current implementation handles single-instruction detection only.
 */
void register_register_dependency_chain_optimization_strategies(void);

#endif // REGISTER_DEPENDENCY_CHAIN_OPTIMIZATION_STRATEGIES_H
