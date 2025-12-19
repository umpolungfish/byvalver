/**
 * polymorphic_immediate_construction_strategies.h
 *
 * Header file for polymorphic immediate value construction strategies.
 * Priority: 90 (Tier 1 - Highest)
 * Applicability: Universal (90% of code)
 */

#ifndef POLYMORPHIC_IMMEDIATE_CONSTRUCTION_STRATEGIES_H
#define POLYMORPHIC_IMMEDIATE_CONSTRUCTION_STRATEGIES_H

#include "strategy.h"

/**
 * Register all polymorphic immediate construction strategies.
 * These strategies provide multiple encoding variants for immediate values
 * to avoid bad characters while maintaining semantic equivalence.
 *
 * Strategies included:
 * 1. XOR Chain Encoding (Priority 90)
 * 2. ADD/SUB Decomposition (Priority 89)
 * 3. Shift/OR Byte Construction (Priority 88)
 */
void register_polymorphic_immediate_construction_strategies(void);

#endif // POLYMORPHIC_IMMEDIATE_CONSTRUCTION_STRATEGIES_H
