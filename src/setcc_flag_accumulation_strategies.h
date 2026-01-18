/**
 * setcc_flag_accumulation_strategies.h
 *
 * Header file for SETcc flag accumulation strategies.
 * Priority: 86 (Tier 1 - High Priority)
 * Applicability: Universal (70% of conditional logic)
 */

#ifndef SETCC_FLAG_ACCUMULATION_STRATEGIES_H
#define SETCC_FLAG_ACCUMULATION_STRATEGIES_H

#include "strategy.h"

/**
 * Register all SETcc flag accumulation strategies.
 * These strategies convert conditional jumps with bad offsets into
 * linear SETcc operations that accumulate flag results.
 *
 * Strategies included:
 * 1. SETcc to Register - Priority 86
 * 2. Arithmetic from Flags - Priority 85
 *
 * Note: Multi-flag accumulation requires multi-instruction pattern detection
 * which is not fully implemented in the current framework.
 */
void register_setcc_flag_accumulation_strategies(void);

#endif // SETCC_FLAG_ACCUMULATION_STRATEGIES_H