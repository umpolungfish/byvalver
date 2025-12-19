/**
 * setcc_jump_elimination_strategies.h
 *
 * Header file for SETcc-based jump elimination strategies.
 * Priority: 86 (Tier 1)
 * Applicability: Universal (70% of conditional logic)
 */

#ifndef SETCC_JUMP_ELIMINATION_STRATEGIES_H
#define SETCC_JUMP_ELIMINATION_STRATEGIES_H

#include "strategy.h"

/**
 * Register all SETcc jump elimination strategies.
 * These strategies eliminate problematic conditional jump offsets
 * by converting them to linear SETcc + TEST patterns.
 *
 * Strategies included:
 * 1. Simple SETcc Jump Elimination (Priority 86)
 * 2. SETcc to Conditional Move (Priority 84)
 */
void register_setcc_jump_elimination_strategies(void);

#endif // SETCC_JUMP_ELIMINATION_STRATEGIES_H
