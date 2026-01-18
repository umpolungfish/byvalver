/**
 * negative_displacement_addressing_strategies.h
 *
 * Header file for negative displacement memory addressing strategies.
 * Priority: 84 (Tier 3 - Medium Value, Low-Medium Effort)
 * Applicability: Universal (40% of memory operations)
 */

#ifndef NEGATIVE_DISPLACEMENT_ADDRESSING_STRATEGIES_H
#define NEGATIVE_DISPLACEMENT_ADDRESSING_STRATEGIES_H

#include "strategy.h"

/**
 * Register all negative displacement addressing strategies.
 * These strategies convert memory accesses with positive displacements
 * containing bad bytes into equivalent operations using negative displacements
 * or base register adjustments.
 *
 * Strategies included:
 * 1. Negative Offset Conversion - Priority 84
 * 2. Alternative Base Register - Priority 83
 * 3. Complement Offset - Priority 82
 *
 * Maintains semantic equivalence while avoiding bad bytes in displacements.
 */
void register_negative_displacement_addressing_strategies(void);

#endif // NEGATIVE_DISPLACEMENT_ADDRESSING_STRATEGIES_H