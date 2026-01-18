/**
 * rip_relative_optimization_strategies.h
 *
 * Header file for RIP-relative addressing optimization strategies.
 * Priority: 87 (Tier 2 - Essential for modern x64)
 * Applicability: x64 PIC code (80% of modern shellcode)
 */

#ifndef RIP_RELATIVE_OPTIMIZATION_STRATEGIES_H
#define RIP_RELATIVE_OPTIMIZATION_STRATEGIES_H

#include "strategy.h"

/**
 * Register all RIP-relative optimization strategies.
 * These strategies provide advanced transformations for x64 position-
 * independent code to avoid bad bytes in RIP-relative offsets.
 *
 * Strategies included:
 * 1. Offset Decomposition - Priority 87
 * 2. Double-RIP Calculation - Priority 86
 * 3. RIP-Relative via Stack - Priority 85
 *
 * All strategies maintain PIC (position-independent code) properties.
 */
void register_rip_relative_optimization_strategies(void);

#endif // RIP_RELATIVE_OPTIMIZATION_STRATEGIES_H