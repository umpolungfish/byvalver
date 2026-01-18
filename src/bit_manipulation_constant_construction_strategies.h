/**
 * bit_manipulation_constant_construction_strategies.h
 *
 * Header file for bit manipulation constant construction strategies.
 * Priority: 83 (Tier 3 - Medium Value, Low-Medium Effort)
 * Applicability: Limited (20% of constants, modern CPUs only)
 */

#ifndef BIT_MANIPULATION_CONSTANT_CONSTRUCTION_STRATEGIES_H
#define BIT_MANIPULATION_CONSTANT_CONSTRUCTION_STRATEGIES_H

#include "strategy.h"

/**
 * Register all bit manipulation constant construction strategies.
 * These strategies use modern x64 bit manipulation instructions to construct
 * constants as alternatives to traditional MOV/ADD/SUB sequences.
 *
 * Strategies included:
 * 1. BSWAP Construction - Priority 83 (Byte reordering)
 * 2. BSF/BSR Construction - Priority 82 (Powers of 2 via bit scanning)
 * 3. POPCNT Construction - Priority 81 (Bit counting)
 * 4. PEXT/PDEP Construction - Priority 80 (Advanced BMI2 bit manipulation)
 *
 * Requires modern CPU support (BSWAP: baseline, POPCNT: SSE4.2, BMI2: 2013+).
 */
void register_bit_manipulation_constant_construction_strategies(void);

#endif // BIT_MANIPULATION_CONSTANT_CONSTRUCTION_STRATEGIES_H