/**
 * multbyte_nop_interlacing_strategies.h
 *
 * Header file for multi-byte NOP interlacing strategies.
 * Priority: 82 (Tier 3 - Medium Value, Low-Medium Effort)
 * Applicability: Obfuscation (50% of alignment code)
 */

#ifndef MULTIBYTE_NOP_INTERLACING_STRATEGIES_H
#define MULTIBYTE_NOP_INTERLACING_STRATEGIES_H

#include "strategy.h"

/**
 * Register all multi-byte NOP interlacing strategies.
 * These strategies replace standard NOP instructions with more complex
 * sequences that have the same semantic effect (no operation) but are
 * harder for disassemblers and emulators to recognize.
 *
 * Strategies included:
 * 1. Arithmetic NOPs - Priority 82
 * 2. Register Rotation NOPs - Priority 81
 * 3. Conditional NOPs - Priority 80
 * 4. FPU NOPs - Priority 79
 *
 * Provides enhanced obfuscation by avoiding recognizable NOP patterns.
 */
void register_multibyte_nop_interlacing_strategies(void);

#endif // MULTIBYTE_NOP_INTERLACING_STRATEGIES_H