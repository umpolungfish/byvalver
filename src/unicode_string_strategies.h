/*
 * Unicode String Handling Strategy - Header
 *
 * Provides null-byte elimination for Windows Unicode (UTF-16) string construction.
 * Implements two complementary strategies:
 *   - Strategy A: STOSW-based byte-by-byte Unicode construction
 *   - Strategy B: ASCII-to-Unicode runtime conversion
 *
 * Priority: 74-78 (Medium-High, Windows-specific)
 * Platform: Windows-only
 */

#ifndef UNICODE_STRING_STRATEGIES_H
#define UNICODE_STRING_STRATEGIES_H

#include "strategy.h"

/*
 * Register Unicode string handling strategies
 * Called from init_strategies() in strategy_registry.c
 */
void register_unicode_string_strategies();

#endif // UNICODE_STRING_STRATEGIES_H
