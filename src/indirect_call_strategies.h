#ifndef INDIRECT_CALL_STRATEGIES_H
#define INDIRECT_CALL_STRATEGIES_H

#include "strategy.h"

/**
 * Indirect Memory CALL/JMP Strategies
 *
 * Handles the pattern: CALL/JMP DWORD PTR [addr]
 * where addr contains null bytes
 *
 * Pattern: FF 15 [addr with nulls]
 * Example: call DWORD PTR ds:0x00401000
 *
 * This is extremely common in Windows shellcode for API resolution,
 * appearing 50+ times across analyzed samples.
 *
 * Replacement strategy:
 *   1. MOV EAX, addr (using null-free construction)
 *   2. MOV EAX, DWORD PTR [EAX] (dereference to get function pointer)
 *   3. CALL/JMP EAX
 *
 * Priority: 100 (highest - critical for Windows API resolution)
 */

void register_indirect_call_strategies(void);

#endif // INDIRECT_CALL_STRATEGIES_H
