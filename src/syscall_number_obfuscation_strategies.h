/**
 * syscall_number_obfuscation_strategies.h
 *
 * Header file for syscall number obfuscation strategies.
 * Priority: 88 (Tier 1 - Linux/x64 specific)
 * Applicability: Linux syscalls (80%+ of Linux shellcode)
 */

#ifndef SYSCALL_NUMBER_OBFUSCATION_STRATEGIES_H
#define SYSCALL_NUMBER_OBFUSCATION_STRATEGIES_H

#include "strategy.h"

/**
 * Register all syscall number obfuscation strategies.
 * These strategies specifically target MOV EAX/RAX, syscall_number
 * patterns to eliminate bad characters in syscall immediates.
 *
 * Strategies included:
 * 1. AL Loading (XOR + MOV AL) - Priority 88
 * 2. PUSH/POP Loading - Priority 87
 * 3. LEA Arithmetic - Priority 86
 * 4. INC Chain (for small numbers) - Priority 85
 */
void register_syscall_number_obfuscation_strategies(void);

#endif // SYSCALL_NUMBER_OBFUSCATION_STRATEGIES_H
