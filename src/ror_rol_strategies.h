/*
 * Header file for ROR/ROL Immediate Rotation Strategy
 *
 * This strategy handles ROR (Rotate Right) and ROL (Rotate Left) instructions
 * with immediate values that produce null bytes in their encoding.
 *
 * These instructions are critical for Windows shellcode that uses hash-based
 * API resolution (e.g., ROR13 hash algorithm used in ~90% of Windows samples).
 *
 * Example problematic patterns:
 *   ror edi, 0x0d  -> Might encode with nulls depending on register/mode
 *   rol eax, 0x05  -> Hash calculation in API resolution
 *
 * Strategy: Transform immediate rotation to register-based rotation using CL:
 *   Original: ROR EDI, imm8
 *   Transformed: PUSH ECX; MOV CL, imm8; ROR EDI, CL; POP ECX
 */

#ifndef ROR_ROL_STRATEGIES_H
#define ROR_ROL_STRATEGIES_H

#include "strategy.h"

// Function to register the ROR/ROL strategies
void register_ror_rol_strategies();

// Strategy implementation functions
int ror_rol_immediate_can_handle(cs_insn *insn);
size_t ror_rol_immediate_get_size(cs_insn *insn);
void ror_rol_immediate_generate(struct buffer *b, cs_insn *insn);

extern strategy_t ror_rol_immediate_strategy;

#endif // ROR_ROL_STRATEGIES_H
