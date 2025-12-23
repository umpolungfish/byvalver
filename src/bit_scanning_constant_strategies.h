#ifndef BIT_SCANNING_CONSTANT_STRATEGIES_H
#define BIT_SCANNING_CONSTANT_STRATEGIES_H

#include "strategy.h"
#include "utils.h"

/*
 * BSF/BSR Bit Scanning Strategy for Bad Character Elimination
 *
 * PURPOSE: Detect MOV immediate with power-of-2 values or values with isolated
 * bits that contain bad characters. Use BSF (Bit Scan Forward) or BSR (Bit Scan
 * Reverse) to find bit positions, then shift to reconstruct the value.
 *
 * TECHNIQUE:
 * Original: MOV EAX, 0x00010000  (contains null bytes)
 * Transform: MOV EBX, 0x10000; BSF EAX, EBX
 *            (BSF finds the index of the first set bit = 16)
 *            Then: MOV ECX, 1; SHL ECX, AL; MOV EAX, ECX
 *
 * Alternatively for single-bit values (powers of 2):
 * Original: MOV EAX, 0x00000100  (bit 8 set, contains nulls)
 * Transform: XOR EAX, EAX; MOV AL, 8; MOV ECX, 1; SHL ECX, AL; MOV EAX, ECX
 *
 * This works well for:
 * - Power-of-2 values (0x1, 0x2, 0x4, 0x8, 0x10, 0x20, ... 0x80000000)
 * - Bitmask values in Windows API calls
 * - Flag values in system structures
 *
 * PRIORITY: 80 (Medium-High - common for flag values)
 */

// Strategy interface functions
int can_handle_bit_scanning_constant(cs_insn *insn);
size_t get_size_bit_scanning_constant(cs_insn *insn);
void generate_bit_scanning_constant(struct buffer *b, cs_insn *insn);

// Helper functions
int is_power_of_two(uint32_t val);
int get_bit_position(uint32_t val);  // Returns bit position for power-of-2 values
int count_set_bits(uint32_t val);

#endif /* BIT_SCANNING_CONSTANT_STRATEGIES_H */
