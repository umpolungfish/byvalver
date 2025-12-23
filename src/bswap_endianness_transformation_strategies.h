#ifndef BSWAP_ENDIANNESS_TRANSFORMATION_STRATEGIES_H
#define BSWAP_ENDIANNESS_TRANSFORMATION_STRATEGIES_H

#include "strategy.h"
#include "utils.h"

/*
 * BSWAP Endianness Transformation Strategy for Bad Character Elimination
 *
 * PURPOSE: Detect MOV instructions with immediate values that contain bad characters.
 * Check if byte-swapped version has fewer/no bad characters, then generate:
 * MOV reg, swapped_value; BSWAP reg
 *
 * This is particularly useful for network byte order in socket shellcode where
 * IP addresses and port numbers may contain null bytes in little-endian but not
 * in big-endian representation.
 *
 * PRIORITY: 85 (High - common in network shellcode)
 */

// Strategy interface functions
int can_handle_bswap_endianness_transformation(cs_insn *insn);
size_t get_size_bswap_endianness_transformation(cs_insn *insn);
void generate_bswap_endianness_transformation(struct buffer *b, cs_insn *insn);

// Helper functions
uint32_t bswap32(uint32_t val);
int count_bad_chars_in_value(uint32_t val);

#endif /* BSWAP_ENDIANNESS_TRANSFORMATION_STRATEGIES_H */
