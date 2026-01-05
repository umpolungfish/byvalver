#ifndef PROFILE_AWARE_SIB_H
#define PROFILE_AWARE_SIB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <capstone/capstone.h>
#include "utils.h"

/**
 * @file profile_aware_sib.h
 * @brief Profile-aware SIB (Scale-Index-Base) byte generation
 *
 * This module provides utilities to generate memory addressing encodings
 * that are safe for the current bad-byte profile. The standard SIB byte
 * 0x20 (SPACE character) is avoided when 0x20 is in the bad-byte set.
 *
 * Standard SIB byte breakdown:
 *   0x20 = 0b00100000
 *   - Bits 7-6 (scale): 00 = scale of 1
 *   - Bits 5-3 (index): 100 = ESP (special value meaning "no index")
 *   - Bits 2-0 (base):  000 = EAX
 *   This encodes [EAX] addressing mode
 *
 * Problem: 0x20 = 32 = SPACE character, which is a bad byte in http-whitespace profile
 */

/**
 * @brief Strategy for encoding memory access without bad bytes
 */
typedef enum {
    SIB_ENCODING_STANDARD,      // Use standard SIB 0x20 if safe
    SIB_ENCODING_DISP8,         // Use [reg + disp8] with compensation
    SIB_ENCODING_ALTERNATIVE,   // Use alternative SIB bytes
    SIB_ENCODING_PUSHPOP        // Use PUSH/POP based approach
} sib_encoding_strategy_t;

/**
 * @brief Result of SIB encoding selection
 */
typedef struct {
    sib_encoding_strategy_t strategy;
    uint8_t sib_byte;           // SIB byte to use (if applicable)
    uint8_t modrm_byte;         // ModR/M byte to use
    int8_t disp8;               // Displacement value (if using DISP8)
    bool needs_compensation;    // Whether address needs compensation
    int8_t compensation;        // Compensation value to apply
} sib_encoding_result_t;

/**
 * @brief Select best SIB encoding for [EAX] based on bad byte profile
 * @param dst_reg Destination register (for ModR/M encoding)
 * @return Encoding result with strategy and bytes to use
 */
sib_encoding_result_t select_sib_encoding_for_eax(x86_reg dst_reg);

/**
 * @brief Select best SIB encoding for [base_reg] based on bad byte profile
 * @param base_reg Base register for addressing
 * @param dst_reg Destination register (for ModR/M encoding)
 * @return Encoding result with strategy and bytes to use
 */
sib_encoding_result_t select_sib_encoding_for_reg(x86_reg base_reg, x86_reg dst_reg);

/**
 * @brief Generate MOV dst_reg, [base_reg] using profile-safe encoding
 * @param b Output buffer
 * @param dst_reg Destination register
 * @param base_reg Base register for memory operand
 * @return 0 on success, -1 on failure
 */
int generate_safe_mov_reg_mem(struct buffer *b, x86_reg dst_reg, x86_reg base_reg);

/**
 * @brief Generate MOV [base_reg], src_reg using profile-safe encoding
 * @param b Output buffer
 * @param base_reg Base register for memory operand
 * @param src_reg Source register
 * @return 0 on success, -1 on failure
 */
int generate_safe_mov_mem_reg(struct buffer *b, x86_reg base_reg, x86_reg src_reg);

/**
 * @brief Generate LEA dst_reg, [base_reg] using profile-safe encoding
 * @param b Output buffer
 * @param dst_reg Destination register
 * @param base_reg Base register for memory operand
 * @return 0 on success, -1 on failure
 */
int generate_safe_lea_reg_mem(struct buffer *b, x86_reg dst_reg, x86_reg base_reg);

/**
 * @brief Invalidate SIB encoding cache (call when bad byte profile changes)
 */
void invalidate_sib_cache(void);

/**
 * @brief Statistics for SIB encoding strategy usage
 */
typedef struct {
    uint32_t standard_count;
    uint32_t disp8_count;
    uint32_t pushpop_count;
} sib_encoding_stats_t;

extern sib_encoding_stats_t g_sib_stats;

/**
 * @brief Print SIB encoding statistics
 */
void print_sib_encoding_stats(void);

/**
 * @brief Reset SIB encoding statistics
 */
void reset_sib_encoding_stats(void);

#endif // PROFILE_AWARE_SIB_H
