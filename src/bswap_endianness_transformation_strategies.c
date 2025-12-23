/*
 * BSWAP Endianness Transformation Strategy for Bad Character Elimination
 *
 * PROBLEM: MOV instructions with immediate values that contain bad characters.
 * Example: MOV EAX, 0x00007F01 (127.0.0.1 in network byte order - contains nulls)
 *
 * SOLUTION: Use BSWAP to reverse byte order, avoiding bad characters.
 * If swapped version has fewer bad chars:
 *   MOV EAX, 0x017F0000  (byte-swapped value)
 *   BSWAP EAX            (reverse to get 0x00007F01)
 *
 * This is particularly effective for:
 * - IP addresses (e.g., 127.0.0.1, 192.168.x.x)
 * - Port numbers in socket structures
 * - Network byte order conversions
 */

#include "bswap_endianness_transformation_strategies.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * Byte-swap a 32-bit value
 */
uint32_t bswap32(uint32_t val) {
    return ((val & 0xFF000000) >> 24) |
           ((val & 0x00FF0000) >> 8)  |
           ((val & 0x0000FF00) << 8)  |
           ((val & 0x000000FF) << 24);
}

/**
 * Count number of bad characters in a 32-bit value
 */
int count_bad_chars_in_value(uint32_t val) {
    int count = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t byte = (val >> (i * 8)) & 0xFF;
        if (!is_bad_char_free_byte(byte)) {
            count++;
        }
    }
    return count;
}

/**
 * Check if this strategy can handle the instruction
 */
int can_handle_bswap_endianness_transformation(cs_insn *insn) {
    if (!insn) {
        return 0;
    }

    // Only handle MOV reg, imm32
    if (insn->id != X86_INS_MOV) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    cs_x86_op *src_op = &insn->detail->x86.operands[1];

    // Destination must be a 32-bit register
    if (dst_op->type != X86_OP_REG || src_op->type != X86_OP_IMM) {
        return 0;
    }

    // Only handle 32-bit registers (EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP)
    // BSWAP requires 32-bit or 64-bit register
    x86_reg reg = dst_op->reg;
    if (reg != X86_REG_EAX && reg != X86_REG_EBX &&
        reg != X86_REG_ECX && reg != X86_REG_EDX &&
        reg != X86_REG_ESI && reg != X86_REG_EDI &&
        reg != X86_REG_EBP && reg != X86_REG_ESP &&
        reg != X86_REG_R8D && reg != X86_REG_R9D &&
        reg != X86_REG_R10D && reg != X86_REG_R11D &&
        reg != X86_REG_R12D && reg != X86_REG_R13D &&
        reg != X86_REG_R14D && reg != X86_REG_R15D) {
        return 0;
    }

    uint32_t imm = (uint32_t)src_op->imm;

    // Check if original value has bad characters
    int original_bad_chars = count_bad_chars_in_value(imm);
    if (original_bad_chars == 0) {
        return 0; // No bad chars, no need to transform
    }

    // Check if byte-swapped version has fewer bad characters
    uint32_t swapped = bswap32(imm);
    int swapped_bad_chars = count_bad_chars_in_value(swapped);

    // Only apply if swapped version has fewer or no bad characters
    if (swapped_bad_chars < original_bad_chars) {
        return 1;
    }

    return 0;
}

/**
 * Calculate size of transformed instruction
 */
size_t get_size_bswap_endianness_transformation(cs_insn *insn) {
    if (!insn) {
        return 0;
    }

    // MOV reg32, imm32 = 5 bytes (B8+r id id id id)
    // BSWAP reg32 = 2 bytes (0F C8+r)
    return 5 + 2; // 7 bytes total
}

/**
 * Generate transformed instruction sequence
 */
void generate_bswap_endianness_transformation(struct buffer *b, cs_insn *insn) {
    if (!insn || !b) {
        return;
    }

    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    cs_x86_op *src_op = &insn->detail->x86.operands[1];

    x86_reg reg = dst_op->reg;
    uint32_t imm = (uint32_t)src_op->imm;
    uint32_t swapped = bswap32(imm);

    // Get register index for encoding
    uint8_t reg_idx = get_reg_index(reg);

    // Step 1: MOV reg32, swapped_imm32
    // Opcode: B8+r for MOV reg32, imm32
    buffer_write_byte(b, 0xB8 + reg_idx);
    buffer_write_dword(b, swapped);

    // Step 2: BSWAP reg32
    // Opcode: 0F C8+r
    buffer_write_byte(b, 0x0F);
    buffer_write_byte(b, 0xC8 + reg_idx);
}

// Define the strategy structure
strategy_t bswap_endianness_transformation_strategy = {
    .name = "BSWAP Endianness Transformation",
    .can_handle = can_handle_bswap_endianness_transformation,
    .get_size = get_size_bswap_endianness_transformation,
    .generate = generate_bswap_endianness_transformation,
    .priority = 85
};
