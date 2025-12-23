/*
 * BSF/BSR Bit Scanning Strategy for Bad Character Elimination
 *
 * PROBLEM: MOV instructions with power-of-2 immediate values often contain
 * null bytes or other bad characters.
 * Example: MOV EAX, 0x00010000 (0x66536 = 65536, bit 16)
 *          Bytes: B8 00 00 01 00 (contains multiple nulls)
 *
 * SOLUTION: Use bit position calculation and shifting:
 * Method 1 (for powers of 2):
 *   XOR EAX, EAX     ; Zero EAX
 *   MOV AL, 16       ; Bit position (no nulls)
 *   MOV ECX, 1       ; Start with 1
 *   SHL ECX, CL      ; Shift left by bit position (CL = AL)
 *   MOV EAX, ECX     ; Move result to EAX
 *
 * Method 2 (using BSF/BSR):
 *   If we have a register with the power-of-2 value already:
 *   BSF/BSR can find the bit position
 */

#include "bit_scanning_constant_strategies.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * Check if a value is a power of 2
 */
int is_power_of_two(uint32_t val) {
    return val != 0 && (val & (val - 1)) == 0;
}

/**
 * Count number of set bits in a value
 */
int count_set_bits(uint32_t val) {
    int count = 0;
    while (val) {
        count += val & 1;
        val >>= 1;
    }
    return count;
}

/**
 * Get bit position for power-of-2 values (0-31)
 * Returns -1 if not a power of 2
 */
int get_bit_position(uint32_t val) {
    if (!is_power_of_two(val)) {
        return -1;
    }

    int pos = 0;
    while (val > 1) {
        val >>= 1;
        pos++;
    }
    return pos;
}

/**
 * Check if this strategy can handle the instruction
 */
int can_handle_bit_scanning_constant(cs_insn *insn) {
    if (!insn) {
        return 0;
    }

    // Only handle MOV reg, imm
    if (insn->id != X86_INS_MOV) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    cs_x86_op *src_op = &insn->detail->x86.operands[1];

    // Destination must be a register, source must be immediate
    if (dst_op->type != X86_OP_REG || src_op->type != X86_OP_IMM) {
        return 0;
    }

    uint32_t imm = (uint32_t)src_op->imm;

    // Must be a power of 2
    if (!is_power_of_two(imm)) {
        return 0;
    }

    // Original value must contain bad characters
    if (is_bad_char_free(imm)) {
        return 0;
    }

    // Get bit position
    int bit_pos = get_bit_position(imm);
    if (bit_pos < 0 || bit_pos > 31) {
        return 0;
    }

    // Check if bit position itself is bad-char-free
    if (!is_bad_char_free_byte((uint8_t)bit_pos)) {
        return 0;  // Can't use this strategy if bit position is a bad char
    }

    return 1;
}

/**
 * Calculate size of transformed instruction
 */
size_t get_size_bit_scanning_constant(cs_insn *insn) {
    if (!insn) {
        return 0;
    }

    // XOR EAX, EAX = 2 bytes (31 C0)
    // MOV AL, bit_pos = 2 bytes (B0 + bit_pos)
    // MOV ECX, 1 = 5 bytes (B9 01 00 00 00)
    // SHL ECX, CL = 3 bytes (D3 E1)
    // MOV dest_reg, ECX = 2 bytes (89 C8+r)

    // Total: 14 bytes (conservative estimate)
    return 14;
}

/**
 * Generate transformed instruction sequence
 */
void generate_bit_scanning_constant(struct buffer *b, cs_insn *insn) {
    if (!insn || !b) {
        return;
    }

    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    cs_x86_op *src_op = &insn->detail->x86.operands[1];

    x86_reg dest_reg = dst_op->reg;
    uint32_t imm = (uint32_t)src_op->imm;

    // Get bit position
    int bit_pos = get_bit_position(imm);
    if (bit_pos < 0) {
        // Fallback: copy original instruction
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    // Use ECX as temporary register for shifting
    x86_reg temp_reg = X86_REG_ECX;
    uint8_t dest_reg_idx = get_reg_index(dest_reg);
    uint8_t temp_reg_idx = get_reg_index(temp_reg);

    // Optimization: If bit position is 0-7, we can use a shorter sequence
    if (bit_pos <= 7) {
        // Method: MOV dest_reg, 1; SHL dest_reg, bit_pos
        // MOV dest_reg, 1
        buffer_write_byte(b, 0xB8 + dest_reg_idx);
        buffer_write_dword(b, 1);

        // SHL dest_reg, bit_pos (use immediate shift)
        buffer_write_byte(b, 0xC1);  // SHL r32, imm8
        buffer_write_byte(b, 0xE0 + dest_reg_idx);  // ModR/M
        buffer_write_byte(b, (uint8_t)bit_pos);
    } else {
        // General method: Use CL register for shift count
        // Step 1: XOR dest_reg, dest_reg (zero the register)
        buffer_write_byte(b, 0x31);  // XOR r32, r32
        buffer_write_byte(b, 0xC0 | (dest_reg_idx << 3) | dest_reg_idx);

        // Step 2: MOV AL, bit_pos (load bit position into AL)
        buffer_write_byte(b, 0xB0);  // MOV AL, imm8
        buffer_write_byte(b, (uint8_t)bit_pos);

        // Step 3: MOV temp_reg, 1 (ECX = 1)
        buffer_write_byte(b, 0xB8 + temp_reg_idx);
        buffer_write_dword(b, 1);

        // Step 4: SHL temp_reg, CL (shift ECX left by CL times)
        buffer_write_byte(b, 0xD3);  // SHL r32, CL
        buffer_write_byte(b, 0xE0 + temp_reg_idx);  // ModR/M for ECX

        // Step 5: MOV dest_reg, temp_reg (move result to destination)
        buffer_write_byte(b, 0x89);  // MOV r32, r32
        buffer_write_byte(b, 0xC0 | (temp_reg_idx << 3) | dest_reg_idx);
    }
}

// Define the strategy structure
strategy_t bit_scanning_constant_strategy = {
    .name = "BSF/BSR Bit Scanning for Power-of-2 Constants",
    .can_handle = can_handle_bit_scanning_constant,
    .get_size = get_size_bit_scanning_constant,
    .generate = generate_bit_scanning_constant,
    .priority = 80
};
