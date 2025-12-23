/*
 * PUSHF/POPF Bit Manipulation Strategy for Bad Character Elimination
 *
 * PROBLEM: Flag-setting instructions may encode with bad characters, particularly:
 * - STC (Set Carry) = F9 (may be bad char)
 * - CLC (Clear Carry) = F8 (may be bad char)
 * - STD (Set Direction) = FD (may be bad char)
 * - CLD (Clear Direction) = FC (may be bad char)
 * - CMC (Complement Carry) = F5 (may be bad char)
 *
 * SOLUTION: Use PUSHF/POPF to manipulate flags via EFLAGS register:
 * Example: STC (set carry flag)
 *   Original: F9
 *   Transform: PUSHF; POP EAX; OR EAX, 0x01; PUSH EAX; POPF
 *
 * Example: CLC (clear carry flag)
 *   Original: F8
 *   Transform: PUSHF; POP EAX; AND EAX, 0xFFFFFFFE; PUSH EAX; POPF
 */

#include "pushf_popf_bit_manipulation_strategies.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * Determine flag mask for specific instructions
 * Returns 1 if transformation applies, 0 otherwise
 */
int get_flag_mask_for_instruction(cs_insn *insn, uint32_t *set_mask, uint32_t *clear_mask) {
    if (!insn || !set_mask || !clear_mask) {
        return 0;
    }

    *set_mask = 0;
    *clear_mask = 0;

    switch (insn->id) {
        case X86_INS_STC:  // Set Carry Flag
            *set_mask = EFLAGS_CF;
            return 1;

        case X86_INS_CLC:  // Clear Carry Flag
            *clear_mask = EFLAGS_CF;
            return 1;

        case X86_INS_STD:  // Set Direction Flag
            *set_mask = EFLAGS_DF;
            return 1;

        case X86_INS_CLD:  // Clear Direction Flag
            *clear_mask = EFLAGS_DF;
            return 1;

        case X86_INS_CMC:  // Complement Carry Flag (XOR)
            // For CMC, we'll use XOR to toggle the bit
            *set_mask = EFLAGS_CF;  // Use set_mask to indicate XOR operation
            *clear_mask = 0xFFFFFFFF;  // Special marker for XOR
            return 1;

        default:
            return 0;
    }
}

/**
 * Check if this strategy can handle the instruction
 */
int can_handle_pushf_popf_flag_manipulation(cs_insn *insn) {
    if (!insn) {
        return 0;
    }

    uint32_t set_mask, clear_mask;
    if (!get_flag_mask_for_instruction(insn, &set_mask, &clear_mask)) {
        return 0;
    }

    // Check if the original instruction encoding contains bad characters
    if (!is_bad_char_free_buffer(insn->bytes, insn->size)) {
        return 1;  // Has bad chars, we can handle it
    }

    return 0;  // No bad chars, no need to transform
}

/**
 * Calculate size of transformed instruction
 */
size_t get_size_pushf_popf_flag_manipulation(cs_insn *insn) {
    if (!insn) {
        return 0;
    }

    // PUSHF = 1 byte (9C)
    // POP EAX = 1 byte (58)
    // OR/AND/XOR EAX, imm32 = 5 bytes (0D/25/35 + 4 bytes imm)
    // PUSH EAX = 1 byte (50)
    // POPF = 1 byte (9D)
    // Total = 9 bytes

    return 9;
}

/**
 * Generate transformed instruction sequence
 */
void generate_pushf_popf_flag_manipulation(struct buffer *b, cs_insn *insn) {
    if (!insn || !b) {
        return;
    }

    uint32_t set_mask, clear_mask;
    if (!get_flag_mask_for_instruction(insn, &set_mask, &clear_mask)) {
        // Fallback: copy original instruction
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    // Use EAX as temporary register for flag manipulation
    x86_reg temp_reg = X86_REG_EAX;
    uint8_t temp_reg_idx = get_reg_index(temp_reg);

    // Step 1: PUSHF - Push EFLAGS onto stack
    // Opcode: 9C
    buffer_write_byte(b, 0x9C);

    // Step 2: POP EAX - Pop EFLAGS into EAX
    // Opcode: 58+r
    buffer_write_byte(b, 0x58 + temp_reg_idx);

    // Step 3: Manipulate flags in EAX
    if (clear_mask == 0xFFFFFFFF) {
        // Special case: CMC (complement carry) - use XOR
        // XOR EAX, set_mask (toggle the bit)
        buffer_write_byte(b, 0x35);  // XOR EAX, imm32
        buffer_write_dword(b, set_mask);
    } else if (set_mask != 0) {
        // Set bits: OR EAX, set_mask
        buffer_write_byte(b, 0x0D);  // OR EAX, imm32
        buffer_write_dword(b, set_mask);
    } else if (clear_mask != 0) {
        // Clear bits: AND EAX, ~clear_mask
        uint32_t and_mask = ~clear_mask;
        buffer_write_byte(b, 0x25);  // AND EAX, imm32
        buffer_write_dword(b, and_mask);
    }

    // Step 4: PUSH EAX - Push modified EFLAGS back onto stack
    // Opcode: 50+r
    buffer_write_byte(b, 0x50 + temp_reg_idx);

    // Step 5: POPF - Pop modified EFLAGS from stack
    // Opcode: 9D
    buffer_write_byte(b, 0x9D);
}

// Define the strategy structure
strategy_t pushf_popf_flag_manipulation_strategy = {
    .name = "PUSHF/POPF Flag Bit Manipulation",
    .can_handle = can_handle_pushf_popf_flag_manipulation,
    .get_size = get_size_pushf_popf_flag_manipulation,
    .generate = generate_pushf_popf_flag_manipulation,
    .priority = 81
};
