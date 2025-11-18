#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

/**
 * RET immediate null-byte elimination strategy
 *
 * Transforms: RET imm16 → ADD ESP, imm16; RET
 *
 * Original:  RET 8
 *           [0xC2 0x08 0x00]        // 3 bytes, has null byte
 *
 * Transform: ADD ESP, 8
 *           RET
 *           [0x83 0xC4 0x08]        // 3 bytes (if imm fits in 8-bit)
 *           [0xC3]                   // 1 byte
 *           Total: 4 bytes, no nulls
 *
 * Priority: 75-80 (high priority, common in Windows API calling conventions)
 */

// Detect RET with immediate operand that contains null bytes
int can_handle_ret_immediate(cs_insn *insn) {
    // Check if this is a RET instruction
    if (insn->id != X86_INS_RET) {
        return 0;
    }

    // Check if RET has an immediate operand (RET imm16)
    if (insn->detail->x86.op_count != 1) {
        return 0;  // Plain RET with no operand
    }

    if (insn->detail->x86.operands[0].type != X86_OP_IMM) {
        return 0;
    }

    // Only handle if the instruction encoding contains null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    return 1;
}

// Calculate replacement size for RET immediate
size_t get_ret_immediate_size(cs_insn *insn) {
    uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;

    // Check if immediate fits in signed 8-bit and the byte value itself is not 0x00
    if ((int32_t)(int8_t)imm == (int32_t)imm && (uint8_t)imm != 0x00) {
        // Use: ADD ESP, imm8 (0x83 0xC4 imm8) + RET (0xC3)
        return 3 + 1;  // 4 bytes total
    } else if (imm <= 0x7F) {
        // If value is small but would be 0x00 as a byte, use byte-by-byte
        return (imm * 3) + 1;
    } else if (is_null_free(imm)) {
        // Use: ADD ESP, imm32 (0x81 0xC4 imm32) + RET (0xC3)
        return 6 + 1;  // 7 bytes total
    } else {
        // Need to add byte-by-byte: each ADD ESP, 1 is 3 bytes
        // This is a fallback for cases where even 32-bit ADD would have nulls
        return (imm * 3) + 1;  // (imm * 3) for byte-by-byte additions + 1 for RET
    }
}

// Generate null-free replacement for RET immediate
void generate_ret_immediate(struct buffer *b, cs_insn *insn) {
    uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;

    // Check if immediate fits in signed 8-bit and the byte value itself is not 0x00
    if ((int32_t)(int8_t)imm == (int32_t)imm && (uint8_t)imm != 0x00) {
        // Generate: ADD ESP, imm8 (0x83 0xC4 imm8)
        uint8_t add_esp_imm8[] = {0x83, 0xC4, (uint8_t)imm};
        buffer_append(b, add_esp_imm8, 3);
    } else if (imm <= 0x7F) {
        // If value is small but would be 0x00 as a byte, use byte-by-byte
        for (uint32_t i = 0; i < imm; i++) {
            uint8_t add_esp_1[] = {0x83, 0xC4, 0x01};
            buffer_append(b, add_esp_1, 3);
        }
    } else if (is_null_free(imm)) {
        // Generate: ADD ESP, imm32 (0x81 0xC4 imm32_le)
        uint8_t add_esp_imm32[] = {
            0x81, 0xC4,
            (uint8_t)(imm & 0xFF),
            (uint8_t)((imm >> 8) & 0xFF),
            (uint8_t)((imm >> 16) & 0xFF),
            (uint8_t)((imm >> 24) & 0xFF)
        };
        buffer_append(b, add_esp_imm32, 6);
    } else {
        // Fallback: byte-by-byte addition
        // Generate multiple: ADD ESP, 1 (0x83 0xC4 0x01)
        for (uint32_t i = 0; i < imm; i++) {
            uint8_t add_esp_1[] = {0x83, 0xC4, 0x01};
            buffer_append(b, add_esp_1, 3);
        }
    }

    // Generate: RET (0xC3)
    uint8_t ret[] = {0xC3};
    buffer_append(b, ret, 1);
}

// Strategy definition
strategy_t ret_immediate_strategy = {
    .name = "ret_immediate",
    .can_handle = can_handle_ret_immediate,
    .get_size = get_ret_immediate_size,
    .generate = generate_ret_immediate,
    .priority = 78  // High priority (75-80 range as recommended)
};

// Registration function
void register_ret_strategies() {
    register_strategy(&ret_immediate_strategy);
}
