#include "syscall_number_strategies.h"
#include "utils.h"
#include "strategy.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Strategy A: Byte-Based Construction for Linux syscall numbers with null bytes (range 1-1024)
// Priority 78 - Handles larger syscall numbers by constructing them with byte operations
static int can_handle_syscall_number_byte_based(cs_insn *insn) {
    if (!insn || insn->id != X86_INS_MOV ||
        insn->detail->x86.op_count != 2 ||
        insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    uint64_t imm = insn->detail->x86.operands[1].imm;

    // Check if this is a syscall number (typically 1-1024 range) with null bytes
    if (imm > 1024 || imm == 0) return 0;

    // Check if immediate value contains null bytes
    uint8_t *bytes = (uint8_t*)&imm;
    for (int i = 0; i < 4; i++) {
        if (bytes[i] == 0x00) return 1; // Contains null byte
    }

    return 0; // No null bytes to eliminate
}

static size_t get_size_syscall_number_byte_based(cs_insn *insn) {
    // Byte-based construction: MOV reg, low_byte; SHL reg, 8; OR reg, high_byte
    // This is typically more efficient than the original instruction with null bytes
    // Use the instruction to make a more accurate size estimate
    if (insn && insn->detail && insn->detail->x86.op_count == 2) {
        uint64_t imm = insn->detail->x86.operands[1].imm;
        // For smaller immediates, we might use shorter sequences
        if (imm < 128) {
            return 6; // MOV reg, imm8 + operations
        } else if (imm < 0x10000) {
            return 8; // MOV reg, imm16 + operations
        }
    }
    return 12; // Conservative estimate for larger immediates
}

static void generate_syscall_number_byte_based(struct buffer *b, cs_insn *insn) {
    uint64_t imm = insn->detail->x86.operands[1].imm;
    uint32_t val32 = (uint32_t)imm;

    // Get the destination register
    x86_reg dest_reg = insn->detail->x86.operands[0].reg;

    // Create null-free construction sequence
    // For example, if original was MOV EAX, 0x00000100 (contains nulls)
    // We might generate: MOV EAX, 1; SHL EAX, 8;

    // Determine register size and generate appropriate code
    if (dest_reg >= X86_REG_EAX && dest_reg <= X86_REG_EDI) {
        // 32-bit register
        uint8_t low_byte = val32 & 0xFF;
        uint16_t high_part = (val32 >> 8) & 0xFFFF;

        // MOV reg, low_byte (if low_byte doesn't contain nulls)
        if (low_byte != 0) {
            buffer_write_byte(b, 0xB8 + (dest_reg - X86_REG_EAX)); // MOV EAX+reg, imm32
            buffer_write_dword(b, low_byte);
        } else {
            buffer_write_byte(b, 0x31); // XOR reg, reg to zero it
            buffer_write_byte(b, 0xC0 + ((dest_reg - X86_REG_EAX) << 3) + (dest_reg - X86_REG_EAX));
        }

        // If high part exists, handle it without nulls
        if (high_part > 0) {
            // Use shift and add operations to build the value without nulls
            if (high_part < 128) {
                // SHL reg, 8; OR reg, high_part
                buffer_write_byte(b, 0xC1); // SHL reg, 8
                buffer_write_byte(b, 0xE0 + (dest_reg - X86_REG_EAX));
                buffer_write_byte(b, 0x08);

                if (high_part != 0) {
                    buffer_write_byte(b, 0x83); // OR reg, imm8
                    buffer_write_byte(b, 0xC8 + (dest_reg - X86_REG_EAX));
                    buffer_write_byte(b, (uint8_t)high_part);
                }
            } else {
                // For larger values, use multiple operations to avoid nulls
                // This is a simplified implementation - a real one would be more sophisticated
                buffer_write_byte(b, 0x68); // PUSH imm32 (if it doesn't contain nulls)
                buffer_write_dword(b, high_part << 8);
                buffer_write_byte(b, 0x58 + (dest_reg - X86_REG_EAX)); // POP reg
                buffer_write_byte(b, 0x09); // OR reg, reg (to combine)
                buffer_write_byte(b, 0xC0 + ((dest_reg - X86_REG_EAX) << 3) + (dest_reg - X86_REG_EAX));
            }
        }
    }
}

// Strategy B: Push/Pop Technique for small syscall numbers (1-127) for size optimization
// Priority 77 - Optimized for smaller syscall numbers
static int can_handle_syscall_number_push_pop(cs_insn *insn) {
    if (!insn || insn->id != X86_INS_MOV ||
        insn->detail->x86.op_count != 2 ||
        insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    uint64_t imm = insn->detail->x86.operands[1].imm;

    // Check if this is a small syscall number (1-127) with null bytes
    if (imm > 127 || imm == 0) return 0;

    // Check if immediate value contains null bytes when encoded in MOV instruction
    uint8_t *bytes = (uint8_t*)&imm;
    for (int i = 0; i < 4; i++) {
        if (bytes[i] == 0x00) return 1; // Contains null byte
    }

    return 0; // No null bytes to eliminate
}

static size_t get_size_syscall_number_push_pop(cs_insn *insn) {
    // PUSH imm32; POP reg is 6 bytes, but PUSH imm8; POP reg is 2 bytes
    // This is more efficient than MOV reg, imm32 with null bytes (5 bytes)
    // Use the instruction to determine the exact size needed
    if (insn && insn->detail && insn->detail->x86.op_count == 2) {
        uint64_t imm = insn->detail->x86.operands[1].imm;
        // For values that fit in imm8, we use PUSH imm8; POP reg (2 bytes)
        // For values requiring imm32, we use PUSH imm32; POP reg (6 bytes)
        if (imm <= 127) { // Only positive values up to 127 can be represented as signed imm8
            return 2;
        } else {
            return 6;
        }
    }
    return 6; // Default to PUSH imm32; POP reg for safety
}

static void generate_syscall_number_push_pop(struct buffer *b, cs_insn *insn) {
    uint64_t imm = insn->detail->x86.operands[1].imm;
    uint8_t imm8 = (uint8_t)imm;

    // Get the destination register
    x86_reg dest_reg = insn->detail->x86.operands[0].reg;

    // For small immediate values, use PUSH imm8; POP reg (2 bytes vs 5 bytes for MOV with nulls)
    buffer_write_byte(b, 0x6A); // PUSH imm8
    buffer_write_byte(b, imm8);
    buffer_write_byte(b, 0x58 + (dest_reg - X86_REG_EAX)); // POP reg
}

// Define the strategies
strategy_t syscall_number_byte_based_strategy = {
    .name = "syscall_number_byte_based",
    .priority = 78,
    .can_handle = can_handle_syscall_number_byte_based,
    .get_size = get_size_syscall_number_byte_based,
    .generate = generate_syscall_number_byte_based
};

strategy_t syscall_number_push_pop_strategy = {
    .name = "syscall_number_push_pop",
    .priority = 77,
    .can_handle = can_handle_syscall_number_push_pop,
    .get_size = get_size_syscall_number_push_pop,
    .generate = generate_syscall_number_push_pop
};