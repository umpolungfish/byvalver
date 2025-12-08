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

    // Use EAX as temporary register for construction to avoid encoding issues
    buffer_write_byte(b, 0x50); // PUSH EAX to save original

    // Build the value in EAX using null-safe construction
    generate_mov_eax_imm(b, val32);

    // MOV dest_reg, EAX to transfer the value
    uint8_t mov_dst_eax[] = {0x89, 0x00};
    mov_dst_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(dest_reg);
    buffer_append(b, mov_dst_eax, 2);

    // POP EAX to restore original value
    buffer_write_byte(b, 0x58);
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

    // Get the destination register
    x86_reg dest_reg = insn->detail->x86.operands[0].reg;

    // Use safe construction - build the value in EAX using null-free approach
    buffer_write_byte(b, 0x50); // PUSH EAX to save original value

    // Generate the immediate value in EAX using null-safe construction
    generate_mov_eax_imm(b, (uint32_t)imm);

    // MOV dest_reg, EAX
    uint8_t mov_dst_eax[] = {0x89, 0x00};
    mov_dst_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(dest_reg);
    buffer_append(b, mov_dst_eax, 2);

    // POP EAX to restore
    buffer_write_byte(b, 0x58);
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

/**
 * Registration function for syscall number strategies
 */
void register_syscall_number_strategies() {
    register_strategy(&syscall_number_byte_based_strategy);
    register_strategy(&syscall_number_push_pop_strategy);
}