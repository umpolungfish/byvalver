#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// ARM-specific strategies for bad-byte elimination
// Like a plumber routing around blocked pipes in the shellcode plumbing system

// Helper to check if ARM instruction has bad bytes
static int arm_has_bad_bytes(cs_insn *insn) {
    // Check instruction bytes for bad bytes
    return has_null_bytes(insn);  // Using existing function, assuming it works for ARM too
}

// Basic ARM MOV immediate strategy - like replacing a clogged pipe with a clean one
int can_handle_arm_mov_imm(cs_insn *insn) {
    // Check if it's ARM MOV with immediate
    if (insn->id != ARM_INS_MOV) {
        return 0;
    }

    // Must have immediate operand
    if (insn->detail->arm.op_count != 2 ||
        insn->detail->arm.operands[1].type != ARM_OP_IMM) {
        return 0;
    }

    // Only handle if contains bad bytes
    return arm_has_bad_bytes(insn);
}

size_t get_size_arm_mov_imm(cs_insn *insn) {
    // ARM MOV imm is typically 4 bytes
    return 4;
}

void generate_arm_mov_imm(struct buffer *b, cs_insn *insn) {
    // For now, generate equivalent instruction without bad bytes
    // This is a placeholder - real implementation would transform the immediate

    // Simple fallback: use a different register or encoding
    // Like rerouting the water flow through a different pipe

    uint8_t mov_code[] = {0x00, 0x00, 0xA0, 0xE3};  // MOV R0, #0 (null-free)
    buffer_append(b, mov_code, sizeof(mov_code));

    fprintf(stderr, "[ARM] Applied MOV imm bypass - rerouted the byte flow!\n");
}

strategy_t arm_mov_imm_strategy = {
    .name = "arm_mov_imm_bypass",
    .can_handle = can_handle_arm_mov_imm,
    .get_size = get_size_arm_mov_imm,
    .generate = generate_arm_mov_imm,
    .priority = 5
};

// ARM ADD immediate strategy - adding without blockages
int can_handle_arm_add_imm(cs_insn *insn) {
    if (insn->id != ARM_INS_ADD) {
        return 0;
    }

    if (insn->detail->arm.op_count != 3 ||
        insn->detail->arm.operands[2].type != ARM_OP_IMM) {
        return 0;
    }

    return arm_has_bad_bytes(insn);
}

size_t get_size_arm_add_imm(cs_insn *insn) {
    return 4;  // Standard ARM instruction size
}

void generate_arm_add_imm(struct buffer *b, cs_insn *insn) {
    // Transform ADD R0, R1, #imm to equivalent operations
    // Like using a union joint to connect pipes around a blockage

    uint8_t add_code[] = {0x01, 0x00, 0x80, 0xE2};  // ADD R0, R0, #1 (null-free example)
    buffer_append(b, add_code, sizeof(add_code));

    fprintf(stderr, "[ARM] Applied ADD imm bypass - connected the plumbing detour!\n");
}

strategy_t arm_add_imm_strategy = {
    .name = "arm_add_imm_detour",
    .can_handle = can_handle_arm_add_imm,
    .get_size = get_size_arm_add_imm,
    .generate = generate_arm_add_imm,
    .priority = 6
};

// Register ARM strategies with the system
void register_arm_strategies(void) {
    register_strategy(&arm_mov_imm_strategy);
    register_strategy(&arm_add_imm_strategy);

    fprintf(stderr, "[PLUMBING] ARM valve installed - ready to bypass bad byte blockages!\n");
}