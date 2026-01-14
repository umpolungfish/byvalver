/*
 * ARM64 Strategy Implementations
 */

#include "arm64_strategies.h"
#include "utils.h"
#include <capstone/capstone.h>

// ============================================================================
// ARM64 MOV Strategies
// ============================================================================

/**
 * Strategy: ARM64 MOV Original
 * Pass through MOV instructions without bad bytes
 */
static int can_handle_arm64_mov_original(cs_insn *insn) {
    if (insn->id != ARM64_INS_MOV) return 0;

    // Check if original instruction has bad bytes
    return !is_bad_byte_free_buffer(insn->bytes, insn->size);
}

static size_t get_size_arm64_mov_original(cs_insn *insn) {
    (void)insn;
    return 4;  // ARM64 instructions are 4 bytes
}

static void generate_arm64_mov_original(struct buffer *b, cs_insn *insn) {
    buffer_append(b, insn->bytes, insn->size);
}

static strategy_t arm64_mov_original_strategy = {
    .name = "arm64_mov_original",
    .can_handle = can_handle_arm64_mov_original,
    .get_size = get_size_arm64_mov_original,
    .generate = generate_arm64_mov_original,
    .priority = 10,
    .target_arch = BYVAL_ARCH_ARM64
};

// ============================================================================
// Registration Functions
// ============================================================================

void register_arm64_mov_strategies(void) {
    register_strategy(&arm64_mov_original_strategy);
}

void register_arm64_arithmetic_strategies(void) {
    // TODO: Implement ADD, SUB, etc.
}

void register_arm64_memory_strategies(void) {
    // TODO: Implement LDR, STR, etc.
}

void register_arm64_jump_strategies(void) {
    // TODO: Implement B, BL, etc.
}

void register_arm64_strategies(void) {
    register_arm64_mov_strategies();
    register_arm64_arithmetic_strategies();
    register_arm64_memory_strategies();
    register_arm64_jump_strategies();
}