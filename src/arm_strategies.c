/*
 * ARM Strategy Implementations
 */

#include "arm_strategies.h"
#include "arm_immediate_encoding.h"
#include "utils.h"
#include "core.h"  // For bad_byte_context_t
#include <capstone/capstone.h>

// ============================================================================
// ARM MOV Strategies
// ============================================================================

/**
 * Strategy: ARM MOV Original
 * Pass through MOV instructions without bad bytes
 */
static int can_handle_arm_mov_original(cs_insn *insn) {
    if (insn->id != ARM_INS_MOV) return 0;
    if (insn->detail->arm.op_count != 2) return 0;

    // Must be register to immediate
    if (insn->detail->arm.operands[0].type != ARM_OP_REG ||
        insn->detail->arm.operands[1].type != ARM_OP_IMM) {
        return 0;
    }

    // Check if original instruction has bad bytes
    extern bad_byte_context_t g_bad_byte_context;
    return !arm_has_bad_bytes(insn, &g_bad_byte_context.config);
}

static size_t get_size_arm_mov_original(cs_insn *insn) {
    (void)insn;
    return 4;  // ARM instructions are 4 bytes
}

static void generate_arm_mov_original(struct buffer *b, cs_insn *insn) {
    // Just copy the original instruction bytes
    buffer_append(b, insn->bytes, insn->size);
}

static strategy_t arm_mov_original_strategy = {
    .name = "arm_mov_original",
    .can_handle = can_handle_arm_mov_original,
    .get_size = get_size_arm_mov_original,
    .generate = generate_arm_mov_original,
    .priority = 10,
    .target_arch = BYVAL_ARCH_ARM
};

/**
 * Strategy: ARM MOV with MVN transformation
 * Transform MOV using MVN (bitwise NOT) when MOV immediate isn't encodable
 */
static int can_handle_arm_mov_mvn(cs_insn *insn) {
    if (insn->id != ARM_INS_MOV) return 0;
    if (insn->detail->arm.op_count != 2) return 0;

    if (insn->detail->arm.operands[0].type != ARM_OP_REG ||
        insn->detail->arm.operands[1].type != ARM_OP_IMM) {
        return 0;
    }

    // Check if original has bad bytes
    extern bad_byte_context_t g_bad_byte_context;
    if (!arm_has_bad_bytes(insn, &g_bad_byte_context.config)) {
        return 0;  // Original is fine
    }

    // Check if MVN transformation would work
    uint32_t imm = (uint32_t)insn->detail->arm.operands[1].imm;
    uint32_t mvn_val;
    return find_arm_mvn_immediate(imm, &mvn_val);
}

static size_t get_size_arm_mov_mvn(cs_insn *insn) {
    (void)insn;
    return 4;  // Single MVN instruction
}

static void generate_arm_mov_mvn(struct buffer *b, cs_insn *insn) {
    uint8_t rd = get_arm_reg_index(insn->detail->arm.operands[0].reg);
    uint32_t imm = (uint32_t)insn->detail->arm.operands[1].imm;

    uint32_t mvn_val;
    if (!find_arm_mvn_immediate(imm, &mvn_val)) {
        // Fallback to original (shouldn't happen if can_handle passed)
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    int encoded_imm = encode_arm_immediate(mvn_val);
    if (encoded_imm == -1) {
        // Fallback
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    // Encode MVN instruction: MVN Rd, #imm
    // Condition: AL (0xE), Opcode: MVN (0xF), I=1, S=0
    uint32_t instruction = 0xE3E00000 | (rd << 12) | encoded_imm;

    // Verify no bad bytes
    if (is_bad_byte_free(instruction)) {
        buffer_append(b, (uint8_t*)&instruction, 4);
    } else {
        // Fallback to original
        buffer_append(b, insn->bytes, insn->size);
    }
}

static strategy_t arm_mov_mvn_strategy = {
    .name = "arm_mov_mvn",
    .can_handle = can_handle_arm_mov_mvn,
    .get_size = get_size_arm_mov_mvn,
    .generate = generate_arm_mov_mvn,
    .priority = 12,
    .target_arch = BYVAL_ARCH_ARM
};

// ============================================================================
// ARM ADD Strategies
// ============================================================================

/**
 * Strategy: ARM ADD Original
 * Pass through ADD instructions without bad bytes
 */
static int can_handle_arm_add_original(cs_insn *insn) {
    if (insn->id != ARM_INS_ADD) return 0;

    extern bad_byte_context_t g_bad_byte_context;
    return !arm_has_bad_bytes(insn, &g_bad_byte_context.config);
}

static size_t get_size_arm_add_original(cs_insn *insn) {
    (void)insn;
    return 4;
}

static void generate_arm_add_original(struct buffer *b, cs_insn *insn) {
    buffer_append(b, insn->bytes, insn->size);
}

static strategy_t arm_add_original_strategy = {
    .name = "arm_add_original",
    .can_handle = can_handle_arm_add_original,
    .get_size = get_size_arm_add_original,
    .generate = generate_arm_add_original,
    .priority = 10,
    .target_arch = BYVAL_ARCH_ARM
};

/**
 * Strategy: ARM ADD with SUB transformation
 * Transform ADD Rn, Rm, #imm -> SUB Rn, Rm, #-imm (if negative immediate works)
 */
static int can_handle_arm_add_sub(cs_insn *insn) {
    if (insn->id != ARM_INS_ADD) return 0;
    if (insn->detail->arm.op_count != 3) return 0;

    if (insn->detail->arm.operands[0].type != ARM_OP_REG ||
        insn->detail->arm.operands[1].type != ARM_OP_REG ||
        insn->detail->arm.operands[2].type != ARM_OP_IMM) {
        return 0;
    }

    // Check if original has bad bytes
    extern bad_byte_context_t g_bad_byte_context;
    if (!arm_has_bad_bytes(insn, &g_bad_byte_context.config)) {
        return 0;
    }

    // Check if SUB with negative immediate would work
    uint32_t imm = (uint32_t)insn->detail->arm.operands[2].imm;
    uint32_t neg_imm = (uint32_t)(-(int32_t)imm);
    return is_arm_immediate_encodable(neg_imm);
}

static size_t get_size_arm_add_sub(cs_insn *insn) {
    (void)insn;
    return 4;
}

static void generate_arm_add_sub(struct buffer *b, cs_insn *insn) {
    uint8_t rd = get_arm_reg_index(insn->detail->arm.operands[0].reg);
    uint8_t rn = get_arm_reg_index(insn->detail->arm.operands[1].reg);
    uint32_t imm = (uint32_t)insn->detail->arm.operands[2].imm;
    uint32_t neg_imm = (uint32_t)(-(int32_t)imm);

    int encoded_imm = encode_arm_immediate(neg_imm);
    if (encoded_imm == -1) {
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    // Encode SUB instruction: SUB Rd, Rn, #imm
    // Condition: AL (0xE), Opcode: SUB (0x4), I=1, S=0
    uint32_t instruction = 0xE0400000 | (rd << 12) | (rn << 16) | encoded_imm;

    // Verify no bad bytes
    extern bad_byte_context_t g_bad_byte_context;
    if (is_bad_byte_free(instruction)) {
        buffer_append(b, (uint8_t*)&instruction, 4);
    } else {
        buffer_append(b, insn->bytes, insn->size);
    }
}

static strategy_t arm_add_sub_strategy = {
    .name = "arm_add_sub",
    .can_handle = can_handle_arm_add_sub,
    .get_size = get_size_arm_add_sub,
    .generate = generate_arm_add_sub,
    .priority = 12,
    .target_arch = BYVAL_ARCH_ARM
};

// ============================================================================
// ARM LDR/STR Strategies
// ============================================================================

/**
 * Strategy: ARM LDR Original
 * Pass through LDR instructions without bad bytes
 */
static int can_handle_arm_ldr_original(cs_insn *insn) {
    if (insn->id != ARM_INS_LDR) return 0;

    extern bad_byte_context_t g_bad_byte_context;
    return !arm_has_bad_bytes(insn, &g_bad_byte_context.config);
}

static size_t get_size_arm_ldr_original(cs_insn *insn) {
    (void)insn;
    return 4;
}

static void generate_arm_ldr_original(struct buffer *b, cs_insn *insn) {
    buffer_append(b, insn->bytes, insn->size);
}

static strategy_t arm_ldr_original_strategy = {
    .name = "arm_ldr_original",
    .can_handle = can_handle_arm_ldr_original,
    .get_size = get_size_arm_ldr_original,
    .generate = generate_arm_ldr_original,
    .priority = 10,
    .target_arch = BYVAL_ARCH_ARM
};

/**
 * Strategy: ARM STR Original
 * Pass through STR instructions without bad bytes
 */
static int can_handle_arm_str_original(cs_insn *insn) {
    if (insn->id != ARM_INS_STR) return 0;

    extern bad_byte_context_t g_bad_byte_context;
    return !arm_has_bad_bytes(insn, &g_bad_byte_context.config);
}

static size_t get_size_arm_str_original(cs_insn *insn) {
    (void)insn;
    return 4;
}

static void generate_arm_str_original(struct buffer *b, cs_insn *insn) {
    buffer_append(b, insn->bytes, insn->size);
}

static strategy_t arm_str_original_strategy = {
    .name = "arm_str_original",
    .can_handle = can_handle_arm_str_original,
    .get_size = get_size_arm_str_original,
    .generate = generate_arm_str_original,
    .priority = 10,
    .target_arch = BYVAL_ARCH_ARM
};

// ============================================================================
// ARM Branch Strategies
// ============================================================================

/**
 * Strategy: ARM B/BL Original
 * Pass through branch instructions without bad bytes
 */
static int can_handle_arm_branch_original(cs_insn *insn) {
    if (insn->id != ARM_INS_B && insn->id != ARM_INS_BL) return 0;

    extern bad_byte_context_t g_bad_byte_context;
    return !arm_has_bad_bytes(insn, &g_bad_byte_context.config);
}

static size_t get_size_arm_branch_original(cs_insn *insn) {
    (void)insn;
    return 4;
}

static void generate_arm_branch_original(struct buffer *b, cs_insn *insn) {
    buffer_append(b, insn->bytes, insn->size);
}

static strategy_t arm_branch_original_strategy = {
    .name = "arm_branch_original",
    .can_handle = can_handle_arm_branch_original,
    .get_size = get_size_arm_branch_original,
    .generate = generate_arm_branch_original,
    .priority = 10,
    .target_arch = BYVAL_ARCH_ARM
};

// ============================================================================
// Registration Functions
// ============================================================================

void register_arm_mov_strategies(void) {
    register_strategy(&arm_mov_original_strategy);
    register_strategy(&arm_mov_mvn_strategy);
}

void register_arm_arithmetic_strategies(void) {
    register_strategy(&arm_add_original_strategy);
    register_strategy(&arm_add_sub_strategy);
}

void register_arm_memory_strategies(void) {
    register_strategy(&arm_ldr_original_strategy);
    register_strategy(&arm_str_original_strategy);
}

void register_arm_jump_strategies(void) {
    register_strategy(&arm_branch_original_strategy);
}

void register_arm_strategies(void) {
    register_arm_mov_strategies();
    register_arm_arithmetic_strategies();
    register_arm_memory_strategies();
    register_arm_jump_strategies();
}