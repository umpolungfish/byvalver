#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>

// ============================================================================
// Strategy: PUSH reg with bad opcode → SUB ESP, 4; MOV [ESP], reg
// ============================================================================

static int can_handle_push_reg_bad_opcode(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    if (insn->id == X86_INS_PUSH &&
        insn->detail->x86.op_count == 1 &&
        insn->detail->x86.operands[0].type == X86_OP_REG) {

        x86_reg reg = insn->detail->x86.operands[0].reg;
        int reg_idx = get_reg_index((uint8_t)reg);
        uint8_t opcode = 0x50 + reg_idx;

        return !is_bad_byte_free_byte(opcode);
    }

    return 0;
}

static size_t get_size_push_reg_bad_opcode(cs_insn *insn) {
    (void)insn;
    // SUB ESP, 4 (3) + MOV [ESP], reg (3) = 6 bytes
    return 6;
}

static void generate_push_reg_bad_opcode(struct buffer *b, cs_insn *insn) {
    x86_reg reg = insn->detail->x86.operands[0].reg;
    int reg_idx = get_reg_index((uint8_t)reg);

    // SUB ESP, 4
    uint8_t sub_esp[] = {0x83, 0xEC, 0x04};
    buffer_append(b, sub_esp, 3);

    // MOV [ESP], reg: 89 /r with ModR/M
    uint8_t mov[] = {0x89, 0x04 | (reg_idx << 3), 0x24};
    buffer_append(b, mov, 3);
}

// ============================================================================
// Strategy: POP reg with bad opcode → MOV reg, [ESP]; ADD ESP, 4
// ============================================================================

static int can_handle_pop_reg_bad_opcode(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    if (insn->id == X86_INS_POP &&
        insn->detail->x86.op_count == 1 &&
        insn->detail->x86.operands[0].type == X86_OP_REG) {

        x86_reg reg = insn->detail->x86.operands[0].reg;
        int reg_idx = get_reg_index((uint8_t)reg);
        uint8_t opcode = 0x58 + reg_idx;

        return !is_bad_byte_free_byte(opcode);
    }

    return 0;
}

static size_t get_size_pop_reg_bad_opcode(cs_insn *insn) {
    (void)insn;
    // MOV reg, [ESP] (3) + ADD ESP, 4 (3) = 6 bytes
    return 6;
}

static void generate_pop_reg_bad_opcode(struct buffer *b, cs_insn *insn) {
    x86_reg reg = insn->detail->x86.operands[0].reg;
    int reg_idx = get_reg_index((uint8_t)reg);

    // MOV reg, [ESP]: 8B /r with ModR/M
    uint8_t mov[] = {0x8B, 0x04 | (reg_idx << 3), 0x24};
    buffer_append(b, mov, 3);

    // ADD ESP, 4
    uint8_t add_esp[] = {0x83, 0xC4, 0x04};
    buffer_append(b, add_esp, 3);
}

// ============================================================================
// Strategy: INC reg with bad opcode → ADD reg, 1
// ============================================================================

static int can_handle_inc_reg_bad_opcode(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    if (insn->id == X86_INS_INC &&
        insn->detail->x86.op_count == 1 &&
        insn->detail->x86.operands[0].type == X86_OP_REG) {

        x86_reg reg = insn->detail->x86.operands[0].reg;
        int reg_idx = get_reg_index((uint8_t)reg);
        uint8_t opcode = 0x40 + reg_idx;

        return !is_bad_byte_free_byte(opcode);
    }

    return 0;
}

static size_t get_size_inc_reg_bad_opcode(cs_insn *insn) {
    (void)insn;
    // ADD reg, 1: 83 /0 imm8 = 3 bytes
    return 3;
}

static void generate_inc_reg_bad_opcode(struct buffer *b, cs_insn *insn) {
    x86_reg reg = insn->detail->x86.operands[0].reg;
    int reg_idx = get_reg_index((uint8_t)reg);

    // ADD reg, 1: 83 C0+r 01
    uint8_t add[] = {0x83, 0xC0 + reg_idx, 0x01};
    buffer_append(b, add, 3);
}

// ============================================================================
// Strategy: DEC reg with bad opcode → SUB reg, 1
// ============================================================================

static int can_handle_dec_reg_bad_opcode(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    if (insn->id == X86_INS_DEC &&
        insn->detail->x86.op_count == 1 &&
        insn->detail->x86.operands[0].type == X86_OP_REG) {

        x86_reg reg = insn->detail->x86.operands[0].reg;
        int reg_idx = get_reg_index((uint8_t)reg);
        uint8_t opcode = 0x48 + reg_idx;

        return !is_bad_byte_free_byte(opcode);
    }

    return 0;
}

static size_t get_size_dec_reg_bad_opcode(cs_insn *insn) {
    (void)insn;
    // SUB reg, 1: 83 /5 imm8 = 3 bytes
    return 3;
}

static void generate_dec_reg_bad_opcode(struct buffer *b, cs_insn *insn) {
    x86_reg reg = insn->detail->x86.operands[0].reg;
    int reg_idx = get_reg_index((uint8_t)reg);

    // SUB reg, 1: 83 E8+r 01
    uint8_t sub[] = {0x83, 0xE8 + reg_idx, 0x01};
    buffer_append(b, sub, 3);
}

// ============================================================================
// Strategy Registration
// ============================================================================

void register_one_byte_opcode_sub_strategies(void) {
    static strategy_t strategy_push_reg = {
        .name = "PUSH reg - Bad Opcode Substitution",
        .can_handle = can_handle_push_reg_bad_opcode,
        .get_size = get_size_push_reg_bad_opcode,
        .generate = generate_push_reg_bad_opcode,
        .priority = 85
    };
    register_strategy(&strategy_push_reg);

    static strategy_t strategy_pop_reg = {
        .name = "POP reg - Bad Opcode Substitution",
        .can_handle = can_handle_pop_reg_bad_opcode,
        .get_size = get_size_pop_reg_bad_opcode,
        .generate = generate_pop_reg_bad_opcode,
        .priority = 85
    };
    register_strategy(&strategy_pop_reg);

    static strategy_t strategy_inc_reg = {
        .name = "INC reg - Bad Opcode Substitution",
        .can_handle = can_handle_inc_reg_bad_opcode,
        .get_size = get_size_inc_reg_bad_opcode,
        .generate = generate_inc_reg_bad_opcode,
        .priority = 85
    };
    register_strategy(&strategy_inc_reg);

    static strategy_t strategy_dec_reg = {
        .name = "DEC reg - Bad Opcode Substitution",
        .can_handle = can_handle_dec_reg_bad_opcode,
        .get_size = get_size_dec_reg_bad_opcode,
        .generate = generate_dec_reg_bad_opcode,
        .priority = 85
    };
    register_strategy(&strategy_dec_reg);
}
