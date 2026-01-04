#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>

// Strategy 6: Stack Frame Pointer Bad-Byte Elimination
// Handles PUSH EBP; MOV EBP, ESP sequences

static int can_handle_push_ebp_bad(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    if (insn->id == X86_INS_PUSH &&
        insn->detail->x86.op_count == 1 &&
        insn->detail->x86.operands[0].type == X86_OP_REG &&
        insn->detail->x86.operands[0].reg == X86_REG_EBP) {

        // PUSH EBP opcode is 0x55
        return !is_bad_byte_free_byte(0x55);
    }

    return 0;
}

static size_t get_size_push_ebp_bad(cs_insn *insn) {
    (void)insn;
    // SUB ESP, 4; MOV [ESP], EBP = 6 bytes
    return 6;
}

static void generate_push_ebp_bad(struct buffer *b, cs_insn *insn) {
    (void)insn;

    // SUB ESP, 4
    uint8_t sub_esp[] = {0x83, 0xEC, 0x04};
    buffer_append(b, sub_esp, 3);

    // MOV [ESP], EBP: 89 2C 24
    uint8_t mov[] = {0x89, 0x2C, 0x24};
    buffer_append(b, mov, 3);
}

static int can_handle_pop_ebp_bad(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    if (insn->id == X86_INS_POP &&
        insn->detail->x86.op_count == 1 &&
        insn->detail->x86.operands[0].type == X86_OP_REG &&
        insn->detail->x86.operands[0].reg == X86_REG_EBP) {

        // POP EBP opcode is 0x5D
        return !is_bad_byte_free_byte(0x5D);
    }

    return 0;
}

static size_t get_size_pop_ebp_bad(cs_insn *insn) {
    (void)insn;
    // MOV EBP, [ESP]; ADD ESP, 4 = 6 bytes
    return 6;
}

static void generate_pop_ebp_bad(struct buffer *b, cs_insn *insn) {
    (void)insn;

    // MOV EBP, [ESP]: 8B 2C 24
    uint8_t mov[] = {0x8B, 0x2C, 0x24};
    buffer_append(b, mov, 3);

    // ADD ESP, 4
    uint8_t add_esp[] = {0x83, 0xC4, 0x04};
    buffer_append(b, add_esp, 3);
}

void register_stack_frame_badbyte_strategies(void) {
    static strategy_t strategy_push = {
        .name = "PUSH EBP - Bad Opcode Substitution",
        .can_handle = can_handle_push_ebp_bad,
        .get_size = get_size_push_ebp_bad,
        .generate = generate_push_ebp_bad,
        .priority = 89
    };
    register_strategy(&strategy_push);

    static strategy_t strategy_pop = {
        .name = "POP EBP - Bad Opcode Substitution",
        .can_handle = can_handle_pop_ebp_bad,
        .get_size = get_size_pop_ebp_bad,
        .generate = generate_pop_ebp_bad,
        .priority = 89
    };
    register_strategy(&strategy_pop);
}
