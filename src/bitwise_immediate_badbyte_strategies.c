#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>

// Strategy 8: Bitwise Operation Immediate Bad-Byte

static int can_handle_bitwise_imm_bad(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    // Check for AND, OR, XOR, TEST with immediate
    if ((insn->id == X86_INS_AND || insn->id == X86_INS_OR ||
         insn->id == X86_INS_XOR || insn->id == X86_INS_TEST) &&
        insn->detail->x86.op_count == 2 &&
        insn->detail->x86.operands[0].type == X86_OP_REG &&
        insn->detail->x86.operands[1].type == X86_OP_IMM) {

        uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
        return !is_bad_byte_free(imm);
    }

    return 0;
}

static size_t get_size_bitwise_imm_bad(cs_insn *insn) {
    (void)insn;
    // MOV temp_reg, imm (null-free) + bitwise temp_reg = ~10 bytes
    return 15;
}

static void generate_bitwise_imm_bad(struct buffer *b, cs_insn *insn) {
    x86_reg dst = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

    // Use ECX as temporary (or EDX if dst is ECX)
    x86_reg temp = (dst == X86_REG_ECX) ? X86_REG_EDX : X86_REG_ECX;
    uint8_t push_temp = (temp == X86_REG_ECX) ? 0x51 : 0x52;
    uint8_t pop_temp = (temp == X86_REG_ECX) ? 0x59 : 0x5A;

    // PUSH temp
    buffer_append(b, &push_temp, 1);

    // MOV temp, imm (using null-free generation)
    generate_mov_eax_imm(b, imm);

    int temp_idx = get_reg_index((uint8_t)temp);

    if (temp != X86_REG_EAX) {
        // MOV temp, EAX
        uint8_t mov[] = {0x89, 0xC0 + temp_idx};
        buffer_append(b, mov, 2);
    }

    // Perform bitwise operation with temp
    int dst_idx = get_reg_index((uint8_t)dst);

    if (insn->id == X86_INS_AND) {
        uint8_t and_op[] = {0x21, 0xC0 + (temp_idx << 3) + dst_idx};
        buffer_append(b, and_op, 2);
    } else if (insn->id == X86_INS_OR) {
        uint8_t or_op[] = {0x09, 0xC0 + (temp_idx << 3) + dst_idx};
        buffer_append(b, or_op, 2);
    } else if (insn->id == X86_INS_XOR) {
        uint8_t xor_op[] = {0x31, 0xC0 + (temp_idx << 3) + dst_idx};
        buffer_append(b, xor_op, 2);
    } else if (insn->id == X86_INS_TEST) {
        uint8_t test_op[] = {0x85, 0xC0 + (temp_idx << 3) + dst_idx};
        buffer_append(b, test_op, 2);
    }

    // POP temp
    buffer_append(b, &pop_temp, 1);
}

void register_bitwise_immediate_badbyte_strategies(void) {
    static strategy_t strategy = {
        .name = "Bitwise Immediate - Bad Byte Elimination",
        .can_handle = can_handle_bitwise_imm_bad,
        .get_size = get_size_bitwise_imm_bad,
        .generate = generate_bitwise_imm_bad,
        .priority = 86
    };
    register_strategy(&strategy);
}
