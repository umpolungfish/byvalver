#include "strategy.h"
#include "utils.h"
#include "core.h"
#include <stdio.h>
#include <string.h>

// Logical immediate strategy for TEST/AND/OR/XOR with null bytes in immediate
int can_handle_logical_immediate(cs_insn *insn) {
    if (insn->id != X86_INS_TEST && insn->id != X86_INS_AND &&
        insn->id != X86_INS_OR && insn->id != X86_INS_XOR) {
        return 0;
    }

    // Check for immediate operand with null bytes
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (op->type == X86_OP_IMM) {
            uint32_t imm = (uint32_t)op->imm;
            for (int j = 0; j < 4; j++) {
                if (((imm >> (j * 8)) & 0xFF) == 0) {
                    return 1; // Has null bytes
                }
            }
        }
    }

    return 0; // No null bytes in immediate
}

size_t get_size_logical_immediate(__attribute__((unused)) cs_insn *insn) {
    // MOV EAX, imm (null-free) + op reg, EAX (2 bytes)
    return get_mov_eax_imm_size((uint32_t)insn->detail->x86.operands[1].imm) + 2;
}

void generate_logical_immediate(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

    // Load immediate into EAX using null-free construction
    generate_mov_eax_imm(b, imm);

    // Perform the operation: op reg, EAX
    uint8_t opcode;
    switch (insn->id) {
        case X86_INS_TEST: opcode = 0x85; break;  // TEST reg, EAX
        case X86_INS_AND: opcode = 0x21; break;   // AND reg, EAX
        case X86_INS_OR: opcode = 0x09; break;    // OR reg, EAX
        case X86_INS_XOR: opcode = 0x31; break;   // XOR reg, EAX
        default: opcode = 0x85; break;
    }

    uint8_t modrm = 0xC0 | (get_reg_index(reg) << 3) | get_reg_index(X86_REG_EAX);
    uint8_t code[] = {opcode, modrm};
    buffer_append(b, code, 2);
}

strategy_t logical_immediate_strategy = {
    .name = "logical_immediate",
    .can_handle = can_handle_logical_immediate,
    .get_size = get_size_logical_immediate,
    .generate = generate_logical_immediate,
    .priority = 20  // Lower priority
};