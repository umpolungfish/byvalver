#include "strategy.h"
#include "utils.h"
#include "core.h"
#include <stdio.h>
#include <string.h>

// RIP-relative CALL/JMP with null bytes in encoding strategy
int can_handle_rip_call_jump(cs_insn *insn) {
    if (insn->id != X86_INS_CALL && insn->id != X86_INS_JMP) {
        return 0;
    }

    // Check for RIP-relative memory operand
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (is_rip_relative_operand(op)) {
            // Check if the original instruction has bad bytes
            return has_null_bytes_in_encoding(insn->bytes, insn->size);
        }
    }

    return 0; // Not RIP-relative CALL/JMP
}

size_t get_size_rip_call_jump(__attribute__((unused)) cs_insn *insn) {
    // MOV RAX, disp (null-free) + CALL/JMP [RAX]
    return 15; // Conservative estimate
}

void generate_rip_call_jump(struct buffer *b, cs_insn *insn) {
    // Get the displacement from the RIP-relative operand
    uint64_t disp = 0;

    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (is_rip_relative_operand(op)) {
            disp = (uint64_t)op->mem.disp;
            break;
        }
    }

    // Load the address into EAX using null-free construction
    generate_mov_eax_imm(b, (uint32_t)disp);

    // Generate CALL [RAX] or JMP [RAX]
    uint8_t rex = 0x48; // REX.W
    buffer_append(b, &rex, 1);

    uint8_t modrm = (insn->id == X86_INS_CALL) ? 0x10 : 0x20; // CALL: /2, JMP: /4
    modrm |= get_reg_index(X86_REG_RAX); // [RAX]

    uint8_t code[] = {0xFF, modrm};
    buffer_append(b, code, 2);
}

strategy_t rip_call_jump_strategy = {
    .name = "rip_call_jump",
    .can_handle = can_handle_rip_call_jump,
    .get_size = get_size_rip_call_jump,
    .generate = generate_rip_call_jump,
    .priority = 95  // Very high priority for CALL/JMP
};