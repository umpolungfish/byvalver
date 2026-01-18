#include "strategy.h"
#include "utils.h"
#include "core.h"
#include <stdio.h>
#include <string.h>

// CALL/JMP with offset containing null bytes strategy
int can_handle_call_jump_offset(cs_insn *insn) {
    if (insn->id != X86_INS_CALL && insn->id != X86_INS_JMP) {
        return 0;
    }

    // Check for immediate operand
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (op->type == X86_OP_IMM) {
            // Check if the instruction encoding has null bytes
            return has_null_bytes_in_encoding(insn->bytes, insn->size);
        }
    }

    return 0; // Not immediate CALL/JMP
}

size_t get_size_call_jump_offset(__attribute__((unused)) cs_insn *insn) {
    // MOV RAX, target (null-free) + CALL/JMP RAX (2-3 bytes)
    return 15; // Conservative estimate
}

void generate_call_jump_offset(struct buffer *b, cs_insn *insn) {
    // Get the target address
    uint64_t target_addr = 0;
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (op->type == X86_OP_IMM) {
            target_addr = (uint64_t)op->imm;
            break;
        }
    }

    // Load target into RAX using null-free construction
    // For 64-bit, we need to handle properly, but for now assume 32-bit
    generate_mov_eax_imm(b, (uint32_t)target_addr);

    // Emit CALL [RAX] or JMP [RAX]
    uint8_t rex = 0x48; // REX.W
    buffer_append(b, &rex, 1);

    uint8_t opcode = (insn->id == X86_INS_CALL) ? 0xFF : 0xFF; // Both use 0xFF
    uint8_t modrm = (insn->id == X86_INS_CALL) ? 0x10 : 0x20; // CALL: /2, JMP: /4
    modrm |= get_reg_index(X86_REG_RAX); // [RAX]

    uint8_t code[] = {opcode, modrm};
    buffer_append(b, code, 2);
}

strategy_t call_jump_offset_strategy = {
    .name = "call_jump_offset",
    .can_handle = can_handle_call_jump_offset,
    .get_size = get_size_call_jump_offset,
    .generate = generate_call_jump_offset,
    .priority = 90  // High priority for CALL/JMP
};