#include "strategy.h"
#include "utils.h"
#include "core.h"
#include <stdio.h>
#include <string.h>

// MOV RIP-relative with null bytes in encoding strategy
int can_handle_mov_rip_relative(cs_insn *insn) {
    if (insn->id != X86_INS_MOV) {
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

    return 0; // Not RIP-relative MOV
}

size_t get_size_mov_rip_relative(__attribute__((unused)) cs_insn *insn) {
    // MOV RAX, disp (null-free) + MOV reg, [RAX] or MOV [RAX], reg
    return 25; // Conservative estimate
}

void generate_mov_rip_relative(struct buffer *b, cs_insn *insn) {
    // Determine which operand is RIP-relative
    cs_x86_op *mem_op = NULL;
    cs_x86_op *reg_op = NULL;

    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (is_rip_relative_operand(op)) {
            mem_op = op;
        } else if (op->type == X86_OP_REG) {
            reg_op = op;
        }
    }

    if (!mem_op || !reg_op) return;

    uint64_t disp = (uint64_t)mem_op->mem.disp;
    uint8_t reg = reg_op->reg;

    // Load the address into EAX using null-free construction
    generate_mov_eax_imm(b, (uint32_t)disp);

    // Determine direction: MOV reg, [RIP + disp] -> MOV reg, [EAX]
    // or MOV [RIP + disp], reg -> MOV [EAX], reg
    if (mem_op == &insn->detail->x86.operands[1]) {
        // MOV reg, [address]
        uint8_t rex = 0x48; // REX.W
        if (get_reg_index(reg) >= 8) rex |= 0x04;
        buffer_append(b, &rex, 1);

        uint8_t mov_code[] = {0x8B, 0x00}; // MOV reg, [RAX] but RAX is EAX here? Wait, EAX is RAX low.
        // MOV reg, [EAX] is 67 48 8B 00 + reg, but 67 is address size override, may have nulls?
        // To avoid, use RAX as base.
        // Since EAX is loaded, MOV reg, [RAX]
        mov_code[1] = (get_reg_index(reg) << 3) | get_reg_index(X86_REG_RAX);
        buffer_append(b, mov_code, 2);
    } else {
        // MOV [address], reg
        uint8_t rex = 0x48; // REX.W
        if (get_reg_index(reg) >= 8) rex |= 0x04;
        buffer_append(b, &rex, 1);

        uint8_t mov_code[] = {0x89, 0x00}; // MOV [RAX], reg
        mov_code[1] = (get_reg_index(reg) << 3) | get_reg_index(X86_REG_RAX);
        buffer_append(b, mov_code, 2);
    }
}

strategy_t mov_rip_relative_strategy = {
    .name = "mov_rip_relative",
    .can_handle = can_handle_mov_rip_relative,
    .get_size = get_size_mov_rip_relative,
    .generate = generate_mov_rip_relative,
    .priority = 80  // High priority for RIP-relative
};