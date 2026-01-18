#include "strategy.h"
#include "utils.h"
#include "core.h"
#include <stdio.h>
#include <string.h>

// LEA RIP-relative with null bytes in encoding strategy
int can_handle_lea_rip_relative(cs_insn *insn) {
    if (insn->id != X86_INS_LEA) {
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

    return 0; // Not RIP-relative LEA
}

size_t get_size_lea_rip_relative(__attribute__((unused)) cs_insn *insn) {
    // MOV RAX, disp (using null-free construction) + LEA reg, [RAX] (3 bytes with REX)
    return 20; // Conservative estimate for null-free MOV + LEA
}

void generate_lea_rip_relative(struct buffer *b, cs_insn *insn) {
    // Get the displacement from the RIP-relative operand
    uint64_t disp = 0;
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;

    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (is_rip_relative_operand(op)) {
            disp = (uint64_t)op->mem.disp;
            break;
        }
    }

    uint32_t val = (uint32_t)disp;

    // Load the address into EAX using null-free partial register construction
    // XOR EAX, EAX
    buffer_append(b, (uint8_t[]){0x31, 0xC0}, 2);

    // MOV AL, byte0
    uint8_t byte0 = val & 0xFF;
    buffer_append(b, (uint8_t[]){0xB0, byte0}, 2);

    // MOV AH, byte1
    uint8_t byte1 = (val >> 8) & 0xFF;
    buffer_append(b, (uint8_t[]){0xB4, byte1}, 2);

    // SHL EAX, 16
    buffer_append(b, (uint8_t[]){0xC1, 0xE0, 0x10}, 3);

    // MOV AL, byte2
    uint8_t byte2 = (val >> 16) & 0xFF;
    buffer_append(b, (uint8_t[]){0xB0, byte2}, 2);

    // MOV AH, byte3
    uint8_t byte3 = (val >> 24) & 0xFF;
    buffer_append(b, (uint8_t[]){0xB4, byte3}, 2);

    // LEA dst_reg, [RIP + disp] is equivalent to MOV dst_reg, address
    // So, MOV dst_reg, EAX (zero extends to 64-bit)
    uint8_t rex = 0x48; // REX.W
    if (get_reg_index(dst_reg) >= 8) rex |= 0x04; // REX.R
    buffer_append(b, &rex, 1);

    uint8_t mov_code = 0x89; // MOV reg, EAX
    buffer_append(b, &mov_code, 1);
    uint8_t modrm = 0xC0 | (get_reg_index(dst_reg) << 3);
    buffer_append(b, &modrm, 1);
}

strategy_t lea_rip_relative_strategy = {
    .name = "lea_rip_relative",
    .can_handle = can_handle_lea_rip_relative,
    .get_size = get_size_lea_rip_relative,
    .generate = generate_lea_rip_relative,
    .priority = 85  // Higher priority than general LEA strategies
};