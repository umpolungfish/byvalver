#include "strategy.h"
#include "utils.h"
#include <stdio.h>

// Strategy: BT (Bit Test) with null immediate value
// BT reg, 0 => PUSH reg; SHR reg, 1; POP reg
// This preserves the register value and sets CF based on bit 0

int can_handle_bt_imm_null(cs_insn *insn) {
    if (insn->id != X86_INS_BT) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    // First operand must be register
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }

    // Second operand must be immediate
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    // Check if has null bytes in encoding
    if (has_null_bytes(insn)) {
        return 1;
    }

    return 0;
}

size_t get_size_bt_imm_null(cs_insn *insn) {
    int64_t bit_index = insn->detail->x86.operands[1].imm;
    uint8_t shift_amount = (uint8_t)(bit_index + 1);

    // Check if shift_amount is safe for direct encoding
    if (shift_amount == 1 || is_bad_byte_free_byte(shift_amount)) {
        // PUSH reg (1) + SHR reg, imm8 (2-3) + POP reg (1) = 4-5 bytes
        return 5;
    }

    // shift_amount contains bad byte - use CL register approach
    // PUSH reg (1) + PUSH temp (1) + generate_mov_eax_imm (5) + MOV CL/DL,AL (2) + SHR reg,CL (2) + POP temp (1) + POP reg (1) = 13 bytes
    return 13;
}

void generate_bt_imm_null(struct buffer *b, cs_insn *insn) {
    x86_reg reg = insn->detail->x86.operands[0].reg;
    int64_t bit_index = insn->detail->x86.operands[1].imm;

    // Get register index for encoding
    uint8_t reg_idx;
    if (reg >= X86_REG_EAX && reg <= X86_REG_EDI) {
        reg_idx = reg - X86_REG_EAX;
    } else if (reg >= X86_REG_RAX && reg <= X86_REG_RDI) {
        reg_idx = reg - X86_REG_RAX;
    } else {
        // Unsupported register, fallback to original
        for (size_t i = 0; i < insn->size; i++) {
            buffer_write_byte(b, insn->bytes[i]);
        }
        return;
    }

    // BT reg, bit_index sets CF = bit at position bit_index
    // Transform: PUSH reg; SHR reg, (bit_index+1); POP reg
    // This shifts the tested bit into CF and restores the register

    // PUSH reg
    buffer_write_byte(b, 0x50 + reg_idx);

    // SHR reg, (bit_index + 1)
    // This shifts the bit we want to test into the CF position
    uint8_t shift_amount = (uint8_t)(bit_index + 1);

    // Check if we can use immediate encoding safely
    if (shift_amount == 1) {
        // SHR reg, 1 (2 bytes: D1 /5) - always safe, opcode 0xD1 is safe
        buffer_write_byte(b, 0xD1);
        buffer_write_byte(b, 0xE8 + reg_idx);
    } else if (shift_amount != 0 && is_bad_byte_free_byte(shift_amount)) {
        // SHR reg, imm8 (3 bytes: C1 /5 ib) - safe immediate
        buffer_write_byte(b, 0xC1);
        buffer_write_byte(b, 0xE8 + reg_idx);
        buffer_write_byte(b, shift_amount);
    } else if (shift_amount != 0) {
        // shift_amount contains bad byte - use CL register instead
        // Determine temp register (use ECX unless target is ECX, then use EDX)
        uint8_t temp_idx = (reg_idx == 1) ? 2 : 1;  // ECX=1, EDX=2

        // PUSH temp_reg (save ECX or EDX)
        buffer_write_byte(b, 0x50 + temp_idx);

        // Construct shift_amount in EAX using null-free method
        generate_mov_eax_imm(b, (uint32_t)shift_amount);

        // MOV CL/DL, AL (transfer to low byte of temp register)
        uint8_t mov_temp_al[] = {0x88, 0xC0 + temp_idx};  // MOV CL/DL, AL
        buffer_append(b, mov_temp_al, 2);

        // SHR reg, CL/DL (D3 /5)
        buffer_write_byte(b, 0xD3);
        buffer_write_byte(b, 0xE8 + reg_idx);

        // POP temp_reg (restore)
        buffer_write_byte(b, 0x58 + temp_idx);
    }

    // POP reg (restore original value)
    buffer_write_byte(b, 0x58 + reg_idx);
}

strategy_t bt_imm_null_strategy = {
    .name = "bt_imm_null",
    .can_handle = can_handle_bt_imm_null,
    .get_size = get_size_bt_imm_null,
    .generate = generate_bt_imm_null,
    .priority = 80
};

void register_bt_strategies() {
    register_strategy(&bt_imm_null_strategy);
}
