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

    // For small bit indices (0-7), we can use a simple transformation
    // PUSH reg (1) + SHR reg, (bit_index+1) (3) + POP reg (1) = 5 bytes
    if (bit_index >= 0 && bit_index <= 7) {
        return 5;
    }

    // For larger bit indices, more complex (not common in shellcode)
    return 10;
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

    if (shift_amount == 1) {
        // SHR reg, 1 (2 bytes: D1 /5)
        buffer_write_byte(b, 0xD1);
        buffer_write_byte(b, 0xE8 + reg_idx);
    } else if (shift_amount != 0) {
        // SHR reg, imm8 (3 bytes: C1 /5 ib)
        buffer_write_byte(b, 0xC1);
        buffer_write_byte(b, 0xE8 + reg_idx);
        buffer_write_byte(b, shift_amount);
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
