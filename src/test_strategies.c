#include "strategy.h"
#include "utils.h"
#include <stdio.h>

// Strategy: TEST memory operand with null ModR/M byte
// TEST byte ptr [reg], reg8 => PUSH temp; MOVZX temp, byte [reg]; TEST temp_low, reg8; POP temp

int can_handle_test_mem_null(cs_insn *insn) {
    if (insn->id != X86_INS_TEST) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    // First operand must be memory
    if (insn->detail->x86.operands[0].type != X86_OP_MEM) {
        return 0;
    }

    // Second operand must be register
    if (insn->detail->x86.operands[1].type != X86_OP_REG) {
        return 0;
    }

    // Check if has null bytes in encoding (typically ModR/M 0x00)
    if (has_null_bytes(insn)) {
        return 1;
    }

    return 0;
}

size_t get_size_test_mem_null(cs_insn *insn) {
    (void)insn;
    // PUSH temp (1) + MOVZX temp, byte [mem] (3-7) + TEST temp_low, reg (2) + POP temp (1)
    // Conservative estimate
    return 12;
}

void generate_test_mem_null(struct buffer *b, cs_insn *insn) {
    x86_reg test_reg = insn->detail->x86.operands[1].reg;
    x86_reg base_reg = insn->detail->x86.operands[0].mem.base;
    int32_t disp = insn->detail->x86.operands[0].mem.disp;

    // Get register indices for 32-bit registers
    uint8_t base_idx, test_idx;
    x86_reg base_32, test_32;

    // Convert 64-bit regs to 32-bit for index calculation
    if (base_reg >= X86_REG_RAX && base_reg <= X86_REG_RDI) {
        base_32 = X86_REG_EAX + (base_reg - X86_REG_RAX);
        base_idx = base_reg - X86_REG_RAX;
    } else if (base_reg >= X86_REG_EAX && base_reg <= X86_REG_EDI) {
        base_32 = base_reg;
        base_idx = base_reg - X86_REG_EAX;
    } else {
        // Unsupported register, output original
        for (size_t i = 0; i < insn->size; i++) {
            buffer_write_byte(b, insn->bytes[i]);
        }
        return;
    }

    // Convert test register (usually 8-bit like AL)
    if (test_reg >= X86_REG_AL && test_reg <= X86_REG_BL) {
        test_32 = X86_REG_EAX + (test_reg - X86_REG_AL);
        test_idx = test_reg - X86_REG_AL;
    } else if (test_reg >= X86_REG_EAX && test_reg <= X86_REG_EDI) {
        test_32 = test_reg;
        test_idx = test_reg - X86_REG_EAX;
    } else {
        // Unsupported, output original
        for (size_t i = 0; i < insn->size; i++) {
            buffer_write_byte(b, insn->bytes[i]);
        }
        return;
    }

    // Choose temp register (avoid test_reg and base_reg)
    x86_reg temp_32 = X86_REG_ECX;
    uint8_t temp_idx = X86_REG_ECX - X86_REG_EAX;

    if (temp_32 == test_32 || temp_32 == base_32) {
        temp_32 = X86_REG_EDX;
        temp_idx = X86_REG_EDX - X86_REG_EAX;
    }
    if (temp_32 == test_32 || temp_32 == base_32) {
        temp_32 = X86_REG_EBX;
        temp_idx = X86_REG_EBX - X86_REG_EAX;
    }

    // Transform strategy depends on whether ModR/M would be 0x00
    uint8_t predicted_modrm = 0x00 + (temp_idx * 8) + base_idx;
    int will_have_null_modrm = (disp == 0 && base_32 != X86_REG_EBP && predicted_modrm == 0x00);

    if (will_have_null_modrm) {
        // Strategy: Copy base to temp, then load from temp
        // PUSH temp; MOV temp, base; MOVZX temp, byte [temp]; TEST temp_low, test_reg; POP temp

        // PUSH temp
        buffer_write_byte(b, 0x50 + temp_idx);

        // MOV temp, base
        buffer_write_byte(b, 0x89);
        uint8_t mov_modrm = 0xC0 + (base_idx * 8) + temp_idx;
        buffer_write_byte(b, mov_modrm);

        // MOVZX temp, byte [temp] - now [temp] won't be [rax] so no null ModR/M
        buffer_write_byte(b, 0x0F);
        buffer_write_byte(b, 0xB6);
        // [temp] mode - temp_idx is now the base
        uint8_t movzx_modrm = 0x00 + (temp_idx * 8) + temp_idx;
        buffer_write_byte(b, movzx_modrm);
    } else {
        // Normal case: PUSH temp; MOVZX temp, byte [base+disp]; ...

        // PUSH temp
        buffer_write_byte(b, 0x50 + temp_idx);

        // MOVZX temp, byte [base+disp]
        buffer_write_byte(b, 0x0F);
        buffer_write_byte(b, 0xB6);

        if (disp == 0 && base_32 != X86_REG_EBP) {
            // [reg] mode (mod=00)
            uint8_t modrm = 0x00 + (temp_idx * 8) + base_idx;
            buffer_write_byte(b, modrm);
        } else if (disp >= -128 && disp <= 127 && disp != 0) {
            // [reg+disp8] mode (mod=01)
            uint8_t modrm = 0x40 + (temp_idx * 8) + base_idx;
            buffer_write_byte(b, modrm);
            buffer_write_byte(b, (uint8_t)disp);
        } else {
            // [reg+disp32] mode (mod=10)
            uint8_t modrm = 0x80 + (temp_idx * 8) + base_idx;
            buffer_write_byte(b, modrm);
            buffer_write_dword(b, (uint32_t)disp);
        }
    }

    // TEST temp_low, test_reg (both 8-bit)
    buffer_write_byte(b, 0x84); // TEST r/m8, r8
    uint8_t modrm = 0xC0 + (test_idx * 8) + temp_idx;
    buffer_write_byte(b, modrm);

    // POP temp
    buffer_write_byte(b, 0x58 + temp_idx);
}

strategy_t test_mem_null_strategy = {
    .name = "test_mem_null",
    .can_handle = can_handle_test_mem_null,
    .get_size = get_size_test_mem_null,
    .generate = generate_test_mem_null,
    .priority = 82
};

void register_test_strategies() {
    register_strategy(&test_mem_null_strategy);
}
