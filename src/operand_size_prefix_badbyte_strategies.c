#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>

// Strategy 10: Operand Size Prefix Bad-Byte
// Handles 0x66 prefix for 16-bit operations

static int can_handle_operand_size_prefix_bad(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    cs_x86 *x86 = &insn->detail->x86;

    // Check for operand-size prefix (0x66) at prefix[2]
    if (x86->prefix[2] == 0x66) {
        if (!is_bad_byte_free_byte(0x66)) {
            return 1;
        }
    }

    return 0;
}

static size_t get_size_operand_size_prefix_bad(cs_insn *insn) {
    (void)insn;
    // 32-bit operation + masking: ~8 bytes
    return 10;
}

static void generate_operand_size_prefix_bad(struct buffer *b, cs_insn *insn) {
    // For 16-bit MOV/operations, convert to 32-bit + mask
    // Simplified implementation - convert PUSH AX to PUSH EAX

    if (insn->id == X86_INS_PUSH &&
        insn->detail->x86.op_count == 1 &&
        insn->detail->x86.operands[0].type == X86_OP_REG) {

        x86_reg reg = insn->detail->x86.operands[0].reg;
        // Map 16-bit to 32-bit register
        x86_reg reg32 = reg;
        switch(reg) {
            case X86_REG_AX: reg32 = X86_REG_EAX; break;
            case X86_REG_CX: reg32 = X86_REG_ECX; break;
            case X86_REG_DX: reg32 = X86_REG_EDX; break;
            case X86_REG_BX: reg32 = X86_REG_EBX; break;
            case X86_REG_SP: reg32 = X86_REG_ESP; break;
            case X86_REG_BP: reg32 = X86_REG_EBP; break;
            case X86_REG_SI: reg32 = X86_REG_ESI; break;
            case X86_REG_DI: reg32 = X86_REG_EDI; break;
            default: reg32 = reg; break;
        }

        if (reg32 != reg) {
            // PUSH reg32 (32-bit version)
            int reg_idx = get_reg_index((uint8_t)reg32);
            uint8_t push = 0x50 + reg_idx;
            buffer_append(b, &push, 1);
            return;
        }
    }

    // Fallback: copy original
    buffer_append(b, insn->bytes, insn->size);
}

void register_operand_size_prefix_badbyte_strategies(void) {
    static strategy_t strategy = {
        .name = "Operand Size Prefix - Bad Byte Elimination",
        .can_handle = can_handle_operand_size_prefix_bad,
        .get_size = get_size_operand_size_prefix_bad,
        .generate = generate_operand_size_prefix_bad,
        .priority = 83
    };
    register_strategy(&strategy);
}
