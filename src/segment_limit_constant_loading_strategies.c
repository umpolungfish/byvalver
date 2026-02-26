/*
 * segment_limit_constant_loading_strategies.c
 * Implementation of the LSL-based constant generation strategy.
 * 
 * This strategy replaces "MOV reg, 0xFFFFFFFF" with a sequence that 
 * avoids immediate fields by querying the segment limit of a valid 
 * segment selector (typically CS).
 */

#include <stdint.h>
#include <stddef.h>
#include <capstone/capstone.h>
#include "strategy.h"
#include "utils.h"

/**
 * Helper to map Capstone x86 registers to their hardware indices.
 * Only handles the standard 32-bit general purpose registers.
 */
static int get_x86_gpr_index(x86_reg reg) {
    switch (reg) {
        case X86_REG_EAX: return 0;
        case X86_REG_ECX: return 1;
        case X86_REG_EDX: return 2;
        case X86_REG_EBX: return 3;
        case X86_REG_ESP: return 4;
        case X86_REG_EBP: return 5;
        case X86_REG_ESI: return 6;
        case X86_REG_EDI: return 7;
        default: return -1;
    }
}

/**
 * Checks if the instruction is a MOV of the constant 0xFFFFFFFF into a 32-bit GPR.
 */
int can_handle_segment_limit_loading(cs_insn *insn) {
    if (insn->id != X86_INS_MOV) {
        return 0;
    }

    if (insn->detail == NULL || insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *ops = insn->detail->x86.operands;

    // Destination must be a 32-bit GPR
    if (ops[0].type != X86_OP_REG) {
        return 0;
    }

    int reg_idx = get_x86_gpr_index(ops[0].reg);
    if (reg_idx == -1) {
        return 0;
    }

    // Source must be an immediate 0xFFFFFFFF
    if (ops[1].type != X86_OP_IMM) {
        return 0;
    }

    uint32_t imm_val = (uint32_t)ops[1].imm;
    if (imm_val != 0xFFFFFFFF) {
        return 0;
    }

    return 1;
}

/**
 * Returns a conservative size estimate for the generated code.
 * MOV Sreg: 2 bytes
 * LSL: 3 bytes
 * Total: 5 bytes
 */
size_t get_size_segment_limit_loading(cs_insn *insn) {
    (void)insn;
    return 10; 
}

/**
 * Generates:
 *   MOV reg, CS   (8C C8 + reg_idx)
 *   LSL reg, reg  (0F 03 C0 + (reg_idx << 3) | reg_idx)
 */
void generate_segment_limit_loading(struct buffer *b, cs_insn *insn) {
    cs_x86_op *ops = insn->detail->x86.operands;
    int reg_idx = get_x86_gpr_index(ops[0].reg);

    /* 
     * MOV r/m16, Sreg
     * Opcode: 8C /r
     * ModRM: Mod=11 (register), Reg=001 (CS), RM=reg_idx
     * Byte: 0xC0 | (1 << 3) | reg_idx = 0xC8 | reg_idx
     */
    buffer_write_byte(b, 0x8C);
    buffer_write_byte(b, (uint8_t)(0xC8 | (uint8_t)reg_idx));

    /*
     * LSL r32, r32
     * Opcode: 0F 03 /r
     * ModRM: Mod=11 (register), Reg=reg_idx, RM=reg_idx
     * Byte: 0xC0 | (reg_idx << 3) | reg_idx
     */
    buffer_write_byte(b, 0x0F);
    buffer_write_byte(b, 0x03);
    buffer_write_byte(b, (uint8_t)(0xC0 | ((uint8_t)reg_idx << 3) | (uint8_t)reg_idx));
}

/* Strategy Definition */
static strategy_t segment_limit_strategy = {
    .name = "segment_limit_constant_loading",
    .can_handle = can_handle_segment_limit_loading,
    .get_size = get_size_segment_limit_loading,
    .generate = generate_segment_limit_loading,
    .priority = 88,
    .target_arch = BYVAL_ARCH_X86
};

/**
 * Strategy registration function.
 */
void register_segment_limit_constant_loading_strategies(void) {
    register_strategy(&segment_limit_strategy);
}