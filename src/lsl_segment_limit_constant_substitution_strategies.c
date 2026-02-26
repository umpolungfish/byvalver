/*
 * lsl_segment_limit_constant_substitution_strategies.c
 * Implementation of the LSL-based 0xFFFFFFFF generation strategy.
 * 
 * This strategy replaces instructions loading 0xFFFFFFFF (like MOV EAX, -1)
 * with a sequence that extracts the code segment limit using the LSL instruction.
 */

#include "strategy.h"
#include "utils.h"
#include <capstone/capstone.h>

/**
 * Maps a Capstone x86 register to its hardware encoding index.
 * Only handles 32-bit GPRs to match the LSL 32-bit destination behavior.
 */
static int get_x86_reg_index(x86_reg reg) {
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
 * Checks if the instruction is a MOV or OR loading 0xFFFFFFFF into a GPR.
 */
static int can_handle_lsl_segment_limit(cs_insn *insn) {
    if (insn->id != X86_INS_MOV && insn->id != X86_INS_OR) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *ops = insn->detail->x86.operands;

    // Destination must be a supported 32-bit GPR
    if (ops[0].type != X86_OP_REG || get_x86_reg_index(ops[0].reg) == -1) {
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
 * Returns the size of the replacement sequence.
 * MOV AX, CS (2 bytes) + LSL reg32, AX (3 bytes) = 5 bytes.
 */
static size_t get_size_lsl_segment_limit(cs_insn *insn) {
    (void)insn;
    return 5;
}

/**
 * Generates:
 * 8C C8       -> MOV AX, CS
 * 0F 03 [ModRM] -> LSL reg32, AX
 */
static void generate_lsl_segment_limit(struct buffer *b, cs_insn *insn) {
    cs_x86_op *ops = insn->detail->x86.operands;
    int reg_idx = get_x86_reg_index(ops[0].reg);

    // MOV AX, CS
    // 8C: MOV r/m16, Sreg
    // C8: Mod=11 (Reg), Sreg=001 (CS), RM=000 (AX)
    buffer_write_byte(b, 0x8C);
    buffer_write_byte(b, 0xC8);

    // LSL reg32, AX
    // 0F 03: LSL opcode
    // ModRM: Mod=11 (Reg), Reg=dest_idx, RM=000 (AX)
    buffer_write_byte(b, 0x0F);
    buffer_write_byte(b, 0x03);
    
    // Construct ModRM byte: 0b11 [reg_idx:3] 000
    uint8_t modrm = 0xC0 | (uint8_t)((reg_idx & 0x07) << 3);
    buffer_write_byte(b, modrm);
}

/* Strategy definition */
static strategy_t lsl_segment_limit_strategy = {
    .name = "lsl_segment_limit_constant_substitution",
    .can_handle = can_handle_lsl_segment_limit,
    .get_size = get_size_lsl_segment_limit,
    .generate = generate_lsl_segment_limit,
    .priority = 82,
    .target_arch = BYVAL_ARCH_X86
};

/**
 * Registration function for the BYVALVER strategy registry.
 */
void register_lsl_segment_limit_constant_substitution_strategies(void) {
    register_strategy(&lsl_segment_limit_strategy);
}