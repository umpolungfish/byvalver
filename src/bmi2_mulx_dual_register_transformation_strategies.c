/*
 * bmi2_mulx_dual_register_transformation_strategies.c
 * Implementation of the BMI2 MULX Flagless Register Copy strategy.
 */
#include "bmi2_mulx_dual_register_transformation_strategies.h"
#include "strategy.h"
#include "utils.h"
#include "core.h"
#include <capstone/capstone.h>

/**
 * can_handle_bmi2_mulx
 *
 * Checks if the instruction is a MOV reg, reg that can be transformed using MULX.
 * Requirements:
 * 1. Must be a MOV instruction with exactly 2 register operands.
 * 2. Source and destination must be 32-bit or 64-bit general-purpose registers.
 * 3. Neither source nor destination can be EDX/RDX (to avoid multiplicand conflict).
 * 4. Register indices must be in the range 0-7 (EAX-EDI) for the provided VEX logic.
 * 5. The instruction must contain null bytes (to qualify for elimination).
 */
static int can_handle_bmi2_mulx(cs_insn *insn) {
    if (insn->id != X86_INS_MOV) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *ops = insn->detail->x86.operands;

    if (ops[0].type != X86_OP_REG || ops[1].type != X86_OP_REG) {
        return 0;
    }

    // Only handle 32-bit (e.g., EAX) or 64-bit (e.g., RAX) registers
    if (ops[0].size != 4 && ops[0].size != 8) {
        return 0;
    }

    // Exclude EDX/RDX because it is used as an implicit input for MULX
    if (ops[0].reg == X86_REG_EDX || ops[0].reg == X86_REG_RDX ||
        ops[1].reg == X86_REG_EDX || ops[1].reg == X86_REG_RDX) {
        return 0;
    }

    int dest_idx = get_reg_index(ops[0].reg);
    int src_idx = get_reg_index(ops[1].reg);

    // Limit to base registers 0-7 (EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI)
    // to match the VEX encoding logic used in generate()
    if (dest_idx < 0 || dest_idx >= 8 || src_idx < 0 || src_idx >= 8) {
        return 0;
    }

    // Only apply if the original instruction has null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    return 1;
}

/**
 * get_size_bmi2_mulx
 *
 * Returns a conservative upper-bound byte count for the replacement.
 * PUSH 1 (2) + POP EDX (1) + VEX MULX (5) = 8 bytes.
 */
static size_t get_size_bmi2_mulx(cs_insn *insn) {
    (void)insn;
    return 16;
}

/**
 * generate_bmi2_mulx
 *
 * Emits the replacement sequence:
 * PUSH 1; POP EDX; MULX EDX, dest, src
 */
static void generate_bmi2_mulx(struct buffer *b, cs_insn *insn) {
    cs_x86_op *ops = insn->detail->x86.operands;

    int dest_idx = get_reg_index(ops[0].reg);
    int src_idx = get_reg_index(ops[1].reg);
    
    // Index for EDX/RDX is 2
    uint8_t vvvv_edx = (uint8_t)(15 - 2); 

    // VEX.W bit: 0 for 32-bit operands, 1 for 64-bit
    uint8_t w_bit = (ops[0].size == 8) ? 0x80 : 0x00;

    // VEX Byte 3: W | vvvv | L | pp
    // vvvv is 4 bits (shifted by 3)
    // L = 0 (scalar/128)
    // pp = 3 (F2 mandatory prefix for MULX)
    uint8_t vex3 = (uint8_t)(w_bit | (vvvv_edx << 3) | 0x03);

    // ModRM: 11 | dest_lo | src
    // 0xC0 = 11000000b
    uint8_t modrm = (uint8_t)(0xC0 | (dest_idx << 3) | src_idx);

    // 1. PUSH 1 (6A 01)
    buffer_write_byte(b, 0x6A);
    buffer_write_byte(b, 0x01);

    // 2. POP EDX (5A)
    // Note: 5A is POP EDX in 32-bit and POP RDX in 64-bit.
    buffer_write_byte(b, 0x5A);

    // 3. MULX EDX, dest, src
    // VEX 3-byte prefix (C4)
    buffer_write_byte(b, 0xC4);
    // VEX Byte 2: R=1, X=1, B=1, m-mmmm=02 (0F 38 map)
    buffer_write_byte(b, 0xE2);
    // VEX Byte 3
    buffer_write_byte(b, vex3);
    // Opcode for MULX (F6)
    buffer_write_byte(b, 0xF6);
    // ModRM
    buffer_write_byte(b, modrm);
}

/* Define the strategy structure */
static strategy_t bmi2_mulx_strategy = {
    .name = "bmi2_mulx_dual_register_transformation",
    .can_handle = can_handle_bmi2_mulx,
    .get_size = get_size_bmi2_mulx,
    .generate = generate_bmi2_mulx,
    .priority = 88,
    .target_arch = BYVAL_ARCH_X86
};

/**
 * register_bmi2_mulx_dual_register_transformation_strategies
 *
 * Registration entry point for the BYVALVER core.
 */
void register_bmi2_mulx_dual_register_transformation_strategies(void) {
    register_strategy(&bmi2_mulx_strategy);
}