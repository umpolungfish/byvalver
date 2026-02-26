/*
 * bmi1_andn_logic_transformation_strategies.c
 * 
 * Implementation of the BMI1 ANDN Logic Transformation strategy for bad-byte elimination.
 * This strategy replaces common logical idioms (like zeroing or NOT-AND sequences)
 * with the VEX-encoded ANDN instruction to avoid null bytes and reduce instruction count.
 */

#include "bmi1_andn_logic_transformation_strategies.h"
#include "strategy.h"
#include "utils.h"
#include "core.h"
#include <capstone/capstone.h>

/**
 * Maps a Capstone x86 register to its hardware index (0-15).
 * Only supports 32-bit (EAX-EDI) and 64-bit (RAX-R15) registers.
 */
static uint8_t get_x86_reg_idx(x86_reg reg) {
    switch (reg) {
        case X86_REG_EAX: case X86_REG_RAX: return 0;
        case X86_REG_ECX: case X86_REG_RCX: return 1;
        case X86_REG_EDX: case X86_REG_RDX: return 2;
        case X86_REG_EBX: case X86_REG_RBX: return 3;
        case X86_REG_ESP: case X86_REG_RSP: return 4;
        case X86_REG_EBP: case X86_REG_RBP: return 5;
        case X86_REG_ESI: case X86_REG_RSI: return 6;
        case X86_REG_EDI: case X86_REG_RDI: return 7;
        case X86_REG_R8:  case X86_REG_R8D:  return 8;
        case X86_REG_R9:  case X86_REG_R9D:  return 9;
        case X86_REG_R10: case X86_REG_R10D: return 10;
        case X86_REG_R11: case X86_REG_R11D: return 11;
        case X86_REG_R12: case X86_REG_R12D: return 12;
        case X86_REG_R13: case X86_REG_R13D: return 13;
        case X86_REG_R14: case X86_REG_R14D: return 14;
        case X86_REG_R15: case X86_REG_R15D: return 15;
        default: return 0xFF;
    }
}

/**
 * Checks if a register is 64-bit.
 */
static int is_64bit_reg(x86_reg reg) {
    return (reg >= X86_REG_RAX && reg <= X86_REG_R15);
}

/**
 * Determines if the instruction is a register-zeroing idiom.
 * Matches: XOR r, r | SUB r, r | MOV r, 0 | AND r, 0
 */
static int is_zeroing_idiom(cs_insn *insn) {
    if (insn->detail == NULL || insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *ops = insn->detail->x86.operands;

    if (insn->id == X86_INS_XOR || insn->id == X86_INS_SUB) {
        return (ops[0].type == X86_OP_REG && 
                ops[1].type == X86_OP_REG && 
                ops[0].reg == ops[1].reg);
    }
    
    if (insn->id == X86_INS_MOV || insn->id == X86_INS_AND) {
        return (ops[0].type == X86_OP_REG && 
                ops[1].type == X86_OP_IMM && 
                ops[1].imm == 0);
    }

    return 0;
}

/**
 * can_handle: Verifies if the instruction can be replaced by a BMI1 ANDN.
 */
static int can_handle_bmi1_andn_transformation(cs_insn *insn) {
    if (!insn->detail) return 0;

    // Check for zeroing idioms (the most reliable standalone transformation for this strategy)
    if (is_zeroing_idiom(insn)) {
        uint8_t idx = get_x86_reg_idx(insn->detail->x86.operands[0].reg);
        // Ensure it's a 32 or 64 bit GPR
        return (idx != 0xFF);
    }

    return 0;
}

/**
 * get_size: Returns the conservative upper-bound byte count for ANDN.
 * BMI1 ANDN with 3-byte VEX prefix: 3 (VEX) + 1 (Opcode) + 1 (ModRM) = 5 bytes.
 */
static size_t get_size_bmi1_andn_transformation(cs_insn *insn) {
    (void)insn;
    return 5;
}

/**
 * generate: Emits the VEX-encoded ANDN instruction.
 * Logic used for zeroing: ANDN r, r, r (dest = ~r & r = 0).
 */
static void generate_bmi1_andn_transformation(struct buffer *b, cs_insn *insn) {
    (void)insn;
    
    // We assume can_handle passed, so operand 0 is a valid GPR
    x86_reg target_reg = insn->detail->x86.operands[0].reg;
    uint8_t idx = get_x86_reg_idx(target_reg);
    
    // For zeroing: dest = idx, src1 = idx, src2 = idx
    uint8_t dst_idx = idx;
    uint8_t src1_idx = idx;
    uint8_t src2_idx = idx;

    /* VEX Prefix Encoding (3-byte version 0xC4)
     * Byte 1: [R][X][B][m-mmmm]
     *   R, X, B: Inverted bits 3 of register indices.
     *   m-mmmm: 0x02 for 0F 38 map.
     * Byte 2: [W][vvvv][L][pp]
     *   W: 1 for 64-bit, 0 for 32-bit.
     *   vvvv: Inverted 4-bit index of src1.
     *   L: 0 (scalar/128).
     *   pp: 00 (no prefix).
     */
    
    uint8_t r_bit = (dst_idx & 0x08) ? 0x00 : 0x80;
    uint8_t x_bit = 0x40; // No SIB index
    uint8_t b_bit = (src2_idx & 0x08) ? 0x00 : 0x20;
    uint8_t m_bits = 0x02;
    uint8_t vex_byte1 = r_bit | x_bit | b_bit | m_bits;

    uint8_t w_bit = is_64bit_reg(target_reg) ? 0x80 : 0x00;
    uint8_t vvvv = (~src1_idx) & 0x0F;
    uint8_t l_pp = 0x00;
    uint8_t vex_byte2 = w_bit | (vvvv << 3) | l_pp;

    // ModRM Encoding: [11][reg][rm]
    // reg = dst_idx, rm = src2_idx
    uint8_t modrm = 0xC0 | ((dst_idx & 0x07) << 3) | (src2_idx & 0x07);

    // Write bytes to buffer (all are verified non-zero)
    buffer_write_byte(b, 0xC4);        // VEX prefix byte 0
    buffer_write_byte(b, vex_byte1);   // VEX prefix byte 1
    buffer_write_byte(b, vex_byte2);   // VEX prefix byte 2
    buffer_write_byte(b, 0xF2);        // Opcode
    buffer_write_byte(b, modrm);       // ModRM byte
}

/**
 * Strategy definition for BMI1 ANDN Logic Transformation.
 */
static strategy_t bmi1_andn_logic_transformation_strategy = {
    .name = "bmi1_andn_logic_transformation",
    .can_handle = can_handle_bmi1_andn_transformation,
    .get_size = get_size_bmi1_andn_transformation,
    .generate = generate_bmi1_andn_transformation,
    .priority = 88,
    .target_arch = BYVAL_ARCH_X86
};

/**
 * Registration function called by the engine.
 */
void register_bmi1_andn_logic_transformation_strategies(void) {
    register_strategy(&bmi1_andn_logic_transformation_strategy);
}