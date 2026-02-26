/*
 * shrd_double_precision_value_synthesis_strategies.c
 * 
 * Implements the SHRD Double-Precision Shift Value Construction strategy.
 * This strategy synthesizes 32-bit constants by clearing a destination
 * register and using SHRD to shift a single non-zero byte from a scratch 
 * register into the desired byte position of the destination.
 * 
 * Target: MOV REG32, IMM32 where IMM32 has null bytes.
 */

#include <stdint.h>
#include <capstone/capstone.h>
#include "strategy.h"
#include "utils.h"

/**
 * Maps a Capstone x86 register enum to its physical 3-bit hardware encoding.
 * Only handles 32-bit general purpose registers.
 * 
 * @param reg The Capstone register ID.
 * @return The 3-bit hardware code or 0xFF if not a supported 32-bit GPR.
 */
static uint8_t get_x86_reg_code(x86_reg reg) {
    switch (reg) {
        case X86_REG_EAX: return 0;
        case X86_REG_ECX: return 1;
        case X86_REG_EDX: return 2;
        case X86_REG_EBX: return 3;
        case X86_REG_ESP: return 4;
        case X86_REG_EBP: return 5;
        case X86_REG_ESI: return 6;
        case X86_REG_EDI: return 7;
        default: return 0xFF;
    }
}

/**
 * Checks if the instruction is a MOV reg32, imm32 that fits the pattern
 * for SHRD synthesis (exactly one non-zero byte in positions 1, 2, or 3).
 */
int can_handle_shrd_double_precision(cs_insn *insn) {
    if (insn->id != X86_INS_MOV) {
        return 0;
    }

    cs_x86_op *ops = insn->detail->x86.operands;
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Must be MOV Reg, Imm
    if (ops[0].type != X86_OP_REG || ops[1].type != X86_OP_IMM) {
        return 0;
    }

    // Must be a 32-bit GPR
    uint8_t dest_code = get_x86_reg_code(ops[0].reg);
    if (dest_code == 0xFF) {
        return 0;
    }

    // Must have null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    uint32_t imm = (uint32_t)ops[1].imm;
    uint8_t b[4];
    b[0] = (uint8_t)(imm & 0xFF);
    b[1] = (uint8_t)((imm >> 8) & 0xFF);
    b[2] = (uint8_t)((imm >> 16) & 0xFF);
    b[3] = (uint8_t)((imm >> 24) & 0xFF);

    int non_zero_count = 0;
    int pos = -1;

    for (int i = 0; i < 4; i++) {
        if (b[i] != 0) {
            non_zero_count++;
            pos = i;
        }
    }

    /* 
     * Pattern requirement:
     * 1. Exactly one byte is non-zero.
     * 2. That byte is not the LSB (pos 0), as LSB is handled by other strategies.
     * 3. The non-zero byte itself must not be a bad byte (null).
     */
    if (non_zero_count == 1 && pos > 0 && is_bad_byte_free(b[pos])) {
        return 1;
    }

    return 0;
}

/**
 * Returns a conservative size estimate for the generated sequence.
 * XOR (2) + PUSH imm8 (2) + POP (1) + SHRD (4) = 9 bytes.
 */
size_t get_size_shrd_double_precision(cs_insn *insn) {
    (void)insn;
    return 12;
}

/**
 * Generates the SHRD-based substitution sequence.
 * 
 * Example: MOV EAX, 0xFF000000
 * Logic:
 *   XOR EAX, EAX
 *   PUSH 0xFF
 *   POP ECX
 *   SHRD EAX, ECX, 8
 */
void generate_shrd_double_precision(struct buffer *b, cs_insn *insn) {
    cs_x86_op *ops = insn->detail->x86.operands;
    uint32_t imm = (uint32_t)ops[1].imm;
    uint8_t dest_code = get_x86_reg_code(ops[0].reg);
    
    // Identify the byte value and its position
    uint8_t val = 0;
    uint8_t pos = 0;
    for (int i = 1; i < 4; i++) {
        uint8_t current_byte = (uint8_t)((imm >> (i * 8)) & 0xFF);
        if (current_byte != 0) {
            val = current_byte;
            pos = (uint8_t)i;
            break;
        }
    }

    /*
     * Calculate shift count for SHRD.
     * SHRD shifts destination right and fills high bits with source low bits.
     * pos 3 (0xXX000000): SHRD shift 8.
     * pos 2 (0x00XX0000): SHRD shift 16.
     * pos 1 (0x0000XX00): SHRD shift 24.
     */
    uint8_t shift = (uint8_t)((4 - pos) * 8);

    // Select scratch register (use ECX if dest is EAX, else use EAX)
    uint8_t scratch_code = (dest_code == 0) ? 1 : 0;

    // 1. XOR dest, dest (0x31 0xC0+reg_code)
    // ModRM = 11 (reg-to-reg) | reg_code << 3 | reg_code
    buffer_write_byte(b, 0x31);
    buffer_write_byte(b, (uint8_t)(0xC0 | (dest_code << 3) | dest_code));

    // 2. PUSH imm8 (0x6A val)
    buffer_write_byte(b, 0x6A);
    buffer_write_byte(b, val);

    // 3. POP scratch (0x58 + scratch_code)
    buffer_write_byte(b, (uint8_t)(0x58 + scratch_code));

    // 4. SHRD dest, scratch, imm8 (0x0F 0xAC ModRM imm8)
    // ModRM = 11 (reg-to-reg) | src_code << 3 | dest_code
    buffer_write_byte(b, 0x0F);
    buffer_write_byte(b, 0xAC);
    buffer_write_byte(b, (uint8_t)(0xC0 | (scratch_code << 3) | dest_code));
    buffer_write_byte(b, shift);
}

/**
 * Strategy definition for registration.
 */
static strategy_t shrd_value_synth_strategy = {
    .name = "shrd_double_precision_value_synthesis",
    .can_handle = can_handle_shrd_double_precision,
    .get_size = get_size_shrd_double_precision,
    .generate = generate_shrd_double_precision,
    .priority = 85,
    .target_arch = BYVAL_ARCH_X86
};

/**
 * Interface function to register this strategy with the core engine.
 */
void register_shrd_double_precision_value_synthesis_strategies(void) {
    register_strategy(&shrd_value_synth_strategy);
}