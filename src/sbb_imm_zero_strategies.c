/**
 * SBB/ADC Immediate Zero Null-Byte Elimination Strategies
 *
 * Handles: sbb al, 0 / sbb reg, 0 / adc al, 0 / adc reg, 0
 * These instructions use the zero immediate which creates null bytes.
 *
 * x64-specific strategy file (v4.2)
 *
 * Common patterns:
 * - SBB AL, 0 (0x1C 0x00) - used for CF-based conditional operations
 * - ADC AL, 0 (0x14 0x00) - used for multi-precision arithmetic
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// ============================================================================
// STRATEGY 1: SBB reg, 0 → SBB reg, zero_reg
// ============================================================================
// Handles: sbb al/reg, 0 where the immediate is zero
// Transformation: Use a zeroed register instead of immediate zero
//
// Example:
//   Original: SBB AL, 0  ; [1C 00]
//   Transformed:
//     PUSH ECX           ; Save temp
//     XOR CL, CL         ; Zero the temp
//     SBB AL, CL         ; Use register operand
//     POP ECX            ; Restore temp

static int can_handle_sbb_imm_zero(cs_insn *insn) {
    // Only handle SBB instructions
    if (insn->id != X86_INS_SBB) {
        return 0;
    }

    // Must have null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Must have exactly 2 operands
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    // First operand must be a register
    if (op0->type != X86_OP_REG) {
        return 0;
    }

    // Second operand must be immediate
    if (op1->type != X86_OP_IMM) {
        return 0;
    }

    // Check if immediate is zero
    return op1->imm == 0;
}

static size_t get_size_sbb_imm_zero(cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];

    // For 8-bit registers: PUSH + XOR + SBB + POP = 1 + 2 + 2 + 1 = 6 bytes
    // For 32/64-bit registers: more complex
    if (op0->size == 1) {
        return 6;
    }

    // For 32/64-bit: PUSH + XOR + SBB + POP
    // With REX prefix for 64-bit: 1 + 3 + 3 + 1 = 8 bytes
    return 10;
}

static void generate_sbb_imm_zero(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    x86_reg dst_reg = op0->reg;

    // Handle 8-bit register case
    if (op0->size == 1) {
        // Find a suitable temp 8-bit register that doesn't conflict
        // Use BL if dst is not BL, otherwise use CL
        uint8_t temp_8bit = (dst_reg == X86_REG_BL) ? 0x01 : 0x03;  // CL or BL
        uint8_t push_reg = (dst_reg == X86_REG_BL) ? 0x51 : 0x53;   // PUSH ECX or PUSH EBX
        uint8_t pop_reg = (dst_reg == X86_REG_BL) ? 0x59 : 0x5B;    // POP ECX or POP EBX

        // PUSH temp_32bit
        buffer_write_byte(b, push_reg);

        // XOR temp_8bit, temp_8bit
        buffer_write_byte(b, 0x30);  // XOR r/m8, r8
        buffer_write_byte(b, 0xC0 | (temp_8bit << 3) | temp_8bit);

        // Get 8-bit register encoding for destination
        uint8_t dst_8bit = 0;
        switch (dst_reg) {
            case X86_REG_AL: dst_8bit = 0; break;
            case X86_REG_CL: dst_8bit = 1; break;
            case X86_REG_DL: dst_8bit = 2; break;
            case X86_REG_BL: dst_8bit = 3; break;
            case X86_REG_AH: dst_8bit = 4; break;
            case X86_REG_CH: dst_8bit = 5; break;
            case X86_REG_DH: dst_8bit = 6; break;
            case X86_REG_BH: dst_8bit = 7; break;
            // x64 low-byte registers
            case X86_REG_SPL: dst_8bit = 4; break;
            case X86_REG_BPL: dst_8bit = 5; break;
            case X86_REG_SIL: dst_8bit = 6; break;
            case X86_REG_DIL: dst_8bit = 7; break;
            case X86_REG_R8B: dst_8bit = 0; break;
            case X86_REG_R9B: dst_8bit = 1; break;
            case X86_REG_R10B: dst_8bit = 2; break;
            case X86_REG_R11B: dst_8bit = 3; break;
            case X86_REG_R12B: dst_8bit = 4; break;
            case X86_REG_R13B: dst_8bit = 5; break;
            case X86_REG_R14B: dst_8bit = 6; break;
            case X86_REG_R15B: dst_8bit = 7; break;
            default: dst_8bit = 0; break;
        }

        // SBB dst_8bit, temp_8bit
        buffer_write_byte(b, 0x1A);  // SBB r8, r/m8
        buffer_write_byte(b, 0xC0 | (dst_8bit << 3) | temp_8bit);

        // POP temp_32bit
        buffer_write_byte(b, pop_reg);

        return;
    }

    // Handle 32-bit and 64-bit register cases
    int is_64bit = is_64bit_register(dst_reg);
    int is_ext = is_extended_register(dst_reg);
    uint8_t dst_idx = get_reg_index(dst_reg);

    // Use ECX/RCX as temp (avoid EAX which might be used in carry chains)
    // PUSH RCX/ECX
    if (is_64bit && is_ext) {
        buffer_write_byte(b, 0x41);  // REX.B
    }
    buffer_write_byte(b, 0x51);  // PUSH RCX/ECX

    // XOR ECX/RCX, ECX/RCX
    if (is_64bit) {
        buffer_write_byte(b, 0x48);  // REX.W
    }
    buffer_write_byte(b, 0x31);  // XOR r32/64, r/m32/64
    buffer_write_byte(b, 0xC9);  // ECX, ECX

    // SBB dst, RCX/ECX
    uint8_t rex = 0;
    if (is_64bit) {
        rex = 0x48;  // REX.W
        if (is_ext) {
            rex |= 0x04;  // REX.R for dst in reg field
        }
    } else if (is_ext) {
        rex = 0x44;  // REX.R
    }

    if (rex) {
        buffer_write_byte(b, rex);
    }
    buffer_write_byte(b, 0x1B);  // SBB r32/64, r/m32/64
    buffer_write_byte(b, 0xC0 | (dst_idx << 3) | 0x01);  // ModR/M: dst, ECX

    // POP RCX/ECX
    if (is_64bit && is_ext) {
        buffer_write_byte(b, 0x41);
    }
    buffer_write_byte(b, 0x59);
}

strategy_t sbb_imm_zero_strategy = {
    .name = "sbb_imm_zero_null_free",
    .can_handle = can_handle_sbb_imm_zero,
    .get_size = get_size_sbb_imm_zero,
    .generate = generate_sbb_imm_zero,
    .priority = 86,
    .target_arch = BYVAL_ARCH_X64
};

// ============================================================================
// STRATEGY 2: ADC reg, 0 → ADC reg, zero_reg
// ============================================================================
// Handles: adc al/reg, 0 where the immediate is zero
// Same transformation as SBB but for ADC

static int can_handle_adc_imm_zero(cs_insn *insn) {
    // Only handle ADC instructions
    if (insn->id != X86_INS_ADC) {
        return 0;
    }

    // Must have null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Must have exactly 2 operands
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    // First operand must be a register
    if (op0->type != X86_OP_REG) {
        return 0;
    }

    // Second operand must be immediate
    if (op1->type != X86_OP_IMM) {
        return 0;
    }

    // Check if immediate is zero
    return op1->imm == 0;
}

static size_t get_size_adc_imm_zero(cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];

    if (op0->size == 1) {
        return 6;
    }
    return 10;
}

static void generate_adc_imm_zero(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    x86_reg dst_reg = op0->reg;

    // Handle 8-bit register case
    if (op0->size == 1) {
        uint8_t temp_8bit = (dst_reg == X86_REG_BL) ? 0x01 : 0x03;
        uint8_t push_reg = (dst_reg == X86_REG_BL) ? 0x51 : 0x53;
        uint8_t pop_reg = (dst_reg == X86_REG_BL) ? 0x59 : 0x5B;

        // PUSH temp_32bit
        buffer_write_byte(b, push_reg);

        // XOR temp_8bit, temp_8bit
        buffer_write_byte(b, 0x30);
        buffer_write_byte(b, 0xC0 | (temp_8bit << 3) | temp_8bit);

        // Get 8-bit encoding
        uint8_t dst_8bit = 0;
        switch (dst_reg) {
            case X86_REG_AL: dst_8bit = 0; break;
            case X86_REG_CL: dst_8bit = 1; break;
            case X86_REG_DL: dst_8bit = 2; break;
            case X86_REG_BL: dst_8bit = 3; break;
            case X86_REG_AH: dst_8bit = 4; break;
            case X86_REG_CH: dst_8bit = 5; break;
            case X86_REG_DH: dst_8bit = 6; break;
            case X86_REG_BH: dst_8bit = 7; break;
            default: dst_8bit = 0; break;
        }

        // ADC dst_8bit, temp_8bit
        buffer_write_byte(b, 0x12);  // ADC r8, r/m8
        buffer_write_byte(b, 0xC0 | (dst_8bit << 3) | temp_8bit);

        // POP temp_32bit
        buffer_write_byte(b, pop_reg);

        return;
    }

    // Handle 32-bit and 64-bit register cases
    int is_64bit = is_64bit_register(dst_reg);
    int is_ext = is_extended_register(dst_reg);
    uint8_t dst_idx = get_reg_index(dst_reg);

    // PUSH RCX/ECX
    if (is_64bit && is_ext) {
        buffer_write_byte(b, 0x41);
    }
    buffer_write_byte(b, 0x51);

    // XOR ECX/RCX, ECX/RCX
    if (is_64bit) {
        buffer_write_byte(b, 0x48);
    }
    buffer_write_byte(b, 0x31);
    buffer_write_byte(b, 0xC9);

    // ADC dst, RCX/ECX
    uint8_t rex = 0;
    if (is_64bit) {
        rex = 0x48;
        if (is_ext) {
            rex |= 0x04;
        }
    } else if (is_ext) {
        rex = 0x44;
    }

    if (rex) {
        buffer_write_byte(b, rex);
    }
    buffer_write_byte(b, 0x13);  // ADC r32/64, r/m32/64
    buffer_write_byte(b, 0xC0 | (dst_idx << 3) | 0x01);

    // POP RCX/ECX
    if (is_64bit && is_ext) {
        buffer_write_byte(b, 0x41);
    }
    buffer_write_byte(b, 0x59);
}

strategy_t adc_imm_zero_strategy = {
    .name = "adc_imm_zero_null_free",
    .can_handle = can_handle_adc_imm_zero,
    .get_size = get_size_adc_imm_zero,
    .generate = generate_adc_imm_zero,
    .priority = 86,
    .target_arch = BYVAL_ARCH_X64
};

// ============================================================================
// Registration Function
// ============================================================================

void register_sbb_imm_zero_strategies() {
    register_strategy(&sbb_imm_zero_strategy);
    register_strategy(&adc_imm_zero_strategy);
}
