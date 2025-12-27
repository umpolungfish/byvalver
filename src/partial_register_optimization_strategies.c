/*
 * Partial Register Optimization Strategy for Bad Character Elimination
 *
 * PROBLEM: Instructions using partial registers (AL, AH, BL, BH, etc.)
 * may result in encodings that contain bad characters, particularly in
 * ModR/M bytes or as immediate values.
 *
 * SOLUTION: Replace partial register operations with equivalent full
 * register operations or alternative encodings that avoid bad characters.
 */

#include "partial_register_optimization_strategies.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**
 * Get register index for 8-bit registers (ModR/M encoding)
 * AL=0, CL=1, DL=2, BL=3, AH=4, CH=5, DH=6, BH=7
 */
static uint8_t get_reg_index_8bit(x86_reg reg) {
    switch (reg) {
        case X86_REG_AL: return 0;
        case X86_REG_CL: return 1;
        case X86_REG_DL: return 2;
        case X86_REG_BL: return 3;
        case X86_REG_AH: return 4;
        case X86_REG_CH: return 5;
        case X86_REG_DH: return 6;
        case X86_REG_BH: return 7;
        default:
            fprintf(stderr, "[WARNING] Invalid 8-bit register: %d\n", reg);
            return 0;
    }
}

/**
 * Transform partial register operations that contain bad characters
 *
 * Original: MOV AL, 0x00 (contains null byte)
 * Transform: MOV EAX, 0x00000000 or XOR EAX, EAX (then use AL)
 */
int can_handle_partial_register_optimization(cs_insn *insn) {
    if (!insn) {
        return 0;
    }

    // ONLY handle MOV instructions with partial registers and immediate values
    // This strategy specifically transforms: MOV r8, imm8
    if (insn->id == X86_INS_MOV && insn->detail->x86.op_count == 2) {
        cs_x86_op *dst_op = &insn->detail->x86.operands[0];
        cs_x86_op *src_op = &insn->detail->x86.operands[1];

        // Check if destination is a partial register and source is immediate
        if (dst_op->type == X86_OP_REG && src_op->type == X86_OP_IMM) {
            // Only handle 8-bit registers (AL, CL, DL, BL, AH, CH, DH, BH)
            // NOTE: These are NOT sequential in the enum!
            x86_reg reg = dst_op->reg;
            if (reg == X86_REG_AL || reg == X86_REG_BL || reg == X86_REG_CL || reg == X86_REG_DL ||
                reg == X86_REG_AH || reg == X86_REG_BH || reg == X86_REG_CH || reg == X86_REG_DH) {
                return 1;
            }
        }
    }

    // Don't claim to handle other instructions - let other strategies handle them
    return 0;
}

size_t get_size_partial_register_optimization(__attribute__((unused)) cs_insn *insn) {
    // Varies depending on transformation, but typically 2-6 bytes
    return 6;  // Conservative estimate
}

void generate_partial_register_optimization(struct buffer *b, cs_insn *insn) {
    if (!insn || !b) {
        return;
    }

    // We know from can_handle that this is MOV r8, imm8
    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    cs_x86_op *src_op = &insn->detail->x86.operands[1];

    x86_reg partial_reg = dst_op->reg;
    uint8_t imm_val = (uint8_t)src_op->imm;

    // Map partial register to its full register
    x86_reg full_reg = X86_REG_EAX;  // Default
    switch(partial_reg) {
        case X86_REG_AL:
        case X86_REG_AH:
            full_reg = X86_REG_EAX;
            break;
        case X86_REG_BL:
        case X86_REG_BH:
            full_reg = X86_REG_EBX;
            break;
        case X86_REG_CL:
        case X86_REG_CH:
            full_reg = X86_REG_ECX;
            break;
        case X86_REG_DL:
        case X86_REG_DH:
            full_reg = X86_REG_EDX;
            break;
        default:
            full_reg = X86_REG_EAX;
            break;
    }

    // Strategy: Transform MOV r8, imm to avoid null bytes

    // Step 1: XOR full_reg, full_reg (zero the register)
    uint8_t reg_idx = get_reg_index(full_reg);
    buffer_write_byte(b, 0x31);  // XOR reg32, reg32
    buffer_write_byte(b, 0xC0 | (reg_idx << 3) | reg_idx);  // MOD/RM byte

    // Step 2: Only ADD the immediate if it's non-zero
    // (for zero, XOR alone is sufficient)
    if (imm_val != 0x00) {
        // ADD partial_reg, imm8 (set the value)
        // Encoding: 80 /0 imm8 for ADD r/m8, imm8
        uint8_t partial_idx = get_reg_index_8bit(partial_reg);
        buffer_write_byte(b, 0x80);  // ADD r/m8, imm8
        buffer_write_byte(b, 0xC0 | partial_idx);  // MOD/RM: 11 000 r/m
        buffer_write_byte(b, imm_val);  // Immediate value
    }
    // For MOV AL, 0 we just use XOR EAX, EAX (2 bytes total, no nulls)
}

/**
 * Transform operations to avoid partial register dependencies that cause bad chars
 */
int can_handle_partial_register_dependency(cs_insn *insn) {
    // Use the same logic as the main optimization function
    return can_handle_partial_register_optimization(insn);
}

size_t get_size_partial_register_dependency(__attribute__((unused)) cs_insn *insn) {
    return 5;  // Conservative estimate
}

void generate_partial_register_dependency(struct buffer *b, cs_insn *insn) {
    // For this implementation, we'll use the main function
    generate_partial_register_optimization(b, insn);
}

// Define the strategy structure
strategy_t partial_register_optimization_strategy = {
    .name = "Partial Register Optimization",
    .can_handle = can_handle_partial_register_dependency,
    .get_size = get_size_partial_register_dependency,
    .generate = generate_partial_register_dependency,
    .priority = 165  // Higher than mov_imm_enhanced (160) for specialized 8-bit register handling
};