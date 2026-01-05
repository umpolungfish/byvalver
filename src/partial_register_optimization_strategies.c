/*
 * Partial Register Optimization Strategy for Bad Character Elimination
 *
 * PROBLEM: Instructions using partial registers (AL, AH, BL, BH, etc.)
 * may result in encodings that contain bad bytes, particularly in
 * ModR/M bytes or as immediate values.
 *
 * SOLUTION: Replace partial register operations with equivalent full
 * register operations or alternative encodings that avoid bad bytes.
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
 * Transform partial register operations that contain bad bytes
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

size_t get_size_partial_register_optimization(cs_insn *insn) {
    // FIXED: More accurate size estimation
    if (!insn || insn->detail->x86.op_count < 2) {
        return 6;
    }

    uint8_t imm_val = (uint8_t)insn->detail->x86.operands[1].imm;

    if (imm_val == 0x00) {
        return 2;  // XOR reg, reg only
    } else if (is_bad_byte_free_byte(imm_val)) {
        return 2 + 3;  // XOR + ADD with imm
    } else {
        // Bad byte: worst case is two ADD operations (3 bytes each)
        return 2 + 6;  // XOR + two ADDs
    }
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

    // Step 2: Set the value if non-zero
    if (imm_val != 0x00) {
        // FIXED: Don't write bad bytes directly! Construct value without bad bytes
        if (!is_bad_byte_free_byte(imm_val)) {
            // Strategy: Find two non-bad bytes that add/subtract to target
            // Try: imm_val = a + b or imm_val = a - b
            uint8_t found = 0;
            for (uint16_t a_val = 1; a_val < 256 && !found; a_val++) {
                for (uint16_t b_val = 1; b_val < 256 && !found; b_val++) {
                    if ((a_val + b_val) % 256 == imm_val) {
                        if (is_bad_byte_free_byte(a_val) && is_bad_byte_free_byte(b_val)) {
                            uint8_t partial_idx = get_reg_index_8bit(partial_reg);
                            // ADD partial_reg, a_val
                            buffer_write_byte(b, 0x80);  // ADD r/m8, imm8
                            buffer_write_byte(b, 0xC0 | partial_idx);
                            buffer_write_byte(b, (uint8_t)a_val);
                            // ADD partial_reg, b_val
                            buffer_write_byte(b, 0x80);
                            buffer_write_byte(b, 0xC0 | partial_idx);
                            buffer_write_byte(b, (uint8_t)b_val);
                            found = 1;
                        }
                    }
                }
            }
            if (!found) {
                // Fallback: Use INC repeatedly (slow but guaranteed to work)
                uint8_t partial_idx = get_reg_index_8bit(partial_reg);
                for (uint8_t i = 0; i < imm_val; i++) {
                    buffer_write_byte(b, 0xFE);  // INC r/m8
                    buffer_write_byte(b, 0xC0 | partial_idx);
                }
            }
        } else {
            // Safe to write directly
            uint8_t partial_idx = get_reg_index_8bit(partial_reg);
            buffer_write_byte(b, 0x80);  // ADD r/m8, imm8
            buffer_write_byte(b, 0xC0 | partial_idx);
            buffer_write_byte(b, imm_val);
        }
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