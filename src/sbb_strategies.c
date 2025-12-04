#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * SBB (Subtract with Borrow) Null-Byte Elimination Strategies
 *
 * SBB is a flag-dependent instruction that subtracts two operands minus the carry flag (CF).
 * Common in multi-precision subtraction (64-bit math on 32-bit systems).
 *
 * Critical Constraint: Must preserve CF state from previous operations
 *
 * Null-byte patterns addressed:
 * 1. ModR/M null byte (e.g., SBB EAX, [EAX] -> 0x1B 0x00)
 * 2. Immediate with null bytes (e.g., SBB EAX, 0x00001000 -> 0x1D 0x00 0x10 0x00 0x00)
 */

// ============================================================================
// STRATEGY 1: SBB ModR/M Null-Byte Bypass
// ============================================================================
// Handles: SBB reg, [mem] and SBB [mem], reg where ModR/M byte is 0x00
// Transformation: Use temporary register to avoid null ModR/M
//
// Example:
//   Original: SBB EAX, [EAX]  ; [1B 00]
//   Transformed:
//     PUSH EBX                ; Save temp register
//     MOV EBX, EAX           ; Copy address to temp
//     SBB EAX, [EBX]         ; Use non-null ModR/M
//     POP EBX                ; Restore temp register

static int can_handle_sbb_modrm_null(cs_insn *insn) {
    // Only handle SBB instructions
    if (insn->id != X86_INS_SBB) {
        return 0;
    }

    // Must have null bytes in encoding
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Must have exactly 2 operands
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    // Check for patterns: reg, [mem] or [mem], reg
    int pattern1 = (op0->type == X86_OP_REG && op1->type == X86_OP_MEM);
    int pattern2 = (op0->type == X86_OP_MEM && op1->type == X86_OP_REG);

    if (!pattern1 && !pattern2) {
        return 0;
    }

    // Check if ModR/M byte would be null (0x00)
    // This happens when addressing mode is [EAX] (ModR/M = 0x00)
    cs_x86_op *mem_op = (op0->type == X86_OP_MEM) ? op0 : op1;

    // [EAX] with no displacement creates ModR/M 0x00
    if (mem_op->mem.base == X86_REG_EAX &&
        mem_op->mem.index == X86_REG_INVALID &&
        mem_op->mem.disp == 0) {
        return 1;
    }

    return 0;
}

static size_t get_size_sbb_modrm_null(cs_insn *insn) {
    // PUSH EBX (1) + MOV EBX, src_reg (2) + SBB with new ModR/M (2-6) + POP EBX (1)
    // Conservative estimate: 1 + 2 + 6 + 1 = 10 bytes
    (void)insn;
    return 10;
}

static void generate_sbb_modrm_null(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    // Determine which operand is register and which is memory
    x86_reg reg_operand;
    cs_x86_op *mem_op;
    int reg_is_dest;

    if (op0->type == X86_OP_REG && op1->type == X86_OP_MEM) {
        // SBB reg, [mem]
        reg_operand = op0->reg;
        mem_op = op1;
        reg_is_dest = 1;
    } else {
        // SBB [mem], reg
        reg_operand = op1->reg;
        mem_op = op0;
        reg_is_dest = 0;
    }

    // PUSH EBX - Save temporary register
    buffer_write_byte(b, 0x53); // PUSH EBX

    // MOV EBX, [mem].base - Copy the address register to temp
    if (mem_op->mem.base == X86_REG_EAX) {
        buffer_write_byte(b, 0x89); // MOV r/m32, r32
        buffer_write_byte(b, 0xC3); // ModR/M: EBX, EAX
    }

    // SBB with new addressing using EBX instead of EAX
    if (reg_is_dest) {
        // SBB reg, [EBX]
        buffer_write_byte(b, 0x1B); // SBB r32, r/m32

        // Calculate ModR/M for [EBX] addressing
        uint8_t reg_code = (reg_operand - X86_REG_EAX) & 0x07;
        uint8_t modrm = (reg_code << 3) | 0x03; // [EBX] = 0x03
        buffer_write_byte(b, modrm);
    } else {
        // SBB [EBX], reg
        buffer_write_byte(b, 0x19); // SBB r/m32, r32

        uint8_t reg_code = (reg_operand - X86_REG_EAX) & 0x07;
        uint8_t modrm = (reg_code << 3) | 0x03; // [EBX] = 0x03
        buffer_write_byte(b, modrm);
    }

    // POP EBX - Restore temporary register
    buffer_write_byte(b, 0x5B); // POP EBX
}

strategy_t sbb_modrm_null_bypass_strategy = {
    .name = "sbb_modrm_null_bypass",
    .can_handle = can_handle_sbb_modrm_null,
    .get_size = get_size_sbb_modrm_null,
    .generate = generate_sbb_modrm_null,
    .priority = 70
};

// ============================================================================
// STRATEGY 2: SBB Immediate Null Handling
// ============================================================================
// Handles: SBB reg, imm32 where immediate contains null bytes
// Transformation: Load immediate into temp register, then SBB with register
//
// Example:
//   Original: SBB EAX, 0x00001000  ; [1D 00 10 00 00]
//   Transformed:
//     PUSH EBX                      ; Save temp
//     MOV EBX, <null-free value>    ; Construct 0x00001000 without nulls
//     SBB EAX, EBX                  ; Use register operand
//     POP EBX                       ; Restore temp

static int can_handle_sbb_immediate_null(cs_insn *insn) {
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

    // First operand must be register
    if (op0->type != X86_OP_REG) {
        return 0;
    }

    // Second operand must be immediate
    if (op1->type != X86_OP_IMM) {
        return 0;
    }

    // Check if immediate contains null bytes
    // Handle both 8-bit and 32-bit register forms
    uint64_t imm = op1->imm;

    if (op0->size == 1) {
        // 8-bit register (AL, BL, CL, DL, etc.) - check if byte is null
        return (imm & 0xFF) == 0;
    } else {
        // 32-bit register - check full immediate
        uint32_t imm32 = (uint32_t)imm;
        return !is_null_free(imm32);
    }
}

static size_t get_size_sbb_immediate_null(cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    // Handle 8-bit register case
    if (op0->size == 1 && (op1->imm & 0xFF) == 0) {
        // PUSH EAX (1) + PUSH EBX (1) + XOR BL,BL (2) + SBB AL,BL (2) + POP EBX (1) + POP EAX (1) = 8 bytes
        return 8;
    }

    // Handle 32-bit register case
    // PUSH EBX (1) + MOV EBX, imm32 (5) + SBB reg, EBX (2) + POP EBX (1)
    // For small immediates we might use shift-based construction
    // Conservative estimate: 15 bytes
    return 15;
}

static void generate_sbb_immediate_null(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    x86_reg dst_reg = op0->reg;
    uint64_t imm = op1->imm;

    // Handle 8-bit register case (SBB AL, 0, etc.)
    if (op0->size == 1 && (imm & 0xFF) == 0) {
        // SBB AL/BL/CL/DL, 0 → use register form with zero register

        // Save registers we'll use
        buffer_write_byte(b, 0x50);  // PUSH EAX (preserve upper bits)
        buffer_write_byte(b, 0x53);  // PUSH EBX

        // XOR BL, BL - Create zero in BL (0x30 0xDB - null-free!)
        buffer_write_byte(b, 0x30);
        buffer_write_byte(b, 0xDB);

        // SBB dst_reg_8bit, BL
        // Map dst_reg to its 8-bit encoding
        uint8_t reg_8bit_code = 0;
        if (dst_reg == X86_REG_AL) reg_8bit_code = 0;
        else if (dst_reg == X86_REG_CL) reg_8bit_code = 1;
        else if (dst_reg == X86_REG_DL) reg_8bit_code = 2;
        else if (dst_reg == X86_REG_BL) reg_8bit_code = 3;
        else if (dst_reg == X86_REG_AH) reg_8bit_code = 4;
        else if (dst_reg == X86_REG_CH) reg_8bit_code = 5;
        else if (dst_reg == X86_REG_DH) reg_8bit_code = 6;
        else if (dst_reg == X86_REG_BH) reg_8bit_code = 7;
        else reg_8bit_code = 0; // default to AL

        buffer_write_byte(b, 0x1A);  // SBB r/m8, r8
        uint8_t modrm = 0xC0 | (reg_8bit_code << 3) | 0x03; // mod=11, reg=dst, r/m=BL(3)
        buffer_write_byte(b, modrm);

        // Restore registers
        buffer_write_byte(b, 0x5B);  // POP EBX
        buffer_write_byte(b, 0x58);  // POP EAX

        return;
    }

    // Handle 32-bit register case
    uint32_t imm32 = (uint32_t)imm;

    // Use EBX as temporary register (avoid destination register)
    uint8_t temp_reg = 0x03; // EBX

    // PUSH EBX
    buffer_write_byte(b, 0x53);

    // Construct the immediate value in EBX using null-free techniques
    int shift_amount = 0;
    uint32_t base_val = imm32;

    // Try to find shift amount that makes value null-free
    for (int i = 0; i < 32; i++) {
        uint32_t shifted = imm32 << i;
        if (is_null_free(shifted)) {
            base_val = shifted;
            shift_amount = i;
            break;
        }
        shifted = imm32 >> i;
        if (is_null_free(shifted) && shifted != 0) {
            base_val = shifted;
            shift_amount = -i;
            break;
        }
    }

    // MOV EBX, base_val (5 bytes if null-free)
    if (is_null_free(base_val)) {
        buffer_write_byte(b, 0xBB); // MOV EBX, imm32
        buffer_write_dword(b, base_val);

        // Apply shift if needed
        if (shift_amount > 0) {
            // SHL EBX, shift_amount
            if (shift_amount == 1) {
                buffer_write_byte(b, 0xD1);
                buffer_write_byte(b, 0xE3); // SHL EBX, 1
            } else {
                buffer_write_byte(b, 0xC1);
                buffer_write_byte(b, 0xE3); // SHL EBX
                buffer_write_byte(b, (uint8_t)shift_amount);
            }
        } else if (shift_amount < 0) {
            // SHR EBX, abs(shift_amount)
            int abs_shift = -shift_amount;
            if (abs_shift == 1) {
                buffer_write_byte(b, 0xD1);
                buffer_write_byte(b, 0xEB); // SHR EBX, 1
            } else {
                buffer_write_byte(b, 0xC1);
                buffer_write_byte(b, 0xEB); // SHR EBX
                buffer_write_byte(b, (uint8_t)abs_shift);
            }
        }
    } else {
        // Fallback: use byte-by-byte construction
        // XOR EBX, EBX
        buffer_write_byte(b, 0x31);
        buffer_write_byte(b, 0xDB);

        // Build value byte by byte
        for (int i = 0; i < 4; i++) {
            uint8_t byte = (imm32 >> (i * 8)) & 0xFF;
            if (byte != 0) {
                // SHL EBX, 8 (if not first byte)
                if (i > 0) {
                    buffer_write_byte(b, 0xC1);
                    buffer_write_byte(b, 0xE3);
                    buffer_write_byte(b, 0x08);
                }
                // OR BL, byte
                buffer_write_byte(b, 0x80);
                buffer_write_byte(b, 0xCB); // OR BL
                buffer_write_byte(b, byte);
            }
        }
    }

    // SBB dst_reg, EBX
    buffer_write_byte(b, 0x1B); // SBB r32, r/m32
    uint8_t dst_code = (dst_reg - X86_REG_EAX) & 0x07;
    uint8_t modrm = 0xC0 | (dst_code << 3) | temp_reg; // reg, EBX
    buffer_write_byte(b, modrm);

    // POP EBX
    buffer_write_byte(b, 0x5B);
}

strategy_t sbb_immediate_null_free_strategy = {
    .name = "sbb_immediate_null_free",
    .can_handle = can_handle_sbb_immediate_null,
    .get_size = get_size_sbb_immediate_null,
    .generate = generate_sbb_immediate_null,
    .priority = 69
};

// ============================================================================
// Registration Function
// ============================================================================

void register_sbb_strategies() {
    register_strategy(&sbb_modrm_null_bypass_strategy);
    register_strategy(&sbb_immediate_null_free_strategy);
}
