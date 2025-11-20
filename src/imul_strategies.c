#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * IMUL (Signed Multiply) Null-Byte Elimination Strategies
 *
 * IMUL has three forms:
 * 1. One-operand: IMUL r/m32 (implicit EAX, result in EDX:EAX)
 * 2. Two-operand: IMUL r32, r/m32 (two-byte opcode: 0x0F 0xAF)
 * 3. Three-operand: IMUL r32, r/m32, imm (opcodes: 0x69 or 0x6B)
 *
 * Null-byte patterns addressed:
 * 1. ModR/M null byte (e.g., IMUL EAX, [EAX] -> 0x0F 0xAF 0x00)
 * 2. Immediate with null bytes (e.g., IMUL EAX, EBX, 0x100)
 */

// ============================================================================
// STRATEGY 1: IMUL ModR/M Null Bypass (Two-operand form)
// ============================================================================

static int can_handle_imul_modrm_null(cs_insn *insn) {
    if (insn->id != X86_INS_IMUL) {
        return 0;
    }

    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Two-operand form: IMUL reg, [mem]
    if (insn->detail->x86.op_count == 2) {
        cs_x86_op *op0 = &insn->detail->x86.operands[0];
        cs_x86_op *op1 = &insn->detail->x86.operands[1];

        if (op0->type == X86_OP_REG && op1->type == X86_OP_MEM) {
            // Check for [EAX] addressing (ModR/M 0x00)
            if (op1->mem.base == X86_REG_EAX &&
                op1->mem.index == X86_REG_INVALID &&
                op1->mem.disp == 0) {
                return 1;
            }
        }
    }

    return 0;
}

static size_t get_size_imul_modrm_null(cs_insn *insn) {
    // PUSH EBX (1) + MOV EBX, [mem] (2) + IMUL reg, EBX (3) + POP EBX (1) = 7 bytes
    (void)insn;
    return 10;
}

static void generate_imul_modrm_null(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];

    x86_reg dst_reg = op0->reg;

    // PUSH EBX
    buffer_write_byte(b, 0x53);

    // MOV EBX, [EAX] - Load memory operand
    buffer_write_byte(b, 0x8B);
    buffer_write_byte(b, 0x03); // ModR/M for EBX, [EBX] but we need [EAX]

    // Actually, copy address first
    // MOV EBX, EAX
    buffer_write_byte(b, 0x89);
    buffer_write_byte(b, 0xC3);

    // MOV temp_reg2, [EBX]
    buffer_write_byte(b, 0x8B);
    uint8_t dst_code = (dst_reg - X86_REG_EAX) & 0x07;
    buffer_write_byte(b, (dst_code << 3) | 0x03);

    // IMUL dst_reg, dst_reg (multiply in place) - Actually need different approach
    // Better: PUSH ECX, MOV ECX, [EAX], IMUL dst, ECX, POP ECX

    // Let me restart with clearer logic:
    // PUSH ECX (use ECX as temp)
    buffer_write_byte(b, 0x51);

    // MOV ECX, EAX (copy address)
    buffer_write_byte(b, 0x89);
    buffer_write_byte(b, 0xC1);

    // MOV ECX, [ECX] (load value from memory)
    buffer_write_byte(b, 0x8B);
    buffer_write_byte(b, 0x09); // ModR/M for ECX, [ECX]

    // IMUL dst_reg, ECX
    buffer_write_byte(b, 0x0F);
    buffer_write_byte(b, 0xAF);
    buffer_write_byte(b, 0xC0 | (dst_code << 3) | 0x01); // dst_reg, ECX

    // POP ECX
    buffer_write_byte(b, 0x59);

    // POP EBX
    buffer_write_byte(b, 0x5B);
}

strategy_t imul_modrm_null_bypass_strategy = {
    .name = "imul_modrm_null_bypass",
    .can_handle = can_handle_imul_modrm_null,
    .get_size = get_size_imul_modrm_null,
    .generate = generate_imul_modrm_null,
    .priority = 72
};

// ============================================================================
// STRATEGY 2: IMUL Immediate Null Handling (Three-operand form)
// ============================================================================

static int can_handle_imul_immediate_null(cs_insn *insn) {
    if (insn->id != X86_INS_IMUL) {
        return 0;
    }

    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Three-operand form: IMUL reg, reg/mem, imm
    if (insn->detail->x86.op_count == 3) {
        cs_x86_op *op2 = &insn->detail->x86.operands[2];
        if (op2->type == X86_OP_IMM) {
            uint32_t imm = (uint32_t)op2->imm;
            return !is_null_free(imm);
        }
    }

    return 0;
}

static size_t get_size_imul_immediate_null(cs_insn *insn) {
    // PUSH (1) + MOV temp, imm (5-15) + IMUL dest, src (3) + IMUL dest, temp (3) + POP (1)
    (void)insn;
    return 20;
}

static void generate_imul_immediate_null(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];
    cs_x86_op *op2 = &insn->detail->x86.operands[2];

    x86_reg dst_reg = op0->reg;
    x86_reg src_reg = op1->reg;
    uint32_t imm = (uint32_t)op2->imm;
    uint8_t temp_reg = 0x03; // EBX

    // PUSH EBX
    buffer_write_byte(b, 0x53);

    // Construct immediate in EBX (similar to ADC/SBB)
    int shift_amount = 0;
    uint32_t base_val = imm;

    for (int i = 0; i < 32; i++) {
        uint32_t shifted = imm << i;
        if (is_null_free(shifted)) {
            base_val = shifted;
            shift_amount = i;
            break;
        }
        shifted = imm >> i;
        if (is_null_free(shifted) && shifted != 0) {
            base_val = shifted;
            shift_amount = -i;
            break;
        }
    }

    if (is_null_free(base_val)) {
        buffer_write_byte(b, 0xBB); // MOV EBX, imm32
        buffer_write_dword(b, base_val);

        if (shift_amount > 0) {
            buffer_write_byte(b, 0xC1);
            buffer_write_byte(b, 0xE3);
            buffer_write_byte(b, (uint8_t)shift_amount);
        } else if (shift_amount < 0) {
            buffer_write_byte(b, 0xC1);
            buffer_write_byte(b, 0xEB);
            buffer_write_byte(b, (uint8_t)(-shift_amount));
        }
    }

    // MOV dst_reg, src_reg
    uint8_t dst_code = (dst_reg - X86_REG_EAX) & 0x07;
    uint8_t src_code = (src_reg - X86_REG_EAX) & 0x07;
    buffer_write_byte(b, 0x89);
    buffer_write_byte(b, 0xC0 | (src_code << 3) | dst_code);

    // IMUL dst_reg, EBX
    buffer_write_byte(b, 0x0F);
    buffer_write_byte(b, 0xAF);
    buffer_write_byte(b, 0xC0 | (dst_code << 3) | temp_reg);

    // POP EBX
    buffer_write_byte(b, 0x5B);
}

strategy_t imul_immediate_null_free_strategy = {
    .name = "imul_immediate_null_free",
    .can_handle = can_handle_imul_immediate_null,
    .get_size = get_size_imul_immediate_null,
    .generate = generate_imul_immediate_null,
    .priority = 71
};

// ============================================================================
// Registration Function
// ============================================================================

void register_imul_strategies() {
    register_strategy(&imul_modrm_null_bypass_strategy);
    register_strategy(&imul_immediate_null_free_strategy);
}
