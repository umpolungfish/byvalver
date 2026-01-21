/**
 * MOVABS x64 Null-Byte Elimination Strategies
 *
 * Handles: movabs rax/reg, imm64 instructions where the 64-bit immediate
 * contains null bytes.
 *
 * x64-specific strategy file (v4.2)
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// ============================================================================
// STRATEGY 1: MOVABS 64-bit Immediate Null-Byte Elimination
// ============================================================================
// Handles: movabs rax, imm64 where immediate contains null bytes
// Uses various techniques to construct the value without nulls:
// 1. Direct encoding if already null-free
// 2. XOR encoding with a null-free key
// 3. Arithmetic construction via shifts/adds
// 4. Byte-by-byte construction

static int can_handle_movabs_imm64_null(cs_insn *insn) {
    // Only handle MOV instructions
    if (insn->id != X86_INS_MOV && insn->id != X86_INS_MOVABS) {
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

    // First operand must be a 64-bit register
    if (op0->type != X86_OP_REG) {
        return 0;
    }

    // Check if it's a 64-bit register
    if (!is_64bit_register(op0->reg)) {
        return 0;
    }

    // Second operand must be an immediate
    if (op1->type != X86_OP_IMM) {
        return 0;
    }

    // Check if this is a 64-bit immediate (larger than 32-bit signed range)
    int64_t imm = (int64_t)op1->imm;

    // If it fits in 32-bit signed range, might be handled by other strategies
    // But we can still handle it for consistency
    // Check if the immediate has null bytes
    return !is_bad_byte_free_qword((uint64_t)imm);
}

static size_t get_size_movabs_imm64_null(cs_insn *insn) {
    uint64_t imm = (uint64_t)insn->detail->x86.operands[1].imm;
    return get_mov_rax_imm64_size(imm);
}

static void generate_movabs_imm64_null(struct buffer *b, cs_insn *insn) {
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    uint64_t imm = (uint64_t)insn->detail->x86.operands[1].imm;

    // Use the comprehensive 64-bit immediate generator
    generate_mov_reg_imm64(b, dst_reg, imm);
}

strategy_t movabs_imm64_null_free_strategy = {
    .name = "movabs_imm64_null_free",
    .can_handle = can_handle_movabs_imm64_null,
    .get_size = get_size_movabs_imm64_null,
    .generate = generate_movabs_imm64_null,
    .priority = 90,
    .target_arch = BYVAL_ARCH_X64
};

// ============================================================================
// STRATEGY 2: MOV r64, imm32 (sign-extended) Null-Byte Elimination
// ============================================================================
// Handles: mov rax, imm32 where the sign-extended 32-bit value fits
// but the immediate encoding contains null bytes

static int can_handle_mov_r64_imm32_null(cs_insn *insn) {
    // Only handle MOV instructions
    if (insn->id != X86_INS_MOV) {
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

    // First operand must be a 64-bit register
    if (op0->type != X86_OP_REG || !is_64bit_register(op0->reg)) {
        return 0;
    }

    // Second operand must be an immediate
    if (op1->type != X86_OP_IMM) {
        return 0;
    }

    // Check if this is a 32-bit immediate (fits in signed 32-bit range)
    int64_t imm = (int64_t)op1->imm;
    if (imm < INT32_MIN || imm > INT32_MAX) {
        return 0;  // Let the 64-bit strategy handle this
    }

    // Check if the 32-bit form has null bytes
    uint32_t imm32 = (uint32_t)(imm & 0xFFFFFFFF);
    return !is_bad_byte_free(imm32);
}

static size_t get_size_mov_r64_imm32_null(cs_insn *insn) {
    // We'll construct via RAX approach if needed
    // Conservative: XOR RAX, RAX (3) + construction (up to 16) = 20 bytes
    (void)insn;
    return 20;
}

static void generate_mov_r64_imm32_null(struct buffer *b, cs_insn *insn) {
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    uint32_t imm32 = (uint32_t)insn->detail->x86.operands[1].imm;

    // For 32-bit immediates that need to be sign-extended to 64-bit,
    // use 32-bit construction techniques but with REX.W prefix

    int is_ext = is_extended_register(dst_reg);
    uint8_t reg_idx = get_reg_index(dst_reg);

    // Try to find a null-free encoding
    if (is_bad_byte_free(imm32)) {
        // Direct encoding: REX.W + C7 /0 + imm32
        uint8_t code[7];
        code[0] = is_ext ? 0x49 : 0x48;  // REX.W or REX.WB
        code[1] = 0xC7;  // MOV r/m64, imm32
        code[2] = 0xC0 + (reg_idx & 0x07);  // ModR/M
        memcpy(&code[3], &imm32, 4);
        buffer_append(b, code, 7);
        return;
    }

    // Try XOR encoding
    uint32_t xor_keys[] = {
        0x01010101, 0x11111111, 0x22222222, 0x33333333,
        0x41414141, 0x55555555, 0xAAAAAAAA, 0xFFFFFFFF,
    };

    for (size_t i = 0; i < sizeof(xor_keys) / sizeof(xor_keys[0]); i++) {
        uint32_t encoded = imm32 ^ xor_keys[i];
        if (is_bad_byte_free(encoded) && is_bad_byte_free(xor_keys[i])) {
            // MOV reg, encoded_value
            uint8_t mov_code[7];
            mov_code[0] = is_ext ? 0x49 : 0x48;
            mov_code[1] = 0xC7;
            mov_code[2] = 0xC0 + (reg_idx & 0x07);
            memcpy(&mov_code[3], &encoded, 4);
            buffer_append(b, mov_code, 7);

            // XOR reg, key
            uint8_t xor_code[7];
            xor_code[0] = is_ext ? 0x49 : 0x48;
            xor_code[1] = 0x81;  // XOR r/m64, imm32
            xor_code[2] = 0xF0 + (reg_idx & 0x07);  // /6 for XOR
            memcpy(&xor_code[3], &xor_keys[i], 4);
            buffer_append(b, xor_code, 7);
            return;
        }
    }

    // Fallback: use the 64-bit construction
    generate_mov_reg_imm64(b, dst_reg, (uint64_t)(int64_t)(int32_t)imm32);
}

strategy_t mov_r64_imm32_null_free_strategy = {
    .name = "mov_r64_imm32_null_free",
    .can_handle = can_handle_mov_r64_imm32_null,
    .get_size = get_size_mov_r64_imm32_null,
    .generate = generate_mov_r64_imm32_null,
    .priority = 89,
    .target_arch = BYVAL_ARCH_X64
};

// ============================================================================
// Registration Function
// ============================================================================

void register_movabs_strategies() {
    register_strategy(&movabs_imm64_null_free_strategy);
    register_strategy(&mov_r64_imm32_null_free_strategy);
}
