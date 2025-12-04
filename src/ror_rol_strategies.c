/*
 * ROR/ROL Immediate Rotation Strategy for BYVALVER
 *
 * This strategy handles ROR (Rotate Right) and ROL (Rotate Left) instructions
 * with immediate values that produce null bytes in their encoding.
 *
 * These instructions are critical for Windows shellcode that uses hash-based
 * API resolution. The ROR13 hash algorithm is observed in ~90% of Windows samples:
 *
 * Example from exploit-db shellcode:
 *   xor edi, edi       ; Clear hash accumulator
 * hash_loop:
 *   lodsb              ; Load next character
 *   test al, al        ; Check for null terminator
 *   jz hash_done
 *   ror edi, 0x0d      ; ROR13 hash rotation <-- THIS PATTERN
 *   add edi, eax       ; Add character to hash
 *   jmp hash_loop
 * hash_done:
 *   ; EDI now contains the hash
 *
 * Transformation approach:
 *   Original: ROR reg, imm8 (may contain null bytes)
 *   Transformed: PUSH ECX; MOV CL, imm8; ROR reg, CL; POP ECX
 */

#include "strategy.h"
#include "utils.h"
#include "core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>
#include <inttypes.h>

/*
 * Helper: Check if register is ECX (we use CL for rotation)
 * If the target register is ECX, we need to use a different temp register
 */
static int uses_ecx(cs_insn *insn) {
    if (insn->detail->x86.op_count < 1) return 0;

    x86_reg reg = insn->detail->x86.operands[0].reg;
    return (reg == X86_REG_ECX || reg == X86_REG_CL ||
            reg == X86_REG_CH || reg == X86_REG_CX);
}

/*
 * Helper: Get the rotation opcode extension (for ModR/M byte)
 * ROR = 1, ROL = 0 (in the reg field of ModR/M)
 */
static uint8_t get_rotation_opcode_ext(x86_insn insn_id) {
    switch (insn_id) {
        case X86_INS_ROR: return 1;  // /1 in ModR/M
        case X86_INS_ROL: return 0;  // /0 in ModR/M
        case X86_INS_RCR: return 3;  // /3 in ModR/M
        case X86_INS_RCL: return 2;  // /2 in ModR/M
        default: return 0;
    }
}

/*
 * Detection: Can this strategy handle the instruction?
 */
int ror_rol_immediate_can_handle(cs_insn *insn) {
    // Only handle ROR, ROL, RCR, RCL instructions
    if (insn->id != X86_INS_ROR && insn->id != X86_INS_ROL &&
        insn->id != X86_INS_RCR && insn->id != X86_INS_RCL) {
        return 0;
    }

    // Must contain null bytes in encoding
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Must have exactly 2 operands (register and immediate)
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    // First operand must be a register
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }

    // Second operand must be an immediate
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    return 1;
}

/*
 * Size calculation: How many bytes will the transformed code take?
 */
size_t ror_rol_immediate_get_size(cs_insn *insn) {
    // Check if rotation is by 0 (no-op case)
    if (insn->detail->x86.op_count >= 2 &&
        insn->detail->x86.operands[1].type == X86_OP_IMM) {
        uint8_t imm8 = (uint8_t)insn->detail->x86.operands[1].imm;
        if (imm8 == 0) {
            return 0;  // No-op, emit nothing
        }
    }

    size_t size = 0;

    // PUSH temp_reg: 1 byte
    size += 1;

    // MOV CL, imm8: 2 bytes (B1 imm8)
    size += 2;

    // ROR/ROL reg, CL: 2 bytes (D3 ModR/M)
    size += 2;

    // POP temp_reg: 1 byte
    size += 1;

    return size;  // Total: 6 bytes (or 0 for no-op)
}

/*
 * Code generation: Emit the null-free replacement code
 */
void ror_rol_immediate_generate(struct buffer *b, cs_insn *insn) {
    x86_reg target_reg = insn->detail->x86.operands[0].reg;
    uint8_t target_idx = get_reg_index(target_reg);
    uint8_t imm8 = (uint8_t)insn->detail->x86.operands[1].imm;
    uint8_t rotation_opcode = get_rotation_opcode_ext(insn->id);

    // Special case: rotation by 0 is a no-op
    // Just skip it entirely instead of generating null bytes
    if (imm8 == 0) {
        return;  // Don't emit anything - rotation by 0 has no effect
    }

    // Determine which register to use as temporary
    // Default to ECX (for CL), but use EDX if target is ECX
    x86_reg temp_reg = X86_REG_ECX;
    uint8_t temp_idx = 1;  // ECX index

    if (uses_ecx(insn)) {
        temp_reg = X86_REG_EDX;
        temp_idx = 2;  // EDX index
    }

    // 1. PUSH temp_reg to preserve its value
    uint8_t push_code = 0x50 + temp_idx;
    buffer_append(b, &push_code, 1);

    // 2. MOV CL/DL, imm8
    // Encoding: B0+reg imm8 (for 8-bit registers)
    // CL = B1, DL = B2
    uint8_t mov_cl_imm[2];
    if (temp_reg == X86_REG_ECX) {
        mov_cl_imm[0] = 0xB1;  // MOV CL, imm8
    } else {
        mov_cl_imm[0] = 0xB2;  // MOV DL, imm8
    }
    mov_cl_imm[1] = imm8;
    buffer_append(b, mov_cl_imm, 2);

    // 3. ROR/ROL target_reg, CL/DL
    // Encoding: D3 /digit where digit is rotation opcode extension
    // ModR/M byte: 11 digit target_reg
    uint8_t ror_cl[2];
    ror_cl[0] = 0xD3;  // Rotation with CL/DL opcode
    ror_cl[1] = 0xC0 | (rotation_opcode << 3) | target_idx;
    buffer_append(b, ror_cl, 2);

    // 4. POP temp_reg to restore its value
    uint8_t pop_code = 0x58 + temp_idx;
    buffer_append(b, &pop_code, 1);
}

/*
 * Strategy definition
 */
strategy_t ror_rol_immediate_strategy = {
    .name = "ROR/ROL Immediate Rotation Strategy",
    .can_handle = ror_rol_immediate_can_handle,
    .get_size = ror_rol_immediate_get_size,
    .generate = ror_rol_immediate_generate,
    .priority = 70  // High priority - critical for hash-based API resolution
};

/*
 * Registration function
 */
void register_ror_rol_strategies() {
    register_strategy(&ror_rol_immediate_strategy);
}
