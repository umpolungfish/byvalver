#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * SETcc (Conditional Set Byte) Null-Byte Elimination Strategies
 *
 * SETcc instructions set a byte to 0 or 1 based on flag conditions.
 * Two-byte opcode: 0x0F 0x9x (where x determines the condition)
 *
 * Conditions supported:
 * - SETE/SETZ (0x94) - Set if Zero (ZF=1)
 * - SETNE/SETNZ (0x95) - Set if Not Zero (ZF=0)
 * - SETB/SETC (0x92) - Set if Below/Carry (CF=1)
 * - SETAE/SETNC (0x93) - Set if Above or Equal/Not Carry (CF=0)
 * - SETL/SETNGE (0x9C) - Set if Less (SF≠OF)
 * - SETG/SETNLE (0x9F) - Set if Greater ((ZF=0) AND (SF=OF))
 * - And many more...
 *
 * Null-byte patterns addressed:
 * 1. ModR/M null byte (e.g., SETE byte ptr [EAX] -> 0x0F 0x94 0x00)
 * 2. Displacement with null bytes
 */

// ============================================================================
// STRATEGY 1: SETcc ModR/M Null Bypass
// ============================================================================
// Handles: SETcc byte ptr [mem] with null ModR/M or displacement
// Transformation: Use register destination then MOV to memory
//
// Example:
//   Original: SETE byte ptr [EAX]  ; [0F 94 00]
//   Transformed:
//     SETE AL                       ; Set AL based on ZF
//     MOV [EAX], AL                ; Store via non-null instruction

static int can_handle_setcc_modrm_null(cs_insn *insn) {
    // Check if it's a SETcc instruction (two-byte opcode 0x0F 0x9x)
    // Capstone represents these with various IDs
    if (insn->id < X86_INS_SETA || insn->id > X86_INS_SETS) {
        // Not a SETcc instruction
        return 0;
    }

    // Must have null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Must have exactly 1 operand (destination)
    if (insn->detail->x86.op_count != 1) {
        return 0;
    }

    cs_x86_op *op0 = &insn->detail->x86.operands[0];

    // Check if destination is memory
    if (op0->type == X86_OP_MEM) {
        // Check if ModR/M would be null
        if (op0->mem.base == X86_REG_EAX &&
            op0->mem.index == X86_REG_INVALID &&
            op0->mem.disp == 0) {
            return 1;
        }
    }

    return 0;
}

static size_t get_size_setcc_modrm_null(cs_insn *insn) {
    // SETE AL (3 bytes: 0x0F 0x94 0xC0) + MOV [mem], AL (variable, ~3-7 bytes)
    // Conservative estimate: 8 bytes
    (void)insn;
    return 8;
}

static void generate_setcc_modrm_null(struct buffer *b, cs_insn *insn) {
    // Get the SETcc condition code from the instruction
    // The second byte of the opcode determines the condition
    uint8_t condition_code = insn->bytes[1]; // 0x9x where x is the condition

    // SETcc AL - Use AL as temporary
    buffer_write_byte(b, 0x0F);
    buffer_write_byte(b, condition_code);
    buffer_write_byte(b, 0xC0); // ModR/M for AL

    // Now MOV the result to the original destination
    cs_x86_op *op0 = &insn->detail->x86.operands[0];

    if (op0->mem.base == X86_REG_EAX) {
        // MOV [EAX], AL - But this also has ModR/M 0x00!
        // Need to use different approach: use displacement
        // MOV [EAX+1], AL then DEC byte ptr [EAX+1] offset
        // Actually, use indirect: MOV [EBX], AL where EBX=EAX

        // PUSH EBX
        buffer_write_byte(b, 0x53);
        // MOV EBX, EAX
        buffer_write_byte(b, 0x89);
        buffer_write_byte(b, 0xC3);
        // MOV [EBX], AL
        buffer_write_byte(b, 0x88);
        buffer_write_byte(b, 0x03); // ModR/M for [EBX], AL
        // POP EBX
        buffer_write_byte(b, 0x5B);
    }
}

strategy_t setcc_modrm_null_bypass_strategy = {
    .name = "setcc_modrm_null_bypass",
    .can_handle = can_handle_setcc_modrm_null,
    .get_size = get_size_setcc_modrm_null,
    .generate = generate_setcc_modrm_null,
    .priority = 75
};

// ============================================================================
// STRATEGY 2: SETcc via Conditional MOV
// ============================================================================
// Handles: SETcc reg with potential encoding issues
// Transformation: Convert to conditional jump sequence
//
// Example:
//   Original: SETE AL              ; [0F 94 C0]
//   Transformed:
//     XOR AL, AL                    ; Clear AL (assume false)
//     JNZ skip                      ; Jump if not zero (ZF=0)
//     INC AL                        ; Set to 1 if ZF=1
//     skip:
//
// This strategy is lower priority and only used if the original encoding
// has null bytes (rare for register destinations)

static int can_handle_setcc_conditional_mov(cs_insn *insn) {
    // Check if it's a SETcc instruction
    if (insn->id < X86_INS_SETA || insn->id > X86_INS_SETS) {
        return 0;
    }

    // Must have null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Must have exactly 1 operand (destination)
    if (insn->detail->x86.op_count != 1) {
        return 0;
    }

    cs_x86_op *op0 = &insn->detail->x86.operands[0];

    // Only handle register destinations (memory handled by other strategy)
    if (op0->type == X86_OP_REG) {
        return 1;
    }

    return 0;
}

static size_t get_size_setcc_conditional_mov(cs_insn *insn) {
    // XOR reg, reg (2) + Jcc skip (2) + INC reg (1) + skip: (0) = 5 bytes
    // But some conditions are inverted, may need different logic
    // Conservative estimate: 7-8 bytes
    (void)insn;
    return 8;
}

static void generate_setcc_conditional_mov(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    x86_reg dst_reg = op0->reg;

    // Get 8-bit register code
    uint8_t reg_code = (dst_reg - X86_REG_AL) & 0x07;

    // Determine the condition
    uint8_t condition_code = insn->bytes[1]; // 0x9x

    // Map SETcc condition to inverse Jcc condition
    // SETE (0x94) -> JNE (0x75)
    // SETNE (0x95) -> JE (0x74)
    // SETB (0x92) -> JAE (0x73)
    // etc.
    uint8_t jcc_opcode;
    switch (condition_code) {
        case 0x94: jcc_opcode = 0x75; break; // SETE -> JNE
        case 0x95: jcc_opcode = 0x74; break; // SETNE -> JE
        case 0x92: jcc_opcode = 0x73; break; // SETB -> JAE
        case 0x93: jcc_opcode = 0x72; break; // SETAE -> JB
        case 0x9C: jcc_opcode = 0x7D; break; // SETL -> JGE
        case 0x9D: jcc_opcode = 0x7C; break; // SETGE -> JL
        case 0x9E: jcc_opcode = 0x7F; break; // SETLE -> JG
        case 0x9F: jcc_opcode = 0x7E; break; // SETG -> JLE
        default: jcc_opcode = 0x75; break; // Default to JNE
    }

    // XOR dst_reg, dst_reg - Clear register
    buffer_write_byte(b, 0x30); // XOR r/m8, r8
    buffer_write_byte(b, 0xC0 | (reg_code << 3) | reg_code);

    // Jcc skip (short jump, 2 bytes forward)
    buffer_write_byte(b, jcc_opcode);
    buffer_write_byte(b, 0x01); // Skip 1 byte (INC instruction)

    // INC dst_reg
    if (reg_code == 0) {
        // INC AL
        buffer_write_byte(b, 0xFE);
        buffer_write_byte(b, 0xC0);
    } else {
        buffer_write_byte(b, 0xFE);
        buffer_write_byte(b, 0xC0 + reg_code);
    }

    // skip: (no bytes, just label)
}

strategy_t setcc_conditional_mov_strategy = {
    .name = "setcc_conditional_mov",
    .can_handle = can_handle_setcc_conditional_mov,
    .get_size = get_size_setcc_conditional_mov,
    .generate = generate_setcc_conditional_mov,
    .priority = 70
};

// ============================================================================
// Registration Function
// ============================================================================

void register_setcc_strategies() {
    register_strategy(&setcc_modrm_null_bypass_strategy);
    register_strategy(&setcc_conditional_mov_strategy);
}
