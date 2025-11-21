#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * x87 FPU Null-Byte Elimination Strategies
 *
 * Handles floating-point operations that may have null ModR/M bytes:
 * - FLD (Load Float) - opcode 0xD9 or 0xDD
 * - FSTP (Store Float and Pop) - opcode 0xD9 or 0xDD
 * - FST (Store Float) - opcode 0xD9 or 0xDD
 *
 * Null-byte pattern: FLD/FSTP qword ptr [EAX] -> 0xDD 0x00
 */

// ============================================================================
// STRATEGY: FPU ModR/M Null Bypass
// ============================================================================

static int can_handle_fpu_modrm_null(cs_insn *insn) {
    // Check for FLD, FSTP, FST instructions
    if (insn->id != X86_INS_FLD && insn->id != X86_INS_FSTP && insn->id != X86_INS_FST) {
        return 0;
    }

    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Must have memory operand
    if (insn->detail->x86.op_count != 1) {
        return 0;
    }

    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    if (op0->type == X86_OP_MEM) {
        // Check for [EAX] addressing (ModR/M 0x00)
        if (op0->mem.base == X86_REG_EAX &&
            op0->mem.index == X86_REG_INVALID &&
            op0->mem.disp == 0) {
            return 1;
        }
    }

    return 0;
}

static size_t get_size_fpu_modrm_null(cs_insn *insn) {
    // PUSH EBX (1) + MOV EBX, EAX (2) + FLD/FSTP [EBX] (2) + POP EBX (1) = 6 bytes
    (void)insn;
    return 8;
}

static void generate_fpu_modrm_null(struct buffer *b, cs_insn *insn) {
    // Save EBX
    buffer_write_byte(b, 0x53); // PUSH EBX

    // MOV EBX, EAX
    buffer_write_byte(b, 0x89);
    buffer_write_byte(b, 0xC3);

    // Generate FPU instruction with [EBX] instead of [EAX]
    uint8_t opcode = insn->bytes[0]; // 0xD9 or 0xDD

    if (insn->id == X86_INS_FLD) {
        // FLD qword ptr [EBX] - 0xDD 0x03
        if (opcode == 0xDD) {
            buffer_write_byte(b, 0xDD);
            buffer_write_byte(b, 0x03); // ModR/M for [EBX]
        } else {
            // FLD dword ptr [EBX] - 0xD9 0x03
            buffer_write_byte(b, 0xD9);
            buffer_write_byte(b, 0x03);
        }
    } else if (insn->id == X86_INS_FSTP) {
        // FSTP qword ptr [EBX] - 0xDD 0x1B
        if (opcode == 0xDD) {
            buffer_write_byte(b, 0xDD);
            buffer_write_byte(b, 0x1B); // ModR/M for FSTP [EBX]
        } else {
            // FSTP dword ptr [EBX] - 0xD9 0x1B
            buffer_write_byte(b, 0xD9);
            buffer_write_byte(b, 0x1B);
        }
    } else if (insn->id == X86_INS_FST) {
        // FST qword ptr [EBX] - 0xDD 0x13
        if (opcode == 0xDD) {
            buffer_write_byte(b, 0xDD);
            buffer_write_byte(b, 0x13);
        } else {
            buffer_write_byte(b, 0xD9);
            buffer_write_byte(b, 0x13);
        }
    }

    // Restore EBX
    buffer_write_byte(b, 0x5B); // POP EBX
}

strategy_t fpu_modrm_null_bypass_strategy = {
    .name = "fpu_modrm_null_bypass",
    .can_handle = can_handle_fpu_modrm_null,
    .get_size = get_size_fpu_modrm_null,
    .generate = generate_fpu_modrm_null,
    .priority = 60
};

// ============================================================================
// STRATEGY: FPU SIB Addressing Null Bypass
// ============================================================================
// Handles: FSTP [EAX+EAX], FLD [reg+reg], etc. where SIB byte is 0x00
//
// Example:
//   Original: FSTP qword ptr [EAX+EAX]  ; [DD 1C 00] - SIB byte is null
//   Transformed:
//     PUSH EBX                           ; Save temp
//     MOV EBX, EAX                      ; Copy base
//     ADD EBX, EAX                      ; EBX = EAX + EAX
//     FSTP qword ptr [EBX]              ; Use simple addressing
//     POP EBX                           ; Restore

static int can_handle_fpu_sib_null(cs_insn *insn) {
    // Check for FLD, FSTP, FST instructions
    if (insn->id != X86_INS_FLD && insn->id != X86_INS_FSTP && insn->id != X86_INS_FST) {
        return 0;
    }

    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Must have memory operand
    if (insn->detail->x86.op_count != 1) {
        return 0;
    }

    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    if (op0->type != X86_OP_MEM) {
        return 0;
    }

    // Check for [reg+reg] addressing with null SIB byte
    // SIB = (scale << 6) | (index << 3) | base
    // For [EAX+EAX]: scale=0, index=0 (EAX), base=0 (EAX) → SIB=0x00
    if (op0->mem.index != X86_REG_INVALID) {
        // Has SIB - check if it produces null byte
        int base = op0->mem.base - X86_REG_EAX;
        int index = op0->mem.index - X86_REG_EAX;

        // Simple [reg+reg] with scale=1
        if (op0->mem.scale == 1 && op0->mem.disp == 0) {
            uint8_t sib = (0 << 6) | ((index & 7) << 3) | (base & 7);
            if (sib == 0x00) {
                return 1;  // [EAX+EAX] produces null SIB
            }
        }
    }

    return 0;
}

static size_t get_size_fpu_sib_null(cs_insn *insn) {
    // PUSH EBX (1) + MOV EBX, base (2) + ADD EBX, index (2) + FPU insn (2) + POP EBX (1) = 8 bytes
    (void)insn;
    return 8;
}

static void generate_fpu_sib_null(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    x86_reg base = op0->mem.base;
    x86_reg index = op0->mem.index;

    // PUSH EBX
    buffer_write_byte(b, 0x53);

    // MOV EBX, base
    buffer_write_byte(b, 0x89);
    uint8_t base_code = (base - X86_REG_EAX) & 0x07;
    uint8_t modrm = 0xC3 | (base_code << 3);  // mod=11, reg=base, r/m=EBX
    buffer_write_byte(b, modrm);

    // ADD EBX, index
    buffer_write_byte(b, 0x01);
    uint8_t index_code = (index - X86_REG_EAX) & 0x07;
    modrm = 0xC3 | (index_code << 3);  // mod=11, reg=index, r/m=EBX
    buffer_write_byte(b, modrm);

    // Generate FPU instruction with [EBX]
    uint8_t opcode = insn->bytes[0]; // 0xD9 or 0xDD

    if (insn->id == X86_INS_FLD) {
        // FLD [EBX]
        if (opcode == 0xDD) {
            buffer_write_byte(b, 0xDD);
            buffer_write_byte(b, 0x03); // ModR/M for [EBX]
        } else {
            buffer_write_byte(b, 0xD9);
            buffer_write_byte(b, 0x03);
        }
    } else if (insn->id == X86_INS_FSTP) {
        // FSTP [EBX]
        if (opcode == 0xDD) {
            buffer_write_byte(b, 0xDD);
            buffer_write_byte(b, 0x1B); // ModR/M for FSTP [EBX]
        } else {
            buffer_write_byte(b, 0xD9);
            buffer_write_byte(b, 0x1B);
        }
    } else if (insn->id == X86_INS_FST) {
        // FST [EBX]
        if (opcode == 0xDD) {
            buffer_write_byte(b, 0xDD);
            buffer_write_byte(b, 0x13);
        } else {
            buffer_write_byte(b, 0xD9);
            buffer_write_byte(b, 0x13);
        }
    }

    // POP EBX
    buffer_write_byte(b, 0x5B);
}

strategy_t fpu_sib_null_strategy = {
    .name = "fpu_sib_null",
    .can_handle = can_handle_fpu_sib_null,
    .get_size = get_size_fpu_sib_null,
    .generate = generate_fpu_sib_null,
    .priority = 65  // Higher than general FPU strategy
};

// ============================================================================
// Registration Function
// ============================================================================

void register_fpu_strategies() {
    // Register SIB strategy first (higher priority)
    register_strategy(&fpu_sib_null_strategy);
    // Then general ModR/M strategy
    register_strategy(&fpu_modrm_null_bypass_strategy);
}
