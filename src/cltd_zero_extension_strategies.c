#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// ============================================================================
// CLTD Zero Extension Optimization Strategy
// ============================================================================
// Priority: 82 (High)
// Target Instructions: XOR EDX, EDX or MOV EDX, 0
// Null-Byte Pattern: XOR encoding or MOV immediate with nulls
// Transformation: XOR EDX, EDX → CLTD (when EAX is positive)
// Preserves Flags: Yes
// Register Requirements: EAX must be non-negative (< 0x80000000)
// Example:
//   Before: 31 D2          (XOR EDX, EDX - 2 bytes)
//   After:  99             (CLTD - 1 byte, EDX=0 if EAX>=0)
// ============================================================================

int can_handle_cltd_xor_edx(cs_insn *insn) {
    // Check for XOR EDX, EDX
    if (insn->id == X86_INS_XOR && insn->detail->x86.op_count == 2) {
        const cs_x86_op *op1 = &insn->detail->x86.operands[0];
        const cs_x86_op *op2 = &insn->detail->x86.operands[1];

        if (op1->type == X86_OP_REG && op2->type == X86_OP_REG) {
            if (op1->reg == X86_REG_EDX && op2->reg == X86_REG_EDX) {
                return 1;
            }
        }
    }

    return 0;
}

size_t get_size_cltd_xor_edx(__attribute__((unused)) cs_insn *insn) {
    // CLTD is 1 byte: 0x99
    return 1;
}

void generate_cltd_xor_edx(struct buffer *b, __attribute__((unused)) cs_insn *insn) {
    // Generate CLTD instruction
    // CLTD (Convert Long to Double) - opcode: 0x99
    // Sign-extends EAX into EDX:EAX
    // If EAX >= 0, EDX becomes 0
    // If EAX < 0 (sign bit set), EDX becomes 0xFFFFFFFF
    buffer_write_byte(b, 0x99);
}

strategy_t cltd_xor_edx_strategy = {
    .name = "CLTD Zero Extension (XOR EDX)",
    .can_handle = can_handle_cltd_xor_edx,
    .get_size = get_size_cltd_xor_edx,
    .generate = generate_cltd_xor_edx,
    .priority = 82  // High priority - very common pattern
};

// Strategy for MOV EDX, 0
int can_handle_cltd_mov_edx_zero(cs_insn *insn) {
    // Check for MOV EDX, 0
    if (insn->id == X86_INS_MOV && insn->detail->x86.op_count == 2) {
        const cs_x86_op *op1 = &insn->detail->x86.operands[0];
        const cs_x86_op *op2 = &insn->detail->x86.operands[1];

        if (op1->type == X86_OP_REG && op2->type == X86_OP_IMM) {
            if (op1->reg == X86_REG_EDX && op2->imm == 0) {
                return 1;
            }
        }
    }

    return 0;
}

size_t get_size_cltd_mov_edx_zero(__attribute__((unused)) cs_insn *insn) {
    // CLTD is 1 byte: 0x99
    return 1;
}

void generate_cltd_mov_edx_zero(struct buffer *b, __attribute__((unused)) cs_insn *insn) {
    // Generate CLTD instruction
    buffer_write_byte(b, 0x99);
}

strategy_t cltd_mov_edx_zero_strategy = {
    .name = "CLTD Zero Extension (MOV EDX, 0)",
    .can_handle = can_handle_cltd_mov_edx_zero,
    .get_size = get_size_cltd_mov_edx_zero,
    .generate = generate_cltd_mov_edx_zero,
    .priority = 81  // High priority, slightly lower than XOR variant
};

// Register the CLTD strategies
void register_cltd_zero_extension_strategies() {
    register_strategy(&cltd_xor_edx_strategy);
    register_strategy(&cltd_mov_edx_zero_strategy);
}
