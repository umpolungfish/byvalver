#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * SLDT (Store Local Descriptor Table) Null-Byte Elimination Strategy
 *
 * SLDT is a system instruction (privileged on modern CPUs) that stores
 * the Local Descriptor Table Register to memory or register.
 *
 * Two-byte opcode: 0x0F 0x00
 * ModR/M byte determines destination
 *
 * Null-byte pattern: SLDT word ptr [EAX] -> 0x0F 0x00 0x00
 */

// ============================================================================
// STRATEGY: SLDT ModR/M Null Bypass
// ============================================================================

static int can_handle_sldt_modrm_null(cs_insn *insn) {
    // Check for SLDT instruction
    if (insn->id != X86_INS_SLDT) {
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

static size_t get_size_sldt_modrm_null(cs_insn *insn) {
    // SLDT AX (3) + MOV [mem], AX (3-7) = ~6 bytes
    (void)insn;
    return 8;
}

static void generate_sldt_modrm_null(struct buffer *b, cs_insn *insn) {
    (void)insn;

    // SLDT AX - Store to register instead of memory
    buffer_write_byte(b, 0x0F);
    buffer_write_byte(b, 0x00);
    buffer_write_byte(b, 0xC0); // ModR/M for AX

    // Now MOV the result to memory
    // But MOV [EAX], AX also has ModR/M 0x00!
    // Use indirect approach via temp register

    // PUSH EBX
    buffer_write_byte(b, 0x53);

    // MOV EBX, EAX (copy address)
    buffer_write_byte(b, 0x89);
    buffer_write_byte(b, 0xC3);

    // MOV [EBX], AX
    buffer_write_byte(b, 0x66); // 16-bit operand prefix
    buffer_write_byte(b, 0x89);
    buffer_write_byte(b, 0x03); // ModR/M for [EBX], AX

    // POP EBX
    buffer_write_byte(b, 0x5B);
}

strategy_t sldt_modrm_null_bypass_strategy = {
    .name = "sldt_modrm_null_bypass",
    .can_handle = can_handle_sldt_modrm_null,
    .get_size = get_size_sldt_modrm_null,
    .generate = generate_sldt_modrm_null,
    .priority = 60
};

// ============================================================================
// Registration Function
// ============================================================================

void register_sldt_strategies() {
    register_strategy(&sldt_modrm_null_bypass_strategy);
}
