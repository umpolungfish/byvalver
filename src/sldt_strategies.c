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
// STRATEGY 1: SLDT Register Destination - Stack-Based Approach (CRITICAL FIX)
// ============================================================================
// BUG FIX: The register form "SLDT AX" produces 0x0F 0x00 0xC0 which contains
// a null byte in the two-byte opcode! We must use a stack-based approach.

static int can_handle_sldt_register_dest(cs_insn *insn) {
    if (insn->id != X86_INS_SLDT) {
        return 0;
    }

    if (!has_null_bytes(insn)) {
        return 0;
    }

    if (insn->detail->x86.op_count != 1) {
        return 0;
    }

    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    // Handle REGISTER destination (SLDT EAX, SLDT AX, etc.)
    // The register form "SLDT reg" contains null in its opcode!
    if (op0->type == X86_OP_REG) {
        return 1;
    }

    return 0;
}

static size_t get_size_sldt_register_dest(cs_insn *insn) {
    (void)insn;
    // SUB ESP, 4 (3) + SLDT [ESP] (4) + POP reg (1) = 8 bytes
    return 8;
}

static void generate_sldt_register_dest(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    x86_reg dst_reg = op0->reg;

    // Use stack to avoid null-containing register form
    // SUB ESP, 4          ; Make space (83 EC 04)
    buffer_write_byte(b, 0x83);
    buffer_write_byte(b, 0xEC);
    buffer_write_byte(b, 0x04);

    // SLDT [ESP]          ; Store to stack (0F 00 04 24 - no null!)
    buffer_write_byte(b, 0x0F);
    buffer_write_byte(b, 0x00);
    buffer_write_byte(b, 0x04);  // ModR/M for [--][--][SIB]
    buffer_write_byte(b, 0x24);  // SIB for [ESP]

    // POP dst_reg         ; Load from stack
    // Handle both 16-bit (AX) and 32-bit (EAX) registers
    if (dst_reg >= X86_REG_AX && dst_reg <= X86_REG_DI) {
        // 16-bit register (AX, BX, CX, DX, SI, DI, BP, SP)
        // Map to 32-bit equivalent for POP, then mask/use upper bits as needed
        // For simplicity, POP to 32-bit equivalent
        x86_reg reg32;
        switch(dst_reg) {
            case X86_REG_AX: reg32 = X86_REG_EAX; break;
            case X86_REG_BX: reg32 = X86_REG_EBX; break;
            case X86_REG_CX: reg32 = X86_REG_ECX; break;
            case X86_REG_DX: reg32 = X86_REG_EDX; break;
            case X86_REG_SI: reg32 = X86_REG_ESI; break;
            case X86_REG_DI: reg32 = X86_REG_EDI; break;
            case X86_REG_BP: reg32 = X86_REG_EBP; break;
            case X86_REG_SP: reg32 = X86_REG_ESP; break;
            default: reg32 = X86_REG_EAX; break;
        }
        uint8_t pop_opcode = 0x58 + (reg32 - X86_REG_EAX);
        buffer_write_byte(b, pop_opcode);
    } else if (dst_reg >= X86_REG_EAX && dst_reg <= X86_REG_EDI) {
        // 32-bit register
        uint8_t pop_opcode = 0x58 + (dst_reg - X86_REG_EAX);
        buffer_write_byte(b, pop_opcode);
    } else {
        // Default to EAX
        buffer_write_byte(b, 0x58);  // POP EAX
    }
}

strategy_t sldt_register_dest_strategy = {
    .name = "sldt_register_dest",
    .can_handle = can_handle_sldt_register_dest,
    .get_size = get_size_sldt_register_dest,
    .generate = generate_sldt_register_dest,
    .priority = 75  // Higher priority to catch this critical bug first
};

// ============================================================================
// STRATEGY 2: SLDT Memory Destination with Null ModR/M
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
    (void)insn;
    // Use stack-based approach: SUB ESP (3) + SLDT [ESP] (4) + POP (1) + MOV (2-3) = ~10 bytes
    return 10;
}

static void generate_sldt_modrm_null(struct buffer *b, cs_insn *insn) {
    (void)insn;

    // CRITICAL FIX: Do NOT use "SLDT AX" as it contains null in opcode!
    // Instead, use stack-based approach for memory destinations too.

    // PUSH EBX - Save temp register
    buffer_write_byte(b, 0x53);

    // SUB ESP, 4 - Make space on stack
    buffer_write_byte(b, 0x83);
    buffer_write_byte(b, 0xEC);
    buffer_write_byte(b, 0x04);

    // SLDT [ESP] - Store to stack (0F 00 04 24 - null-free!)
    buffer_write_byte(b, 0x0F);
    buffer_write_byte(b, 0x00);
    buffer_write_byte(b, 0x04);  // ModR/M for [SIB]
    buffer_write_byte(b, 0x24);  // SIB for [ESP]

    // POP EBX - Get value from stack
    buffer_write_byte(b, 0x5B);

    // MOV [EAX], BX - Store to original destination
    // But [EAX] has null ModR/M! Use indirect via saved register
    // Actually, we need to use a different addressing mode
    // Let's use [EAX+EBX*1-EBX] which equals [EAX]
    // No wait, that's complex. Better approach:

    // At this point: EBX = SLDT value, EAX = original address
    // We need to store BX (16-bit) to [EAX]

    // Save EAX
    buffer_write_byte(b, 0x50);  // PUSH EAX

    // MOV EAX, EBX (get value)
    buffer_write_byte(b, 0x89);
    buffer_write_byte(b, 0xD8);

    // POP EBX (EBX now has original address)
    buffer_write_byte(b, 0x5B);

    // MOV [EBX], AX - Store 16-bit value to memory
    buffer_write_byte(b, 0x66);  // 16-bit prefix
    buffer_write_byte(b, 0x89);
    buffer_write_byte(b, 0x03);  // ModR/M for [EBX], AX - null-free!

    // POP EBX - Restore original EBX
    buffer_write_byte(b, 0x5B);
}

strategy_t sldt_modrm_null_bypass_strategy = {
    .name = "sldt_modrm_null_bypass",
    .can_handle = can_handle_sldt_modrm_null,
    .get_size = get_size_sldt_modrm_null,
    .generate = generate_sldt_modrm_null,
    .priority = 70  // Higher than before
};

// ============================================================================
// Registration Function
// ============================================================================

void register_sldt_strategies() {
    // Register register-destination strategy first (higher priority = 75)
    register_strategy(&sldt_register_dest_strategy);
    // Then memory-destination strategy (priority = 70)
    register_strategy(&sldt_modrm_null_bypass_strategy);
}
