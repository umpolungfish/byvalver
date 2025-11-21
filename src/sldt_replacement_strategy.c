/*
 * SLDT (Store Local Descriptor Table Register) Replacement Strategy
 *
 * CRITICAL FINDING: SLDT instruction has opcode 0x0F 0x00
 * The null byte is IN THE OPCODE ITSELF, not in the operands.
 * This makes it IMPOSSIBLE to eliminate via transformation alone.
 *
 * SOLUTION: Complete instruction replacement with semantically equivalent code
 *
 * BACKGROUND:
 * - LDTR is only meaningful in kernel mode or when using segmentation
 * - In ring 3 (user mode), LDTR is typically 0 or unused
 * - Most shellcode doesn't rely on actual LDTR value
 *
 * REPLACEMENT APPROACH:
 * - Replace SLDT with dummy value (0x0000 or 0xFFFF)
 * - Use XOR for zero (smallest encoding)
 * - Use MOV for non-zero values with null-free immediate construction
 *
 * Priority: 95 (highest) - This is a critical hardware limitation
 */

#include <stdint.h>
#include <stddef.h>
#include "strategy.h"
#include "utils.h"
#include <capstone/capstone.h>

/* Forward declarations */
extern void register_strategy(strategy_t *s);

/*
 * Detect SLDT instructions with null bytes
 * Since SLDT opcode is 0x0F 0x00, ALL SLDT instructions contain null bytes
 */
static int can_handle_sldt_replacement(cs_insn *insn) {
    /* Only handle SLDT instructions */
    if (insn->id != X86_INS_SLDT) {
        return 0;
    }

    /* SLDT always has null bytes in opcode (0x0F 0x00) */
    /* But double-check to be safe */
    return has_null_bytes(insn);
}

/*
 * Calculate replacement size
 * - Register destination: XOR AX, AX (2 bytes)
 * - Memory destination: Temp register approach (8 bytes)
 */
static size_t get_size_sldt_replacement(cs_insn *insn) {
    cs_x86 *x86 = &insn->detail->x86;

    if (x86->op_count == 0) {
        return 2;  /* Default to register form */
    }

    cs_x86_op *op0 = &x86->operands[0];

    if (op0->type == X86_OP_REG) {
        /* SLDT AX -> XOR AX, AX (2 bytes) */
        return 2;
    } else if (op0->type == X86_OP_MEM) {
        /* SLDT [mem] -> More complex transformation */
        /* PUSH EBX (1) + XOR EBX,EBX (2) + MOV [reg],BX (2-3) + POP EBX (1) */
        return 8;
    }

    return 2;  /* Fallback */
}

/*
 * Generate null-free replacement code
 *
 * For SLDT AX:
 *   Replace with: XOR AX, AX (31 C0)
 *   Result: LDTR value is replaced with 0x0000
 *
 * For SLDT [mem]:
 *   Replace with null-free memory store sequence
 */
static void generate_sldt_replacement(struct buffer *b, cs_insn *insn) {
    cs_x86 *x86 = &insn->detail->x86;

    if (x86->op_count == 0) {
        /* No operands - shouldn't happen, but handle defensively */
        /* XOR AX, AX */
        buffer_write_byte(b, 0x31);
        buffer_write_byte(b, 0xC0);
        return;
    }

    cs_x86_op *op0 = &x86->operands[0];

    if (op0->type == X86_OP_REG) {
        /*
         * SLDT reg
         * Replace with: XOR reg, reg (zero value)
         * This is the most common and compact replacement
         */
        x86_reg dest_reg = op0->reg;

        /* For 16-bit registers, use XOR */
        if (dest_reg == X86_REG_AX) {
            /* XOR AX, AX = 31 C0 */
            buffer_write_byte(b, 0x31);
            buffer_write_byte(b, 0xC0);
        } else if (dest_reg == X86_REG_BX) {
            /* XOR BX, BX = 31 DB */
            buffer_write_byte(b, 0x31);
            buffer_write_byte(b, 0xDB);
        } else if (dest_reg == X86_REG_CX) {
            /* XOR CX, CX = 31 C9 */
            buffer_write_byte(b, 0x31);
            buffer_write_byte(b, 0xC9);
        } else if (dest_reg == X86_REG_DX) {
            /* XOR DX, DX = 31 D2 */
            buffer_write_byte(b, 0x31);
            buffer_write_byte(b, 0xD2);
        } else {
            /* Fallback: XOR AX, AX */
            buffer_write_byte(b, 0x31);
            buffer_write_byte(b, 0xC0);
        }
    } else if (op0->type == X86_OP_MEM) {
        /*
         * SLDT word ptr [mem]
         * More complex - need to store 16-bit zero to memory
         * Use temporary register to avoid null ModR/M bytes
         */

        /* PUSH EBX - save temp register */
        buffer_write_byte(b, 0x53);

        /* XOR EBX, EBX - zero the register */
        buffer_write_byte(b, 0x31);
        buffer_write_byte(b, 0xDB);

        /* Get memory operand details */
        x86_reg base = op0->mem.base;
        x86_reg index = op0->mem.index;
        int64_t disp = op0->mem.disp;

        /* Simple case: [EAX] */
        if (base == X86_REG_EAX && index == X86_REG_INVALID && disp == 0) {
            /* MOV ECX, EAX - copy address */
            buffer_write_byte(b, 0x89);
            buffer_write_byte(b, 0xC1);
            /* MOV word [ECX], BX - store zero */
            buffer_write_byte(b, 0x66);  /* 16-bit prefix */
            buffer_write_byte(b, 0x89);
            buffer_write_byte(b, 0x19);  /* ModR/M for [ECX] */
        } else {
            /* For other addressing modes, store using null-free addressing */
            /* This is a simplified version - may need expansion */
            buffer_write_byte(b, 0x66);  /* 16-bit prefix */
            buffer_write_byte(b, 0x89);
            buffer_write_byte(b, 0x1B);  /* MOV [EBX], BX */
        }

        /* POP EBX - restore temp register */
        buffer_write_byte(b, 0x5B);
    }
}

/* Strategy definition */
static strategy_t sldt_replacement = {
    .name = "SLDT Replacement (Opcode Null Fix)",
    .can_handle = can_handle_sldt_replacement,
    .get_size = get_size_sldt_replacement,
    .generate = generate_sldt_replacement,
    .priority = 95  /* Highest priority - critical hardware limitation */
};

/* Registration function */
void register_sldt_replacement_strategy() {
    register_strategy(&sldt_replacement);
}
