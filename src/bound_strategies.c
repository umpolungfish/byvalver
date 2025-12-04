/*
 * BOUND (Check Array Bounds) Null-Byte Elimination Strategy
 *
 * PROBLEM: BOUND reg, [mem] can generate encoding with null ModR/M byte
 *
 * Example:
 *   BOUND EAX, [EAX] → 62 00
 *   Opcode: 62
 *   ModR/M: 00 (mod=00, reg=000/EAX, r/m=000/[EAX])
 *
 * INSTRUCTION SEMANTICS:
 *   BOUND checks if signed value in reg is within bounds specified by
 *   two consecutive memory locations [mem] and [mem+4]
 *   If out of bounds, generates INT 5 (Bound Range Exceeded exception)
 *
 * FREQUENCY:
 *   - 2,797 total BOUND instructions in corpus
 *   - Only 1 instance causes null bytes (module_4.bin)
 *   - Rare in modern code, sometimes used for obfuscation
 *
 * SOLUTION: Temp register indirection to change ModR/M encoding
 *   BOUND reg, [EAX] → PUSH EBX + MOV EBX,EAX + BOUND reg,[EBX] + POP EBX
 *
 * WHY THIS WORKS:
 *   [EAX] has ModR/M = 0x00 (NULL!)
 *   [EBX] has ModR/M = 0x03 (null-free)
 *
 * Priority: 70 (medium)
 */

#include <stdint.h>
#include <stddef.h>
#include "strategy.h"
#include "utils.h"
#include <capstone/capstone.h>

/* Forward declarations */
extern void register_strategy(strategy_t *s);

/*
 * Detect BOUND with null ModR/M byte
 */
static int can_handle_bound_modrm_null(cs_insn *insn) {
    /* Must be BOUND instruction */
    if (insn->id != X86_INS_BOUND) {
        return 0;
    }

    /* Must have null bytes */
    if (!has_null_bytes(insn)) {
        return 0;
    }

    cs_x86 *x86 = &insn->detail->x86;

    /* BOUND has 2 operands: reg, mem */
    if (x86->op_count == 2) {
        cs_x86_op *op1 = &x86->operands[1];  /* Memory operand */

        /* Check if memory operand is [EAX] (null ModR/M) */
        if (op1->type == X86_OP_MEM) {
            if (op1->mem.base == X86_REG_EAX &&
                op1->mem.index == X86_REG_INVALID &&
                op1->mem.disp == 0) {
                return 1;
            }
        }
    }

    return 0;
}

/*
 * Calculate replacement size
 * PUSH EBX (1) + MOV EBX,EAX (2) + BOUND reg,[EBX] (2) + POP EBX (1) = 6 bytes
 */
static size_t get_size_bound_modrm_null(cs_insn *insn) {
    (void)insn;  /* Unused parameter */
    return 6;
}

/*
 * Generate null-free BOUND replacement using temp register indirection
 */
static void generate_bound_modrm_null(struct buffer *b, cs_insn *insn) {
    cs_x86 *x86 = &insn->detail->x86;
    cs_x86_op *op0 = &x86->operands[0];  /* Register operand */

    /* PUSH EBX - save temp register */
    buffer_write_byte(b, 0x53);

    /* MOV EBX, EAX - copy address to different register */
    buffer_write_byte(b, 0x89);
    buffer_write_byte(b, 0xC3);  /* ModR/M for MOV EBX, EAX */

    /*
     * BOUND reg, [EBX]
     * Opcode: 62
     * ModR/M: Encodes register + [EBX]
     */

    buffer_write_byte(b, 0x62);  /* BOUND opcode */

    /* Calculate ModR/M byte for reg + [EBX] */
    uint8_t modrm = 0x03;  /* Base: [EBX] with mod=00, r/m=011 */

    /* Add register encoding */
    x86_reg dest_reg = op0->reg;

    if (dest_reg == X86_REG_EAX) {
        modrm |= (0 << 3);  /* reg=000 for EAX */
    } else if (dest_reg == X86_REG_ECX) {
        modrm |= (1 << 3);  /* reg=001 for ECX */
    } else if (dest_reg == X86_REG_EDX) {
        modrm |= (2 << 3);  /* reg=010 for EDX */
    } else if (dest_reg == X86_REG_EBX) {
        modrm |= (3 << 3);  /* reg=011 for EBX */
    } else if (dest_reg == X86_REG_ESP) {
        modrm |= (4 << 3);  /* reg=100 for ESP */
    } else if (dest_reg == X86_REG_EBP) {
        modrm |= (5 << 3);  /* reg=101 for EBP */
    } else if (dest_reg == X86_REG_ESI) {
        modrm |= (6 << 3);  /* reg=110 for ESI */
    } else if (dest_reg == X86_REG_EDI) {
        modrm |= (7 << 3);  /* reg=111 for EDI */
    } else {
        /* Default to EAX if unknown register */
        modrm |= (0 << 3);
    }

    buffer_write_byte(b, modrm);

    /* POP EBX - restore temp register */
    buffer_write_byte(b, 0x5B);
}

/* Strategy definition */
static strategy_t bound_modrm_null_strategy = {
    .name = "BOUND ModR/M Null Bypass",
    .can_handle = can_handle_bound_modrm_null,
    .get_size = get_size_bound_modrm_null,
    .generate = generate_bound_modrm_null,
    .priority = 70
};

/* Registration function */
void register_bound_strategies() {
    register_strategy(&bound_modrm_null_strategy);
}
