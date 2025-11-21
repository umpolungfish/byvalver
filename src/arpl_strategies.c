/*
 * ARPL (Adjust RPL Field of Segment Selector) Null-Byte Elimination Strategy
 *
 * PROBLEM: ARPL word ptr [EAX], reg generates encoding with null ModR/M byte
 *
 * Example:
 *   ARPL [EAX], AX → 63 00
 *   Opcode: 63
 *   ModR/M: 00 (mod=00, reg=000/AX, r/m=000/[EAX])
 *
 * FREQUENCY:
 *   - 8,942 total ARPL instructions in corpus
 *   - Only 2 instances cause null bytes (uhmento.bin, uhmento_buttered.bin)
 *   - Often used for obfuscation rather than actual privilege-level adjustment
 *
 * SOLUTION: Temp register indirection to change ModR/M encoding
 *   ARPL [EAX], reg → PUSH EBX + MOV EBX,EAX + ARPL [EBX],reg + POP EBX
 *
 * WHY THIS WORKS:
 *   [EAX] has ModR/M = 0x00 (NULL!)
 *   [EBX] has ModR/M = 0x03 (null-free)
 *
 * Priority: 75 (medium-high)
 */

#include <stdint.h>
#include <stddef.h>
#include "strategy.h"
#include "utils.h"
#include <capstone/capstone.h>

/* Forward declarations */
extern void register_strategy(strategy_t *s);

/*
 * Detect ARPL with null ModR/M byte
 */
static int can_handle_arpl_modrm_null(cs_insn *insn) {
    /* Must be ARPL instruction */
    if (insn->id != X86_INS_ARPL) {
        return 0;
    }

    /* Must have null bytes */
    if (!has_null_bytes(insn)) {
        return 0;
    }

    cs_x86 *x86 = &insn->detail->x86;

    /* ARPL has 2 operands: dest (mem/reg), src (reg) */
    if (x86->op_count == 2) {
        cs_x86_op *op0 = &x86->operands[0];

        /* Check if destination is memory operand */
        if (op0->type == X86_OP_MEM) {
            /*
             * Check for [EAX] addressing mode (null ModR/M)
             * ModR/M = 0x00 when:
             *   - base = EAX
             *   - no index register
             *   - displacement = 0
             */
            if (op0->mem.base == X86_REG_EAX &&
                op0->mem.index == X86_REG_INVALID &&
                op0->mem.disp == 0) {
                return 1;
            }
        }
    }

    return 0;
}

/*
 * Calculate replacement size
 * PUSH EBX (1) + MOV EBX,EAX (2) + ARPL [EBX],reg (2) + POP EBX (1) = 6 bytes
 */
static size_t get_size_arpl_modrm_null(cs_insn *insn) {
    (void)insn;  /* Unused parameter */
    return 6;
}

/*
 * Generate null-free ARPL replacement using temp register indirection
 */
static void generate_arpl_modrm_null(struct buffer *b, cs_insn *insn) {
    cs_x86 *x86 = &insn->detail->x86;
    cs_x86_op *op1 = &x86->operands[1];  /* Source register */

    /* PUSH EBX - save temp register */
    buffer_write_byte(b, 0x53);

    /* MOV EBX, EAX - copy address to different register */
    buffer_write_byte(b, 0x89);
    buffer_write_byte(b, 0xC3);  /* ModR/M for MOV EBX, EAX */

    /*
     * ARPL [EBX], src_reg
     * Opcode: 63
     * ModR/M: Encodes [EBX] + source register
     */

    buffer_write_byte(b, 0x63);  /* ARPL opcode */

    /* Calculate ModR/M byte for [EBX] + src_reg */
    uint8_t modrm = 0x03;  /* Base: [EBX] with mod=00, r/m=011 */

    /* Add source register encoding */
    x86_reg src_reg = op1->reg;

    if (src_reg == X86_REG_AX) {
        modrm |= (0 << 3);  /* reg=000 for AX */
    } else if (src_reg == X86_REG_CX) {
        modrm |= (1 << 3);  /* reg=001 for CX */
    } else if (src_reg == X86_REG_DX) {
        modrm |= (2 << 3);  /* reg=010 for DX */
    } else if (src_reg == X86_REG_BX) {
        modrm |= (3 << 3);  /* reg=011 for BX */
    } else if (src_reg == X86_REG_SP) {
        modrm |= (4 << 3);  /* reg=100 for SP */
    } else if (src_reg == X86_REG_BP) {
        modrm |= (5 << 3);  /* reg=101 for BP */
    } else if (src_reg == X86_REG_SI) {
        modrm |= (6 << 3);  /* reg=110 for SI */
    } else if (src_reg == X86_REG_DI) {
        modrm |= (7 << 3);  /* reg=111 for DI */
    } else {
        /* Default to AX if unknown register */
        modrm |= (0 << 3);
    }

    buffer_write_byte(b, modrm);

    /* POP EBX - restore temp register */
    buffer_write_byte(b, 0x5B);
}

/* Strategy definition */
static strategy_t arpl_modrm_null_strategy = {
    .name = "ARPL ModR/M Null Bypass",
    .can_handle = can_handle_arpl_modrm_null,
    .get_size = get_size_arpl_modrm_null,
    .generate = generate_arpl_modrm_null,
    .priority = 75
};

/* Registration function */
void register_arpl_strategies() {
    register_strategy(&arpl_modrm_null_strategy);
}
