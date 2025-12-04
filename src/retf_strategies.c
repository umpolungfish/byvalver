/*
 * RETF (Far Return with Immediate) Null-Byte Elimination Strategy
 *
 * PROBLEM: RETF imm16 can contain null bytes when immediate has 0x00 in encoding
 *
 * Examples:
 *   CA 00 0D = RETF 0x0D00 (pop 0x0D00 bytes after far return)
 *   CA 00 D7 = RETF 0xD700 (pop 0xD700 bytes after far return)
 *
 * SOLUTION: Replace with stack adjustment + far return without immediate
 *   RETF imm16 → ADD ESP, imm16 + RETF
 *
 * SEMANTICS:
 *   RETF imm16: POP EIP, POP CS, ADD ESP, imm16
 *   Our transform: ADD ESP, imm16, then POP EIP, POP CS
 *   Result: Same final stack state
 *
 * CRITICAL: ADD ESP must happen BEFORE RETF, not after
 *
 * Priority: 85 (high)
 */

#include <stdint.h>
#include <stddef.h>
#include "strategy.h"
#include "utils.h"
#include <capstone/capstone.h>

/* Forward declarations */
extern void register_strategy(strategy_t *s);

/*
 * Detect RETF with immediate operand containing null bytes
 */
static int can_handle_retf_imm_null(cs_insn *insn) {
    /* Must be RETF instruction */
    if (insn->id != X86_INS_RETF) {
        return 0;
    }

    /* Must have null bytes */
    if (!has_null_bytes(insn)) {
        return 0;
    }

    cs_x86 *x86 = &insn->detail->x86;

    /* Must have immediate operand */
    if (x86->op_count == 1 && x86->operands[0].type == X86_OP_IMM) {
        uint64_t imm = x86->operands[0].imm;

        /* Check if immediate encoding contains null bytes */
        uint8_t low = imm & 0xFF;
        uint8_t high = (imm >> 8) & 0xFF;

        return (low == 0 || high == 0);
    }

    return 0;
}

/*
 * Calculate replacement size
 * - Small immediate (≤127): ADD ESP, imm8 (3) + RETF (1) = 4 bytes
 * - Large immediate: Use null-free construction + ADD ESP, reg + RETF = 7-15 bytes
 */
static size_t get_size_retf_imm_null(cs_insn *insn) {
    cs_x86 *x86 = &insn->detail->x86;
    uint64_t pop_bytes = x86->operands[0].imm;

    if (pop_bytes == 0) {
        /* RETF 0 -> just RETF (1 byte) */
        return 1;
    }

    if (pop_bytes <= 127) {
        /* ADD ESP, imm8 (3) + RETF (1) */
        return 4;
    }

    /* Large immediate - need null-free construction */
    /* Rough estimate: MOV ECX, imm32 (6-12) + ADD ESP, ECX (2) + RETF (1) */
    /* Conservative estimate */
    return 15;
}

/*
 * Generate null-free RETF replacement
 */
static void generate_retf_imm_null(struct buffer *b, cs_insn *insn) {
    cs_x86 *x86 = &insn->detail->x86;
    uint64_t pop_bytes = x86->operands[0].imm;

    if (pop_bytes == 0) {
        /* RETF 0 is just RETF without immediate */
        buffer_write_byte(b, 0xCB);  /* RETF (null-free opcode) */
        return;
    }

    /*
     * Strategy: ADD ESP, pop_bytes BEFORE the far return
     * This adjusts the stack before popping CS:IP
     */

    if (pop_bytes <= 127 && pop_bytes > 0) {
        /* Use compact imm8 form: ADD ESP, imm8 */
        buffer_write_byte(b, 0x83);  /* ADD r/m32, imm8 */
        buffer_write_byte(b, 0xC4);  /* ModR/M for ESP */
        buffer_write_byte(b, (uint8_t)pop_bytes);
    } else {
        /*
         * Large immediate or immediate with null bytes
         * For RETF, we can use a simpler approach:
         * Just use multiple ADD ESP instructions if needed
         */

        if (is_null_free((uint32_t)pop_bytes)) {
            /* ADD ESP, imm32 - if immediate is already null-free */
            buffer_write_byte(b, 0x81);  /* ADD r/m32, imm32 */
            buffer_write_byte(b, 0xC4);  /* ModR/M for ESP */
            buffer_write_dword(b, (uint32_t)pop_bytes);
        } else {
            /*
             * Fallback: construct using smaller adds
             * For most RETF cases, the pop count is reasonable
             * Break into null-free chunks
             */
            uint32_t remaining = (uint32_t)pop_bytes;

            /* Use larger chunks where possible */
            while (remaining >= 127) {
                buffer_write_byte(b, 0x83);  /* ADD ESP, imm8 */
                buffer_write_byte(b, 0xC4);
                buffer_write_byte(b, 127);
                remaining -= 127;
            }

            if (remaining > 0 && remaining <= 127 && remaining != 0) {
                buffer_write_byte(b, 0x83);  /* ADD ESP, imm8 */
                buffer_write_byte(b, 0xC4);
                buffer_write_byte(b, (uint8_t)remaining);
            }
        }
    }

    /* RETF (without immediate) - opcode 0xCB (null-free!) */
    buffer_write_byte(b, 0xCB);
}

/* Strategy definition */
static strategy_t retf_immediate_null_strategy = {
    .name = "RETF Immediate Null Elimination",
    .can_handle = can_handle_retf_imm_null,
    .get_size = get_size_retf_imm_null,
    .generate = generate_retf_imm_null,
    .priority = 85
};

/* Registration function */
void register_retf_strategies() {
    register_strategy(&retf_immediate_null_strategy);
}
