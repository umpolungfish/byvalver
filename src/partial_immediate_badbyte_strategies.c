#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>

// Strategy 5: Multi-Byte Immediate Partial Bad-Byte
// Optimizes immediate values where only specific bytes are bad

static int can_handle_mov_imm_partial_bad(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    if (insn->id == X86_INS_MOV &&
        insn->detail->x86.op_count == 2 &&
        insn->detail->x86.operands[0].type == X86_OP_REG &&
        insn->detail->x86.operands[1].type == X86_OP_IMM) {

        uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

        // Check if value has some bad bytes but not all
        int bad_count = 0;
        int good_count = 0;

        for (int i = 0; i < 4; i++) {
            uint8_t byte = (imm >> (i * 8)) & 0xFF;
            if (is_bad_byte_free_byte(byte)) {
                good_count++;
            } else {
                bad_count++;
            }
        }

        // Only handle if we have a mix (optimization opportunity)
        return (bad_count > 0 && good_count > 0);
    }

    return 0;
}

static size_t get_size_mov_imm_partial_bad(cs_insn *insn) {
    (void)insn;
    // MOV reg, partial (5) + shift/arithmetic operations (6-10)
    return 15;
}

static void generate_mov_imm_partial_bad(struct buffer *b, cs_insn *insn) {
    x86_reg dst = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    int dst_idx = get_reg_index((uint8_t)dst);

    // Strategy: Build value from safe bytes using rotations
    // Find the largest sequence of safe bytes
    uint32_t safe_part = 0;
    int rotate = 0;

    // Simple approach: rotate until we have maximum safe bytes at low end
    for (int r = 0; r < 4; r++) {
        uint32_t rotated = (imm >> (r * 8)) | (imm << (32 - r * 8));
        uint16_t low_word = rotated & 0xFFFF;

        if (is_bad_byte_free_byte(low_word & 0xFF) &&
            is_bad_byte_free_byte((low_word >> 8) & 0xFF)) {
            safe_part = rotated;
            rotate = r;
            break;
        }
    }

    if (rotate > 0) {
        // MOV reg, safe_part
        uint8_t mov[] = {0xB8 + dst_idx, 0, 0, 0, 0};
        memcpy(mov + 1, &safe_part, 4);
        buffer_append(b, mov, 5);

        // ROR reg, rotate*8
        uint8_t ror[] = {0xC1, 0xC8 + dst_idx, rotate * 8};
        buffer_append(b, ror, 3);
    } else {
        // Use existing null-free generation as fallback
        generate_mov_eax_imm(b, imm);
        if (dst != X86_REG_EAX) {
            // MOV dst, EAX
            uint8_t mov_from_eax[] = {0x89, 0xC0 + dst_idx};
            buffer_append(b, mov_from_eax, 2);
        }
    }
}

void register_partial_immediate_badbyte_strategies(void) {
    static strategy_t strategy = {
        .name = "MOV imm - Partial Bad-Byte Optimization",
        .can_handle = can_handle_mov_imm_partial_bad,
        .get_size = get_size_mov_imm_partial_bad,
        .generate = generate_mov_imm_partial_bad,
        .priority = 87
    };
    register_strategy(&strategy);
}
