#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>

// Map of conditional jump opcodes
typedef struct {
    x86_insn cond;
    uint8_t short_opcode;    // 0x70-0x7F
    uint8_t near_opcode_1;   // 0x0F
    uint8_t near_opcode_2;   // 0x80-0x8F
    x86_insn inverse_cond;
    uint8_t inverse_short_opcode;
} jcc_info_t;

static const jcc_info_t jcc_table[] = {
    {X86_INS_JO,   0x70, 0x0F, 0x80, X86_INS_JNO,  0x71},
    {X86_INS_JNO,  0x71, 0x0F, 0x81, X86_INS_JO,   0x70},
    {X86_INS_JB,   0x72, 0x0F, 0x82, X86_INS_JAE,  0x73},
    {X86_INS_JAE,  0x73, 0x0F, 0x83, X86_INS_JB,   0x72},
    {X86_INS_JE,   0x74, 0x0F, 0x84, X86_INS_JNE,  0x75},
    {X86_INS_JNE,  0x75, 0x0F, 0x85, X86_INS_JE,   0x74},
    {X86_INS_JBE,  0x76, 0x0F, 0x86, X86_INS_JA,   0x77},
    {X86_INS_JA,   0x77, 0x0F, 0x87, X86_INS_JBE,  0x76},
    {X86_INS_JS,   0x78, 0x0F, 0x88, X86_INS_JNS,  0x79},
    {X86_INS_JNS,  0x79, 0x0F, 0x89, X86_INS_JS,   0x78},
    {X86_INS_JP,   0x7A, 0x0F, 0x8A, X86_INS_JNP,  0x7B},
    {X86_INS_JNP,  0x7B, 0x0F, 0x8B, X86_INS_JP,   0x7A},
    {X86_INS_JL,   0x7C, 0x0F, 0x8C, X86_INS_JGE,  0x7D},
    {X86_INS_JGE,  0x7D, 0x0F, 0x8D, X86_INS_JL,   0x7C},
    {X86_INS_JLE,  0x7E, 0x0F, 0x8E, X86_INS_JG,   0x7F},
    {X86_INS_JG,   0x7F, 0x0F, 0x8F, X86_INS_JLE,  0x7E},
};

static const jcc_info_t* get_jcc_info(x86_insn insn_id) {
    for (size_t i = 0; i < sizeof(jcc_table) / sizeof(jcc_table[0]); i++) {
        if (jcc_table[i].cond == insn_id) {
            return &jcc_table[i];
        }
    }
    return NULL;
}

// Check if conditional jump opcode contains bad bytes
static int jcc_has_bad_opcode(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    const jcc_info_t *info = get_jcc_info(insn->id);
    if (!info) return 0;

    // Check short form opcode
    if (!is_bad_byte_free_byte(info->short_opcode)) {
        return 1;
    }

    // Check near form opcodes
    if (!is_bad_byte_free_byte(info->near_opcode_1) ||
        !is_bad_byte_free_byte(info->near_opcode_2)) {
        return 1;
    }

    return 0;
}

// ============================================================================
// Strategy: Conditional jump with bad opcode → Inverse condition + JMP
// ============================================================================

static int can_handle_jcc_bad_opcode(cs_insn *insn) {
    return jcc_has_bad_opcode(insn);
}

static size_t get_size_jcc_bad_opcode(cs_insn *insn) {
    (void)insn;
    // Inverse JCC short (2 bytes) + JMP short (2 bytes) = 4 bytes minimum
    // Or JMP near (5 bytes) if needed
    return 7;
}

// Helper function to adjust offset to avoid null bytes
static int32_t adjust_offset_for_nulls(int32_t original_offset, int is_short) {
    int max_adjust = 10; // Try ±10 adjustments

    for (int adjust = 0; adjust <= max_adjust; adjust++) {
        // Try +adjust
        int32_t test_offset = original_offset + adjust;
        if (is_short) {
            if (test_offset >= -128 && test_offset <= 127) {
                uint8_t byte = (uint8_t)(int8_t)test_offset;
                if (is_bad_byte_free_byte(byte)) {
                    return test_offset;
                }
            }
        } else {
            // Check 4 bytes of near offset
            if (is_bad_byte_free((uint32_t)test_offset)) {
                return test_offset;
            }
        }

        // Try -adjust
        if (adjust > 0) {
            test_offset = original_offset - adjust;
            if (is_short) {
                if (test_offset >= -128 && test_offset <= 127) {
                    uint8_t byte = (uint8_t)(int8_t)test_offset;
                    if (is_bad_byte_free_byte(byte)) {
                        return test_offset;
                    }
                }
            } else {
                if (is_bad_byte_free((uint32_t)test_offset)) {
                    return test_offset;
                }
            }
        }
    }

    // If no adjustment works, return original
    return original_offset;
}

static void generate_jcc_bad_opcode(struct buffer *b, cs_insn *insn) {
    const jcc_info_t *info = get_jcc_info(insn->id);
    if (!info) {
        // Fallback: just copy original
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    // Get the target offset from the original instruction
    cs_x86_op *op = &insn->detail->x86.operands[0];
    int64_t target_addr = op->imm;
    int64_t current_addr = insn->address;
    int32_t rel_offset = (int32_t)(target_addr - (current_addr + insn->size));

    // Strategy: JNC skip; JMP target; skip:
    // We need to use the inverse condition to skip over the JMP

    // Check if inverse short opcode is safe
    if (is_bad_byte_free_byte(info->inverse_short_opcode)) {
        // Use: JNC +2; JMP target
        uint8_t inv_jcc[] = {info->inverse_short_opcode, 0x02};
        buffer_append(b, inv_jcc, 2);

        // Now emit JMP to target
        // Calculate new offset from after this instruction
        int64_t new_current = current_addr + 2; // After inverse JCC

        if (rel_offset >= -128 && rel_offset <= 127) {
            // Short JMP
            uint8_t jmp_short = 0xEB;
            if (is_bad_byte_free_byte(jmp_short)) {
                int32_t adjusted_offset = adjust_offset_for_nulls((int32_t)(target_addr - (new_current + 2)), 1);
                int8_t jmp_offset = (int8_t)adjusted_offset;
                uint8_t jmp[] = {jmp_short, (uint8_t)jmp_offset};
                buffer_append(b, jmp, 2);
                // Adjust target_addr if offset was adjusted
                target_addr = new_current + 2 + jmp_offset;
            } else {
                // JMP short opcode is bad, use near JMP
                uint8_t jmp_near = 0xE9;
                int32_t jmp_offset_near = adjust_offset_for_nulls((int32_t)(target_addr - (new_current + 5)), 0);
                uint8_t jmp[] = {jmp_near, 0, 0, 0, 0};
                memcpy(jmp + 1, &jmp_offset_near, 4);
                buffer_append(b, jmp, 5);
                // Adjust target_addr if offset was adjusted
                target_addr = new_current + 5 + jmp_offset_near;
            }
        } else {
            // Near JMP
            uint8_t jmp_near = 0xE9;
            int32_t jmp_offset_near = adjust_offset_for_nulls((int32_t)(target_addr - (new_current + 5)), 0);
            uint8_t jmp[] = {jmp_near, 0, 0, 0, 0};
            memcpy(jmp + 1, &jmp_offset_near, 4);
            buffer_append(b, jmp, 5);
            // Adjust target_addr if offset was adjusted
            target_addr = new_current + 5 + jmp_offset_near;
        }
    } else {
        // Inverse opcode is also bad, try near form of inverse
        uint8_t inv_near_opcode_2 = info->near_opcode_2 ^ 0x01; // Flip last bit for inverse

        if (is_bad_byte_free_byte(0x0F) && is_bad_byte_free_byte(inv_near_opcode_2)) {
            // Use near form: 0F 8X +6; JMP target
            uint8_t inv_jcc_near[] = {0x0F, inv_near_opcode_2, 0x06, 0x00, 0x00, 0x00};
            buffer_append(b, inv_jcc_near, 6);

            // JMP target (near)
            int64_t new_current = current_addr + 6;
            uint8_t jmp_near = 0xE9;
            int32_t jmp_offset_near = adjust_offset_for_nulls((int32_t)(target_addr - (new_current + 5)), 0);
            uint8_t jmp[] = {jmp_near, 0, 0, 0, 0};
            memcpy(jmp + 1, &jmp_offset_near, 4);
            buffer_append(b, jmp, 5);
            // Adjust target_addr if offset was adjusted
            target_addr = new_current + 5 + jmp_offset_near;
        } else {
            // Last resort: copy original (may still have bad bytes)
            buffer_append(b, insn->bytes, insn->size);
        }
    }
}

// ============================================================================
// Strategy Registration
// ============================================================================

void register_conditional_jump_opcode_badbyte_strategies(void) {
    static strategy_t strategy_jcc_bad_opcode = {
        .name = "Conditional Jump - Bad Opcode Elimination",
        .can_handle = can_handle_jcc_bad_opcode,
        .get_size = get_size_jcc_bad_opcode,
        .generate = generate_jcc_bad_opcode,
        .priority = 92,
    .target_arch = BYVAL_ARCH_X86
    };
    register_strategy(&strategy_jcc_bad_opcode);
}
