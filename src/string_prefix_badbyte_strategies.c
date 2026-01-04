#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>

// Strategy 7: String Instruction Length Prefix Bad-Byte
// Handles REP prefix (0xF3) when it's a bad byte

static int can_handle_rep_prefix_bad(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    // Check for REP prefix instructions at prefix[0]
    cs_x86 *x86 = &insn->detail->x86;

    // REP (0xF3) or REPNE (0xF2) at prefix[0]
    uint8_t rep_prefix = x86->prefix[0];
    if (rep_prefix == 0xF3 || rep_prefix == 0xF2) {
        if (!is_bad_byte_free_byte(rep_prefix)) {
            return 1;
        }
    }

    return 0;
}

static size_t get_size_rep_prefix_bad(cs_insn *insn) {
    (void)insn;
    // Loop unrolling or LOOP-based alternative: ~10-20 bytes
    return 20;
}

static void generate_rep_prefix_bad(struct buffer *b, cs_insn *insn) {
    // For REP STOSB/MOVSB/etc, convert to loop
    // Simplified: LOOP-based replacement
    // loop_start: STOSB; DEC ECX; JNZ loop_start

    if (insn->id == X86_INS_STOSB) {
        // Simple loop for STOSB
        // loop_start:
        uint8_t stosb = 0xAA;
        buffer_append(b, &stosb, 1);

        // DEC ECX
        if (is_bad_byte_free_byte(0x49)) { // DEC ECX opcode
            uint8_t dec = 0x49;
            buffer_append(b, &dec, 1);
        } else {
            uint8_t dec_alt[] = {0x83, 0xE9, 0x01}; // SUB ECX, 1
            buffer_append(b, dec_alt, 3);
        }

        // JNZ loop_start
        uint8_t jnz[] = {0x75, 0xFA}; // JNZ -6 (approximate)
        buffer_append(b, jnz, 2);
    } else {
        // Fallback: copy original
        buffer_append(b, insn->bytes, insn->size);
    }
}

void register_string_prefix_badbyte_strategies(void) {
    static strategy_t strategy = {
        .name = "REP Prefix - Bad Byte Elimination",
        .can_handle = can_handle_rep_prefix_bad,
        .get_size = get_size_rep_prefix_bad,
        .generate = generate_rep_prefix_bad,
        .priority = 84
    };
    register_strategy(&strategy);
}
