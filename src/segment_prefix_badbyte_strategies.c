#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>

// Strategy 9: Segment Register Bad-Byte
// Handles FS/GS segment prefixes (0x64, 0x65)

static int can_handle_segment_prefix_bad(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    cs_x86 *x86 = &insn->detail->x86;

    // Check for segment override prefixes at prefix[1]
    // FS (0x64) or GS (0x65)
    uint8_t seg_prefix = x86->prefix[1];
    if (seg_prefix == 0x64 || seg_prefix == 0x65) {
        if (!is_bad_byte_free_byte(seg_prefix)) {
            return 1;
        }
    }

    return 0;
}

static size_t get_size_segment_prefix_bad(cs_insn *insn) {
    (void)insn;
    // Alternative encoding or indirect access: ~15 bytes
    return 15;
}

static void generate_segment_prefix_bad(struct buffer *b, cs_insn *insn) {
    // Simplified: For FS:[offset], we can't easily avoid the prefix
    // This is a limitation - just copy original for now
    // A full implementation would require TEB/PEB base calculation
    buffer_append(b, insn->bytes, insn->size);
}

void register_segment_prefix_badbyte_strategies(void) {
    static strategy_t strategy = {
        .name = "Segment Prefix - Bad Byte Detection",
        .can_handle = can_handle_segment_prefix_bad,
        .get_size = get_size_segment_prefix_bad,
        .generate = generate_segment_prefix_bad,
        .priority = 81
    };
    register_strategy(&strategy);
}
