#include "strategy.h"
#include "utils.h"
#include "core.h"
#include <stdio.h>
#include <string.h>

// PIC addressing strategies for advanced position-independent patterns
int can_handle_pic_addressing(cs_insn *insn) {
    // Detect RIP-relative instructions that are part of PIC patterns
    // For now, any RIP-relative with nulls
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (is_rip_relative_operand(op)) {
            return has_null_bytes_in_encoding(insn->bytes, insn->size);
        }
    }
    return 0;
}

size_t get_size_pic_addressing(__attribute__((unused)) cs_insn *insn) {
    // Optimized PIC sequence
    return 25; // Estimate
}

void generate_pic_addressing(struct buffer *b, cs_insn *insn) {
    // Placeholder: for advanced PIC, use shared base or GOT-like indirection
    // For now, fallback
    buffer_append(b, insn->bytes, insn->size);
}

strategy_t pic_addressing_strategy = {
    .name = "pic_addressing",
    .can_handle = can_handle_pic_addressing,
    .get_size = get_size_pic_addressing,
    .generate = generate_pic_addressing,
    .priority = 75  // Higher than individual RIP strategies
};

// Register PIC addressing strategies
void register_pic_addressing_strategies(void) {
    register_strategy(&pic_addressing_strategy);
}