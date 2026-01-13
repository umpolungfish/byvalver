/*
 * BYVALVER - Overlapping Instruction Obfuscation (Priority 84)
 * Basic implementation for overlapping instruction generation
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/capstone.h>
#include "utils.h"
#include "core.h"
#include "strategy.h"
#include "obfuscation_strategy_registry.h"

// ============================================================================
// Strategy: Overlapping Instruction (Priority 84)
// Generates instructions that can be interpreted differently when jumped to
// ============================================================================

int can_handle_overlapping(cs_insn *insn) {
    // Apply to any instruction for now
    (void)insn;
    return 1;
}

size_t get_overlapping_size(cs_insn *insn) {
    // Original jump + overlapping sequence (~5 bytes)
    return insn->size + 5;
}

void generate_overlapping(struct buffer *b, cs_insn *insn) {
    // Append original jump
    buffer_append(b, insn->bytes, insn->size);

    // Add overlapping bytes (e.g., INC EAX; DEC EAX which is NOP but different disassembly)
    uint8_t overlap[] = {0x40, 0x48}; // INC EAX; DEC EAX
    buffer_append(b, overlap, 2);
}

static strategy_t overlapping_strategy = {
    .name = "Overlapping Instruction",
    .can_handle = can_handle_overlapping,
    .get_size = get_overlapping_size,
    .generate = generate_overlapping,
    .priority = 84
};

void register_overlapping_instruction_obfuscation() {
    register_obfuscation_strategy(&overlapping_strategy);
}
