/*
 * BYVALVER - Runtime Self-Modification Obfuscation (Priority 99)
 * Basic implementation for self-modifying code generation
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
// Strategy: Runtime Self-Modification (Priority 99)
// Generates code that modifies itself at runtime
// ============================================================================

int can_handle_runtime_selfmod(cs_insn *insn) {
    // Apply to any instruction for now
    (void)insn;
    return 1;
}

size_t get_runtime_selfmod_size(cs_insn *insn) {
    // Original + self-modification setup (~10 bytes)
    return insn->size + 10;
}

void generate_runtime_selfmod(struct buffer *b, cs_insn *insn) {
    // For basic implementation, just append the original instruction
    // TODO: Add actual self-modification logic (e.g., MOV byte ptr [RIP+offset], value)
    buffer_append(b, insn->bytes, insn->size);

    // Add a simple self-modifying instruction (placeholder)
    // MOV BYTE PTR [RIP + 1], 0x90 (change next byte to NOP)
    uint8_t selfmod[] = {0xC6, 0x05, 0x01, 0x00, 0x00, 0x00, 0x90};
    buffer_append(b, selfmod, 7);
}

static strategy_t runtime_selfmod_strategy = {
    .name = "Runtime Self-Modification",
    .can_handle = can_handle_runtime_selfmod,
    .get_size = get_runtime_selfmod_size,
    .generate = generate_runtime_selfmod,
    .priority = 99
};

void register_runtime_selfmod_obfuscation() {
    register_obfuscation_strategy(&runtime_selfmod_strategy);
}
