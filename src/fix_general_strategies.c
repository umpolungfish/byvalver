#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// PUSH imm32 strategy - FIXED to be more conservative
int can_handle_push_imm32(__attribute__((unused)) cs_insn *insn) {
    // Temporarily disable this strategy due to null byte issues in testing
    // This needs more careful implementation
    return 0; // Disable until fixed
}

size_t get_size_push_imm32(cs_insn *insn) {
    uint32_t imm = insn->detail->x86.operands[0].imm;
    
    // Check if can be represented as sign-extended 8-bit
    if ((int32_t)(int8_t)imm == (int32_t)imm) {
        return get_push_imm8_size();
    } else {
        // Use MOV EAX, imm + PUSH EAX approach for null-free construction
        return get_mov_eax_imm_size(imm) + 1;  // +1 for PUSH EAX
    }
}

void generate_push_imm32_strat(struct buffer *b, cs_insn *insn) {
    uint32_t imm = insn->detail->x86.operands[0].imm;
    
    // Check if can be represented as sign-extended 8-bit
    if ((int32_t)(int8_t)imm == (int32_t)imm) {
        generate_push_imm8(b, (int8_t)imm);
    } else {
        // Use MOV EAX, imm + PUSH EAX for null-free construction
        generate_mov_eax_imm(b, imm);
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);
    }
}

strategy_t push_imm32_strategy = {
    .name = "push_imm32",
    .can_handle = can_handle_push_imm32,
    .get_size = get_size_push_imm32,
    .generate = generate_push_imm32_strat,
    .priority = 9
};

// Stack string strategy - FIXED to be more specific
int can_handle_stack_string(cs_insn *insn) {
    if (insn->id != X86_INS_PUSH) {
        return 0;
    }
    
    if (insn->detail->x86.op_count != 1) {
        return 0;
    }
    
    if (insn->detail->x86.operands[0].type != X86_OP_IMM) {
        return 0;
    }
    
    if (!has_null_bytes(insn)) {
        return 0;
    }
    
    uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
    
    // Check if this looks like a string (at least 2 printable ASCII chars)
    int likely_char_count = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t byte_val = (imm >> (i * 8)) & 0xFF;
        if ((byte_val >= 0x20 && byte_val <= 0x7E)) {
            likely_char_count++;
        }
    }
    
    // Temporarily disable this strategy due to potential null byte issues
    // This needs more careful implementation
    return 0; // Disable until fixed
}

size_t get_size_stack_string(cs_insn *insn) {
    // Use MOV EAX, imm + PUSH EAX
    uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
    return get_mov_eax_imm_size(imm) + 1;
}

void generate_stack_string(struct buffer *b, cs_insn *insn) {
    uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
    
    // Use null-free MOV construction + PUSH
    generate_mov_eax_imm(b, imm);
    
    uint8_t push_eax[] = {0x50};
    buffer_append(b, push_eax, 1);
}

strategy_t stack_string_strategy = {
    .name = "stack_string",
    .can_handle = can_handle_stack_string,
    .get_size = get_size_stack_string,
    .generate = generate_stack_string,
    .priority = 10  // Higher priority than generic push for strings
};

// REMOVED: self_modify_strategy (was redundant and overlapping)

void register_general_strategies() {
    register_strategy(&push_imm32_strategy);
    register_strategy(&stack_string_strategy);
}
