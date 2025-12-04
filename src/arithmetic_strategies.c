#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Helper to check if instruction is arithmetic with reg, imm operands
static int is_valid_arithmetic_reg_imm(cs_insn *insn) {
    if (!is_arithmetic_instruction(insn)) {
        return 0;
    }
    
    // Must have exactly 2 operands
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }
    
    // CRITICAL FIX: First operand must be register (not memory!)
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }
    
    // Second operand must be immediate
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }
    
    return 1;
}

// Arithmetic with original strategy
int can_handle_arithmetic_original(cs_insn *insn) {
    if (!is_valid_arithmetic_reg_imm(insn)) {
        return 0;
    }
    
    // Only handle if no null bytes
    return !has_null_bytes(insn);
}

size_t get_size_arithmetic_original(cs_insn *insn) {
    return get_op_reg_imm_size(insn);
}

void generate_arithmetic_original(struct buffer *b, cs_insn *insn) {
    generate_op_reg_imm(b, insn);
}

strategy_t arithmetic_original_strategy = {
    .name = "arithmetic_original",
    .can_handle = can_handle_arithmetic_original,
    .get_size = get_size_arithmetic_original,
    .generate = generate_arithmetic_original,
    .priority = 10
};

// Arithmetic with NEG strategy
int can_handle_arithmetic_neg(cs_insn *insn) {
    if (!is_valid_arithmetic_reg_imm(insn)) {
        return 0;
    }
    
    if (!has_null_bytes(insn)) {
        return 0;
    }
    
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t negated_val;
    return find_neg_equivalent(target, &negated_val);
}

size_t get_size_arithmetic_neg(cs_insn *insn) {
    return get_op_reg_imm_neg_size(insn);
}

void generate_arithmetic_neg(struct buffer *b, cs_insn *insn) {
    generate_op_reg_imm_neg(b, insn);
}

strategy_t arithmetic_neg_strategy = {
    .name = "arithmetic_neg",
    .can_handle = can_handle_arithmetic_neg,
    .get_size = get_size_arithmetic_neg,
    .generate = generate_arithmetic_neg,
    .priority = 9
};

// Arithmetic with NOT strategy - FIXED to only handle valid cases
int can_handle_arithmetic_not(cs_insn *insn) {
    // NOT strategy only makes sense for MOV, not arithmetic operations
    // Removing this strategy from arithmetic operations
    (void)insn;  // Parameter intentionally unused
    return 0;
}

size_t get_size_arithmetic_not(cs_insn *insn) {
    return get_mov_reg_imm_not_size(insn);
}

void generate_arithmetic_not(struct buffer *b, cs_insn *insn) {
    generate_mov_reg_imm_not(b, insn);
}

strategy_t arithmetic_not_strategy = {
    .name = "arithmetic_not",
    .can_handle = can_handle_arithmetic_not,
    .get_size = get_size_arithmetic_not,
    .generate = generate_arithmetic_not,
    .priority = 9
};

// Arithmetic with XOR strategy
int can_handle_arithmetic_xor(cs_insn *insn) {
    if (!is_valid_arithmetic_reg_imm(insn)) {
        return 0;
    }
    
    return has_null_bytes(insn);
}

size_t get_size_arithmetic_xor(cs_insn *insn) {
    return get_xor_encoded_arithmetic_size(insn);
}

void generate_arithmetic_xor(struct buffer *b, cs_insn *insn) {
    generate_xor_encoded_arithmetic(b, insn);
}

strategy_t arithmetic_xor_strategy = {
    .name = "arithmetic_xor",
    .can_handle = can_handle_arithmetic_xor,
    .get_size = get_size_arithmetic_xor,
    .generate = generate_arithmetic_xor,
    .priority = 7
};

// Arithmetic with ADD/SUB strategy
int can_handle_arithmetic_addsub(cs_insn *insn) {
    if (!is_valid_arithmetic_reg_imm(insn)) {
        return 0;
    }
    
    return has_null_bytes(insn);
}

size_t get_size_arithmetic_addsub(cs_insn *insn) {
    return get_addsub_encoded_arithmetic_size(insn);
}

void generate_arithmetic_addsub(struct buffer *b, cs_insn *insn) {
    generate_addsub_encoded_arithmetic(b, insn);
}

strategy_t arithmetic_addsub_strategy = {
    .name = "arithmetic_addsub",
    .can_handle = can_handle_arithmetic_addsub,
    .get_size = get_size_arithmetic_addsub,
    .generate = generate_arithmetic_addsub,
    .priority = 7
};

// REMOVED: arithmetic_substitution_strategy (was redundant and buggy)
// REMOVED: push_xor_polymorph (doesn't belong in arithmetic_strategies.c)
// REMOVED: rotation_encoded (doesn't belong in arithmetic_strategies.c)

void register_arithmetic_strategies() {
    register_strategy(&arithmetic_original_strategy);
    register_strategy(&arithmetic_neg_strategy);
    // register_strategy(&arithmetic_not_strategy);  // Disabled - doesn't make sense for arithmetic
    register_strategy(&arithmetic_xor_strategy);
    register_strategy(&arithmetic_addsub_strategy);
}
