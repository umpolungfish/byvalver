#include "strategy.h"
#include "utils.h"
#include <stdio.h>

// MOV with original strategy
int can_handle_mov_original(cs_insn *insn) {
    return is_mov_instruction(insn) && 
           !has_null_bytes(insn) && 
           (insn->detail->x86.operands[1].imm == 0 || 
            (((insn->detail->x86.operands[1].imm >> 0) & 0xFF) != 0 && 
             ((insn->detail->x86.operands[1].imm >> 8) & 0xFF) != 0 && 
             ((insn->detail->x86.operands[1].imm >> 16) & 0xFF) != 0 && 
             ((insn->detail->x86.operands[1].imm >> 24) & 0xFF) != 0));
}

size_t get_size_mov_original(cs_insn *insn) {
    return get_mov_reg_imm_size(insn);
}

void generate_mov_original(struct buffer *b, cs_insn *insn) {
    generate_mov_reg_imm(b, insn);
}

strategy_t mov_original_strategy = {
    .name = "mov_original",
    .can_handle = can_handle_mov_original,
    .get_size = get_size_mov_original,
    .generate = generate_mov_original,
    .priority = 10  // High priority when no null bytes
};

// MOV with arithmetic equivalent strategy
int can_handle_mov_arithmetic(cs_insn *insn) {
    if (!is_mov_instruction(insn) || !has_null_bytes(insn)) {
        return 0;
    }
    
    // Check if arithmetic strategy is applicable (this would call the find function from byvalver.c)
    // For now, we'll implement a simplified check
    // This is a placeholder - in the real implementation we'd check if arithmetic equivalent exists
    return 1;  // For now, assume it can be handled
}

size_t get_size_mov_arithmetic(__attribute__((unused)) cs_insn *insn) {
    // Using arithmetic to construct the value: MOV EAX, base_val + arithmetic to get target
    return 10; // Placeholder for arithmetic value construction
}

void generate_mov_arithmetic(struct buffer *b, cs_insn *insn) {
    // Using arithmetic to construct the value
    // For example: MOV EAX, 0x00200404; SUB EAX, 0x404 (if target is 0x00200000)
    
    // This is a complex implementation that would find arithmetic equivalents
    // For now, use a simpler approach
    generate_mov_reg_imm(b, insn);
}

strategy_t mov_arithmetic_strategy = {
    .name = "mov_arithmetic",
    .can_handle = can_handle_mov_arithmetic,
    .get_size = get_size_mov_arithmetic,
    .generate = generate_mov_arithmetic,
    .priority = 8
};

// MOV with shift strategy
int can_handle_mov_shift(cs_insn *insn) {
    return is_mov_instruction(insn) && has_null_bytes(insn);
}

size_t get_size_mov_shift(cs_insn *insn) {
    return get_mov_reg_imm_shift_size(insn);
}

void generate_mov_shift(struct buffer *b, cs_insn *insn) {
    generate_mov_reg_imm_shift(b, insn);
}

strategy_t mov_shift_strategy = {
    .name = "mov_shift",
    .can_handle = can_handle_mov_shift,
    .get_size = get_size_mov_shift,
    .generate = generate_mov_shift,
    .priority = 7
};

// MOV with NEG strategy
int can_handle_mov_neg(cs_insn *insn) {
    if (!is_mov_instruction(insn) || !has_null_bytes(insn)) {
        return 0;
    }
    
    // Check if NEG equivalent exists (would call find_neg_equivalent from byvalver.c)
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t negated_val;
    extern int find_neg_equivalent(uint32_t target, uint32_t *negated_val);
    return find_neg_equivalent(target, &negated_val);
}

size_t get_size_mov_neg(cs_insn *insn) {
    return get_mov_reg_imm_neg_size(insn);
}

void generate_mov_neg(struct buffer *b, cs_insn *insn) {
    generate_mov_reg_imm_neg(b, insn);
}

strategy_t mov_neg_strategy = {
    .name = "mov_neg",
    .can_handle = can_handle_mov_neg,
    .get_size = get_size_mov_neg,
    .generate = generate_mov_neg,
    .priority = 9  // High priority since it's very effective when applicable
};

// MOV with XOR strategy
int can_handle_mov_xor(cs_insn *insn) {
    return is_mov_instruction(insn) && has_null_bytes(insn);
}

size_t get_size_mov_xor(cs_insn *insn) {
    return get_xor_encoded_mov_size(insn);
}

void generate_mov_xor(struct buffer *b, cs_insn *insn) {
    generate_xor_encoded_mov(b, insn);
}

strategy_t mov_xor_strategy = {
    .name = "mov_xor",
    .can_handle = can_handle_mov_xor,
    .get_size = get_size_mov_xor,
    .generate = generate_mov_xor,
    .priority = 6
};

// MOV with NOT strategy
int can_handle_mov_not(cs_insn *insn) {
    if (!is_mov_instruction(insn) || !has_null_bytes(insn)) {
        return 0;
    }
    
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t not_val;
    extern int find_not_equivalent(uint32_t target, uint32_t *not_val);
    return find_not_equivalent(target, &not_val);
}

size_t get_size_mov_not(cs_insn *insn) {
    return get_mov_reg_imm_not_size(insn);
}

void generate_mov_not(struct buffer *b, cs_insn *insn) {
    generate_mov_reg_imm_not(b, insn);
}

strategy_t mov_not_strategy = {
    .name = "mov_not",
    .can_handle = can_handle_mov_not,
    .get_size = get_size_mov_not,
    .generate = generate_mov_not,
    .priority = 9
};

// MOV with ADD/SUB strategy
int can_handle_mov_addsub(cs_insn *insn) {
    return is_mov_instruction(insn) && has_null_bytes(insn);
}

size_t get_size_mov_addsub(cs_insn *insn) {
    return get_addsub_encoded_mov_size(insn);
}

void generate_mov_addsub(struct buffer *b, cs_insn *insn) {
    generate_addsub_encoded_mov(b, insn);
}

strategy_t mov_addsub_strategy = {
    .name = "mov_addsub",
    .can_handle = can_handle_mov_addsub,
    .get_size = get_size_mov_addsub,
    .generate = generate_mov_addsub,
    .priority = 6
};

void register_mov_strategies() {
    register_strategy(&mov_original_strategy);
    register_strategy(&mov_arithmetic_strategy);
    register_strategy(&mov_shift_strategy);
    register_strategy(&mov_neg_strategy);
    register_strategy(&mov_not_strategy);
    register_strategy(&mov_xor_strategy);
    register_strategy(&mov_addsub_strategy);
}