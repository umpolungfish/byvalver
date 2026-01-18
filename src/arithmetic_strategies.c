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
    .priority = 10,
    .target_arch = BYVAL_ARCH_X86
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
    if (find_neg_equivalent(target, &negated_val)) {
        // Additional check: make sure negated value itself is null-free
        return is_bad_byte_free(negated_val);
    }
    return 0;
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
    .priority = 9,
    .target_arch = BYVAL_ARCH_X86
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
    .priority = 9,
    .target_arch = BYVAL_ARCH_X86
};

// Arithmetic with XOR strategy
int can_handle_arithmetic_xor(cs_insn *insn) {
    if (!is_valid_arithmetic_reg_imm(insn)) {
        return 0;
    }

    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Check if we can find a good XOR equivalent
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t xor_key;
    if (find_xor_key(target, &xor_key)) {
        // find_xor_key finds key such that both key and (target^key) are null-free
        // So we'll generate: MOV reg, (target^key); XOR reg, key
        uint32_t encoded_val = target ^ xor_key;
        return is_bad_byte_free(xor_key) && is_bad_byte_free(encoded_val);
    }
    return 0;
}

size_t get_size_arithmetic_xor(cs_insn *insn) {
    return get_xor_encoded_arithmetic_size(insn);
}

void generate_arithmetic_xor(struct buffer *b, cs_insn *insn) {
    // Extract operands
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

    // Find XOR decomposition: we have imm = (~imm) XOR xor_key
    uint32_t xor_key;
    if (!find_xor_key(imm, &xor_key)) {
        // If no XOR key found, fall back to regular construction
        if (reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, imm);
        } else {
            // Save EAX first
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, imm);

            // MOV reg, EAX
            uint8_t mov_reg_eax[] = {0x89, 0xC0};
            mov_reg_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(reg);
            buffer_append(b, mov_reg_eax, 2);

            // Restore EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }
        return;
    }

    // Correct XOR decomposition based on how find_xor_key actually works:
    // find_xor_key finds a key such that: (target ^ key) ^ key = target
    // So we do: MOV reg, (target ^ xor_key); XOR reg, xor_key
    uint32_t encoded_val = imm ^ xor_key;

    // Use the decomposition: MOV reg, encoded_val; XOR reg, xor_key
    if (reg == X86_REG_EAX) {
        generate_mov_eax_imm(b, encoded_val);
    } else {
        // Save EAX first
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);

        generate_mov_eax_imm(b, encoded_val);

        // MOV reg, EAX
        uint8_t mov_reg_eax[] = {0x89, 0xC0};
        mov_reg_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(reg);
        buffer_append(b, mov_reg_eax, 2);

        // Restore EAX
        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
    }

    // Then XOR with xor_key
    if (is_bad_byte_free(xor_key)) {
        // Use immediate XOR
        if (xor_key <= 0xFF) {
            // Try to use 8-bit immediate if possible
            uint8_t xor8_code[] = {0x83, 0x00, 0x00};
            xor8_code[1] = 0xF0 + get_reg_index(reg);  // F0-F7 for XOR reg, imm8
            xor8_code[2] = (uint8_t)xor_key;
            buffer_append(b, xor8_code, 3);
        } else {
            // Use 32-bit immediate
            uint8_t xor32_code[] = {0x81, 0x00, 0x00, 0x00, 0x00, 0x00};
            xor32_code[1] = 0xF0 + get_reg_index(reg);  // F0-F7 for XOR reg, imm32
            memcpy(xor32_code + 2, &xor_key, 4);
            buffer_append(b, xor32_code, 6);
        }
    } else {
        // xor_key has nulls, need to load via EAX (though this shouldn't happen due to can_handle check)
        uint8_t push_eax[] = {0x50};  // Save EAX
        buffer_append(b, push_eax, 1);

        generate_mov_eax_imm(b, xor_key);  // Load xor_key into EAX (null-free)

        // XOR reg, EAX
        uint8_t xor_reg_eax[] = {0x31, 0xC0};
        xor_reg_eax[1] = 0xC0 + (get_reg_index(reg) << 3) + get_reg_index(X86_REG_EAX);
        buffer_append(b, xor_reg_eax, 2);

        uint8_t pop_eax[] = {0x58};  // Restore EAX
        buffer_append(b, pop_eax, 1);
    }
}

strategy_t arithmetic_xor_strategy = {
    .name = "arithmetic_xor",
    .can_handle = can_handle_arithmetic_xor,
    .get_size = get_size_arithmetic_xor,
    .generate = generate_arithmetic_xor,
    .priority = 7,
    .target_arch = BYVAL_ARCH_X86
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
    .priority = 7,
    .target_arch = BYVAL_ARCH_X86
};

// REMOVED: arithmetic_substitution_strategy (was redundant and buggy)
// REMOVED: push_xor_polymorph (doesn't belong in arithmetic_strategies.c)
// REMOVED: rotation_encoded (doesn't belong in arithmetic_strategies.c)

void register_arithmetic_strategies() {
    extern strategy_t immediate_arithmetic_strategy;  // From immediate_arithmetic_strategies.c
    extern strategy_t logical_immediate_strategy;  // From test_immediate_strategies.c
    register_strategy(&arithmetic_original_strategy);
    register_strategy(&arithmetic_neg_strategy);
    // register_strategy(&arithmetic_not_strategy);  // Disabled - doesn't make sense for arithmetic
    register_strategy(&arithmetic_xor_strategy);
    register_strategy(&arithmetic_addsub_strategy);
    register_strategy(&immediate_arithmetic_strategy);  // Priority 15
    register_strategy(&logical_immediate_strategy);  // Priority 20
}
