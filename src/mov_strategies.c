#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// MOV with original strategy - FIXED to check operand types
int can_handle_mov_original(cs_insn *insn) {
    // Only handle MOV reg, imm (NOT memory operands)
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }
    
    // CRITICAL FIX: Must be register destination, not memory
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }
    
    // Must be immediate source
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }
    
    // Only handle if no null bytes
    if (has_null_bytes(insn)) {
        return 0;
    }
    
    return 1;
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
    .priority = 10
};

// MOV with NEG strategy - FIXED to check operand types
int can_handle_mov_neg(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }
    
    // CRITICAL FIX: Must be register destination
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }
    
    // Must be immediate source
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }
    
    if (!has_null_bytes(insn)) {
        return 0;
    }
    
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t negated_val;
    return find_neg_equivalent(target, &negated_val);
}

size_t get_size_mov_neg(cs_insn *insn) {
    // MOV reg, negated_val (5-15 bytes depending on construction complexity) + NEG reg (2 bytes)
    // Total: 7-17 bytes depending on how complex the null-free construction is
    (void)insn; // Unused parameter
    return 15; // Conservative estimate
}

void generate_mov_neg(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

    // Find the negated value that has no null bytes
    uint32_t negated_val;
    if (find_neg_equivalent(imm, &negated_val)) {
        // MOV reg, negated_val (using null-free construction)
        cs_insn temp_insn = *insn;
        temp_insn.detail->x86.operands[1].imm = negated_val;
        generate_mov_reg_imm(b, &temp_insn);

        // NEG reg (to get the original value back)
        uint8_t neg_code[] = {0xF7, 0xD8};
        neg_code[1] = neg_code[1] + get_reg_index(reg);
        buffer_append(b, neg_code, 2);
    } else {
        // If no suitable negated value found, fall back to original
        generate_mov_reg_imm(b, insn);
    }
}

strategy_t mov_neg_strategy = {
    .name = "mov_neg",
    .can_handle = can_handle_mov_neg,
    .get_size = get_size_mov_neg,
    .generate = generate_mov_neg,
    .priority = 13
};

// MOV with NOT strategy - FIXED
int can_handle_mov_not(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }
    
    // CRITICAL FIX: Must be register destination
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }
    
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }
    
    if (!has_null_bytes(insn)) {
        return 0;
    }
    
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t not_val;
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
    .priority = 12
};

// MOV with XOR strategy - FIXED
int can_handle_mov_xor(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }
    
    // CRITICAL FIX: Must be register destination
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }
    
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }
    
    return has_null_bytes(insn);
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

// MOV with shift strategy - FIXED
int can_handle_mov_shift(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }

    // CRITICAL FIX: Must be register destination
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }

    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    return has_null_bytes(insn);
}

size_t get_size_mov_shift(cs_insn *insn) {
    // Conservative estimate accounting for the MOV reg, shifted_val (5 bytes) + shift operation (3 bytes)
    // Total: ~8 bytes (could be more complex)
    (void)insn; // Unused parameter
    return 12; // Conservative estimate with buffer for complex cases
}

void generate_mov_shift(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;

    // Try different shift amounts to see if we can get a null-free intermediate value
    for (int shift_amount = 1; shift_amount <= 24; shift_amount++) {
        // Try left shifts (SHL) - multiply by 2^shift
        uint32_t shifted = target << shift_amount;
        if (is_null_free(shifted)) {
            // MOV reg, shifted_value
            cs_insn temp_insn = *insn;
            temp_insn.detail->x86.operands[1].imm = shifted;
            generate_mov_reg_imm(b, &temp_insn);

            // SHR reg, shift_amount (to get back to original value)
            uint8_t code[] = {0xC1, 0xE8, 0};
            code[1] = 0xE8 + get_reg_index(reg);
            code[2] = shift_amount;
            buffer_append(b, code, 3);
            return;
        }

        // Try right shifts (SHR) - divide by 2^shift, then compensate by multiplying
        // Note: this is more complex because we'd need to multiply back, which introduces more complexity
        // So we'll focus on left shifts which are more straightforward
    }

    // Try the reverse: see if shifting a null-free value can produce our target
    for (int shift_amount = 1; shift_amount <= 24; shift_amount++) {
        // For right shifts: shifted_value >> shift_amount = target
        // So shifted_value = target << shift_amount (with potential issues)
        // Instead, let's try: if target << shift produces a null-free value, we can shift right
        uint32_t shifted = target << shift_amount;
        if (is_null_free(shifted)) {
            // MOV reg, shifted_value (null-free)
            cs_insn temp_insn = *insn;
            temp_insn.detail->x86.operands[1].imm = shifted;
            generate_mov_reg_imm(b, &temp_insn);

            // SHR reg, shift_amount (to get target value back)
            uint8_t code[] = {0xC1, 0xE8, 0};
            code[1] = 0xE8 + get_reg_index(reg);
            code[2] = shift_amount;
            buffer_append(b, code, 3);
            return;
        }
    }

    // If no suitable shift found, fall back to the original implementation
    generate_mov_reg_imm(b, insn);
}

strategy_t mov_shift_strategy = {
    .name = "mov_shift",
    .can_handle = can_handle_mov_shift,
    .get_size = get_size_mov_shift,
    .generate = generate_mov_shift,
    .priority = 7
};

// MOV with ADD/SUB strategy - FIXED
int can_handle_mov_addsub(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }
    
    // CRITICAL FIX: Must be register destination
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }
    
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }
    
    if (!has_null_bytes(insn)) {
        return 0;
    }
    
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t val1, val2;
    int is_add;
    return find_addsub_key(target, &val1, &val2, &is_add);
}

size_t get_size_mov_addsub(cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    if (reg == X86_REG_EAX) {
        return 10;
    }
    return 14;
}

void generate_mov_addsub(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t target_reg = insn->detail->x86.operands[0].reg;

    uint32_t val1, val2;
    int is_add;
    if (!find_addsub_key(target, &val1, &val2, &is_add)) {
        generate_mov_reg_imm(b, insn);
        return;
    }

    cs_insn temp_insn = *insn;

    if (target_reg == X86_REG_EAX) {
        temp_insn.detail->x86.operands[1].imm = val1;
        generate_mov_reg_imm(b, &temp_insn);

        uint8_t opcode = is_add ? 0x05 : 0x2D;
        uint8_t code[] = {opcode, 0, 0, 0, 0};
        memcpy(code + 1, &val2, 4);
        buffer_append(b, code, 5);
    } else {
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);

        generate_mov_eax_imm(b, val1);

        uint8_t opcode = is_add ? 0x05 : 0x2D;
        uint8_t code[] = {opcode, 0, 0, 0, 0};
        memcpy(code + 1, &val2, 4);
        buffer_append(b, code, 5);

        uint8_t mov_reg_eax[] = {0x89, 0xC0 + get_reg_index(target_reg)};
        buffer_append(b, mov_reg_eax, 2);

        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
    }
}

strategy_t mov_addsub_strategy = {
    .name = "mov_addsub",
    .can_handle = can_handle_mov_addsub,
    .get_size = get_size_mov_addsub,
    .generate = generate_mov_addsub,
    .priority = 11
};

// MOV with arithmetic equivalent - REMOVED (redundant with addsub)

void register_mov_strategies() {
    register_strategy(&mov_original_strategy);
    register_strategy(&mov_shift_strategy);
    register_strategy(&mov_neg_strategy);
    register_strategy(&mov_not_strategy);
    register_strategy(&mov_xor_strategy);
    register_strategy(&mov_addsub_strategy);
}
