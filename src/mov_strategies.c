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
    .priority = 10,
    .target_arch = BYVAL_ARCH_X86
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
    if (find_neg_equivalent(target, &negated_val) && is_bad_byte_free(negated_val)) {
        return 1; // Can handle with NEG
    }
    return 0;
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
        // Use EAX as temporary to ensure null-free construction
        if (reg == X86_REG_EAX) {
            // MOV EAX, negated_val (null-free construction)
            generate_mov_eax_imm(b, negated_val);
        } else {
            // Use EAX temporarily, then move to target reg
            uint8_t push_eax[] = {0x50};  // Save original EAX
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, negated_val);  // MOV EAX, negated_val (null-free)

            // MOV reg, EAX
            uint8_t mov_reg_eax[] = {0x89, 0xC0};
            mov_reg_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(reg);
            buffer_append(b, mov_reg_eax, 2);

            // Restore original EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }

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
    .priority = 13,
    .target_arch = BYVAL_ARCH_X86
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
    if (find_not_equivalent(target, &not_val) && is_bad_byte_free(not_val)) {
        // Check if other higher-priority strategies can handle it first
        uint32_t neg_val;

        // Don't handle if NEG strategy can handle it (NEG is more efficient than NOT)
        if (find_neg_equivalent(target, &neg_val) && is_bad_byte_free(neg_val)) {
            return 0;
        }

        return 1; // Can handle with NOT
    }
    return 0;
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
    .priority = 12,
    .target_arch = BYVAL_ARCH_X86
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

    if (!has_null_bytes(insn)) {
        return 0;
    }

    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t xor_key;
    if (find_xor_key(target, &xor_key)) {
        // Check if other higher-priority strategies can handle it first
        uint32_t not_val, neg_val;
        uint32_t val1, val2;
        int is_add;

        // Don't handle if NOT strategy can handle it
        if (find_not_equivalent(target, &not_val) && is_bad_byte_free(not_val)) {
            return 0;
        }

        // Don't handle if NEG strategy can handle it
        if (find_neg_equivalent(target, &neg_val) && is_bad_byte_free(neg_val)) {
            return 0;
        }

        // Don't handle if ADD/SUB strategy can handle it
        if (find_addsub_key(target, &val1, &val2, &is_add) && is_bad_byte_free(val1) && is_bad_byte_free(val2)) {
            return 0;
        }

        return 1; // Can handle with XOR
    }
    return 0;
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
    .priority = 6,
    .target_arch = BYVAL_ARCH_X86
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

    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Check if other higher-priority strategies can handle it first
    // to avoid unnecessary attempts
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t not_val, neg_val;
    uint32_t val1, val2;
    int is_add;

    // Don't handle if NOT strategy can handle it
    if (find_not_equivalent(target, &not_val) && is_bad_byte_free(not_val)) {
        return 0;
    }

    // Don't handle if NEG strategy can handle it
    if (find_neg_equivalent(target, &neg_val) && is_bad_byte_free(neg_val)) {
        return 0;
    }

    // Don't handle if ADD/SUB strategy can handle it
    if (find_addsub_key(target, &val1, &val2, &is_add) && is_bad_byte_free(val1) && is_bad_byte_free(val2)) {
        return 0;
    }

    // If no other strategies can handle it efficiently, this strategy can try
    return 1;
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
        if (is_bad_byte_free(shifted)) {
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

    // Try the reverse: shift a null-free value to get our target
    for (int shift_amount = 1; shift_amount <= 24; shift_amount++) {
        // Try to find if we can shift RIGHT to get our target: null_free_val >> shift = target
        // This means null_free_val = target << shift (we shift the target left and then shift it back right)
        uint32_t candidate = target << shift_amount;
        // Check if this recreates target when shifted back (to avoid issues with shifted out bits)
        if ((candidate >> shift_amount) == target) {  // Ensure shifting back gives original target
            if (is_bad_byte_free(candidate)) {
                // MOV reg, candidate (null-free)
                cs_insn temp_insn = *insn;
                temp_insn.detail->x86.operands[1].imm = candidate;
                generate_mov_reg_imm(b, &temp_insn);

                // SHR reg, shift_amount (to get target value)
                uint8_t code[] = {0xC1, 0xE8, 0};
                code[1] = 0xE8 + get_reg_index(reg); // SHR reg, imm8
                code[2] = shift_amount;
                buffer_append(b, code, 3);
                return;
            }
        }

        // Also try: null_free_val << shift = target, so null_free_val = target >> shift
        if (shift_amount < 32) {  // Avoid undefined behavior
            uint32_t candidate = target >> shift_amount;
            // Check if this recreates target when shifted back left (to avoid issues with shifted out bits)
            if ((candidate << shift_amount) == target) {  // Ensure shifting back gives original target
                if (is_bad_byte_free(candidate)) {
                    // MOV reg, candidate (null-free)
                    cs_insn temp_insn = *insn;
                    temp_insn.detail->x86.operands[1].imm = candidate;
                    generate_mov_reg_imm(b, &temp_insn);

                    // SHL reg, shift_amount (to get target value)
                    uint8_t code[] = {0xC1, 0xE0, 0};
                    code[1] = 0xE0 + get_reg_index(reg); // SHL reg, imm8
                    code[2] = shift_amount;
                    buffer_append(b, code, 3);
                    return;
                }
            }
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
    .priority = 7,
    .target_arch = BYVAL_ARCH_X86
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
    if (find_addsub_key(target, &val1, &val2, &is_add) && is_bad_byte_free(val1) && is_bad_byte_free(val2)) {
        // Check if other higher-priority strategies can handle it first
        uint32_t not_val, neg_val;

        // Don't handle if NOT strategy can handle it
        if (find_not_equivalent(target, &not_val) && is_bad_byte_free(not_val)) {
            return 0;
        }

        // Don't handle if NEG strategy can handle it
        if (find_neg_equivalent(target, &neg_val) && is_bad_byte_free(neg_val)) {
            return 0;
        }

        return 1; // Can handle with ADD/SUB
    }
    return 0;
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

    // Double-check that both values are null-free (should be per can_handle)
    if (!is_bad_byte_free(val1) || !is_bad_byte_free(val2)) {
        generate_mov_reg_imm(b, insn);
        return;
    }

    if (target_reg == X86_REG_EAX) {
        // MOV EAX, val1 using null-free construction
        generate_mov_eax_imm(b, val1);

        // ADD/SUB EAX, val2 (where val2 is null-free)
        uint8_t opcode = is_add ? 0x05 : 0x2D;
        uint8_t code[] = {opcode, 0, 0, 0, 0};
        memcpy(code + 1, &val2, 4);
        buffer_append(b, code, 5);
    } else {
        // Save original EAX
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);

        // MOV EAX, val1 using null-free construction
        // The function find_addsub_key finds val1, val2 such that:
        // if is_add: val1 + val2 = target  =>  MOV EAX, val1; ADD EAX, val2
        // if !is_add: val1 - val2 = target  =>  MOV EAX, val1; SUB EAX, val2
        generate_mov_eax_imm(b, val1);

        // ADD/SUB EAX, val2 (where val2 is null-free)
        uint8_t opcode = is_add ? 0x05 : 0x2D;
        uint8_t code[] = {opcode, 0, 0, 0, 0};
        memcpy(code + 1, &val2, 4);
        buffer_append(b, code, 5);

        // MOV target_reg, EAX
        uint8_t mov_reg_eax[] = {0x89, 0xC0};
        mov_reg_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(target_reg);
        buffer_append(b, mov_reg_eax, 2);

        // Restore original EAX
        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
    }
}

strategy_t mov_addsub_strategy = {
    .name = "mov_addsub",
    .can_handle = can_handle_mov_addsub,
    .get_size = get_size_mov_addsub,
    .generate = generate_mov_addsub,
    .priority = 11,
    .target_arch = BYVAL_ARCH_X86
};

// MOV with arithmetic equivalent - REMOVED (redundant with addsub)

void register_mov_strategies() {
    extern strategy_t mov_rip_relative_strategy;  // From mov_rip_strategy.c
    register_strategy(&mov_original_strategy);
    register_strategy(&mov_shift_strategy);
    register_strategy(&mov_neg_strategy);
    register_strategy(&mov_not_strategy);
    register_strategy(&mov_xor_strategy);
    register_strategy(&mov_addsub_strategy);
    register_strategy(&mov_rip_relative_strategy);  // Priority 80
}
