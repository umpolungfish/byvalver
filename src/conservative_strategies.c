#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// Conservative MOV strategy that attempts to preserve original instruction format
int can_handle_conservative_mov(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Must be register destination
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }

    // Must be immediate source
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    // Only handle if it has null bytes (this is for null byte removal)
    return has_null_bytes(insn);
}

size_t get_size_conservative_mov(cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    // uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;  // Removed unused variable

    // For EAX, we can try to use XOR, NEG, or other equivalents
    if (reg == X86_REG_EAX) {
        return 7; // MOV EAX, ~imm + NOT EAX or similar
    }

    // For other registers, we try to maintain the same format
    // C7 /0 with null-free immediate
    return 6;
}

void generate_conservative_mov(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

    // Try various encoding methods to preserve instruction semantics

    // Method 1: Try NOT encoding first (higher priority for conservation)
    uint32_t not_val;
    if (find_not_equivalent(imm, &not_val) && is_null_free(not_val)) {
        // MOV reg, ~imm then NOT reg
        if (reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, not_val);  // Use reliable null-free construction
        } else {
            // Use EAX as temporary
            uint8_t push_eax[] = {0x50};  // Save EAX
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, not_val);  // MOV EAX, not_val (null-free)

            // MOV reg, EAX
            uint8_t mov_reg_eax[] = {0x89, 0xC0};
            mov_reg_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(reg);
            buffer_append(b, mov_reg_eax, 2);

            // Restore original EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }

        // NOT reg
        uint8_t not_code[] = {0xF7, 0xD0};
        not_code[1] = not_code[1] + get_reg_index(reg);
        buffer_append(b, not_code, 2);
        return;
    }

    // Method 2: Try NEG encoding
    uint32_t negated_val;
    if (find_neg_equivalent(imm, &negated_val) && is_null_free(negated_val)) {
        // MOV reg, -imm then NEG reg
        if (reg == X86_REG_EAX) {
            generate_mov_eax_imm(b, negated_val);  // Use reliable null-free construction
        } else {
            // Use EAX as temporary
            uint8_t push_eax[] = {0x50};  // Save EAX
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

        // NEG reg
        uint8_t neg_code[] = {0xF7, 0xD8};
        neg_code[1] = neg_code[1] + get_reg_index(reg);
        buffer_append(b, neg_code, 2);
        return;
    }

    // Method 3: Try ADD/SUB encoding
    uint32_t val1, val2;
    int is_add;
    if (find_addsub_key(imm, &val1, &val2, &is_add) && is_null_free(val1) && is_null_free(val2)) {
        if (reg == X86_REG_EAX) {
            // MOV EAX, val1 (null-free construction)
            generate_mov_eax_imm(b, val1);

            // ADD/SUB EAX, val2 (val2 is null-free per check above)
            uint8_t opcode = is_add ? 0x05 : 0x2D;
            uint8_t code[] = {opcode, 0, 0, 0, 0};
            memcpy(code + 1, &val2, 4);
            buffer_append(b, code, 5);
        } else {
            // For other registers, use save/restore
            uint8_t push_eax[] = {0x50};  // Save EAX
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, val1);  // MOV EAX, val1 (null-free)

            // ADD/SUB EAX, val2 (val2 is null-free per check above)
            uint8_t opcode = is_add ? 0x05 : 0x2D;
            uint8_t code[] = {opcode, 0, 0, 0, 0};
            memcpy(code + 1, &val2, 4);
            buffer_append(b, code, 5);

            // MOV reg, EAX
            uint8_t mov_reg_eax[] = {0x89, 0xC0};
            mov_reg_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(reg);
            buffer_append(b, mov_reg_eax, 2);

            // Restore original EAX
            uint8_t pop_eax[] = {0x58};
            buffer_append(b, pop_eax, 1);
        }
        return;
    }

    // If all conservative methods fail, fall back to the original approach
    // But first, ensure we use our reliable null-free construction
    if (reg == X86_REG_EAX) {
        generate_mov_eax_imm(b, imm);
    } else {
        // Save original register value
        uint8_t push_reg = 0x50 + get_reg_index(reg);
        buffer_append(b, &push_reg, 1);

        // Use EAX to construct the value null-free
        generate_mov_eax_imm(b, imm);

        // Move to target register
        uint8_t mov_to_reg[] = {0x89, 0xC0};
        mov_to_reg[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(reg);
        buffer_append(b, mov_to_reg, 2);

        // Restore original register value
        uint8_t pop_reg = 0x58 + get_reg_index(reg);
        buffer_append(b, &pop_reg, 1);
    }
}

strategy_t conservative_mov_strategy = {
    .name = "conservative_mov",
    .can_handle = can_handle_conservative_mov,
    .get_size = get_size_conservative_mov,
    .generate = generate_conservative_mov,
    .priority = 15  // Higher priority - prefer conservative approaches that preserve original patterns
};

// Conservative arithmetic strategy
int can_handle_conservative_arithmetic(cs_insn *insn) {
    return is_arithmetic_instruction(insn) && has_null_bytes(insn);
}

size_t get_size_conservative_arithmetic(cs_insn *insn) {
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t base, offset;
    int operation;

    if (find_arithmetic_equivalent(imm, &base, &offset, &operation)) {
        // Check if offset has null bytes
        int offset_has_null = 0;
        if (offset > 0xFF) {
            for (int i = 0; i < 4; i++) {
                if (((offset >> (i * 8)) & 0xFF) == 0) {
                    offset_has_null = 1;
                    break;
                }
            }
        }

        if (offset_has_null) {
            // Fall back to standard size
            return 6;
        }

        size_t mov_size = get_mov_eax_imm_size(base);
        size_t arith_size = ((int32_t)(int8_t)offset == (int32_t)offset) ? 3 : 5;
        size_t mov_reg_eax_size = 2;
        return mov_size + arith_size + mov_reg_eax_size;
    }

    return 6;  // Standard size for fallback
}

void generate_conservative_arithmetic(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

    // Try to find arithmetic equivalent
    uint32_t base, offset;
    int operation; // 0 for addition, 1 for subtraction
    if (find_arithmetic_equivalent(imm, &base, &offset, &operation)) {
        // CRITICAL FIX: Check that offset encoding won't have nulls
        int offset_has_null = 0;
        if (offset > 0xFF) {  // Must use 32-bit immediate form
            for (int i = 0; i < 4; i++) {
                if (((offset >> (i * 8)) & 0xFF) == 0) {
                    offset_has_null = 1;
                    break;
                }
            }
        }

        if (offset_has_null) {
            // Offset has null bytes, can't use this approach - fall back
            generate_op_reg_imm(b, insn);
            return;
        }

        // MOV EAX, base
        generate_mov_eax_imm(b, base);

        // Perform the arithmetic operation using EAX
        // Use sign-extended 8-bit form if possible (avoids nulls for small values)
        if ((int32_t)(int8_t)offset == (int32_t)offset) {
            // 83 C0/E8 imm8 - ADD/SUB EAX, imm8 (sign-extended)
            if (operation == 0) {
                uint8_t add_eax_offset[] = {0x83, 0xC0, (uint8_t)offset};
                buffer_append(b, add_eax_offset, 3);
            } else {
                uint8_t sub_eax_offset[] = {0x83, 0xE8, (uint8_t)offset};
                buffer_append(b, sub_eax_offset, 3);
            }
        } else {
            // Must use 32-bit immediate form
            if (operation == 0) { // Addition
                uint8_t add_eax_offset[] = {0x05, 0, 0, 0, 0};
                memcpy(add_eax_offset + 1, &offset, 4);
                buffer_append(b, add_eax_offset, 5);
            } else { // Subtraction
                uint8_t sub_eax_offset[] = {0x2D, 0, 0, 0, 0};
                memcpy(sub_eax_offset + 1, &offset, 4);
                buffer_append(b, sub_eax_offset, 5);
            }
        }

        // Now move the result to the original register
        uint8_t mov_reg_eax[] = {0x89, 0xC0};
        mov_reg_eax[1] = mov_reg_eax[1] + get_reg_index(reg);
        buffer_append(b, mov_reg_eax, 2);
    } else {
        // Fall back to standard approach
        generate_op_reg_imm(b, insn);
    }
}

strategy_t conservative_arithmetic_strategy = {
    .name = "conservative_arithmetic",
    .can_handle = can_handle_conservative_arithmetic,
    .get_size = get_size_conservative_arithmetic,
    .generate = generate_conservative_arithmetic,
    .priority = 14  // High priority - prefer conservative approaches that preserve original patterns
};

// Register the conservative strategies
void register_conservative_strategies() {
    register_strategy(&conservative_mov_strategy);
    register_strategy(&conservative_arithmetic_strategy);
}