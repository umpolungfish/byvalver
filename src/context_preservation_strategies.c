/*
 * Context-aware instruction preservation strategies
 *
 * This file implements strategies that preserve original instruction patterns
 * by making minimal changes while still removing null bytes. These strategies
 * consider the current execution context to make optimal register usage decisions.
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// Context tracking structure
typedef struct {
    uint8_t available_regs[8];  // Track which registers are available
    uint8_t reg_states[8];      // Track the state of registers
} context_t;

// Helper function to check if an instruction contains null bytes in its raw bytes
int instruction_has_null_bytes_raw(cs_insn *insn) {
    for (int i = 0; i < insn->size; i++) {
        if (insn->bytes[i] == 0x00) {
            return 1;
        }
    }
    return 0;
}

// Strategy for register-to-register MOV operations that preserves original pattern when possible
int can_handle_mov_reg_reg(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Must be register to register
    if (insn->detail->x86.operands[0].type != X86_OP_REG || 
        insn->detail->x86.operands[1].type != X86_OP_REG) {
        return 0;
    }

    // Check if the original encoding has null bytes
    return instruction_has_null_bytes_raw(insn);
}

size_t get_size_mov_reg_reg(__attribute__((unused)) cs_insn *insn) {
    // MOV reg1, reg2 is typically 2 bytes with ModR/M byte, but if it has nulls,
    // we might need to go through EAX
    return 4; // Conservative estimate for MOV EAX, reg + MOV dest, EAX
}

void generate_mov_reg_reg(struct buffer *b, cs_insn *insn) {
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;
    uint8_t src_reg = insn->detail->x86.operands[1].reg;

    // If both registers are NOT EAX, use EAX as intermediary
    if (dst_reg != X86_REG_EAX && src_reg != X86_REG_EAX) {
        // MOV EAX, src_reg
        uint8_t mov_eax_src[] = {0x8B, 0x00};
        mov_eax_src[1] = 0xC0 + get_reg_index(src_reg);  // MOV EAX, src_reg
        buffer_append(b, mov_eax_src, 2);

        // MOV dst_reg, EAX
        uint8_t mov_dst_eax[] = {0x8B, 0x00};
        mov_dst_eax[1] = (get_reg_index(dst_reg) << 3) + 0x04;  // MOV dst_reg, EAX using SIB to avoid null
        uint8_t sib_byte = 0x20;  // SIB: scale=00, index=100 (no index), base=000 (EAX)
        buffer_append(b, mov_dst_eax, 2);
        buffer_append(b, &sib_byte, 1);
    } else {
        // One of the registers is EAX, try to avoid ModR/M null byte issues
        uint8_t code[] = {0x89, 0xC0};
        code[1] = (get_reg_index(dst_reg) << 3) + get_reg_index(src_reg);
        if (code[1] == 0) {
            // This would create a null byte in ModR/M, use SIB byte
            if (dst_reg == X86_REG_EAX && src_reg == X86_REG_EAX) {
                // MOV EAX, EAX - this is redundant, so just skip
                return;
            } else if (dst_reg == X86_REG_EAX) {
                // MOV EAX, [EAX] format with SIB
                uint8_t sib_code[] = {0x8B, 0x04, 0x20};  // MOV EAX, [EAX] using SIB
                buffer_append(b, sib_code, 3);
            } else {
                // Use standard approach avoiding the null byte
                uint8_t temp_code[] = {0x8B, 0x00};
                temp_code[1] = (get_reg_index(dst_reg) << 3) + get_reg_index(src_reg);
                buffer_append(b, temp_code, 2);
            }
        } else {
            buffer_append(b, code, 2);
        }
    }
}

strategy_t mov_reg_reg_strategy = {
    .name = "mov_reg_reg",
    .can_handle = can_handle_mov_reg_reg,
    .get_size = get_size_mov_reg_reg,
    .generate = generate_mov_reg_reg,
    .priority = 17  // Very high priority for register-to-register moves
};

// Strategy for INC/DEC register operations
int can_handle_incdec_reg(cs_insn *insn) {
    if ((insn->id != X86_INS_INC && insn->id != X86_INS_DEC) || insn->detail->x86.op_count != 1) {
        return 0;
    }

    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }

    return instruction_has_null_bytes_raw(insn);
}

size_t get_size_incdec_reg(__attribute__((unused)) cs_insn *insn) {
    return 3; // PUSH + INC/DEC + POP pattern
}

void generate_incdec_reg(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;

    // Determine if it's INC or DEC
    uint8_t op_is_inc = (insn->id == X86_INS_INC) ? 1 : 0;

    // Since INC/DEC reg might have null bytes in ModR/M, we'll use arithmetic
    // PUSH reg, ADD reg, 1 (or SUB reg, 1), POP reg pattern
    uint8_t push_reg = 0x50 + get_reg_index(reg);
    buffer_append(b, &push_reg, 1);

    if (op_is_inc) {
        // ADD reg, 1
        if (get_reg_index(reg) == 0) {  // EAX
            uint8_t add_eax_one[] = {0x05, 0x01, 0x00, 0x00, 0x00};  // ADD EAX, 1
            buffer_append(b, add_eax_one, 5);
        } else {
            // Use ADD r32, imm8 form
            uint8_t add_reg_one[] = {0x83, 0xC0, 0x01};
            add_reg_one[1] += get_reg_index(reg);  // ADD reg, 1
            buffer_append(b, add_reg_one, 3);
        }
    } else {
        // DEC: SUB reg, 1
        if (get_reg_index(reg) == 0) {  // EAX
            uint8_t sub_eax_one[] = {0x2D, 0x01, 0x00, 0x00, 0x00};  // SUB EAX, 1
            buffer_append(b, sub_eax_one, 5);
        } else {
            // Use SUB r32, imm8 form
            uint8_t sub_reg_one[] = {0x83, 0xE8, 0x01};
            sub_reg_one[1] += get_reg_index(reg);  // SUB reg, 1
            buffer_append(b, sub_reg_one, 3);
        }
    }

    uint8_t pop_reg = 0x58 + get_reg_index(reg);
    buffer_append(b, &pop_reg, 1);
}

strategy_t incdec_reg_strategy = {
    .name = "incdec_reg",
    .can_handle = can_handle_incdec_reg,
    .get_size = get_size_incdec_reg,
    .generate = generate_incdec_reg,
    .priority = 15  // High priority for INC/DEC operations
};

// Strategy for XOR reg, reg operations (common for zeroing)
int can_handle_xor_reg_reg(cs_insn *insn) {
    if (insn->id != X86_INS_XOR || insn->detail->x86.op_count != 2) {
        return 0;
    }

    if (insn->detail->x86.operands[0].type != X86_OP_REG || 
        insn->detail->x86.operands[1].type != X86_OP_REG) {
        return 0;
    }

    // Check if it's XOR reg, reg (same register)
    if (insn->detail->x86.operands[0].reg != insn->detail->x86.operands[1].reg) {
        return 0;
    }

    return instruction_has_null_bytes_raw(insn);
}

size_t get_size_xor_reg_reg(__attribute__((unused)) cs_insn *insn) {
    return 2; // XOR reg, reg (with SIB if needed to avoid nulls)
}

void generate_xor_reg_reg_context(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;

    // XOR reg, reg is normally 0x31 /r but if ModR/M creates null, use SIB
    uint8_t base_code[] = {0x31, 0xC0};
    base_code[1] = (get_reg_index(reg) << 3) + get_reg_index(reg);

    if (base_code[1] == 0) {
        // This would create null in ModR/M, use SIB byte to avoid it
        // For XOR EAX, EAX specifically
        uint8_t sib_code[] = {0x31, 0x04, 0x20};  // XOR [EAX], EAX using SIB
        sib_code[1] = 0x04 + ((get_reg_index(reg) << 3) & 0x38);  // ModR/M: reg=EAX, r/m=SIB
        buffer_append(b, sib_code, 3);
    } else {
        buffer_append(b, base_code, 2);
    }
}

strategy_t xor_reg_reg_strategy = {
    .name = "xor_reg_reg",
    .can_handle = can_handle_xor_reg_reg,
    .get_size = get_size_xor_reg_reg,
    .generate = generate_xor_reg_reg_context,
    .priority = 16  // High priority for XOR reg, reg
};

// Strategy for simple register PUSH/POP operations
int can_handle_push_pop_reg(cs_insn *insn) {
    if ((insn->id != X86_INS_PUSH && insn->id != X86_INS_POP) || insn->detail->x86.op_count != 1) {
        return 0;
    }

    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }

    return instruction_has_null_bytes_raw(insn);
}

size_t get_size_push_pop_reg(__attribute__((unused)) cs_insn *insn) {
    return 1; // Standard push/pop should be 1 byte
}

void generate_push_pop_reg(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    
    if (insn->id == X86_INS_PUSH) {
        uint8_t push_code = 0x50 + get_reg_index(reg);
        buffer_append(b, &push_code, 1);
    } else { // POP
        uint8_t pop_code = 0x58 + get_reg_index(reg);
        buffer_append(b, &pop_code, 1);
    }
}

strategy_t push_pop_reg_strategy = {
    .name = "push_pop_reg",
    .can_handle = can_handle_push_pop_reg,
    .get_size = get_size_push_pop_reg,
    .generate = generate_push_pop_reg,
    .priority = 17  // Very high priority for push/pop
};

// Register all context preservation strategies
void register_context_preservation_strategies() {
    register_strategy(&mov_reg_reg_strategy);
    register_strategy(&incdec_reg_strategy);
    register_strategy(&xor_reg_reg_strategy);
    register_strategy(&push_pop_reg_strategy);
}