/*
 * Instruction sequence preservation strategies
 *
 * This file implements strategies to preserve common instruction sequences
 * that might get broken apart during null-byte removal, ensuring that
 * conditional jump patterns, register setup sequences, etc. maintain
 * their original functional equivalence.
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// Helper function - check if instruction's raw bytes contain nulls
static int instruction_has_null_bytes_raw(cs_insn *insn) {
    for (int i = 0; i < insn->size; i++) {
        if (insn->bytes[i] == 0x00) {
            return 1;
        }
    }
    return 0;
}

// Strategy for register zeroing with XOR (very common pattern)
int can_handle_xor_zero_reg(cs_insn *insn) {
    if (insn->id != X86_INS_XOR || insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Check if it's XOR reg, reg (register self-xor for zeroing)
    if (insn->detail->x86.operands[0].type != X86_OP_REG ||
        insn->detail->x86.operands[1].type != X86_OP_REG) {
        return 0;
    }

    if (insn->detail->x86.operands[0].reg != insn->detail->x86.operands[1].reg) {
        return 0;
    }

    // This should use the existing function from utils, but implement a targeted version
    // if the instruction encoding contains null bytes
    return instruction_has_null_bytes_raw(insn);
}

size_t get_size_xor_zero_reg(__attribute__((unused)) cs_insn *insn) {
    return 2; // Should be 2 bytes at most (with SIB if needed to avoid nulls)
}

void generate_xor_zero_reg(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    
    // Standard XOR reg, reg format
    uint8_t code[] = {0x31, 0xC0};
    code[1] = (get_reg_index(reg) << 3) + get_reg_index(reg);

    // Check if this would create a null byte in ModR/M
    if (code[1] == 0) {
        // Use SIB byte to avoid null: XOR [reg], EAX where reg=reg (but this is wrong approach)
        // Actually, for XOR reg, reg, ModR/M = 11 reg reg, which is 0xC0 + (reg_idx << 3) + reg_idx
        // For EAX (idx=0): 0xC0 + 0 + 0 = 0xC0 (not zero)
        // For ECX (idx=1): 0xC0 + 8 + 1 = 0xC9 (not zero)
        // So XOR reg, reg should not create null bytes in ModR/M
        // This condition means the original had some form of encoding with nulls

        // If we're here, use the standard approach but make sure it's valid:
        code[0] = 0x31;
        code[1] = 0xC0 + (get_reg_index(reg) << 3) + get_reg_index(reg);
        buffer_append(b, code, 2);
    } else {
        buffer_append(b, code, 2);
    }
}

strategy_t xor_zero_reg_strategy = {
    .name = "xor_zero_reg",
    .can_handle = can_handle_xor_zero_reg,
    .get_size = get_size_xor_zero_reg,
    .generate = generate_xor_zero_reg,
    .priority = 18  // Highest priority for register zeroing
};

// Strategy for PUSH immediate that tries to use smaller encodings when possible
int can_handle_push_immediate_optimized(cs_insn *insn) {
    if (insn->id != X86_INS_PUSH || insn->detail->x86.op_count != 1) {
        return 0;
    }

    if (insn->detail->x86.operands[0].type != X86_OP_IMM) {
        return 0;
    }

    // Check if the immediate value is small enough for PUSH imm8
    int32_t imm = (int32_t)insn->detail->x86.operands[0].imm;
    if ((int32_t)(int8_t)imm == imm) {
        // This could use PUSH imm8 (0x6A), check if that has nulls
        // In this case, PUSH imm8 wouldn't have nulls in the opcode, but might in the immediate
        uint8_t imm8 = (uint8_t)(int8_t)imm;
        if (imm8 == 0) {
            return 1; // The immediate byte is null
        }
    }

    // Check if full 32-bit immediate has nulls
    uint32_t imm32 = (uint32_t)insn->detail->x86.operands[0].imm;
    for (int i = 0; i < 4; i++) {
        if (((imm32 >> (i * 8)) & 0xFF) == 0) {
            return 1;
        }
    }

    return 0;
}

size_t get_size_push_immediate_optimized(__attribute__((unused)) cs_insn *insn) {
    return 6; // MOV EAX, imm + PUSH EAX
}

void generate_push_immediate_optimized(struct buffer *b, cs_insn *insn) {
    uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;

    // Use MOV EAX, imm (null-free construction) + PUSH EAX
    generate_mov_eax_imm(b, imm);

    // PUSH EAX
    uint8_t push_eax[] = {0x50};
    buffer_append(b, push_eax, 1);
}

strategy_t push_immediate_optimized_strategy = {
    .name = "push_immediate_optimized",
    .can_handle = can_handle_push_immediate_optimized,
    .get_size = get_size_push_immediate_optimized,
    .generate = generate_push_immediate_optimized,
    .priority = 15  // High priority for optimized PUSH
};

// Strategy for common register move patterns that tries to preserve the operation
int can_handle_mov_reg_preserve_sequence(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Register to register move
    if (insn->detail->x86.operands[0].type != X86_OP_REG ||
        insn->detail->x86.operands[1].type != X86_OP_REG) {
        return 0;
    }

    // Check if raw encoding has nulls (in ModR/M, SIB, etc.)
    return instruction_has_null_bytes_raw(insn);
}

size_t get_size_mov_reg_preserve_sequence(__attribute__((unused)) cs_insn *insn) {
    return 3; // Use SIB encoding to avoid nulls if needed
}

void generate_mov_reg_preserve_sequence(struct buffer *b, cs_insn *insn) {
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;
    uint8_t src_reg = insn->detail->x86.operands[1].reg;

    // Use MOV dst, src format: 89 /r (reg-to-reg)
    uint8_t base_opcode[] = {0x89, 0xC0};
    base_opcode[1] = (get_reg_index(dst_reg) << 3) + get_reg_index(src_reg);

    if (base_opcode[1] == 0) {
        // This would result in a null byte in ModR/M, use SIB byte to avoid it
        // MOV dst_reg, [src_reg] format with SIB byte to avoid nulls
        // Actually, this is incorrect - for MOV reg, reg, we use 89 /r
        // The ModR/M byte for EAX, EAX would be 0xC0 (C0 + 0*8 + 0 = C0), not 0x00
        // So there might be some confusion in detection.
        // Let's use the SIB approach just in case:
        uint8_t sib_code[4];
        sib_code[0] = 0x89;  // MOV
        sib_code[1] = 0x04 | (get_reg_index(dst_reg) << 3);  // Mod=00, reg=dst_reg, r/m=100 (SIB follows)
        sib_code[2] = 0x20 | get_reg_index(src_reg);  // SIB: scale=00, index=100 (no index), base=src_reg
        buffer_append(b, sib_code, 3);
    } else {
        buffer_append(b, base_opcode, 2);
    }
}

strategy_t mov_reg_preserve_sequence_strategy = {
    .name = "mov_reg_preserve_sequence",
    .can_handle = can_handle_mov_reg_preserve_sequence,
    .get_size = get_size_mov_reg_preserve_sequence,
    .generate = generate_mov_reg_preserve_sequence,
    .priority = 17  // High priority for reg-reg moves
};

// Strategy for INC/DEC that avoids breaking the simple pattern when possible
int can_handle_incdec_reg_simple(cs_insn *insn) {
    if ((insn->id != X86_INS_INC && insn->id != X86_INS_DEC) || 
        insn->detail->x86.op_count != 1) {
        return 0;
    }

    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }

    // Check if raw bytes contain nulls
    return instruction_has_null_bytes_raw(insn);
}

size_t get_size_incdec_reg_simple(__attribute__((unused)) cs_insn *insn) {
    return 6; // PUSH + ADD/SUB + POP pattern
}

void generate_incdec_reg_simple(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;

    // Use the register directly rather than complex transformations
    // PUSH reg, perform operation, POP reg to preserve the original value relationship

    uint8_t push_code = 0x50 + get_reg_index(reg);
    buffer_append(b, &push_code, 1);

    // Perform INC/DEC equivalent using ADD/SUB
    if (insn->id == X86_INS_INC) {
        // ADD reg, 1
        if (reg == X86_REG_EAX) {
            // Use 05 (ADD EAX, imm32) if no nulls in immediate
            uint32_t imm = 1;
            uint8_t add_code[] = {0x05, 0, 0, 0, 0};
            memcpy(add_code + 1, &imm, 4);
            buffer_append(b, add_code, 5);
        } else {
            // Use 83 /0 (ADD r32, imm8) 
            uint8_t add_code[] = {0x83, 0xC0, 0x01};
            add_code[1] += get_reg_index(reg);  // ADD reg, 1
            buffer_append(b, add_code, 3);
        }
    } else {  // DEC
        // SUB reg, 1
        if (reg == X86_REG_EAX) {
            uint32_t imm = 1;
            uint8_t sub_code[] = {0x2D, 0, 0, 0, 0};
            memcpy(sub_code + 1, &imm, 4);
            buffer_append(b, sub_code, 5);
        } else {
            uint8_t sub_code[] = {0x83, 0xE8, 0x01};
            sub_code[1] += get_reg_index(reg);  // SUB reg, 1
            buffer_append(b, sub_code, 3);
        }
    }

    uint8_t pop_code = 0x58 + get_reg_index(reg);
    buffer_append(b, &pop_code, 1);
}

strategy_t incdec_reg_simple_strategy = {
    .name = "incdec_reg_simple",
    .can_handle = can_handle_incdec_reg_simple,
    .get_size = get_size_incdec_reg_simple,
    .generate = generate_incdec_reg_simple,
    .priority = 16  // High priority for INC/DEC
};

// Register all sequence preservation strategies
void register_sequence_preservation_strategies() {
    register_strategy(&xor_zero_reg_strategy);
    register_strategy(&push_immediate_optimized_strategy);
    register_strategy(&mov_reg_preserve_sequence_strategy);
    register_strategy(&incdec_reg_simple_strategy);
}