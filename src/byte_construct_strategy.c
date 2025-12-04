#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

/*
 * Strategy: Byte-by-byte construction for immediate values that can't be handled by other methods
 * This strategy constructs the target value byte-by-byte, starting with clearing a register
 * and then setting each non-zero byte individually.
 */

int can_handle_byte_construct(cs_insn *insn) {
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
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Check if other strategies can handle this first
    // We only want to use this as a fallback when other strategies fail
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t negated_val, not_val;
    uint32_t val1, val2;
    int is_add;

    // Check if NEG strategy can handle it
    if (find_neg_equivalent(target, &negated_val)) {
        return 0;
    }

    // Check if NOT strategy can handle it
    if (find_not_equivalent(target, &not_val)) {
        return 0;
    }

    // Check if ADD/SUB strategy can handle it
    if (find_addsub_key(target, &val1, &val2, &is_add)) {
        return 0;
    }

    // Check if XOR strategy can handle it
    uint32_t xor_key;
    if (find_xor_key(target, &xor_key)) {
        return 0;
    }

    // Check if arithmetic equivalent strategy can handle it
    uint32_t base, offset;
    int operation;
    if (find_arithmetic_equivalent(target, &base, &offset, &operation)) {
        return 0;
    }

    // If none of the other strategies can handle it, use byte construction
    return 1;
}

size_t get_size_byte_construct(cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t reg = insn->detail->x86.operands[0].reg;
    
    // Size calculation: 
    // - Clear register: XOR reg, reg (2 bytes if not EAX, 1 if EAX with 31 C0 pattern)
    // - For each non-zero byte: MOV reg+offs, imm8 (2-4 bytes depending on addressing)
    size_t size = 2; // Initial clear operation
    
    // Add size for each non-zero byte
    for (int i = 0; i < 4; i++) {
        uint8_t byte_val = (target >> (i * 8)) & 0xFF;
        if (byte_val != 0) {
            // MOV to specific byte in register
            if (reg == X86_REG_EAX && i == 0) {
                size += 2; // MOV AL, imm8 (0xB0 + imm8)
            } else if (reg == X86_REG_ECX && i == 0) {
                size += 2; // MOV CL, imm8 (0xB1 + imm8)
            } else if (reg == X86_REG_EDX && i == 0) {
                size += 2; // MOV DL, imm8 (0xB2 + imm8)
            } else if (reg == X86_REG_EBX && i == 0) {
                size += 2; // MOV BL, imm8 (0xB3 + imm8)
            } else {
                // Use MOV [reg+offs], imm8 pattern
                size += 3; // MOV [reg], imm8 with appropriate addressing
            }
            
            // Need to shift if not the lowest byte
            if (i > 0) {
                size += 4; // SHL reg, 8 (for each position shift)
            }
        }
    }
    
    // Conservative estimate - actual size may vary based on implementation
    return 15; // Conservative upper bound
}

void generate_byte_construct(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t reg = insn->detail->x86.operands[0].reg;

    // First, clear the target register
    if (reg == X86_REG_EAX) {
        // Use XOR EAX, EAX (2 bytes) to clear
        uint8_t clear_eax[] = {0x31, 0xC0};
        buffer_append(b, clear_eax, 2);
    } else {
        // Use XOR reg, reg to clear
        uint8_t clear_reg[] = {0x31, 0xC0};
        clear_reg[1] = clear_reg[1] + (get_reg_index(reg) << 3) + get_reg_index(reg);
        buffer_append(b, clear_reg, 2);
    }

    // Now construct the value byte by byte
    // We'll build the value by setting each byte position
    uint8_t temp_reg = X86_REG_ECX; // Use ECX as temporary
    if (reg == X86_REG_ECX) temp_reg = X86_REG_EDX;
    if (reg == X86_REG_EDX) temp_reg = X86_REG_EBX;
    if (reg == X86_REG_EBX) temp_reg = X86_REG_ESI;

    // Process each byte of the target value
    for (int byte_pos = 0; byte_pos < 4; byte_pos++) {
        uint8_t byte_val = (target >> (byte_pos * 8)) & 0xFF;
        
        if (byte_val != 0) {
            // Load the byte value into temporary register
            uint8_t mov_temp_val[] = {0xB0, byte_val}; // MOV AL, imm8
            mov_temp_val[0] = 0xB0 + get_reg_index(temp_reg); // Adjust for correct register
            buffer_append(b, mov_temp_val, 2);
            
            // Shift the byte to correct position
            for (int shift = 0; shift < byte_pos; shift++) {
                uint8_t shl_temp[] = {0xC1, 0xE0, 0x08}; // SHL temp_reg, 8
                shl_temp[1] = 0xE0 + get_reg_index(temp_reg);
                buffer_append(b, shl_temp, 3);
            }
            
            // OR the temporary value into the target register
            uint8_t or_reg_temp[] = {0x09, 0xC0};
            or_reg_temp[1] = or_reg_temp[1] + (get_reg_index(reg) << 3) + get_reg_index(temp_reg);
            buffer_append(b, or_reg_temp, 2);
        }
    }
}

strategy_t byte_construct_strategy = {
    .name = "BYTE_CONSTRUCT_MOV",
    .can_handle = can_handle_byte_construct,
    .get_size = get_size_byte_construct,
    .generate = generate_byte_construct,
    .priority = 5  // Lower priority - this is a fallback strategy
};

void register_byte_construct_strategy() {
    register_strategy(&byte_construct_strategy);
}