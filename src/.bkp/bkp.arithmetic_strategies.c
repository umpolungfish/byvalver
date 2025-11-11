#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Arithmetic with original strategy
int can_handle_arithmetic_original(cs_insn *insn) {
    return is_arithmetic_instruction(insn) && 
           !has_null_bytes(insn) && 
           (insn->detail->x86.operands[1].imm == 0 || 
            (((insn->detail->x86.operands[1].imm >> 0) & 0xFF) != 0 && 
             ((insn->detail->x86.operands[1].imm >> 8) & 0xFF) != 0 && 
             ((insn->detail->x86.operands[1].imm >> 16) & 0xFF) != 0 && 
             ((insn->detail->x86.operands[1].imm >> 24) & 0xFF) != 0));
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
    .priority = 10  // High priority when no null bytes
};

// Arithmetic with NEG strategy
int can_handle_arithmetic_neg(cs_insn *insn) {
    if (!is_arithmetic_instruction(insn) || !has_null_bytes(insn)) {
        return 0;
    }
    
    // Check if NEG equivalent exists
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t negated_val;
    extern int find_neg_equivalent(uint32_t target, uint32_t *negated_val);
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
    .priority = 9  // High priority when applicable
};

// Arithmetic with XOR strategy
int can_handle_arithmetic_xor(cs_insn *insn) {
    return is_arithmetic_instruction(insn) && has_null_bytes(insn);
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

// Arithmetic with NOT strategy
int can_handle_arithmetic_not(cs_insn *insn) {
    // For this strategy to work with arithmetic operations, we'll focus on MOV operations
    // since the NOT strategy in utils.c is designed for MOV operations
    if (insn->id != X86_INS_MOV || !has_null_bytes(insn)) {
        return 0;
    }
    
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint32_t not_val;
    extern int find_not_equivalent(uint32_t target, uint32_t *not_val);
    return find_not_equivalent(target, &not_val);
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

// Polymorphic XOR encoding strategy for PUSH operations
// This adds polymorphism by providing a XOR-based approach for PUSH instructions
int can_handle_push_xor_polymorph(cs_insn *insn) {
    if (insn->id != X86_INS_PUSH || 
        insn->detail->x86.op_count != 1 || 
        insn->detail->x86.operands[0].type != X86_OP_IMM) {
        return 0;
    }
    
    uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
    
    // Check if it's not handled by string strategy (avoid overlap)
    int likely_char_count = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t byte_val = (imm >> (i * 8)) & 0xFF;
        if ((byte_val >= 0x20 && byte_val <= 0x7E) || 
            (byte_val >= 'A' && byte_val <= 'Z') || 
            (byte_val >= 'a' && byte_val <= 'z') || 
            (byte_val >= '0' && byte_val <= '9')) {
            likely_char_count++;
        }
    }
    
    // Don't handle string-like values to avoid conflict with string strategy
    if (likely_char_count >= 2) {
        return 0;
    }
    
    // Check if the immediate value contains null bytes
    for (int i = 0; i < 4; i++) {
        if (((imm >> (i * 8)) & 0xFF) == 0) {
            return 1;
        }
    }
    return 0;
}

// Find a suitable XOR key that when applied to the target doesn't produce null bytes in the encoded value
int find_xor_key(uint32_t target, uint32_t *xor_key) {
    // Try different XOR keys to see if any produce an encoded value without null bytes
    for (uint32_t key = 0x11111111; key <= 0xEEEEEEEE; key += 0x11111111) {
        uint32_t encoded = target ^ key;
        
        // Check if encoded value has null bytes
        int has_null = 0;
        for (int i = 0; i < 4; i++) {
            if (((encoded >> (i * 8)) & 0xFF) == 0) {
                has_null = 1;
                break;
            }
        }
        
        if (!has_null) {
            *xor_key = key;
            return 1; // Found a suitable key
        }
    }
    return 0; // No suitable key found
}

size_t get_size_push_xor_polymorph(__attribute__((unused)) cs_insn *insn) {
    // MOV EAX, encoded_val + XOR EAX, key + PUSH EAX
    return 11; // 5 (MOV) + 5 (XOR) + 1 (PUSH) = 11 bytes
}

void generate_push_xor_polymorph(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[0].imm;
    
    uint32_t xor_key;
    if (!find_xor_key(target, &xor_key)) {
        // If we can't find a good XOR key, this strategy can't handle it
        // The system will fall back to other strategies
        uint8_t dummy[] = {0x90}; // NOP as placeholder (should not happen in practice due to can_handle check)
        buffer_append(b, dummy, 1);
        return;
    }
    
    uint32_t encoded_val = target ^ xor_key;
    
    // MOV EAX, encoded_val (using null-free construction)
    generate_mov_eax_imm(b, encoded_val);
    
    // XOR EAX, xor_key
    uint8_t xor_eax_key[] = {0x35, 0, 0, 0, 0};  // XOR EAX, imm32
    memcpy(xor_eax_key + 1, &xor_key, 4);
    buffer_append(b, xor_eax_key, 5);
    
    // PUSH EAX
    uint8_t push_eax[] = {0x50};
    buffer_append(b, push_eax, 1);
}

// ROL/ROR encoding strategy for immediate values
// This provides additional polymorphism by using rotation operations

// Find a suitable rotation that produces an encoded value without null bytes
int find_rotation_encoding(uint32_t target, uint8_t *rotation_amount, uint32_t *rotated_value) {
    for (uint8_t rot = 1; rot < 32; rot++) {
        // Try ROL (rotate left)
        uint32_t r = ((target << rot) | (target >> (32 - rot)));
        
        // Check if rotated value has null bytes
        int has_null = 0;
        for (int i = 0; i < 4; i++) {
            if (((r >> (i * 8)) & 0xFF) == 0) {
                has_null = 1;
                break;
            }
        }
        
        if (!has_null) {
            *rotation_amount = rot;
            *rotated_value = r;
            return 1; // ROL found
        }
        
        // Also try ROR (rotate right)
        r = ((target >> rot) | (target << (32 - rot)));
        
        // Check if this rotated value has null bytes
        has_null = 0;
        for (int i = 0; i < 4; i++) {
            if (((r >> (i * 8)) & 0xFF) == 0) {
                has_null = 1;
                break;
            }
        }
        
        if (!has_null) {
            *rotation_amount = rot | 0x80; // Use high bit to indicate ROR vs ROL
            *rotated_value = r;
            return 2; // ROR found
        }
    }
    return 0; // No suitable rotation found
}

int can_handle_rotation_encoded(cs_insn *insn) {
    if (insn->id == X86_INS_PUSH && 
        insn->detail->x86.op_count == 1 && 
        insn->detail->x86.operands[0].type == X86_OP_IMM) {
        
        uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
        
        // Check if it's not handled by string strategy (avoid overlap)
        int likely_char_count = 0;
        for (int i = 0; i < 4; i++) {
            uint8_t byte_val = (imm >> (i * 8)) & 0xFF;
            if ((byte_val >= 0x20 && byte_val <= 0x7E) || 
                (byte_val >= 'A' && byte_val <= 'Z') || 
                (byte_val >= 'a' && byte_val <= 'z') || 
                (byte_val >= '0' && byte_val <= '9')) {
                likely_char_count++;
            }
        }
        
        // Don't handle string-like values to avoid conflict with string strategy
        if (likely_char_count >= 2) {
            return 0;
        }
        
        // Check if the immediate value contains null bytes
        for (int i = 0; i < 4; i++) {
            if (((imm >> (i * 8)) & 0xFF) == 0) {
                // Try to find a rotation encoding
                uint8_t rot_amount;
                uint32_t rot_value;
                return find_rotation_encoding(imm, &rot_amount, &rot_value) != 0;
            }
        }
    }
    return 0;
}

size_t get_size_rotation_encoded(__attribute__((unused)) cs_insn *insn) {
    // MOV EAX, rotated_val + ROL/ROR EAX, imm8 + PUSH EAX
    return 12; // Approximately 5 (MOV) + 3 (ROL/ROR) + 1 (PUSH) = 9-12 bytes
}

void generate_rotation_encoded(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[0].imm;
    
    uint8_t rotation_amount;
    uint32_t rotated_value;
    int rotation_type = find_rotation_encoding(target, &rotation_amount, &rotated_value);
    
    if (rotation_type == 0) {
        // If no rotation found, fall back to system's other strategies
        uint8_t dummy[] = {0x90}; // NOP as placeholder
        buffer_append(b, dummy, 1);
        return;
    }
    
    // MOV EAX, rotated_value (null-free construction)
    generate_mov_eax_imm(b, rotated_value);
    
    // Apply rotation: ROL or ROR
    if ((rotation_amount & 0x80) == 0) {
        // ROL EAX, rotation_amount
        uint8_t ror_inst[] = {0xC1, 0xC0, 0x00}; // ROL EAX, imm8 (C1 C0 is ROL reg32, imm8)
        ror_inst[2] = rotation_amount;
        buffer_append(b, ror_inst, 3);
    } else {
        // ROR EAX, (rotation_amount & 0x7F)
        uint8_t ror_inst[] = {0xC1, 0xC8, 0x00}; // ROR EAX, imm8 (C1 C8 is ROR reg32, imm8)
        ror_inst[2] = (rotation_amount & 0x7F);
        buffer_append(b, ror_inst, 3);
    }
    
    // PUSH EAX
    uint8_t push_eax[] = {0x50};
    buffer_append(b, push_eax, 1);
}

// Arithmetic Equivalent Substitution Strategy
// Find arithmetic combinations that produce target values without null bytes in immediate operands

// Find suitable base and offset values that when combined arithmetically produce the target
int find_arithmetic_equivalent(uint32_t target, uint32_t *base, uint32_t *offset, int *operation) {
    // Check if target itself has null bytes first
    int target_has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((target >> (i * 8)) & 0xFF) == 0) {
            target_has_null = 1;
            break;
        }
    }
    if (!target_has_null) return 0; // Only proceed if target has null bytes
    
    // Use a more efficient approach: try specific patterns that are known to work well
    // For addition: try with small addends that have no nulls
    for (uint32_t o = 1; o < 20000 && o < target; o++) {  // Limit range for efficiency
        uint32_t b = target - o;
        
        // Check if both b and o are null-free
        int base_has_null = 0, offset_has_null = 0;
        
        // Check b for nulls
        for (int i = 0; i < 4; i++) {
            if (((b >> (i * 8)) & 0xFF) == 0) {
                base_has_null = 1;
                break;
            }
        }
        
        // Check o for nulls
        for (int i = 0; i < 4; i++) {
            if (((o >> (i * 8)) & 0xFF) == 0) {
                offset_has_null = 1;
                break;
            }
        }
        
        if (!base_has_null && !offset_has_null) {
            *base = b;
            *offset = o;
            *operation = 0; // Addition (target = b + o, so we do MOV reg, b; ADD reg, o)
            return 1;
        }
    }
    
    // For subtraction: try with small subtrahends that have no nulls
    for (uint32_t o = 1; o < 20000; o++) {  // Limit range for efficiency
        uint32_t b = target + o;  // b - o = target, so b = target + o
        
        // Check if both b and o are null-free
        int base_has_null = 0, offset_has_null = 0;
        
        // Check b for nulls
        for (int i = 0; i < 4; i++) {
            if (((b >> (i * 8)) & 0xFF) == 0) {
                base_has_null = 1;
                break;
            }
        }
        
        // Check o for nulls
        for (int i = 0; i < 4; i++) {
            if (((o >> (i * 8)) & 0xFF) == 0) {
                offset_has_null = 1;
                break;
            }
        }
        
        if (!base_has_null && !offset_has_null) {
            *base = b;
            *offset = o;
            *operation = 1; // Subtraction (target = b - o, so we do MOV reg, b; SUB reg, o)
            return 1;
        }
    }
    
    return 0; // No suitable arithmetic equivalent found
}

int can_handle_arithmetic_substitution(cs_insn *insn) {
    // Handle MOV, ADD, SUB, AND, OR, XOR, CMP instructions where immediate contains nulls
    if ((insn->id == X86_INS_MOV || insn->id == X86_INS_ADD || insn->id == X86_INS_SUB || 
         insn->id == X86_INS_AND || insn->id == X86_INS_OR || insn->id == X86_INS_XOR || 
         insn->id == X86_INS_CMP) &&
        insn->detail->x86.op_count >= 2 && 
        insn->detail->x86.operands[1].type == X86_OP_IMM) {
        
        uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
        
        // Check if the immediate value contains null bytes
        int has_null = 0;
        for (int i = 0; i < 4; i++) {
            if (((imm >> (i * 8)) & 0xFF) == 0) {
                has_null = 1;
                break;
            }
        }
        
        if (has_null) {
            // Check if we can find an arithmetic equivalent
            uint32_t base, offset;
            int operation;
            return find_arithmetic_equivalent(imm, &base, &offset, &operation);
        }
    }
    return 0;
}

size_t get_size_arithmetic_substitution(__attribute__((unused)) cs_insn *insn) {
    // MOV EAX, base_val (5 bytes) + ADD/SUB EAX, offset (6 bytes) = 11 bytes for EAX
    // For other registers: MOV reg, base_val (6 bytes) + PUSH EAX (1) + MOV EAX, base_val (5) + OP EAX, offset (6) + MOV reg, EAX (2) + POP EAX (1) = 21 bytes
    return 12; // Conservative estimate
}

void generate_arithmetic_substitution(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t target_reg = insn->detail->x86.operands[0].reg;
    uint32_t base, offset;
    int operation; // 0 for addition, 1 for subtraction
    
    if (!find_arithmetic_equivalent(target, &base, &offset, &operation)) {
        // Fallback to other strategies if arithmetic equivalent not found
        generate_mov_reg_imm(b, insn);
        return;
    }
    
    // If target register is EAX, we can work directly
    if (target_reg == X86_REG_EAX) {
        // MOV EAX, base
        cs_insn temp_insn = *insn;
        temp_insn.detail->x86.operands[0].reg = X86_REG_EAX;
        temp_insn.detail->x86.operands[1].imm = base;
        generate_mov_reg_imm(b, &temp_insn);
        
        // Perform the arithmetic operation
        if (operation == 0) { // Addition
            uint8_t add_eax_offset[] = {0x05, 0, 0, 0, 0};  // ADD EAX, offset
            memcpy(add_eax_offset + 1, &offset, 4);
            buffer_append(b, add_eax_offset, 5);
        } else { // Subtraction
            uint8_t sub_eax_offset[] = {0x2D, 0, 0, 0, 0};  // SUB EAX, offset  
            memcpy(sub_eax_offset + 1, &offset, 4);
            buffer_append(b, sub_eax_offset, 5);
        }
    } else {
        // For other registers, use a save/restore approach
        // PUSH EAX
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);
        
        // MOV EAX, base
        cs_insn temp_insn = *insn;
        temp_insn.detail->x86.operands[0].reg = X86_REG_EAX;
        temp_insn.detail->x86.operands[1].imm = base;
        generate_mov_reg_imm(b, &temp_insn);
        
        // Perform the arithmetic operation (add/sub)
        if (operation == 0) { // Addition
            uint8_t add_eax_offset[] = {0x05, 0, 0, 0, 0};  // ADD EAX, offset
            memcpy(add_eax_offset + 1, &offset, 4);
            buffer_append(b, add_eax_offset, 5);
        } else { // Subtraction
            uint8_t sub_eax_offset[] = {0x2D, 0, 0, 0, 0};  // SUB EAX, offset
            memcpy(sub_eax_offset + 1, &offset, 4);
            buffer_append(b, sub_eax_offset, 5);
        }
        
        // MOV target_reg, EAX
        uint8_t mov_reg_eax[] = {0x89, 0xC0};  // MOV reg, EAX
        mov_reg_eax[1] = mov_reg_eax[1] + get_reg_index(target_reg);
        buffer_append(b, mov_reg_eax, 2);
        
        // POP EAX
        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
    }
}

strategy_t arithmetic_substitution_strategy = {
    .name = "arithmetic_substitution",
    .can_handle = can_handle_arithmetic_substitution,
    .get_size = get_size_arithmetic_substitution,
    .generate = generate_arithmetic_substitution,
    .priority = 10 // High priority to ensure arithmetic substitution is considered
};

// Arithmetic with ADD/SUB encoding strategy
int can_handle_arithmetic_addsub(cs_insn *insn) {
    return is_arithmetic_instruction(insn) && has_null_bytes(insn);
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

void register_arithmetic_strategies() {
    register_strategy(&arithmetic_original_strategy);
    register_strategy(&arithmetic_neg_strategy);
    register_strategy(&arithmetic_not_strategy);
    register_strategy(&arithmetic_xor_strategy);
    register_strategy(&arithmetic_substitution_strategy);
    register_strategy(&arithmetic_addsub_strategy);
}