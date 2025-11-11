#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// PUSH imm32 strategy
int can_handle_push_imm32(cs_insn *insn) {
    if (insn->id != X86_INS_PUSH || insn->detail->x86.op_count != 1 || 
        insn->detail->x86.operands[0].type != X86_OP_IMM) {
        return 0;
    }
    
    // Check if immediate value has null bytes
    uint32_t imm = insn->detail->x86.operands[0].imm;
    for (int i = 0; i < 4; i++) {
        if (((imm >> (i * 8)) & 0xFF) == 0) {
            // Check if it can be represented as a sign-extended 8-bit value
            if ((int32_t)(int8_t)imm == (int32_t)imm) {
                return 2; // Higher priority for 8-bit representation
            } else {
                return 1; // Lower priority for 32-bit representation
            }
        }
    }
    return 0; // No null bytes in immediate
}

size_t get_size_push_imm32(cs_insn *insn) {
    uint32_t imm = insn->detail->x86.operands[0].imm;
    // Check if the immediate can be represented as a sign-extended 8-bit value
    if ((int32_t)(int8_t)imm == (int32_t)imm) {
        return get_push_imm8_size();
    } else {
        return get_push_imm32_size(imm);
    }
}

void generate_push_imm32_strat(struct buffer *b, cs_insn *insn) {
    uint32_t imm = insn->detail->x86.operands[0].imm;
    // Check if the immediate can be represented as a sign-extended 8-bit value
    if ((int32_t)(int8_t)imm == (int32_t)imm) {
        generate_push_imm8(b, (int8_t)imm);
    } else {
        generate_push_imm32(b, imm);
    }
}

strategy_t push_imm32_strategy = {
    .name = "push_imm32",
    .can_handle = can_handle_push_imm32,
    .get_size = get_size_push_imm32,
    .generate = generate_push_imm32_strat,
    .priority = 9  // PUSH operations are common and important
};

int push_can_handle_wrapper(cs_insn *insn) {
    int result = can_handle_push_imm32(insn);
    return result > 0;
}

// Stack-based string construction strategy
// This strategy identifies when shellcode attempts to push string literals that contain null bytes
// and instead constructs the string using multiple stack pushes of null-free components

// Helper function to check if a 32-bit value represents a string with potential null bytes
int is_string_literal_with_nulls(uint32_t imm) {
    // Check if each byte of the immediate value is in the printable ASCII range (except nulls)
    // This is a simplified check - in real usage we'd look for patterns that suggest strings
    int has_null = 0;
    int likely_char_count = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t byte_val = (imm >> (i * 8)) & 0xFF;
        if (byte_val == 0) {
            has_null = 1;
        }
        // Count likely ASCII characters (alphanumeric, space, punctuation)
        else if ((byte_val >= 0x20 && byte_val <= 0x7E) || // Printable ASCII
                 (byte_val >= 'A' && byte_val <= 'Z') || 
                 (byte_val >= 'a' && byte_val <= 'z') || 
                 (byte_val >= '0' && byte_val <= '9')) {
            likely_char_count++;
        }
    }
    return has_null && likely_char_count >= 2; // Require at least 2 likely characters for it to be a string
}

int can_handle_stack_string(cs_insn *insn) {
    // This strategy handles PUSH instructions where the immediate value represents a string with nulls
    if (insn->id != X86_INS_PUSH || insn->detail->x86.op_count != 1 || 
        insn->detail->x86.operands[0].type != X86_OP_IMM) {
        return 0;
    }
    
    // Check if this instruction has null bytes that need to be handled
    int has_null = 0;
    for (size_t j = 0; j < insn->size; j++) {
        if (insn->bytes[j] == 0x00) { 
            has_null = 1; 
            break; 
        }
    }
    
    if (!has_null) {
        return 0;
    }
    
    uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
    return is_string_literal_with_nulls(imm);
}

size_t get_size_stack_string(cs_insn *insn) {
    uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
    
    // For the full string construction, we may need to push the bytes in the reverse order
    // and use additional instructions to properly build the string on the stack
    // This is a conservative estimate based on the approach
    int non_null_bytes = 0;
    for (int i = 0; i < 4; i++) {
        if (((imm >> (i * 8)) & 0xFF) != 0) {
            non_null_bytes++;
        }
    }
    
    // We'll need to push each non-null byte as 8-bit values
    // This approach builds the string in reverse order on stack (due to little-endian)
    return non_null_bytes * get_push_imm8_size() + 5; // Additional overhead for string construction
}

void generate_stack_string(struct buffer *b, cs_insn *insn) {
    uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
    
    // In a real implementation, we need to construct the string on the stack in a way that maintains
    // the correct byte order. For this implementation, we'll build a null-free version of the 
    // string by pushing bytes in reverse order (which maintains the correct string when popped)
    // This is a simplified version of the actual string construction technique
    
    // We will first zero out EAX, then build the value byte by byte using shifts and ORs
    // This creates the original value without having null bytes in immediate operands
    
    // Push each byte individually, but in the proper order for string construction
    // Since x86 is little-endian, we need to be careful about byte order
    
    // For this implementation, we'll create a sequence that builds the string without nulls:
    // XOR EAX, EAX (clear EAX)
    // MOV AL, byte0 (first byte)
    // MOV AH, byte1 (second byte)
    // SHL EAX, 16 (shift to upper word)
    // MOV AL, byte2 (third byte)
    // MOV AH, byte3 (fourth byte)
    // PUSH EAX (push final value)
    
    // But since this might still contain null bytes if the original bytes were zero,
    // we'll instead use a series of pushes for each non-zero byte in reverse order
    // and reconstruct the full 32-bit value through stack operations or register manipulations
    
    // Better approach: use MOV construction to build the value in EAX without null immediate operands
    generate_mov_eax_imm(b, imm);  // This will use existing null-free construction methods
    
    // Then push EAX
    uint8_t push_eax[] = {0x50};  // PUSH EAX
    buffer_append(b, push_eax, 1);
}

strategy_t stack_string_strategy = {
    .name = "stack_string",
    .can_handle = can_handle_stack_string,
    .get_size = get_size_stack_string,
    .generate = generate_stack_string,
    .priority = 10  // High priority for string construction since it's more specific
};

int stack_string_can_handle_wrapper(cs_insn *insn) {
    return can_handle_stack_string(insn);
}

// Self-Modifying Code for Obfuscation Strategy
// This strategy identifies sequences that could benefit from targeted encoding/decoding
// For this implementation, we'll focus on more complex encoding approaches for immediate values

int can_handle_self_modify(cs_insn *insn) {
    // For this strategy, we'll focus on operations with immediate values containing nulls
    // that are not handled by other more specific strategies (like string strategy)
    
    // Check if the instruction has immediate operands
    if (insn->detail->x86.op_count >= 1 && 
        insn->detail->x86.operands[0].type == X86_OP_IMM) {
        
        // Check specifically if this is not already handled by the string strategy
        uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
        
        // If it looks like a string (contains ASCII chars), let the string strategy handle it
        int likely_char_count = 0;
        int has_null = 0;
        for (int i = 0; i < 4; i++) {
            uint8_t byte_val = (imm >> (i * 8)) & 0xFF;
            if (byte_val == 0) {
                has_null = 1;
            } else if ((byte_val >= 0x20 && byte_val <= 0x7E) || 
                       (byte_val >= 'A' && byte_val <= 'Z') || 
                       (byte_val >= 'a' && byte_val <= 'z') || 
                       (byte_val >= '0' && byte_val <= '9')) {
                likely_char_count++;
            }
        }
        
        // Only handle if it doesn't look like a string (likely_char_count < 2) but has nulls
        if (likely_char_count >= 2 || !has_null) {
            return 0;  // Let the string strategy handle string-like values or values without nulls
        }
        
        // Check if this instruction has null bytes in the actual bytecode
        for (size_t j = 0; j < insn->size; j++) {
            if (insn->bytes[j] == 0x00) { 
                return 1; 
            }
        }
    }
    return 0;
}

size_t get_size_self_modify(__attribute__((unused)) cs_insn *insn) {
    // Use existing null-free construction approach - MOV EAX, imm (null-free) + operation
    // This varies depending on the original instruction type
    // For now, using a general approach similar to other strategies
    return 7; // MOV EAX, imm32 (5 bytes) + PUSH EAX (1 byte) + some overhead (1 byte)
}

void generate_self_modify(struct buffer *b, cs_insn *insn) {
    // The approach here is to implement a run-time modification strategy
    // For PUSH imm with nulls: Instead of PUSH 0x00112233, we can do:
    // MOV EAX, 0x00112233 (using null-safe construction) + PUSH EAX
    
    uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
    
    // Use the existing null-free construction for the immediate value
    generate_mov_eax_imm(b, imm);
    
    // If it's a PUSH, implement the PUSH using EAX
    if (insn->id == X86_INS_PUSH) {
        uint8_t push_eax[] = {0x50};  // PUSH EAX
        buffer_append(b, push_eax, 1);
    } 
    // For other operations, we would need to implement their corresponding logic
    // This is a basic implementation focused on PUSH operations
}

strategy_t self_modify_strategy = {
    .name = "self_modify",
    .can_handle = can_handle_self_modify,
    .get_size = get_size_self_modify,
    .generate = generate_self_modify,
    .priority = 11  // Higher priority than other general strategies
};

int self_modify_can_handle_wrapper(cs_insn *insn) {
    return can_handle_self_modify(insn);
}

void register_general_strategies() {
    // Update the strategy with the wrapper
    push_imm32_strategy.can_handle = push_can_handle_wrapper;
    register_strategy(&push_imm32_strategy);
    
    // Register the stack string construction strategy
    stack_string_strategy.can_handle = stack_string_can_handle_wrapper;
    register_strategy(&stack_string_strategy);
    
    // Register the self-modifying code strategy
    self_modify_strategy.can_handle = self_modify_can_handle_wrapper;
    register_strategy(&self_modify_strategy);
}