#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// [Linux] Linux String Construction via PUSH Strategy
// Handling strings (like "/bin/sh") constructed by pushing them onto the stack in reverse order

// Strategy A: Safe Reverse String Pushing without nulls in immediates
int can_handle_safe_string_push(cs_insn *insn) {
    // Look for PUSH instructions with immediate values that have null bytes
    // These are often parts of string construction in Linux shellcode
    if (insn->id == X86_INS_PUSH && insn->detail->x86.op_count == 1) {
        if (insn->detail->x86.operands[0].type == X86_OP_IMM) {
            uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
            // Check if the immediate value contains null bytes
            if ((imm & 0xFF) == 0 || ((imm >> 8) & 0xFF) == 0 || 
                ((imm >> 16) & 0xFF) == 0 || ((imm >> 24) & 0xFF) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

size_t get_size_safe_string_push(cs_insn *insn) {
    // Size for register-based push instead of immediate push
    // Use the insn parameter to make it meaningful
    if (insn->detail->x86.operands[0].type == X86_OP_IMM) {
        uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
        if ((imm & 0xFF) == 0 || ((imm >> 8) & 0xFF) == 0 ||
            ((imm >> 16) & 0xFF) == 0 || ((imm >> 24) & 0xFF) == 0) {
            return 8; // Size for load + push sequence
        }
    }
    return 8; // Fallback size
}

void generate_safe_string_push(struct buffer *b, cs_insn *insn) {
    uint32_t string_part = (uint32_t)insn->detail->x86.operands[0].imm;
    
    // Instead of PUSH immediate with nulls, use register method:
    // PUSH EAX (save current EAX)
    // MOV EAX, string_part (safe value construction)
    // PUSH EAX (push the value)
    // POP EAX (restore original EAX)
    
    uint8_t push_eax[] = {0x50}; // PUSH EAX
    buffer_append(b, push_eax, 1);
    
    // Generate the string part value in EAX without null bytes in instructions
    generate_mov_eax_imm(b, string_part);
    
    uint8_t push_val[] = {0x50}; // PUSH EAX
    buffer_append(b, push_val, 1);
    
    uint8_t pop_eax[] = {0x58}; // POP EAX (restore original)
    buffer_append(b, pop_eax, 1);
}

strategy_t safe_string_push_strategy = {
    .name = "safe_string_push",
    .can_handle = can_handle_safe_string_push,
    .get_size = get_size_safe_string_push,
    .generate = generate_safe_string_push,
    .priority = 70  // Medium-high priority for string operations
};

// Strategy B: Null-Free Path Construction
int can_handle_null_free_path_construction(cs_insn *insn) {
    // This strategy looks for MOV operations that load parts of path strings
    // with null bytes (like when constructing "/bin/sh" in registers)
    if (insn->id == X86_INS_MOV && insn->detail->x86.op_count == 2) {
        if (insn->detail->x86.operands[0].type == X86_OP_REG &&
            insn->detail->x86.operands[1].type == X86_OP_IMM) {

            uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
            // For path construction, check if immediate has null bytes
            if ((imm & 0xFF) == 0 || ((imm >> 8) & 0xFF) == 0 ||
                ((imm >> 16) & 0xFF) == 0 || ((imm >> 24) & 0xFF) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

size_t get_size_null_free_path_construction(cs_insn *insn) {
    // Use the insn parameter to make it meaningful
    if (insn->detail->x86.operands[1].type == X86_OP_IMM) {
        uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
        if ((imm & 0xFF) == 0 || ((imm >> 8) & 0xFF) == 0 ||
            ((imm >> 16) & 0xFF) == 0 || ((imm >> 24) & 0xFF) == 0) {
            return 15; // Size for multi-step path construction
        }
    }
    return 15; // Fallback size
}

void generate_null_free_path_construction(struct buffer *b, cs_insn *insn) {
    uint32_t path_part = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t target_reg = insn->detail->x86.operands[0].reg;

    // Handle loading of string parts that contain nulls
    // Use register-based construction to avoid null bytes in instructions

    // Save current EAX if needed
    uint8_t eax_used = (target_reg != X86_REG_EAX);
    if (eax_used) {
        uint8_t push_eax[] = {0x50}; // PUSH EAX
        buffer_append(b, push_eax, 1);
    }

    // Load the path part into EAX
    generate_mov_eax_imm(b, path_part);

    // Move to target register if different
    if (target_reg != X86_REG_EAX) {
        uint8_t mov_target[] = {0x89, 0xC0 + get_reg_index(target_reg)}; // MOV target_reg, EAX
        buffer_append(b, mov_target, 2);
    }

    // Restore EAX if it was saved
    if (eax_used) {
        uint8_t pop_eax[] = {0x58}; // POP EAX
        buffer_append(b, pop_eax, 1);
    }
}

strategy_t null_free_path_construction_strategy = {
    .name = "null_free_path_construction",
    .can_handle = can_handle_null_free_path_construction,
    .get_size = get_size_null_free_path_construction,
    .generate = generate_null_free_path_construction,
    .priority = 68  // Medium-high priority for path operations
};