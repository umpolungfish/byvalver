#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// [Linux] Linux Socketcall Multiplexer Pattern Strategy
// Handling Linux 32-bit socketcall syscall patterns that may contain null bytes

// Strategy A: Safe Argument Array Construction for socketcall
int can_handle_socketcall_argument_array(cs_insn *insn) {
    // Look for MOV instructions that load values that will be used in socketcall arguments
    // and contain null bytes (like protocol = 0, or addresses with nulls)
    if ((insn->id == X86_INS_MOV || insn->id == X86_INS_PUSH) && 
        insn->detail->x86.op_count >= 1) {
        if (insn->detail->x86.operands[0].type == X86_OP_REG && 
            insn->detail->x86.operands[1].type == X86_OP_IMM) {
            
            uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
            // For socketcalls, check if it's protocol=0 or other socketcall parameters
            // that might need null-free construction
            if (imm == 0) {  // Protocol parameter is often 0
                return 1;
            }
        } else if (insn->id == X86_INS_PUSH && 
                   insn->detail->x86.operands[0].type == X86_OP_IMM) {
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

size_t get_size_socketcall_argument_array(cs_insn *insn) {
    // Size for null-free constant construction in socketcall context
    // Use the insn parameter to make it meaningful
    if (insn->detail->x86.operands[0].type == X86_OP_IMM) {
        uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
        if ((imm & 0xFF) == 0 || ((imm >> 8) & 0xFF) == 0 ||
            ((imm >> 16) & 0xFF) == 0 || ((imm >> 24) & 0xFF) == 0) {
            return 10; // Size for null-free constant construction
        }
    } else if (insn->detail->x86.operands[1].type == X86_OP_IMM) {
        uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
        if (imm == 0) {  // Looking for protocol=0 cases
            return 10; // Size for null-free constant construction
        }
    }
    return 10; // Fallback size
}

void generate_socketcall_argument_array(struct buffer *b, cs_insn *insn) {
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    
    // For socketcall arguments, handle special cases like protocol=0
    if (imm == 0 && insn->id == X86_INS_MOV) {
        // Use register clearing without PUSH immediate that contains null
        uint8_t target_reg = insn->detail->x86.operands[0].reg;
        
        // Clear the register using XOR
        if (target_reg == X86_REG_EAX) {
            uint8_t xor_eax[] = {0x31, 0xC0}; // XOR EAX, EAX
            buffer_append(b, xor_eax, 2);
        } else {
            // Use XOR with same register to clear: XOR reg, reg
            uint8_t idx = get_reg_index(target_reg);
            uint8_t xor_reg[] = {0x31, 0xC0 + (idx << 3) + idx}; // XOR reg, reg
            buffer_append(b, xor_reg, 2);
        }
    } else if (insn->id == X86_INS_PUSH && 
               insn->detail->x86.operands[0].type == X86_OP_IMM) {
        // Handle PUSH with immediate containing nulls
        uint32_t push_val = (uint32_t)insn->detail->x86.operands[0].imm;
        
        // For socketcall arguments, if we need to push a value with nulls:
        // Push register loaded with the value instead of pushing immediate
        uint8_t push_eax_save[] = {0x50}; // PUSH EAX to save
        buffer_append(b, push_eax_save, 1);
        
        generate_mov_eax_imm(b, push_val);
        
        uint8_t push_result[] = {0x50}; // PUSH EAX
        buffer_append(b, push_result, 1);
        
        uint8_t pop_eax_restore[] = {0x58}; // POP EAX to restore
        buffer_append(b, pop_eax_restore, 1);
    } else {
        // Default to regular handling
        generate_mov_reg_imm(b, insn);
    }
}

strategy_t socketcall_argument_array_strategy = {
    .name = "socketcall_argument_array",
    .can_handle = can_handle_socketcall_argument_array,
    .get_size = get_size_socketcall_argument_array,
    .generate = generate_socketcall_argument_array,
    .priority = 75  // High priority for socket operations
};

// Strategy B: Null-Free Socketcall Constant Construction
int can_handle_socketcall_constant(cs_insn *insn) {
    // Detect patterns specific to socketcall where constants might contain nulls
    // This includes syscalls like SYS_SOCKET (1), SYS_BIND (2), SYS_CONNECT (3), etc.
    if (insn->id == X86_INS_MOV && insn->detail->x86.op_count == 2) {
        if (insn->detail->x86.operands[0].type == X86_OP_REG &&
            insn->detail->x86.operands[1].type == X86_OP_IMM) {

            uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

            // Check for socketcall numbers or address family values that might contain nulls
            // AF_INET = 2, SOCK_STREAM = 1 (these are safe)
            // But some IP addresses like 0.0.0.0 (0x00000000) or 127.0.0.1 (0x0100007F) have nulls
            if ((imm & 0xFF) == 0 || ((imm >> 8) & 0xFF) == 0 ||
                ((imm >> 16) & 0xFF) == 0 || ((imm >> 24) & 0xFF) == 0) {

                // Check if this looks like it's related to socket operations
                // by looking at the register being used or by context
                // For now, assume any immediate with nulls in socketcall context is relevant
                return 1;
            }
        }
    }
    return 0;
}

size_t get_size_socketcall_constant(cs_insn *insn) {
    // Use the insn parameter to make it meaningful
    if (insn->detail->x86.operands[1].type == X86_OP_IMM) {
        uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
        if ((imm & 0xFF) == 0 || ((imm >> 8) & 0xFF) == 0 ||
            ((imm >> 16) & 0xFF) == 0 || ((imm >> 24) & 0xFF) == 0) {
            return 12; // Size for alternative constant construction
        }
    }
    return 12; // Fallback size
}

void generate_socketcall_constant(struct buffer *b, cs_insn *insn) {
    uint32_t const_val = (uint32_t)insn->detail->x86.operands[1].imm;
    uint8_t target_reg = insn->detail->x86.operands[0].reg;

    // Use safe construction for constants with nulls in socketcall context
    // Use arithmetic or other approaches to build the value in register

    // First, save current EAX if needed
    uint8_t eax_saved = (target_reg != X86_REG_EAX);
    if (eax_saved) {
        uint8_t push_eax[] = {0x50}; // PUSH EAX
        buffer_append(b, push_eax, 1);
    }

    // Load the constant into EAX using safe methods
    generate_mov_eax_imm(b, const_val);

    // Move to target register if different from EAX
    if (target_reg != X86_REG_EAX) {
        uint8_t mov_target[] = {0x89, 0xC0 + get_reg_index(target_reg)}; // MOV target_reg, EAX
        buffer_append(b, mov_target, 2);
    }

    // Restore EAX if it was saved
    if (eax_saved) {
        uint8_t pop_eax[] = {0x58}; // POP EAX
        buffer_append(b, pop_eax, 1);
    }
}

strategy_t socketcall_constant_strategy = {
    .name = "socketcall_constant",
    .can_handle = can_handle_socketcall_constant,
    .get_size = get_size_socketcall_constant,
    .generate = generate_socketcall_constant,
    .priority = 72  // High priority for socket operations
};