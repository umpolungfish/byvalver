#include "strategy.h"
#include "utils.h"
#include <stdio.h>

// CALL imm32 strategy
int can_handle_call_imm(cs_insn *insn) {
    return (insn->id == X86_INS_CALL && insn->detail->x86.op_count == 1 && 
            insn->detail->x86.operands[0].type == X86_OP_IMM && 
            has_null_bytes(insn));
}

size_t get_size_call_imm(cs_insn *insn) {
    return get_call_imm_size(insn);
}

void generate_call_imm_strat(struct buffer *b, cs_insn *insn) {
    generate_call_imm(b, insn);
}

strategy_t call_imm_strategy = {
    .name = "call_imm",
    .can_handle = can_handle_call_imm,
    .get_size = get_size_call_imm,
    .generate = generate_call_imm_strat,
    .priority = 8
};

// CALL [disp32] strategy - for indirect calls with displacement containing null bytes
int can_handle_call_mem_disp32(cs_insn *insn) {
    return (insn->id == X86_INS_CALL && insn->detail->x86.op_count == 1 && 
            insn->detail->x86.operands[0].type == X86_OP_MEM && 
            insn->detail->x86.operands[0].mem.base == X86_REG_INVALID &&
            insn->detail->x86.operands[0].mem.index == X86_REG_INVALID &&
            has_null_bytes(insn));
}

size_t get_size_call_mem_disp32(cs_insn *insn) {
    // MOV EAX, disp32 + CALL EAX = 5 + 2 = 7 bytes (approximation)
    return get_mov_reg_imm_size(insn) + 2;  // Adjust based on actual implementation
}

void generate_call_mem_disp32(struct buffer *b, cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;
    
    // MOV EAX, addr (null-free construction)
    generate_mov_eax_imm(b, addr);
    
    // CALL EAX
    uint8_t call_eax[] = {0xFF, 0xD0}; // CALL EAX
    buffer_append(b, call_eax, 2);
}

strategy_t call_mem_disp32_strategy = {
    .name = "call_mem_disp32",
    .can_handle = can_handle_call_mem_disp32,
    .get_size = get_size_call_mem_disp32,
    .generate = generate_call_mem_disp32,
    .priority = 8
};

// JMP [disp32] strategy - for indirect jumps with displacement containing null bytes
int can_handle_jmp_mem_disp32(cs_insn *insn) {
    return (insn->id == X86_INS_JMP && insn->detail->x86.op_count == 1 && 
            insn->detail->x86.operands[0].type == X86_OP_MEM && 
            insn->detail->x86.operands[0].mem.base == X86_REG_INVALID &&
            insn->detail->x86.operands[0].mem.index == X86_REG_INVALID &&
            has_null_bytes(insn));
}

size_t get_size_jmp_mem_disp32(cs_insn *insn) {
    // MOV EAX, disp32 + JMP EAX = 5 + 2 = 7 bytes (approximation)
    return get_mov_reg_imm_size(insn) + 2;  // Adjust based on actual implementation
}

void generate_jmp_mem_disp32(struct buffer *b, cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;
    
    // MOV EAX, addr (null-free construction)
    generate_mov_eax_imm(b, addr);
    
    // JMP EAX
    uint8_t jmp_eax[] = {0xFF, 0xE0}; // JMP EAX
    buffer_append(b, jmp_eax, 2);
}

strategy_t jmp_mem_disp32_strategy = {
    .name = "jmp_mem_disp32",
    .can_handle = can_handle_jmp_mem_disp32,
    .get_size = get_size_jmp_mem_disp32,
    .generate = generate_jmp_mem_disp32,
    .priority = 8
};

// Generic strategy for any instruction with memory operands having displacement containing nulls
int can_handle_generic_mem_null_disp(cs_insn *insn) {
    // Check for any instruction with memory operand containing null bytes in displacement
    if (insn->detail->x86.op_count > 0) {
        for (int i = 0; i < insn->detail->x86.op_count; i++) {
            if (insn->detail->x86.operands[i].type == X86_OP_MEM &&
                insn->detail->x86.operands[i].mem.base == X86_REG_INVALID &&
                insn->detail->x86.operands[i].mem.index == X86_REG_INVALID) {
                
                uint32_t disp = (uint32_t)insn->detail->x86.operands[i].mem.disp;
                
                // Check if displacement has null bytes
                int has_null_in_disp = 0;
                for (int j = 0; j < 4; j++) {
                    if (((disp >> (j * 8)) & 0xFF) == 0) {
                        has_null_in_disp = 1;
                        break;
                    }
                }
                
                if (has_null_in_disp) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

size_t get_size_generic_mem_null_disp(__attribute__((unused)) cs_insn *insn) {
    return 20; // Conservative estimate for complex memory operations
}

void generate_generic_mem_null_disp(struct buffer *b, cs_insn *insn) {
    // This is a catch-all for memory operations with null displacement
    // Handle based on instruction type
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        if (insn->detail->x86.operands[i].type == X86_OP_MEM &&
            insn->detail->x86.operands[i].mem.base == X86_REG_INVALID &&
            insn->detail->x86.operands[i].mem.index == X86_REG_INVALID) {
            
            uint32_t addr = (uint32_t)insn->detail->x86.operands[i].mem.disp;
            
            // MOV EAX, addr (null-free construction)
            generate_mov_eax_imm(b, addr);
            
            // Handle different instruction types
            if (insn->id == X86_INS_MOV) {
                if (i == 0) { // Destination is memory [disp32]
                    uint8_t src_reg = insn->detail->x86.operands[1].reg;
                    uint8_t code[] = {0x89, 0x00}; // MOV [EAX], reg
                    code[1] = 0x00 + get_reg_index(src_reg);
                    buffer_append(b, code, 2);
                } else { // Source is memory [disp32]
                    uint8_t dst_reg = insn->detail->x86.operands[0].reg;
                    uint8_t code[] = {0x8B, 0x00}; // MOV reg, [EAX]
                    code[1] = 0x00 + (get_reg_index(dst_reg) << 3);
                    buffer_append(b, code, 2);
                }
            } else if (insn->id == X86_INS_PUSH) {
                // PUSH [EAX] - push from memory location
                uint8_t push_mem_eax[] = {0xFF, 0x30}; // PUSH [EAX]
                buffer_append(b, push_mem_eax, 2);
            } else if (insn->id == X86_INS_CMP) {
                // For CMP [disp32], reg
                uint8_t reg = insn->detail->x86.operands[1].reg;
                uint8_t code[] = {0x39, 0x00}; // CMP [EAX], reg
                code[1] = 0x00 + get_reg_index(reg);
                buffer_append(b, code, 2);
            }
            // Add more instruction types as needed
        }
    }
}

strategy_t generic_mem_null_disp_strategy = {
    .name = "generic_mem_null_disp",
    .can_handle = can_handle_generic_mem_null_disp,
    .get_size = get_size_generic_mem_null_disp,
    .generate = generate_generic_mem_null_disp,
    .priority = 5 // Lower priority than specific strategies
};

void register_jump_strategies() {
    register_strategy(&call_imm_strategy);
    register_strategy(&call_mem_disp32_strategy);
    register_strategy(&jmp_mem_disp32_strategy);
    register_strategy(&generic_mem_null_disp_strategy);
}