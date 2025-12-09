#include "strategy.h"
#include "utils.h"
#include <stdio.h>

// Memory MOV strategy for [imm32] addressing
int can_handle_mov_mem_imm(cs_insn *insn) {
    return (insn->id == X86_INS_MOV && insn->detail->x86.op_count == 2 &&
            insn->detail->x86.operands[1].type == X86_OP_MEM &&
            insn->detail->x86.operands[1].mem.base == X86_REG_INVALID &&
            insn->detail->x86.operands[1].mem.index == X86_REG_INVALID &&
            has_null_bytes(insn));
}

size_t get_size_mov_mem_imm(cs_insn *insn) {
    return get_mov_reg_mem_imm_size(insn);
}

void generate_mov_mem_imm(struct buffer *b, cs_insn *insn) {
    // Handle MOV reg, [disp32] where disp32 contains nulls
    if (insn->detail->x86.operands[1].type != X86_OP_MEM) {
        return; // Safety check
    }

    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    uint32_t addr = (uint32_t)insn->detail->x86.operands[1].mem.disp;

    // Find a temporary register that's different from the destination register
    x86_reg temp_reg = X86_REG_ECX;
    if (dst_reg == X86_REG_ECX) {
        temp_reg = X86_REG_EDX;
        if (dst_reg == X86_REG_EDX) {
            temp_reg = X86_REG_EBX;
            if (dst_reg == X86_REG_EBX) {
                temp_reg = X86_REG_ESI;  // Fallback register
            }
        }
    }

    // PUSH the temp register to save its original value
    uint8_t push_temp[] = {0x50 + get_reg_index(temp_reg)};
    buffer_append(b, push_temp, 1);

    // MOV temp_reg, addr (null-free construction using utilities)
    generate_mov_eax_imm(b, addr);

    // MOV temp_reg, EAX (move the constructed address to our temp register)
    uint8_t mov_temp_eax[] = {0x89, 0xC0};
    mov_temp_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(temp_reg);
    buffer_append(b, mov_temp_eax, 2);

    // MOV dst_reg, [temp_reg] (read from the memory address stored in temp_reg)
    if (dst_reg == temp_reg) {
        // Special case: if dst_reg and temp_reg are the same, we need to be careful
        // Use SIB addressing to avoid null bytes when both registers are the same
        uint8_t code[] = {0x8B, 0x04, 0x20}; // MOV EAX, [EAX] type with SIB
        code[1] = 0x04 + (get_reg_index(dst_reg) << 3);  // ModR/M with SIB byte
        code[2] = (0 << 6) | (4 << 3) | get_reg_index(temp_reg);  // SIB: scale=0, index=ESP, base=temp_reg
        buffer_append(b, code, 3);
    } else {
        // Standard case: MOV dst_reg, [temp_reg]
        uint8_t modrm = 0x00 + (get_reg_index(dst_reg) << 3) + get_reg_index(temp_reg);

        // Check if modrm creates a problematic byte (when both regs are EAX, it creates 0x00)
        if (modrm == 0x00) {
            // Use SIB to avoid nulls: [EAX] becomes 04 20 (ModR/M=SIB, SIB=[EAX])
            uint8_t code[] = {0x8B, 0x04, 0x20};
            code[1] = 0x04 + (get_reg_index(dst_reg) << 3);  // ModR/M
            code[2] = 0x20 + get_reg_index(temp_reg);  // SIB: scale=0, index=ESP, base=temp_reg
            buffer_append(b, code, 3);
        } else {
            uint8_t code[] = {0x8B, modrm};
            buffer_append(b, code, 2);
        }
    }

    // POP the temp register to restore its original value
    uint8_t pop_temp[] = {0x58 + get_reg_index(temp_reg)};
    buffer_append(b, pop_temp, 1);
}

strategy_t mov_mem_imm_strategy = {
    .name = "mov_mem_imm",
    .can_handle = can_handle_mov_mem_imm,
    .get_size = get_size_mov_mem_imm,
    .generate = generate_mov_mem_imm,
    .priority = 8
};

// Memory MOV strategy for [imm32] destination
int can_handle_mov_mem_dst(cs_insn *insn) {
    return (insn->id == X86_INS_MOV && insn->detail->x86.op_count == 2 && 
            insn->detail->x86.operands[0].type == X86_OP_MEM && 
            insn->detail->x86.operands[0].mem.base == X86_REG_INVALID && 
            insn->detail->x86.operands[0].mem.index == X86_REG_INVALID &&
            insn->detail->x86.operands[1].type == X86_OP_REG && 
            has_null_bytes(insn));
}

size_t get_size_mov_mem_dst(cs_insn *insn) {
    return get_mov_disp32_reg_size(insn);
}

void generate_mov_mem_dst(struct buffer *b, cs_insn *insn) {
    generate_mov_disp32_reg(b, insn);
}

strategy_t mov_mem_dst_strategy = {
    .name = "mov_mem_dst",
    .can_handle = can_handle_mov_mem_dst,
    .get_size = get_size_mov_mem_dst,
    .generate = generate_mov_mem_dst,
    .priority = 8
};

// CMP [imm32], reg strategy
int can_handle_cmp_mem_reg(cs_insn *insn) {
    return (insn->id == X86_INS_CMP && insn->detail->x86.op_count == 2 &&
            insn->detail->x86.operands[0].type == X86_OP_MEM &&
            insn->detail->x86.operands[0].mem.base == X86_REG_INVALID &&
            insn->detail->x86.operands[0].mem.index == X86_REG_INVALID &&
            insn->detail->x86.operands[1].type == X86_OP_REG &&
            has_null_bytes(insn));
}

size_t get_size_cmp_mem_reg(cs_insn *insn) {
    return get_cmp_mem32_reg_size(insn);
}

void generate_cmp_mem_reg(struct buffer *b, cs_insn *insn) {
    generate_cmp_mem32_reg(b, insn);
}

strategy_t cmp_mem_reg_strategy = {
    .name = "cmp_mem_reg",
    .can_handle = can_handle_cmp_mem_reg,
    .get_size = get_size_cmp_mem_reg,
    .generate = generate_cmp_mem_reg,
    .priority = 8
};

// Arithmetic operations on [disp32] with immediate
int can_handle_arith_mem_imm(cs_insn *insn) {
    return ((insn->id == X86_INS_ADD || insn->id == X86_INS_SUB || 
             insn->id == X86_INS_AND || insn->id == X86_INS_OR || 
             insn->id == X86_INS_XOR || insn->id == X86_INS_CMP) && 
            insn->detail->x86.op_count == 2 &&
            insn->detail->x86.operands[0].type == X86_OP_MEM &&
            insn->detail->x86.operands[0].mem.base == X86_REG_INVALID &&
            insn->detail->x86.operands[0].mem.index == X86_REG_INVALID &&
            insn->detail->x86.operands[1].type == X86_OP_IMM &&
            has_null_bytes(insn));
}

size_t get_size_arith_mem_imm(cs_insn *insn) {
    return get_arith_mem32_imm32_size(insn);
}

void generate_arith_mem_imm(struct buffer *b, cs_insn *insn) {
    generate_arith_mem32_imm32(b, insn);
}

strategy_t arith_mem_imm_strategy = {
    .name = "arith_mem_imm",
    .can_handle = can_handle_arith_mem_imm,
    .get_size = get_size_arith_mem_imm,
    .generate = generate_arith_mem_imm,
    .priority = 7
};

// LEA reg, [disp32] strategy
int can_handle_lea_disp32(cs_insn *insn) {
    if (insn->id != X86_INS_LEA || insn->detail->x86.op_count != 2 ||
        insn->detail->x86.operands[1].type != X86_OP_MEM ||
        insn->detail->x86.operands[1].mem.disp == 0) {
        return 0;
    }

    // Check if the memory displacement specifically contains null bytes
    uint32_t disp = (uint32_t)insn->detail->x86.operands[1].mem.disp;
    if (is_null_free(disp)) {
        return 0;  // No null bytes in displacement
    }

    // Additionally check if the original instruction has null bytes
    return has_null_bytes(insn);
}

size_t get_size_lea_disp32(cs_insn *insn) {
    // This should use the same size calculation as the standard function but with a more conservative estimate
    uint32_t addr = (uint32_t)insn->detail->x86.operands[1].mem.disp;
    // MOV EAX, addr (null-free) + LEA reg, [EAX] with safe encoding
    size_t mov_size = get_mov_eax_imm_size(addr);
    // LEA reg, [EAX] takes 2 bytes, or 3 bytes with SIB if reg is EAX
    size_t lea_size = (insn->detail->x86.operands[0].reg == X86_REG_EAX) ? 3 : 2;
    return mov_size + lea_size;
}

void generate_lea_disp32(struct buffer *b, cs_insn *insn) {
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;
    uint32_t addr = (uint32_t)insn->detail->x86.operands[1].mem.disp;

    // MOV EAX, addr - using null-free construction
    generate_mov_eax_imm(b, addr);

    // LEA dst_reg, [EAX] - with safe ModR/M encoding
    if (dst_reg == X86_REG_EAX) {
        // Use SIB byte to avoid null: LEA EAX, [EAX] = 8D 04 20
        uint8_t code[] = {0x8D, 0x04, 0x20}; // LEA EAX, [EAX] with SIB byte (scale=0, index=ESP, base=EAX)
        buffer_append(b, code, 3);
    } else {
        // For other registers: LEA reg, [EAX] = 8D /0
        uint8_t code[] = {0x8D, 0x00}; // LEA reg, [EAX] format
        code[1] = (get_reg_index(dst_reg) << 3) | 0;  // Encode dst_reg in reg field, [EAX] in r/m field
        buffer_append(b, code, 2);
    }
}

strategy_t lea_disp32_strategy = {
    .name = "lea_disp32",
    .can_handle = can_handle_lea_disp32,
    .get_size = get_size_lea_disp32,
    .generate = generate_lea_disp32,
    .priority = 10  // Higher priority for LEA-specific handling
};

void register_memory_strategies() {
    register_strategy(&mov_mem_imm_strategy);
    register_strategy(&mov_mem_dst_strategy);
    register_strategy(&cmp_mem_reg_strategy);
    register_strategy(&arith_mem_imm_strategy);
    register_strategy(&lea_disp32_strategy);
}