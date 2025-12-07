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
    // Handle MOV reg, [imm32] where imm32 contains nulls
    if (insn->detail->x86.operands[1].type != X86_OP_MEM) {
        return; // Safety check
    }

    uint8_t dst_reg = insn->detail->x86.operands[0].reg;
    uint32_t addr = (uint32_t)insn->detail->x86.operands[1].mem.disp;

    // MOV EAX, addr (null-free construction)
    generate_mov_eax_imm(b, addr);

    // MOV dst_reg, [EAX]
    // Handle the case where dst_reg is EAX specially to avoid null bytes
    if (dst_reg == X86_REG_EAX) {
        // Use SIB byte to avoid null: MOV EAX, [EAX]
        // This becomes: 8B 04 20 (where 04 is ModR/M with SIB, 20 is SIB for [EAX])
        uint8_t code[] = {0x8B, 0x04, 0x20}; // MOV EAX, [EAX]
        buffer_append(b, code, 3);
    } else {
        // For other registers, the ModR/M byte is safe
        uint8_t code[] = {0x8B, 0x00}; // MOV reg, [EAX] format
        uint8_t reg_index = get_reg_index(dst_reg);
        code[1] = (reg_index << 3) | 0;  // Encode reg in reg field, [EAX] in r/m field
        buffer_append(b, code, 2);
    }
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