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
    generate_mov_reg_mem_imm(b, insn);
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
    return (insn->id == X86_INS_LEA && insn->detail->x86.op_count == 2 && 
            insn->detail->x86.operands[1].type == X86_OP_MEM && 
            insn->detail->x86.operands[1].mem.disp != 0 &&
            has_null_bytes(insn));
}

size_t get_size_lea_disp32(cs_insn *insn) {
    return get_lea_reg_mem_disp32_size(insn);
}

void generate_lea_disp32(struct buffer *b, cs_insn *insn) {
    generate_lea_reg_mem_disp32(b, insn);
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