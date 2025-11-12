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

// 8-bit Arithmetic operations on [disp32] with register (e.g., "add byte ptr [disp32], reg")
int can_handle_arith_mem8_reg(cs_insn *insn) {
    // Check for 8-bit operations like "add byte ptr [disp32], al"
    return ((insn->id == X86_INS_ADD || insn->id == X86_INS_SUB ||
             insn->id == X86_INS_AND || insn->id == X86_INS_OR ||
             insn->id == X86_INS_XOR || insn->id == X86_INS_CMP) &&
            insn->detail->x86.op_count == 2 &&
            insn->detail->x86.operands[0].type == X86_OP_MEM &&
            insn->detail->x86.operands[0].mem.base == X86_REG_INVALID &&
            insn->detail->x86.operands[0].mem.index == X86_REG_INVALID &&
            insn->detail->x86.operands[1].type == X86_OP_REG && // Register operand, not immediate
            has_null_bytes(insn));
}

size_t get_size_arith_mem8_reg(__attribute__((unused)) cs_insn *insn) {
    // For 8-bit memory operations, we need to load address to EAX, then perform operation
    // MOV EAX, addr (null-free) + memory operation with SIB byte
    return 10;  // Conservative estimate
}

void generate_arith_mem8_reg(struct buffer *b, cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;

    // MOV EAX, addr (null-free construction)
    generate_mov_eax_imm(b, addr);

    // Get the register for the operation
    uint8_t reg = X86_REG_EAX; // Default fallback
    if (insn->detail->x86.operands[1].type == X86_OP_REG) {
        reg = insn->detail->x86.operands[1].reg;
    }

    uint8_t reg_index = get_reg_index(reg);
    uint8_t opcode;

    switch(insn->id) {
        case X86_INS_ADD: opcode = 0x00; break; // ADD byte ptr
        case X86_INS_SUB: opcode = 0x28; break; // SUB byte ptr
        case X86_INS_AND: opcode = 0x20; break; // AND byte ptr
        case X86_INS_OR:  opcode = 0x08; break; // OR byte ptr
        case X86_INS_XOR: opcode = 0x30; break; // XOR byte ptr
        case X86_INS_CMP: opcode = 0x38; break; // CMP byte ptr
        default: opcode = 0x00; break; // Default to ADD byte ptr
    }

    // Use SIB byte to avoid null: [EAX] using SIB byte format
    uint8_t code[] = {opcode, 0x04, 0x20}; // op [EAX], reg using SIB
    code[2] = 0x20 + (reg_index << 3); // SIB: scale=00 (1x), index=100 (no index), base=000 (EAX)
    buffer_append(b, code, 3);
}

strategy_t arith_mem8_reg_strategy = {
    .name = "arith_mem8_reg",
    .can_handle = can_handle_arith_mem8_reg,
    .get_size = get_size_arith_mem8_reg,
    .generate = generate_arith_mem8_reg,
    .priority = 8  // High priority to handle before generic fallback
};

// 8-bit Arithmetic operations on [disp32] with immediate (for operations like "add byte ptr [disp32], imm8")
int can_handle_arith_mem8_imm(cs_insn *insn) {
    // Check for 8-bit operations like "add byte ptr [disp32], imm8"
    return ((insn->id == X86_INS_ADD || insn->id == X86_INS_SUB ||
             insn->id == X86_INS_AND || insn->id == X86_INS_OR ||
             insn->id == X86_INS_XOR || insn->id == X86_INS_CMP) &&
            insn->detail->x86.op_count == 2 &&
            insn->detail->x86.operands[0].type == X86_OP_MEM &&
            insn->detail->x86.operands[0].mem.base == X86_REG_INVALID &&
            insn->detail->x86.operands[0].mem.index == X86_REG_INVALID &&
            insn->detail->x86.operands[1].type == X86_OP_IMM && // Immediate operand, not register
            has_null_bytes(insn));
}

size_t get_size_arith_mem8_imm(__attribute__((unused)) cs_insn *insn) {
    // For 8-bit memory operations, we need to load address to EAX, then perform operation
    // MOV EAX, addr (null-free) + memory operation with SIB byte
    return 10;  // Conservative estimate
}

void generate_arith_mem8_imm(struct buffer *b, cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;

    // MOV EAX, addr (null-free construction)
    generate_mov_eax_imm(b, addr);

    // Get the immediate value
    uint8_t op_subcode;
    switch(insn->id) {
        case X86_INS_ADD: op_subcode = 0x00; break; // ADD
        case X86_INS_OR:  op_subcode = 0x01; break; // OR
        case X86_INS_ADC: op_subcode = 0x02; break; // ADC
        case X86_INS_SBB: op_subcode = 0x03; break; // SBB
        case X86_INS_AND: op_subcode = 0x04; break; // AND
        case X86_INS_SUB: op_subcode = 0x05; break; // SUB
        case X86_INS_XOR: op_subcode = 0x06; break; // XOR
        case X86_INS_CMP: op_subcode = 0x07; break; // CMP
        default: op_subcode = 0x00; break;
    }

    uint8_t opcode = 0x80 + op_subcode;

    // Use SIB byte to avoid null: [EAX] using SIB byte format
    uint8_t imm_val = (uint8_t)insn->detail->x86.operands[1].imm;
    uint8_t code[] = {opcode, 0x04, 0x20, 0x00}; // op [EAX], imm8 using SIB
    code[2] = 0x20; // SIB: scale=00 (1x), index=100 (no index), base=000 (EAX)
    code[3] = imm_val;
    buffer_append(b, code, 4);
}

strategy_t arith_mem8_imm_strategy = {
    .name = "arith_mem8_imm",
    .can_handle = can_handle_arith_mem8_imm,
    .get_size = get_size_arith_mem8_imm,
    .generate = generate_arith_mem8_imm,
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
    .priority = 8
};

void register_memory_strategies() {
    register_strategy(&mov_mem_imm_strategy);
    register_strategy(&mov_mem_dst_strategy);
    register_strategy(&cmp_mem_reg_strategy);
    register_strategy(&arith_mem_imm_strategy);
    register_strategy(&arith_mem8_reg_strategy);
    register_strategy(&arith_mem8_imm_strategy);
    register_strategy(&lea_disp32_strategy);
}