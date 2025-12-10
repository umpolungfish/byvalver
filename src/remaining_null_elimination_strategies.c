#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// Enhanced LEA displacement strategy to handle 0x10b8 displacement
int can_handle_lea_disp_enhanced(cs_insn *insn) {
    if (insn->id != X86_INS_LEA || insn->detail->x86.op_count != 2) {
        return 0;
    }

    if (insn->detail->x86.operands[1].type != X86_OP_MEM) {
        return 0;
    }

    // Check if it has a displacement that contains nulls
    int64_t disp = insn->detail->x86.operands[1].mem.disp;
    if (disp != 0) {
        uint32_t disp32 = (uint32_t)disp;
        if (!is_null_free(disp32)) {
            return 1;
        }
    }

    return 0;
}

size_t get_size_lea_disp_enhanced(__attribute__((unused)) cs_insn *insn) {
    return 20; // Conservative estimate
}

void generate_lea_disp_enhanced(struct buffer *b, cs_insn *insn) {
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    cs_x86_op *mem_op = &insn->detail->x86.operands[1]; // This is the memory operand

    fprintf(stderr, "[DEBUG LEA] Processing LEA: dst_reg=%d, base=%d, index=%d, disp=0x%llx\n",
            dst_reg, mem_op->mem.base, mem_op->mem.index, (unsigned long long)mem_op->mem.disp);

    // Use base + index*scale + disp approach with null-safe construction
    // PUSH temp_reg
    x86_reg temp_reg = X86_REG_ECX;
    if (temp_reg == dst_reg) temp_reg = X86_REG_EDX;
    if (temp_reg == dst_reg) temp_reg = X86_REG_EBX;

    uint8_t push_temp[] = {0x50 + get_reg_index(temp_reg)};
    fprintf(stderr, "[DEBUG LEA] Writing PUSH temp_reg: 0x%02x\n", push_temp[0]);
    buffer_append(b, push_temp, 1);

    // Clear temp_reg first
    uint8_t xor_temp[] = {0x31, 0x00};
    xor_temp[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(temp_reg);
    buffer_append(b, xor_temp, 2);

    // Add base register if present
    if (mem_op->mem.base != X86_REG_INVALID) {
        uint8_t add_temp_base[] = {0x01, 0x00};
        add_temp_base[1] = 0xC0 + (get_reg_index(mem_op->mem.base) << 3) + get_reg_index(temp_reg);
        buffer_append(b, add_temp_base, 2);
    }

    // Add scaled index register if present
    if (mem_op->mem.index != X86_REG_INVALID) {
        // Load index into temp and scale it
        uint8_t mov_temp_index[] = {0x89, 0x00};
        mov_temp_index[1] = 0xC0 + (get_reg_index(mem_op->mem.index) << 3) + get_reg_index(temp_reg);
        buffer_append(b, mov_temp_index, 2);

        if (mem_op->mem.scale == 2) {
            uint8_t shl_temp[] = {0xD1, 0xE0};
            shl_temp[1] = 0xE0 + get_reg_index(temp_reg);
            buffer_append(b, shl_temp, 2);
        } else if (mem_op->mem.scale == 4) {
            uint8_t shl_temp[] = {0xD1, 0xE0};
            shl_temp[1] = 0xE0 + get_reg_index(temp_reg);
            buffer_append(b, shl_temp, 2);
            buffer_append(b, shl_temp, 2); // Double shift for x4
        } else if (mem_op->mem.scale == 8) {
            uint8_t shl_temp[] = {0xD1, 0xE0};
            shl_temp[1] = 0xE0 + get_reg_index(temp_reg);
            buffer_append(b, shl_temp, 2);
            buffer_append(b, shl_temp, 2); // x2
            buffer_append(b, shl_temp, 2); // x4
        }
    }

    // Add displacement using null-safe construction
    uint32_t disp = (uint32_t)mem_op->mem.disp;
    fprintf(stderr, "[DEBUG LEA] Displacement: 0x%08x\n", disp);
    if (disp != 0) {
        // Use EAX as temporary for displacement
        uint8_t push_eax[] = {0x50};
        fprintf(stderr, "[DEBUG LEA] Writing PUSH EAX: 0x%02x\n", push_eax[0]);
        buffer_append(b, push_eax, 1);

        // Load displacement into EAX with null-safe construction
        fprintf(stderr, "[DEBUG LEA] Calling generate_mov_eax_imm for disp=0x%08x\n", disp);
        size_t before_size = b->size;
        generate_mov_eax_imm(b, disp);
        size_t after_size = b->size;
        fprintf(stderr, "[DEBUG LEA] generate_mov_eax_imm wrote %zu bytes\n", after_size - before_size);

        // Print the actual bytes written
        fprintf(stderr, "[DEBUG LEA] Bytes written by generate_mov_eax_imm: ");
        for (size_t i = before_size; i < after_size; i++) {
            fprintf(stderr, "%02x ", b->data[i]);
        }
        fprintf(stderr, "\n");

        // ADD temp_reg, EAX
        uint8_t add_temp_eax[] = {0x01, 0xC0};
        add_temp_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(temp_reg);
        fprintf(stderr, "[DEBUG LEA] Writing ADD temp_reg, EAX: 0x%02x 0x%02x\n", add_temp_eax[0], add_temp_eax[1]);
        buffer_append(b, add_temp_eax, 2);

        // POP EAX to restore
        uint8_t pop_eax[] = {0x58};
        fprintf(stderr, "[DEBUG LEA] Writing POP EAX: 0x%02x\n", pop_eax[0]);
        buffer_append(b, pop_eax, 1);
    }

    // MOV dst_reg, temp_reg - but need to handle case where dst_reg is EAX specially
    if (dst_reg != X86_REG_EAX) {
        uint8_t mov_dst_temp[] = {0x89, 0x00};
        mov_dst_temp[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(dst_reg);
        buffer_append(b, mov_dst_temp, 2);
    } else {
        // If destination is EAX, we already have the value in EAX from the ADD operation
        // Actually, in our construction EAX was used temporarily, so we need to move temp to EAX
        uint8_t mov_eax_temp[] = {0x89, 0x00};
        mov_eax_temp[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(X86_REG_EAX);
        buffer_append(b, mov_eax_temp, 2);
    }

    // POP temp_reg
    uint8_t pop_temp[] = {0x58 + get_reg_index(temp_reg)};
    buffer_append(b, pop_temp, 1);
}

strategy_t lea_disp_enhanced_strategy = {
    .name = "lea_disp_enhanced",
    .can_handle = can_handle_lea_disp_enhanced,
    .get_size = get_size_lea_disp_enhanced,
    .generate = generate_lea_disp_enhanced,
    .priority = 160  // Highest priority for final cleanup (higher than conditional jumps at 150)
};

// Enhanced MOV memory with displacement that contains nulls
int can_handle_mov_mem_disp_enhanced(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Handle MOV reg, [disp32] where disp32 contains nulls
    if (insn->detail->x86.operands[0].type == X86_OP_REG && 
        insn->detail->x86.operands[1].type == X86_OP_MEM &&
        insn->detail->x86.operands[1].mem.base == X86_REG_INVALID &&
        insn->detail->x86.operands[1].mem.index == X86_REG_INVALID) {

        uint32_t disp = (uint32_t)insn->detail->x86.operands[1].mem.disp;
        if (!is_null_free(disp)) {
            return 1;
        }
    }

    return 0;
}

size_t get_size_mov_mem_disp_enhanced(__attribute__((unused)) cs_insn *insn) {
    // PUSH EAX (1) + MOV EAX, imm32 (7 max) + MOV dst_reg, [EAX] with SIB (3) + POP EAX (1) = 12 max
    return 15; // Conservative estimate
}

void generate_mov_mem_disp_enhanced(struct buffer *b, cs_insn *insn) {
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    uint32_t disp = (uint32_t)insn->detail->x86.operands[1].mem.disp;

    // PUSH EAX to save
    uint8_t push_eax[] = {0x50};
    buffer_append(b, push_eax, 1);

    // MOV EAX, disp (null-safe construction)
    generate_mov_eax_imm(b, disp);

    // MOV dst_reg, [EAX] using SIB addressing to completely avoid ModR/M null issues
    // This uses the format: 8B /r where /r = [SIB] and SIB addresses [EAX]
    uint8_t mov_inst[] = {0x8B, 0x04, 0x20};  // MOV REG, [EAX] using SIB: [0x04][0x20] where [0x20] = [EAX+0*1]
    mov_inst[1] = 0x04 | (get_reg_index(dst_reg) << 3);  // Encode destination register in ModR/M reg field
    buffer_append(b, mov_inst, 3);

    // POP EAX to restore
    uint8_t pop_eax[] = {0x58};
    buffer_append(b, pop_eax, 1);
}

strategy_t mov_mem_disp_enhanced_strategy = {
    .name = "mov_mem_disp_enhanced",
    .can_handle = can_handle_mov_mem_disp_enhanced,
    .get_size = get_size_mov_mem_disp_enhanced,
    .generate = generate_mov_mem_disp_enhanced,
    .priority = 160  // Highest priority for final cleanup (higher than conditional jumps at 150)
};

// Enhanced MOV immediate strategy specifically for immediate values like 0x104
int can_handle_mov_imm_enhanced(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }

    if (insn->detail->x86.operands[0].type != X86_OP_REG || 
        insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    // Check if immediate contains null bytes
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    if (!is_null_free(imm)) {
        return 1;
    }

    return 0;
}

size_t get_size_mov_imm_enhanced(__attribute__((unused)) cs_insn *insn) {
    return 15; // Conservative estimate
}

void generate_mov_imm_enhanced(struct buffer *b, cs_insn *insn) {
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

    // Use the enhanced MOV EAX immediate construction
    if (dst_reg == X86_REG_EAX) {
        generate_mov_eax_imm(b, imm);
    } else {
        // PUSH EAX to save
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);

        // MOV EAX, imm (null-safe construction)
        generate_mov_eax_imm(b, imm);

        // MOV dst_reg, EAX
        uint8_t mov_dst_eax[] = {0x89, 0x00};
        mov_dst_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(dst_reg);
        buffer_append(b, mov_dst_eax, 2);

        // POP EAX to restore
        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
    }
}

strategy_t mov_imm_enhanced_strategy = {
    .name = "mov_imm_enhanced",
    .can_handle = can_handle_mov_imm_enhanced,
    .get_size = get_size_mov_imm_enhanced,
    .generate = generate_mov_imm_enhanced,
    .priority = 160  // Highest priority for final cleanup (higher than conditional jumps at 150)
};

// Enhanced arithmetic immediate for cases like ADD esp, 0x100
int can_handle_arithmetic_imm_enhanced(cs_insn *insn) {
    if ((insn->id != X86_INS_ADD && insn->id != X86_INS_SUB &&
         insn->id != X86_INS_AND && insn->id != X86_INS_OR &&
         insn->id != X86_INS_XOR && insn->id != X86_INS_CMP) ||
        insn->detail->x86.op_count != 2) {
        return 0;
    }

    if (insn->detail->x86.operands[0].type != X86_OP_REG || 
        insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    // Check if immediate contains null bytes
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    if (!is_null_free(imm)) {
        return 1;
    }

    return 0;
}

size_t get_size_arithmetic_imm_enhanced(__attribute__((unused)) cs_insn *insn) {
    return 20; // Conservative estimate
}

void generate_arithmetic_imm_enhanced(struct buffer *b, cs_insn *insn) {
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

    // Choose temp register different from destination
    x86_reg temp_reg = X86_REG_ECX;
    if (temp_reg == dst_reg) temp_reg = X86_REG_EDX;
    if (temp_reg == dst_reg) temp_reg = X86_REG_EBX;

    // PUSH temp_reg
    uint8_t push_temp[] = {0x50 + get_reg_index(temp_reg)};
    buffer_append(b, push_temp, 1);

    // MOV temp_reg, imm (null-safe construction)
    if (temp_reg == X86_REG_EAX) {
        generate_mov_eax_imm(b, imm);
    } else {
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);
        
        generate_mov_eax_imm(b, imm);
        
        uint8_t mov_temp_eax[] = {0x89, 0x00};
        mov_temp_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(temp_reg);
        buffer_append(b, mov_temp_eax, 2);
        
        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
    }

    // Apply operation: dst_reg OP temp_reg
    uint8_t op_code = 0;
    switch(insn->id) {
        case X86_INS_ADD: op_code = 0x01; break;  // ADD r32, r32
        case X86_INS_SUB: op_code = 0x29; break;  // SUB r32, r32
        case X86_INS_AND: op_code = 0x21; break;  // AND r32, r32
        case X86_INS_OR:  op_code = 0x09; break;  // OR r32, r32
        case X86_INS_XOR: op_code = 0x31; break;  // XOR r32, r32
        case X86_INS_CMP: op_code = 0x39; break;  // CMP r32, r32
        default: op_code = 0x01; break;  // Default to ADD
    }

    uint8_t op_code_bytes[] = {op_code, 0xC0};
    op_code_bytes[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(dst_reg);
    buffer_append(b, op_code_bytes, 2);

    // POP temp_reg
    uint8_t pop_temp[] = {0x58 + get_reg_index(temp_reg)};
    buffer_append(b, pop_temp, 1);
}

strategy_t arithmetic_imm_enhanced_strategy = {
    .name = "arithmetic_imm_enhanced",
    .can_handle = can_handle_arithmetic_imm_enhanced,
    .get_size = get_size_arithmetic_imm_enhanced,
    .generate = generate_arithmetic_imm_enhanced,
    .priority = 160  // Highest priority for final cleanup (higher than conditional jumps at 150)
};

// Let me revert the ultra_cleanup strategy since it was problematic
// Instead, let me make the existing strategies more robust by making sure they're not buggy

void register_remaining_null_elimination_strategies() {
    register_strategy(&lea_disp_enhanced_strategy);
    register_strategy(&mov_mem_disp_enhanced_strategy);
    register_strategy(&mov_imm_enhanced_strategy);
    register_strategy(&arithmetic_imm_enhanced_strategy);
    // Removed problematic ultra_cleanup_strategy that was introducing more nulls
}