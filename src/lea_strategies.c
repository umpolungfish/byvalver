#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// LEA with displacement containing null bytes strategy
int can_handle_lea_disp_nulls(cs_insn *insn) {
    if (insn->id != X86_INS_LEA) {
        return 0;
    }

    // Check if it has memory operands with displacement containing nulls
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        if (insn->detail->x86.operands[i].type == X86_OP_MEM &&
            insn->detail->x86.operands[i].mem.disp != 0) {
            
            uint32_t disp = (uint32_t)insn->detail->x86.operands[i].mem.disp;
            
            // Check if displacement has null bytes
            for (int j = 0; j < 4; j++) {
                if (((disp >> (j * 8)) & 0xFF) == 0) {
                    return 1; // Has null bytes in displacement
                }
            }
        }
    }
    
    return 0; // No memory operand with null bytes in displacement
}

size_t get_size_lea_disp_nulls(__attribute__((unused)) cs_insn *insn) {
    // MOV EAX, disp (typically 5-7 bytes using null-free construction) + MOV reg, EAX (2 bytes)
    return 9; // Conservative estimate
}

void generate_lea_disp_nulls(struct buffer *b, cs_insn *insn) {
    // Get the displacement from the memory operand
    uint32_t disp = 0;
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;
    
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        if (insn->detail->x86.operands[i].type == X86_OP_MEM) {
            disp = (uint32_t)insn->detail->x86.operands[i].mem.disp;
            break;
        }
    }
    
    // Load the displacement into EAX using null-free construction
    generate_mov_eax_imm(b, disp);
    
    // Move from EAX to the destination register
    if (dst_reg != X86_REG_EAX) {
        uint8_t mov_reg_eax[] = {0x89, 0xC0};
        mov_reg_eax[1] = mov_reg_eax[1] + get_reg_index(dst_reg);
        buffer_append(b, mov_reg_eax, 2);
    }
}

strategy_t lea_disp_nulls_strategy = {
    .name = "lea_disp_nulls",
    .can_handle = can_handle_lea_disp_nulls,
    .get_size = get_size_lea_disp_nulls,
    .generate = generate_lea_disp_nulls,
    .priority = 13  // Higher priority than other strategies
};

// Register the LEA strategy
void register_lea_strategies() {
    register_strategy(&lea_disp_nulls_strategy);
}