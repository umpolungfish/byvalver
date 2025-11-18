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

    // Use LEA reg, [EAX] to get the address (which is the value in EAX)
    // The ModR/M byte for LEA r32, [r32] is: MM RRR MMM
    // For [EAX] (MMM=000) and dst_reg (RRR), ModR/M = 00 (RRR<<3) 000
    if (dst_reg == X86_REG_EAX) {
        // Use SIB byte to avoid null: LEA EAX, [EAX]
        uint8_t code[] = {0x8D, 0x04, 0x20}; // LEA EAX, [EAX] with SIB byte
        buffer_append(b, code, 3);
    } else {
        // For other registers, the ModR/M byte is safe
        uint8_t code[] = {0x8D, 0x00}; // LEA reg, [EAX] format
        code[1] = (get_reg_index(dst_reg) << 3) | 0;  // Encode dst_reg in reg field, [EAX] in r/m field
        buffer_append(b, code, 2);
    }
}

strategy_t lea_disp_nulls_strategy = {
    .name = "lea_disp_nulls",
    .can_handle = can_handle_lea_disp_nulls,
    .get_size = get_size_lea_disp_nulls,
    .generate = generate_lea_disp_nulls,
    .priority = 8  // Reduced priority to allow more targeted strategies to take precedence
};

// Register the LEA strategy
void register_lea_strategies() {
    register_strategy(&lea_disp_nulls_strategy);
}