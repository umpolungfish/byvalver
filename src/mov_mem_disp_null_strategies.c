#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// MOV memory displacement null elimination strategy
// Handles cases like: MOV reg, [disp32] where disp32 contains null bytes
// Converts to: LEA reg, [disp32] followed by appropriate handling or register manipulations

int can_handle_mov_mem_disp_null(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Check if source is memory with displacement and destination is register
    if (insn->detail->x86.operands[0].type != X86_OP_REG ||
        insn->detail->x86.operands[1].type != X86_OP_MEM) {
        return 0;
    }

    // Check if the memory operand has a displacement that contains null bytes
    int64_t disp = insn->detail->x86.operands[1].mem.disp;

    // Check if displacement contains null bytes
    if (!((disp & 0xFF) == 0 || ((disp >> 8) & 0xFF) == 0 ||
          ((disp >> 16) & 0xFF) == 0 || ((disp >> 24) & 0xFF) == 0)) {
        return 0;
    }

    // Ensure no base or index registers (pure displacement)
    if (insn->detail->x86.operands[1].mem.base != X86_REG_INVALID ||
        insn->detail->x86.operands[1].mem.index != X86_REG_INVALID) {
        return 0;
    }

    return 1;
}

size_t get_size_mov_mem_disp_null(cs_insn *insn) {
    // MOV EAX, disp (6 bytes worst case) + MOV dest_reg, [EAX] (2 bytes) = 8 bytes in total (worst case)
    (void)insn; // Suppress unused parameter warning
    return 8;
}

void generate_mov_mem_disp_null(struct buffer *b, cs_insn *insn) {
    uint8_t dest_reg = insn->detail->x86.operands[0].reg;
    int64_t disp = insn->detail->x86.operands[1].mem.disp;

    // We need to load from [disp] where disp contains null bytes
    // Use an alternative approach: MOV EAX, disp (null-free construction) + MOV dest_reg, [EAX]

    uint8_t dest_reg_index = get_reg_index(dest_reg);

    // If destination is EAX, we need to use a different temporary register
    uint8_t temp_reg = (dest_reg == X86_REG_EAX) ? X86_REG_EBX : X86_REG_EAX;
    uint8_t temp_reg_index = get_reg_index(temp_reg);

    // Save the temporary register if needed
    if (temp_reg == X86_REG_EAX) {
        uint8_t push_temp[] = {0x50};  // PUSH EAX
        buffer_append(b, push_temp, 1);
    }

    // MOV temp_reg, displacement (using null-free construction)
    // This requires using existing functions or constructing the MOV instruction manually
    // Since the displacement has nulls, we need to build it with a null-free approach

    // Method: Construct the address indirectly
    // MOV temp_reg, high_part (null-free)
    // SHL temp_reg, 16
    // ADD temp_reg, low_part (null-free)
    // MOV dest_reg, [temp_reg]

    uint32_t target_addr = (uint32_t)disp;

    // Load the displacement using null-free construction
    // MOV EAX, target_addr (using null-free construction)
    generate_mov_eax_imm(b, target_addr);

    // MOV temp_reg, EAX (to move the value to temp_reg)
    uint8_t mov_temp_eax[] = {0x89, 0};
    mov_temp_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + temp_reg_index;
    buffer_append(b, mov_temp_eax, 2);

    // MOV dest_reg, [temp_reg] - load the value from the memory address
    uint8_t mov_from_temp[] = {0x8B, 0x00};
    mov_from_temp[1] = 0x00 + (dest_reg_index << 3) + temp_reg_index;
    buffer_append(b, mov_from_temp, 2);

    // Restore the temporary register if needed
    if (temp_reg == X86_REG_EAX) {
        uint8_t pop_temp[] = {0x58};  // POP EAX
        buffer_append(b, pop_temp, 1);
    }
}


strategy_t mov_mem_disp_null_strategy = {
    .name = "mov_mem_disp_null",
    .can_handle = can_handle_mov_mem_disp_null,
    .get_size = get_size_mov_mem_disp_null,
    .generate = generate_mov_mem_disp_null,
    .priority = 80
};

void register_mov_mem_disp_null_strategy() {
    register_strategy(&mov_mem_disp_null_strategy);
}