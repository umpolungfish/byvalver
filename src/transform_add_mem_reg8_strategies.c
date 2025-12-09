#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// Enhanced ADD memory register8 null elimination strategy
// Handles ADD [memory], reg8 patterns where memory operand has null bytes

int can_handle_transform_add_mem_reg8(cs_insn *insn) {
    if (insn->id != X86_INS_ADD || insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Check for ADD [memory], reg8 pattern where memory contains null bytes
    if (insn->detail->x86.operands[0].type != X86_OP_MEM || 
        insn->detail->x86.operands[1].type != X86_OP_REG) {
        return 0;
    }

    // Check if the destination register is an 8-bit register
    uint8_t reg = insn->detail->x86.operands[1].reg;
    if (!(reg >= X86_REG_AL && reg <= X86_REG_BH) && 
        !(reg >= X86_REG_SIL && reg <= X86_REG_DIL) &&
        !(reg >= X86_REG_R8B && reg <= X86_REG_R15B)) {
        return 0;
    }

    // Check if memory operand has displacement with nulls
    int64_t disp = insn->detail->x86.operands[0].mem.disp;
    if (!((disp & 0xFF) == 0 || ((disp >> 8) & 0xFF) == 0 || 
          ((disp >> 16) & 0xFF) == 0 || ((disp >> 24) & 0xFF) == 0)) {
        // If displacement doesn't have nulls, check if instruction itself has null bytes
        if (!has_null_bytes(insn)) {
            return 0;
        }
    }

    return 1;
}

size_t get_size_transform_add_mem_reg8(cs_insn *insn) {
    // Use LEA + ADD approach: LEA reg, [mem] + ADD [reg], reg8 + MOV [mem], reg
    (void)insn;
    return 15;  // Conservative estimate
}

void generate_transform_add_mem_reg8(struct buffer *b, cs_insn *insn) {
    uint8_t src_reg = insn->detail->x86.operands[1].reg;
    x86_op_mem mem = insn->detail->x86.operands[0].mem;
    
    // For ADD [mem], reg8 where [mem] displacement contains nulls
    // 1. Load the value at [mem] to a temporary register
    // 2. Add the 8-bit register value to it
    // 3. Store the result back to [mem]
    
    // Get a temporary register (avoid conflicts)
    uint8_t temp_reg = (src_reg == X86_REG_EAX) ? X86_REG_EBX : X86_REG_EAX;
    uint8_t temp_reg_index = get_reg_index(temp_reg);
    uint8_t src_reg_index = get_reg_index(src_reg);
    
    // Save temporary register if needed
    if (temp_reg == X86_REG_EAX) {
        uint8_t push_temp[] = {0x50};
        buffer_append(b, push_temp, 1);
    }
    
    // Method 1: Calculate the memory address without null displacement
    // MOV temp_reg, disp (null-free construction)
    // Since generate_mov_eax_imm only works for EAX, we need to use a different approach
    // MOV EAX, disp (using null-free construction)
    generate_mov_eax_imm(b, (uint32_t)mem.disp);

    // MOV temp_reg, EAX (to move the value to temp_reg)
    uint8_t mov_temp_eax[] = {0x89, 0};
    mov_temp_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + temp_reg_index;
    buffer_append(b, mov_temp_eax, 2);
    
    // Add base register if present
    if (mem.base != X86_REG_INVALID) {
        uint8_t add_base[] = {0x01, 0};
        add_base[1] = 0xC0 + (get_reg_index(mem.base) << 3) + temp_reg_index;
        buffer_append(b, add_base, 2);
    }
    
    // Add scaled index register if present
    if (mem.index != X86_REG_INVALID) {
        // Handle scale factor (1, 2, 4, 8)
        if (mem.scale == 2) {
            // SHL index_reg, 1 then add
            // To avoid modifying the original index register, we'll work with temp
            uint8_t save_temp = temp_reg_index;
            
            // Save current temp value
            uint8_t push_curr_temp[] = {0x50};
            push_curr_temp[0] = 0x50 + save_temp;
            buffer_append(b, push_curr_temp, 1);
            
            // MOV temp2, index_reg (for calculation)
            uint8_t temp2 = (temp_reg == X86_REG_EAX || temp_reg == X86_REG_ECX) ? X86_REG_EDX : X86_REG_ECX;
            uint8_t mov_index[] = {0x89, 0};
            mov_index[1] = 0xC0 + (get_reg_index(mem.index) << 3) + get_reg_index(temp2);
            buffer_append(b, mov_index, 2);
            
            // SHL temp2, 1 (multiply by 2)
            uint8_t shl_code[] = {0xC1, 0xE0, 1};
            shl_code[1] = 0xE0 + get_reg_index(temp2);
            buffer_append(b, shl_code, 3);
            
            // ADD temp_reg, temp2 (add scaled index to address)
            uint8_t add_scaled[] = {0x01, 0};
            add_scaled[1] = 0xC0 + (get_reg_index(temp2) << 3) + temp_reg_index;
            buffer_append(b, add_scaled, 2);
            
            // Restore original temp value
            uint8_t pop_orig_temp[] = {0x58};
            pop_orig_temp[0] = 0x58 + save_temp;
            buffer_append(b, pop_orig_temp, 1);
            
            // Add the scaled index value to temp_reg
            uint8_t add_to_temp[] = {0x01, 0};
            add_to_temp[1] = 0xC0 + (get_reg_index(temp2) << 3) + temp_reg_index;
            buffer_append(b, add_to_temp, 2);
        } else if (mem.scale == 4) {
            // Similar approach for scale=4 (SHL index_reg, 2)
            uint8_t save_temp = temp_reg_index;
            uint8_t push_curr_temp[] = {0x50};
            push_curr_temp[0] = 0x50 + save_temp;
            buffer_append(b, push_curr_temp, 1);
            
            uint8_t temp2 = (temp_reg == X86_REG_EAX || temp_reg == X86_REG_ECX) ? X86_REG_EDX : X86_REG_ECX;
            uint8_t mov_index[] = {0x89, 0};
            mov_index[1] = 0xC0 + (get_reg_index(mem.index) << 3) + get_reg_index(temp2);
            buffer_append(b, mov_index, 2);
            
            uint8_t shl_code[] = {0xC1, 0xE0, 2};
            shl_code[1] = 0xE0 + get_reg_index(temp2);
            buffer_append(b, shl_code, 3);
            
            uint8_t add_scaled[] = {0x01, 0};
            add_scaled[1] = 0xC0 + (get_reg_index(temp2) << 3) + temp_reg_index;
            buffer_append(b, add_scaled, 2);
            
            uint8_t pop_orig_temp[] = {0x58};
            pop_orig_temp[0] = 0x58 + save_temp;
            buffer_append(b, pop_orig_temp, 1);
            
            uint8_t add_to_temp[] = {0x01, 0};
            add_to_temp[1] = 0xC0 + (get_reg_index(temp2) << 3) + temp_reg_index;
            buffer_append(b, add_to_temp, 2);
        } else if (mem.scale == 8) {
            // Similar approach for scale=8 (SHL index_reg, 3)
            uint8_t save_temp = temp_reg_index;
            uint8_t push_curr_temp[] = {0x50};
            push_curr_temp[0] = 0x50 + save_temp;
            buffer_append(b, push_curr_temp, 1);
            
            uint8_t temp2 = (temp_reg == X86_REG_EAX || temp_reg == X86_REG_ECX) ? X86_REG_EDX : X86_REG_ECX;
            uint8_t mov_index[] = {0x89, 0};
            mov_index[1] = 0xC0 + (get_reg_index(mem.index) << 3) + get_reg_index(temp2);
            buffer_append(b, mov_index, 2);
            
            uint8_t shl_code[] = {0xC1, 0xE0, 3};
            shl_code[1] = 0xE0 + get_reg_index(temp2);
            buffer_append(b, shl_code, 3);
            
            uint8_t add_scaled[] = {0x01, 0};
            add_scaled[1] = 0xC0 + (get_reg_index(temp2) << 3) + temp_reg_index;
            buffer_append(b, add_scaled, 2);
            
            uint8_t pop_orig_temp[] = {0x58};
            pop_orig_temp[0] = 0x58 + save_temp;
            buffer_append(b, pop_orig_temp, 1);
            
            uint8_t add_to_temp[] = {0x01, 0};
            add_to_temp[1] = 0xC0 + (get_reg_index(temp2) << 3) + temp_reg_index;
            buffer_append(b, add_to_temp, 2);
        } else {
            // Default case (scale = 1)
            uint8_t add_index[] = {0x01, 0};
            add_index[1] = 0xC0 + (get_reg_index(mem.index) << 3) + temp_reg_index;
            buffer_append(b, add_index, 2);
        }
    }
    
    // Now temp_reg holds the calculated memory address
    // We need to: 
    // 1. Load the value at [temp_reg] into another register
    // 2. Add the 8-bit register value to it
    // 3. Store the result back to [temp_reg]
    
    uint8_t value_reg = (temp_reg == X86_REG_EAX) ? X86_REG_EBX : 
                        (temp_reg == X86_REG_EBX) ? X86_REG_ECX : X86_REG_EAX;
    uint8_t value_reg_index = get_reg_index(value_reg);
    
    // Save value_reg if needed
    if (value_reg == X86_REG_EAX && temp_reg != X86_REG_EAX) {
        uint8_t push_val[] = {0x50};
        buffer_append(b, push_val, 1);
    }
    
    // MOV value_reg, [temp_reg] - load the memory value
    uint8_t mov_from_mem[] = {0x8B, 0x00};
    mov_from_mem[1] = 0x00 + (temp_reg_index << 3) + value_reg_index;  // MOD=00, reg=value_reg, r/m=temp_reg
    buffer_append(b, mov_from_mem, 2);
    
    // MOVZX value_reg, src_reg - zero-extend the 8-bit register to 32-bit
    uint8_t movzx_code[] = {0x0F, 0xB6, 0x00};
    movzx_code[2] = 0xC0 + (src_reg_index << 3) + value_reg_index;  // MOD=11, reg=value_reg, r/m=src_reg
    buffer_append(b, movzx_code, 3);
    
    // ADD value_reg, [temp_reg] - add the original memory value to the 8-bit register value
    uint8_t add_together[] = {0x01, 0x00};
    add_together[1] = 0x00 + (value_reg_index << 3) + temp_reg_index;  // ADD [temp_reg], value_reg
    buffer_append(b, add_together, 2);
    
    // Restore value_reg if needed
    if (value_reg == X86_REG_EAX && temp_reg != X86_REG_EAX) {
        uint8_t pop_val[] = {0x58};
        buffer_append(b, pop_val, 1);
    }
    
    // Restore temp register if needed
    if (temp_reg == X86_REG_EAX) {
        uint8_t pop_temp[] = {0x58};
        buffer_append(b, pop_temp, 1);
    }
}

strategy_t transform_add_mem_reg8_strategy = {
    .name = "transform_add_mem_reg8",
    .can_handle = can_handle_transform_add_mem_reg8,
    .get_size = get_size_transform_add_mem_reg8,
    .generate = generate_transform_add_mem_reg8,
    .priority = 85
};

void register_transform_add_mem_reg8_strategy() {
    register_strategy(&transform_add_mem_reg8_strategy);
}