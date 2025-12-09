#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// MOV register to memory self transformation strategy
// This strategy likely handles cases where MOV reg, [reg] patterns need transformation
// Or other patterns where register and memory operand interact in self-referential ways

int can_handle_transform_mov_reg_mem_self(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Handle MOV [memory], reg patterns where memory addressing involves the same register
    // or where the instruction contains null bytes that need elimination
    if (insn->detail->x86.operands[0].type != X86_OP_MEM || 
        insn->detail->x86.operands[1].type != X86_OP_REG) {
        return 0;
    }

    // Check if the memory operand has displacement with null bytes
    int64_t disp = insn->detail->x86.operands[0].mem.disp;
    if (((disp & 0xFF) == 0 || ((disp >> 8) & 0xFF) == 0 || 
         ((disp >> 16) & 0xFF) == 0 || ((disp >> 24) & 0xFF) == 0)) {
        return 1;  // Displacement has null bytes
    }
    
    // Or check if the instruction itself contains null bytes
    if (has_null_bytes(insn)) {
        return 1;
    }

    return 0;
}

size_t get_size_transform_mov_reg_mem_self(cs_insn *insn) {
    // Use temporary register approach: MOV temp_reg, src_reg + MOV [address], temp_reg
    (void)insn;
    return 10;  // Conservative estimate
}

void generate_transform_mov_reg_mem_self(struct buffer *b, cs_insn *insn) {
    uint8_t src_reg = insn->detail->x86.operands[1].reg;
    x86_op_mem mem = insn->detail->x86.operands[0].mem;
    
    // For MOV [mem], reg where mem displacement contains nulls
    // 1. Calculate the memory address using null-free approach
    // 2. Store the source register value to that calculated address
    
    uint8_t src_reg_index = get_reg_index(src_reg);
    
    // Use a temporary register approach to avoid null bytes in displacement
    uint8_t addr_reg = (src_reg == X86_REG_EAX) ? X86_REG_EBX : X86_REG_EAX;
    uint8_t addr_reg_index = get_reg_index(addr_reg);
    
    // Save address register if needed
    if (addr_reg == X86_REG_EAX) {
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);
    }
    
    // MOV EAX, displacement (null-free construction)
    generate_mov_eax_imm(b, (uint32_t)mem.disp);

    // MOV addr_reg, EAX (to move the value to addr_reg)
    uint8_t mov_addr_eax[] = {0x89, 0};
    mov_addr_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + addr_reg_index;
    buffer_append(b, mov_addr_eax, 2);
    
    // Add base register if present
    if (mem.base != X86_REG_INVALID) {
        uint8_t add_base[] = {0x01, 0};
        add_base[1] = 0xC0 + (get_reg_index(mem.base) << 3) + addr_reg_index;
        buffer_append(b, add_base, 2);
    }
    
    // Add scaled index register if present
    if (mem.index != X86_REG_INVALID) {
        if (mem.scale == 2) {
            // For scale=2: SHL index_reg, 1 then add
            uint8_t save_addr = addr_reg_index;
            uint8_t push_addr[] = {0x50};
            push_addr[0] = 0x50 + save_addr;
            buffer_append(b, push_addr, 1);
            
            // MOV temp, index_reg
            uint8_t temp_reg = (addr_reg == X86_REG_EAX) ? X86_REG_ECX : 
                              (addr_reg == X86_REG_ECX) ? X86_REG_EDX : X86_REG_ECX;
            uint8_t mov_index[] = {0x89, 0};
            mov_index[1] = 0xC0 + (get_reg_index(mem.index) << 3) + get_reg_index(temp_reg);
            buffer_append(b, mov_index, 2);
            
            // SHL temp, 1
            uint8_t shl_code[] = {0xC1, 0xE0, 1};
            shl_code[1] = 0xE0 + get_reg_index(temp_reg);
            buffer_append(b, shl_code, 3);
            
            // ADD addr_reg, temp
            uint8_t add_scaled[] = {0x01, 0};
            add_scaled[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + addr_reg_index;
            buffer_append(b, add_scaled, 2);
            
            uint8_t pop_addr[] = {0x58};
            pop_addr[0] = 0x58 + save_addr;
            buffer_append(b, pop_addr, 1);
        } else if (mem.scale == 4) {
            // For scale=4: SHL index_reg, 2 then add
            uint8_t save_addr = addr_reg_index;
            uint8_t push_addr[] = {0x50};
            push_addr[0] = 0x50 + save_addr;
            buffer_append(b, push_addr, 1);
            
            uint8_t temp_reg = (addr_reg == X86_REG_EAX) ? X86_REG_ECX : 
                              (addr_reg == X86_REG_ECX) ? X86_REG_EDX : X86_REG_ECX;
            uint8_t mov_index[] = {0x89, 0};
            mov_index[1] = 0xC0 + (get_reg_index(mem.index) << 3) + get_reg_index(temp_reg);
            buffer_append(b, mov_index, 2);
            
            uint8_t shl_code[] = {0xC1, 0xE0, 2};
            shl_code[1] = 0xE0 + get_reg_index(temp_reg);
            buffer_append(b, shl_code, 3);
            
            uint8_t add_scaled[] = {0x01, 0};
            add_scaled[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + addr_reg_index;
            buffer_append(b, add_scaled, 2);
            
            uint8_t pop_addr[] = {0x58};
            pop_addr[0] = 0x58 + save_addr;
            buffer_append(b, pop_addr, 1);
        } else if (mem.scale == 8) {
            // For scale=8: SHL index_reg, 3 then add
            uint8_t save_addr = addr_reg_index;
            uint8_t push_addr[] = {0x50};
            push_addr[0] = 0x50 + save_addr;
            buffer_append(b, push_addr, 1);
            
            uint8_t temp_reg = (addr_reg == X86_REG_EAX) ? X86_REG_ECX : 
                              (addr_reg == X86_REG_ECX) ? X86_REG_EDX : X86_REG_ECX;
            uint8_t mov_index[] = {0x89, 0};
            mov_index[1] = 0xC0 + (get_reg_index(mem.index) << 3) + get_reg_index(temp_reg);
            buffer_append(b, mov_index, 2);
            
            uint8_t shl_code[] = {0xC1, 0xE0, 3};
            shl_code[1] = 0xE0 + get_reg_index(temp_reg);
            buffer_append(b, shl_code, 3);
            
            uint8_t add_scaled[] = {0x01, 0};
            add_scaled[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + addr_reg_index;
            buffer_append(b, add_scaled, 2);
            
            uint8_t pop_addr[] = {0x58};
            pop_addr[0] = 0x58 + save_addr;
            buffer_append(b, pop_addr, 1);
        } else {
            // Default scale=1: add index directly
            uint8_t add_index[] = {0x01, 0};
            add_index[1] = 0xC0 + (get_reg_index(mem.index) << 3) + addr_reg_index;
            buffer_append(b, add_index, 2);
        }
    }
    
    // Now addr_reg contains the target memory address
    // MOV [addr_reg], src_reg - store the source register value at the calculated address
    uint8_t mov_to_mem[] = {0x89, 0x00};
    mov_to_mem[1] = 0x00 + (src_reg_index << 3) + addr_reg_index;  // MOD=00, reg=src_reg, r/m=addr_reg
    buffer_append(b, mov_to_mem, 2);
    
    // Restore address register if needed
    if (addr_reg == X86_REG_EAX) {
        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
    }
}

strategy_t transform_mov_reg_mem_self_strategy = {
    .name = "transform_mov_reg_mem_self",
    .can_handle = can_handle_transform_mov_reg_mem_self,
    .get_size = get_size_transform_mov_reg_mem_self,
    .generate = generate_transform_mov_reg_mem_self,
    .priority = 85
};

void register_transform_mov_reg_mem_self_strategy() {
    register_strategy(&transform_mov_reg_mem_self_strategy);
}