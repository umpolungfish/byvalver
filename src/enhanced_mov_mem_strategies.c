#include "strategy.h"
#include "utils.h"
#include "profile_aware_sib.h"
#include <stdio.h>
#include <string.h>

// Enhanced MOV mem, imm strategy for when the immediate operand contains nulls
int can_handle_mov_mem_imm_enhanced(__attribute__((unused)) cs_insn *insn) {
    // DISABLED: Complex implementation with multiple null-introduction paths
    // Recursive calls to generate_mov_eax_imm() may introduce nulls
    // ModR/M byte calculations can produce 0x00
    // See analysis report: 3,286 attempts with 0% success rate
    // Issue: https://github.com/mrnob0dy666/byvalver/issues/XXX
    return 0;
}

size_t get_size_mov_mem_imm_enhanced(__attribute__((unused)) cs_insn *insn) {
    // MOV EAX, imm (null-free) + MOV [mem], EAX = ~10-20 bytes depending on memory operand
    return 20; // Conservative estimate
}

void generate_mov_mem_imm_enhanced(struct buffer *b, cs_insn *insn) {
    // Extract operands
    cs_x86_op *dst = &insn->detail->x86.operands[0]; // memory destination
    cs_x86_op *src = &insn->detail->x86.operands[1]; // immediate source
    uint32_t imm = (uint32_t)src->imm;

    // For memory operand, we'll use EAX as temporary to load the immediate value, 
    // then store it to the destination memory location
    
    // Save original EAX
    uint8_t push_eax[] = {0x50};
    buffer_append(b, push_eax, 1);

    // MOV EAX, imm (null-free construction)
    generate_mov_eax_imm(b, imm);

    // Prepare to store EAX to memory destination
    // Handle different memory addressing modes
    
    // If destination is [disp32] (no base/index registers)
    if (dst->mem.base == X86_REG_INVALID && dst->mem.index == X86_REG_INVALID) {
        uint32_t addr = (uint32_t)dst->mem.disp;
        
        // MOV EAX, addr (for address calculation)
        if (is_bad_byte_free(addr)) {
            // Direct addressing is safe
            uint8_t mov_addr[] = {0xB8, 0, 0, 0, 0};
            memcpy(mov_addr + 1, &addr, 4);
            buffer_append(b, mov_addr, 5);
            
            // MOV [EAX], EAX (where EAX now contains the original immediate value)
            // Wait, we need to restore the original EAX value first
            // Instead, we'll use alternative approach:
            // MOV [addr], EAX -> but this might have nulls if addr has nulls
            // Better approach: MOV ECX, addr; MOV [ECX], EAX
            
            uint8_t push_ecx[] = {0x51};
            buffer_append(b, push_ecx, 1);
            
            // MOV ECX, addr
            generate_mov_eax_imm(b, addr);
            uint8_t mov_ecx_eax[] = {0x89, 0xC1}; // MOV ECX, EAX
            buffer_append(b, mov_ecx_eax, 2);
            
            // MOV [ECX], EAX (store original immediate value from EAX to [ECX])
            uint8_t mov_ecx_eax_store[] = {0x89, 0x01}; // MOV [ECX], EAX
            buffer_append(b, mov_ecx_eax_store, 2);
            
            // POP ECX (restore original ECX)
            uint8_t pop_ecx[] = {0x59};
            buffer_append(b, pop_ecx, 1);
        } else {
            // Use SIB addressing to avoid nulls in address
            uint8_t push_ecx[] = {0x51};
            buffer_append(b, push_ecx, 1);
            
            // MOV ECX, addr (null-free construction)
            generate_mov_eax_imm(b, addr);
            uint8_t mov_ecx_eax[] = {0x89, 0xC1}; // MOV ECX, EAX
            buffer_append(b, mov_ecx_eax, 2);
            
            // MOV [ECX], EAX (store original immediate value from EAX to [ECX])
            uint8_t mov_ecx_eax_store[] = {0x89, 0x01}; // MOV [ECX], EAX
            buffer_append(b, mov_ecx_eax_store, 2);
            
            // POP ECX (restore original ECX)
            uint8_t pop_ecx[] = {0x59};
            buffer_append(b, pop_ecx, 1);
        }
    } 
    // If destination has base register (e.g., [EAX], [EBX+disp], etc.)
    else if (dst->mem.base != X86_REG_INVALID) {
        // Handle [base + disp] addressing
        x86_reg base_reg = dst->mem.base;
        
        // If it's just [base] with no displacement
        if (dst->mem.disp == 0) {
            // MOV [base_reg], EAX
            uint8_t modrm = 0x00 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(base_reg);
            
            // Check if modrm creates a null byte (when both regs are EAX)
            if (modrm == 0x00) {
                // Use profile-safe approach to avoid null
                if (generate_safe_mov_mem_reg(b, X86_REG_EAX, X86_REG_EAX) != 0) {
                    // Fallback: PUSH/POP
                    uint8_t push[] = {0x50};
                    buffer_append(b, push, 1);
                    uint8_t pop[] = {0x8F, 0x00};
                    buffer_append(b, pop, 2);
                }
            } else {
                uint8_t code[] = {0x89, modrm};
                buffer_append(b, code, 2);
            }
        } 
        // If it has displacement
        else {
            uint32_t disp = (uint32_t)dst->mem.disp;
            
            if ((int32_t)disp >= -128 && (int32_t)disp <= 127 && is_bad_byte_free_byte((uint8_t)disp)) {
                // Use disp8 format
                uint8_t modrm = 0x40 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(base_reg);
                if (modrm == 0x40) {
                    // Avoid null when both regs are EAX: MOV [EAX+disp8], EAX -> use SIB instead
                    uint8_t code[] = {0x89, 0x44, 0x20, 0};
                    code[3] = (uint8_t)disp;
                    buffer_append(b, code, 4);
                } else {
                    uint8_t code[] = {0x89, modrm, (uint8_t)disp};
                    buffer_append(b, code, 3);
                }
            } else if (is_bad_byte_free(disp)) {
                // Use disp32 format
                uint8_t modrm = 0x80 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(base_reg);
                uint8_t code[] = {0x89, modrm, 0, 0, 0, 0};
                memcpy(code + 2, &disp, 4);
                
                if (modrm == 0x80) {
                    // Avoid null when both regs are EAX: MOV [EAX+disp32], EAX -> use SIB instead
                    uint8_t code_sib[] = {0x89, 0x84, 0x20, 0, 0, 0, 0};
                    memcpy(code_sib + 3, &disp, 4);
                    buffer_append(b, code_sib, 7);
                } else {
                    buffer_append(b, code, 6);
                }
            } else {
                // Both displacement and ModR/M would have nulls, use indirect approach
                // PUSH ECX; MOV ECX, base_reg; ADD ECX, disp; MOV [ECX], EAX; POP ECX
                uint8_t push_ecx[] = {0x51};
                buffer_append(b, push_ecx, 1);
                
                // MOV ECX, base_reg
                uint8_t mov_ecx_basereg[] = {0x89, 0xC1};
                mov_ecx_basereg[1] = 0xC1 + (get_reg_index(base_reg) << 3) + get_reg_index(X86_REG_ECX);
                buffer_append(b, mov_ecx_basereg, 2);
                
                // ADD ECX, disp (null-free construction)
                generate_mov_eax_imm(b, disp);
                uint8_t add_ecx_eax[] = {0x01, 0xC1};
                buffer_append(b, add_ecx_eax, 2);
                
                // MOV [ECX], EAX
                uint8_t mov_ecx_eax[] = {0x89, 0x01};
                buffer_append(b, mov_ecx_eax, 2);
                
                // POP ECX
                uint8_t pop_ecx[] = {0x59};
                buffer_append(b, pop_ecx, 1);
            }
        }
    }
    // If destination has index register (e.g., [EAX*4], [EBX*2+disp], etc.)
    else if (dst->mem.index != X86_REG_INVALID) {
        // Complex SIB addressing
        x86_reg index_reg = dst->mem.index;
        x86_reg base_reg = dst->mem.base;
        int scale = dst->mem.scale;
        
        // This is complex, for now we'll handle using the general approach
        // Save ECX, compute address in ECX, then move EAX to [ECX]
        
        uint8_t push_ecx[] = {0x51};
        buffer_append(b, push_ecx, 1);
        
        // Calculate address: base + index*scale + disp
        // MOV ECX, base (if exists)
        if (base_reg != X86_REG_INVALID) {
            uint8_t mov_ecx_base[] = {0x89, 0xC1};
            mov_ecx_base[1] = 0xC1 + (get_reg_index(base_reg) << 3) + get_reg_index(X86_REG_ECX);
            buffer_append(b, mov_ecx_base, 2);
        } else {
            // XOR ECX, ECX to zero it out
            uint8_t xor_ecx[] = {0x31, 0xC9};
            buffer_append(b, xor_ecx, 2);
        }
        
        // Scale and add index: MOV EAX, index; SHL EAX, scale_log2; ADD ECX, EAX
        uint8_t log2_scale = 0;
        switch(scale) {
            case 2: log2_scale = 1; break;
            case 4: log2_scale = 2; break;
            case 8: log2_scale = 3; break;
            default: log2_scale = 0; break; // scale = 1
        }
        
        if (log2_scale > 0) {
            // MOV EAX, index_reg
            uint8_t mov_eax_index[] = {0x89, 0xC0};
            mov_eax_index[1] = 0xC0 + (get_reg_index(index_reg) << 3) + get_reg_index(X86_REG_EAX);
            buffer_append(b, mov_eax_index, 2);
            
            // SHL EAX, log2_scale
            uint8_t shl_eax[] = {0xC1, 0xE0, log2_scale};
            buffer_append(b, shl_eax, 3);
            
            // ADD ECX, EAX
            uint8_t add_ecx_eax[] = {0x01, 0xC1};
            buffer_append(b, add_ecx_eax, 2);
        } else {
            // MOV EAX, index_reg; ADD ECX, EAX
            uint8_t mov_eax_index[] = {0x89, 0xC0};
            mov_eax_index[1] = 0xC0 + (get_reg_index(index_reg) << 3) + get_reg_index(X86_REG_EAX);
            buffer_append(b, mov_eax_index, 2);
            
            uint8_t add_ecx_eax[] = {0x01, 0xC1};
            buffer_append(b, add_ecx_eax, 2);
        }
        
        // Add displacement if exists
        if (dst->mem.disp != 0) {
            uint32_t disp = (uint32_t)dst->mem.disp;
            if (is_bad_byte_free(disp)) {
                // ADD ECX, disp
                uint8_t add_ecx_disp[] = {0x81, 0xC1, 0, 0, 0, 0};
                memcpy(add_ecx_disp + 2, &disp, 4);
                buffer_append(b, add_ecx_disp, 6);
            } else {
                // Use null-free construction: MOV EAX, disp; ADD ECX, EAX
                generate_mov_eax_imm(b, disp);
                uint8_t add_ecx_eax[] = {0x01, 0xC1};
                buffer_append(b, add_ecx_eax, 2);
            }
        }
        
        // MOV [ECX], EAX (store the immediate value to calculated address)
        uint8_t mov_ecx_eax[] = {0x89, 0x01};
        buffer_append(b, mov_ecx_eax, 2);
        
        // POP ECX
        uint8_t pop_ecx[] = {0x59};
        buffer_append(b, pop_ecx, 1);
    }
    
    // Restore original EAX
    uint8_t pop_eax[] = {0x58};
    buffer_append(b, pop_eax, 1);
}

strategy_t mov_mem_imm_enhanced_strategy = {
    .name = "mov_mem_imm_enhanced",
    .can_handle = can_handle_mov_mem_imm_enhanced,
    .get_size = get_size_mov_mem_imm_enhanced,
    .generate = generate_mov_mem_imm_enhanced,
    .priority = 75  // High priority to catch cases that simpler strategies miss
};

// Enhanced strategy to handle generic memory displacement with nulls
int can_handle_generic_mem_null_disp_enhanced(cs_insn *insn) {
    // General handler for any memory operation with displacement containing nulls
    if (insn->detail->x86.op_count < 1) {
        return 0;
    }

    // Check all operands for memory with displacement that contains nulls
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        if (insn->detail->x86.operands[i].type == X86_OP_MEM) {
            if (insn->detail->x86.operands[i].mem.disp != 0) {
                uint32_t disp = (uint32_t)insn->detail->x86.operands[i].mem.disp;
                if (!is_bad_byte_free(disp)) {
                    return 1; // Has null in displacement
                }
            }
        }
    }

    return 0;
}

size_t get_size_generic_mem_null_disp_enhanced(__attribute__((unused)) cs_insn *insn) {
    // Conservative estimate: MOV reg, disp + actual instruction with [reg]
    return 25;
}

void generate_generic_mem_null_disp_enhanced(struct buffer *b, cs_insn *insn) {
    // Find which operand has the memory displacement with nulls
    int mem_operand_idx = -1;
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        if (insn->detail->x86.operands[i].type == X86_OP_MEM) {
            if (insn->detail->x86.operands[i].mem.disp != 0) {
                uint32_t disp = (uint32_t)insn->detail->x86.operands[i].mem.disp;
                if (!is_bad_byte_free(disp)) {
                    mem_operand_idx = i;
                    break;
                }
            }
        }
    }

    if (mem_operand_idx == -1) {
        // No memory operand with null displacement found, append original
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    // Find a free register to use for address calculation (avoid conflicts with operands)
    x86_reg addr_reg = X86_REG_ECX; // Default register
    // Check if ECX is used in the instruction; if so, use another register
    int j;
    for (j = 0; j < insn->detail->x86.op_count; j++) {
        if (insn->detail->x86.operands[j].type == X86_OP_REG &&
            insn->detail->x86.operands[j].reg == addr_reg) {
            addr_reg = X86_REG_EDX; // Use EDX instead
            break;
        }
    }
    if (j < insn->detail->x86.op_count) { // If EDX was also used
        for (j = 0; j < insn->detail->x86.op_count; j++) {
            if (insn->detail->x86.operands[j].type == X86_OP_REG &&
                insn->detail->x86.operands[j].reg == addr_reg) {
                addr_reg = X86_REG_EBX; // Use EBX instead
                break;
            }
        }
        if (j < insn->detail->x86.op_count) { // If EBX was also used
            addr_reg = X86_REG_ESI; // Use ESI as fallback
        }
    }

    // PUSH the chosen register to save its original value
    uint8_t push_reg[] = {0x50 + get_reg_index(addr_reg)};
    buffer_append(b, push_reg, 1);

    // Calculate the effective address: base + index*scale + disp
    cs_x86_op *mem_op = &insn->detail->x86.operands[mem_operand_idx];
    uint32_t disp = (uint32_t)mem_op->mem.disp;

    // MOV addr_reg, disp (null-free construction)
    generate_mov_eax_imm(b, disp);

    // MOV addr_reg, EAX (move the immediate to our address register)
    uint8_t mov_addr_reg[] = {0x89, 0xC0};
    mov_addr_reg[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(addr_reg);
    buffer_append(b, mov_addr_reg, 2);

    // If there's a base register, add it to the address
    if (mem_op->mem.base != X86_REG_INVALID) {
        // MOV EAX, base_reg
        uint8_t mov_eax_base[] = {0x89, 0xC0};
        mov_eax_base[1] = 0xC0 + (get_reg_index(mem_op->mem.base) << 3) + get_reg_index(X86_REG_EAX);
        buffer_append(b, mov_eax_base, 2);

        // ADD addr_reg, EAX
        uint8_t add_addr_eax[] = {0x01, 0xC0};
        add_addr_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(addr_reg);
        buffer_append(b, add_addr_eax, 2);
    }

    // If there's an index register with scale, add it to the address
    if (mem_op->mem.index != X86_REG_INVALID) {
        // MOV EAX, index_reg
        uint8_t mov_eax_index[] = {0x89, 0xC0};
        mov_eax_index[1] = 0xC0 + (get_reg_index(mem_op->mem.index) << 3) + get_reg_index(X86_REG_EAX);
        buffer_append(b, mov_eax_index, 2);

        // Apply scaling if needed (scale 2, 4, or 8)
        if (mem_op->mem.scale > 1) {
            uint8_t log2_scale = 0;
            switch(mem_op->mem.scale) {
                case 2: log2_scale = 1; break;
                case 4: log2_scale = 2; break;
                case 8: log2_scale = 3; break;
                default: log2_scale = 0; break;
            }

            if (log2_scale > 0) {
                // SHL EAX, log2_scale
                uint8_t shl_eax[] = {0xC1, 0xE0, log2_scale};
                buffer_append(b, shl_eax, 3);
            }
        }

        // ADD addr_reg, EAX
        uint8_t add_addr_eax[] = {0x01, 0xC0};
        add_addr_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(addr_reg);
        buffer_append(b, add_addr_eax, 2);
    }

    // Now replace the memory operand with [addr_reg] and generate the corresponding instruction
    // For now, let's handle the most common instruction types: MOV, ADD, SUB, CMP
    if (insn->id == X86_INS_MOV) {
        // Handle MOV instruction with memory operand replacement
        if (mem_operand_idx == 0) { // Destination is memory
            // The address is now in addr_reg, so we need to create MOV [addr_reg], source
            if (insn->detail->x86.operands[1].type == X86_OP_REG) {
                x86_reg src_reg = insn->detail->x86.operands[1].reg;
                // MOV [addr_reg], src_reg
                uint8_t modrm = 0x00 + (get_reg_index(src_reg) << 3) + get_reg_index(addr_reg);
                if (modrm == 0x00) {
                    // Use profile-safe approach
                    if (generate_safe_mov_mem_reg(b, addr_reg, src_reg) != 0) {
                        uint8_t push[] = {0x50 | get_reg_index(src_reg)};
                        buffer_append(b, push, 1);
                        uint8_t pop[] = {0x8F, 0x00 | get_reg_index(addr_reg)};
                        buffer_append(b, pop, 2);
                    }
                } else {
                    uint8_t mov_reg[] = {0x89, modrm};
                    buffer_append(b, mov_reg, 2);
                }
            } else if (insn->detail->x86.operands[1].type == X86_OP_IMM) {
                uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
                if (is_bad_byte_free(imm)) {
                    // MOV [addr_reg], imm32
                    uint8_t modrm = 0x80 + get_reg_index(addr_reg);
                    if (modrm == 0x80) {
                        // Profile-safe fallback: use EAX as intermediary
                        generate_mov_eax_imm(b, imm);
                        if (generate_safe_mov_mem_reg(b, addr_reg, X86_REG_EAX) != 0) {
                            uint8_t push[] = {0x50};
                            buffer_append(b, push, 1);
                            uint8_t pop[] = {0x8F, 0x00 | get_reg_index(addr_reg)};
                            buffer_append(b, pop, 2);
                        }
                    } else {
                        uint8_t mov_imm[] = {0xC7, modrm, 0, 0, 0, 0};
                        memcpy(mov_imm + 2, &imm, 4);
                        buffer_append(b, mov_imm, 6);
                    }
                } else {
                    // Use null-free construction for immediate: MOV EAX, imm; MOV [addr_reg], EAX
                    generate_mov_eax_imm(b, imm);
                    uint8_t modrm = 0x00 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(addr_reg);
                    if (modrm == 0x00) {
                        // Use profile-safe approach
                        if (generate_safe_mov_mem_reg(b, addr_reg, X86_REG_EAX) != 0) {
                            uint8_t push[] = {0x50};
                            buffer_append(b, push, 1);
                            uint8_t pop[] = {0x8F, 0x00 | get_reg_index(addr_reg)};
                            buffer_append(b, pop, 2);
                        }
                    } else {
                        uint8_t mov_eax[] = {0x89, modrm};
                        buffer_append(b, mov_eax, 2);
                    }
                }
            }
        } else { // Source is memory (shouldn't happen in MOV, but for completeness)
            // Handle MOV destination, [addr_reg]
            if (insn->detail->x86.operands[0].type == X86_OP_REG) {
                x86_reg dst_reg = insn->detail->x86.operands[0].reg;
                // MOV dst_reg, [addr_reg]
                uint8_t modrm = 0x00 + (get_reg_index(dst_reg) << 3) + get_reg_index(addr_reg);
                if (modrm == 0x00) {
                    // Use profile-safe approach
                    if (generate_safe_mov_reg_mem(b, dst_reg, addr_reg) != 0) {
                        uint8_t push[] = {0xFF, 0x30 | get_reg_index(addr_reg)};
                        buffer_append(b, push, 2);
                        uint8_t pop[] = {0x58 | get_reg_index(dst_reg)};
                        buffer_append(b, pop, 1);
                    }
                } else {
                    uint8_t mov[] = {0x8B, modrm};
                    buffer_append(b, mov, 2);
                }
            }
        }
    } else if (insn->id == X86_INS_ADD) {
        // Handle ADD instruction with memory operand replacement
        if (mem_operand_idx == 0) { // Destination is memory
            if (insn->detail->x86.operands[1].type == X86_OP_REG) {
                x86_reg src_reg = insn->detail->x86.operands[1].reg;
                // ADD [addr_reg], src_reg
                uint8_t modrm = 0x00 + (get_reg_index(src_reg) << 3) + get_reg_index(addr_reg);
                if (modrm == 0x00) {
                    // Profile-safe fallback for ADD
                    // PUSH [addr_reg], POP EDX, ADD EDX,src, PUSH EDX, POP [addr_reg]
                    uint8_t push_mem[] = {0xFF, 0x30 | get_reg_index(addr_reg)};
                    buffer_append(b, push_mem, 2);
                    uint8_t pop_edx[] = {0x5A};
                    buffer_append(b, pop_edx, 1);
                    uint8_t add_edx[] = {0x01, 0xC0 | (get_reg_index(src_reg) << 3) | 2};
                    buffer_append(b, add_edx, 2);
                    uint8_t push_edx[] = {0x52};
                    buffer_append(b, push_edx, 1);
                    uint8_t pop_mem[] = {0x8F, 0x00 | get_reg_index(addr_reg)};
                    buffer_append(b, pop_mem, 2);
                } else {
                    uint8_t add[] = {0x01, modrm};
                    buffer_append(b, add, 2);
                }
            } else if (insn->detail->x86.operands[1].type == X86_OP_IMM) {
                uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
                if (is_bad_byte_free(imm)) {
                    // ADD [addr_reg], imm32
                    uint8_t modrm = 0x80 + get_reg_index(addr_reg);
                    if (modrm == 0x80) {
                        // FIXED: Use PUSH/POP approach instead of hardcoded SIB 0x20
                        // PUSH [addr_reg], modify TOS, POP back
                        uint8_t push[] = {0xFF, 0x30 | get_reg_index(addr_reg)};
                        buffer_append(b, push, 2);
                        uint8_t add_tos[] = {0x83, 0x04, 0x24, (uint8_t)imm}; // ADD [ESP], imm
                        buffer_append(b, add_tos, 4);
                        uint8_t pop[] = {0x8F, 0x00 | get_reg_index(addr_reg)};
                        buffer_append(b, pop, 2);
                    } else {
                        uint8_t add_imm[] = {0x83, modrm, (uint8_t)imm};
                        buffer_append(b, add_imm, 3);
                    }
                } else {
                    // Use null-free construction for immediate
                    generate_mov_eax_imm(b, imm);
                    // ADD [addr_reg], EAX
                    uint8_t modrm = 0x00 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(addr_reg);
                    if (modrm == 0x00) {
                        // FIXED: Use PUSH/POP approach instead of hardcoded SIB 0x20
                        uint8_t push[] = {0xFF, 0x30 | get_reg_index(addr_reg)};
                        buffer_append(b, push, 2);
                        uint8_t add_tos[] = {0x01, 0x04, 0x24}; // ADD [ESP], EAX
                        buffer_append(b, add_tos, 3);
                        uint8_t pop[] = {0x8F, 0x00 | get_reg_index(addr_reg)};
                        buffer_append(b, pop, 2);
                    } else {
                        uint8_t add[] = {0x01, modrm};
                        buffer_append(b, add, 2);
                    }
                }
            }
        }
    } else if (insn->id == X86_INS_CMP) {
        // Handle CMP instruction with memory operand replacement
        if (mem_operand_idx == 0) { // First operand (memory) is compared with second
            if (insn->detail->x86.operands[1].type == X86_OP_REG) {
                x86_reg src_reg = insn->detail->x86.operands[1].reg;
                // CMP [addr_reg], src_reg
                uint8_t modrm = 0x00 + (get_reg_index(src_reg) << 3) + get_reg_index(addr_reg);
                if (modrm == 0x00) {
                    // Profile-safe fallback for CMP
                    uint8_t push_mem[] = {0xFF, 0x30 | get_reg_index(addr_reg)};
                    buffer_append(b, push_mem, 2);
                    uint8_t pop_edx[] = {0x5A};
                    buffer_append(b, pop_edx, 1);
                    uint8_t cmp_edx[] = {0x39, 0xC0 | (get_reg_index(src_reg) << 3) | 2};
                    buffer_append(b, cmp_edx, 2);
                } else {
                    uint8_t cmp[] = {0x39, modrm};
                    buffer_append(b, cmp, 2);
                }
            } else if (insn->detail->x86.operands[1].type == X86_OP_IMM) {
                uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
                if (is_bad_byte_free(imm)) {
                    // CMP [addr_reg], imm32
                    uint8_t modrm = 0x80 + get_reg_index(addr_reg);
                    if (modrm == 0x80) {
                        // FIXED: Use register-based approach instead of hardcoded SIB 0x20
                        // Load value, then compare
                        uint8_t push[] = {0xFF, 0x30 | get_reg_index(addr_reg)};
                        buffer_append(b, push, 2);
                        uint8_t pop_edx[] = {0x5A}; // POP EDX
                        buffer_append(b, pop_edx, 1);
                        uint8_t cmp_edx[] = {0x83, 0xFA, (uint8_t)imm}; // CMP EDX, imm
                        buffer_append(b, cmp_edx, 3);
                    } else {
                        uint8_t cmp_imm[] = {0x83, modrm, (uint8_t)imm};
                        buffer_append(b, cmp_imm, 3);
                    }
                } else {
                    // Use null-free construction for immediate
                    generate_mov_eax_imm(b, imm);
                    // CMP [addr_reg], EAX
                    uint8_t modrm = 0x00 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(addr_reg);
                    if (modrm == 0x00) {
                        // FIXED: Use register-based approach instead of hardcoded SIB 0x20
                        uint8_t push[] = {0xFF, 0x30 | get_reg_index(addr_reg)};
                        buffer_append(b, push, 2);
                        uint8_t pop_edx[] = {0x5A}; // POP EDX
                        buffer_append(b, pop_edx, 1);
                        uint8_t cmp_edx[] = {0x39, 0xC2}; // CMP EDX, EAX
                        buffer_append(b, cmp_edx, 2);
                    } else {
                        uint8_t cmp[] = {0x39, modrm};
                        buffer_append(b, cmp, 2);
                    }
                }
            }
        } else { // First operand is compared with memory operand
            if (insn->detail->x86.operands[0].type == X86_OP_REG) {
                x86_reg dst_reg = insn->detail->x86.operands[0].reg;
                // CMP dst_reg, [addr_reg]
                uint8_t modrm = 0x00 + (get_reg_index(dst_reg) << 3) + get_reg_index(addr_reg);
                if (modrm == 0x00) {
                    // Profile-safe fallback for CMP
                    uint8_t push_mem[] = {0xFF, 0x30 | get_reg_index(addr_reg)};
                    buffer_append(b, push_mem, 2);
                    uint8_t pop_edx[] = {0x5A};
                    buffer_append(b, pop_edx, 1);
                    uint8_t cmp_reg_edx[] = {0x3B, 0xC0 | (get_reg_index(dst_reg) << 3) | 2};
                    buffer_append(b, cmp_reg_edx, 2);
                } else {
                    uint8_t cmp[] = {0x3B, modrm};
                    buffer_append(b, cmp, 2);
                }
            }
        }
    } else {
        // For other instructions, we will use the most common pattern:
        // use register instead of memory displacement
        // This is a general fallback that will handle a wide range of instructions
        // For now, just append the original instruction as a fallback - but this should be expanded
        buffer_append(b, insn->bytes, insn->size);
    }

    // POP the register to restore its original value
    uint8_t pop_reg[] = {0x58 + get_reg_index(addr_reg)};
    buffer_append(b, pop_reg, 1);
}

strategy_t generic_mem_null_disp_enhanced_strategy = {
    .name = "generic_mem_null_disp_enhanced",
    .can_handle = can_handle_generic_mem_null_disp_enhanced,
    .get_size = get_size_generic_mem_null_disp_enhanced,
    .generate = generate_generic_mem_null_disp_enhanced,
    .priority = 65  // Medium priority
};

void register_enhanced_mov_mem_strategies() {
    register_strategy(&mov_mem_imm_enhanced_strategy);
    register_strategy(&generic_mem_null_disp_enhanced_strategy);
}