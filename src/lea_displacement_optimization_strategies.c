/*
 * LEA Displacement Optimization Strategies
 *
 * This strategy module handles LEA (Load Effective Address) instructions
 * that contain null bytes in displacement values. LEA is commonly used
 * with displacement addressing modes that can contain null bytes.
 */

#include "strategy.h"
#include "utils.h"
#include "lea_displacement_optimization_strategies.h"
#include <stdio.h>
#include <string.h>

/*
 * Detection for LEA instructions with null-byte displacements
 * LEA reg, [base + disp32] where disp32 contains null bytes
 */
int can_handle_lea_displacement_nulls(cs_insn *insn) {
    if (insn->id != X86_INS_LEA) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *dst = &insn->detail->x86.operands[0];
    cs_x86_op *src = &insn->detail->x86.operands[1];

    if (dst->type != X86_OP_REG || src->type != X86_OP_MEM) {
        return 0;
    }

    // Check if the memory operand has displacement that contains null bytes
    if (src->mem.disp != 0) {
        uint64_t disp = src->mem.disp;
        for (int i = 0; i < 8; i++) {
            if (((disp >> (i * 8)) & 0xFF) == 0x00) {
                return 1;
            }
        }
    }
    
    // Also check if entire instruction contains null bytes (in encoding)
    for (int i = 0; i < insn->size; i++) {
        if (insn->bytes[i] == 0x00) {
            return 1;
        }
    }

    return 0;
}

/*
 * Detection for LEA with problematic addressing that creates null encoding
 */
int can_handle_lea_problematic_encoding(cs_insn *insn) {
    if (insn->id != X86_INS_LEA) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *src = &insn->detail->x86.operands[1];
    if (src->type != X86_OP_MEM) {
        return 0;
    }

    // Check for addressing modes that create problematic encodings
    // For example, when using EBP/R13 as base without displacement
    if ((src->mem.base == X86_REG_EBP || src->mem.base == X86_REG_R13) && 
        src->mem.disp == 0) {
        // This requires a displacement byte (0x00), which is a null
        return 1;
    }

    return 0;
}

size_t get_size_lea_displacement_nulls(__attribute__((unused)) cs_insn *insn) {
    // Alternative LEA patterns might require additional instructions
    return 15;
}

size_t get_size_lea_problematic_encoding(__attribute__((unused)) cs_insn *insn) {
    // Complex LEA rewrites might need several instructions
    return 18;
}

/*
 * Generate LEA with null-byte displacement replacement
 */
void generate_lea_displacement_nulls(struct buffer *b, cs_insn *insn) {
    cs_x86_op *dst = &insn->detail->x86.operands[0];
    cs_x86_op *src = &insn->detail->x86.operands[1];

    x86_reg dst_reg = dst->reg;
    x86_reg base_reg = src->mem.base;
    x86_reg index_reg = src->mem.index;
    uint32_t scale = src->mem.scale;
    uint64_t disp = src->mem.disp;

    // Find a temporary register that doesn't conflict with operands
    x86_reg temp_reg = X86_REG_ECX;
    if (dst_reg == X86_REG_ECX || base_reg == X86_REG_ECX ||
        (index_reg != X86_REG_INVALID && index_reg == X86_REG_ECX)) {
        temp_reg = X86_REG_EDX;
        if (dst_reg == X86_REG_EDX || base_reg == X86_REG_EDX ||
            (index_reg != X86_REG_INVALID && index_reg == X86_REG_EDX)) {
            temp_reg = X86_REG_EBX;
        }
    }

    // Strategy: Calculate the address [base + index*scale + disp] using register arithmetic
    // PUSH the temp register to preserve its value
    uint8_t push_temp[] = {0x50 + get_reg_index(temp_reg)};
    buffer_append(b, push_temp, 1);

    // If base register exists, start with it
    if (base_reg != X86_REG_INVALID) {
        // MOV dst_reg, base_reg (if different)
        if (dst_reg != base_reg) {
            uint8_t mov_dst_base[] = {0x89, 0xC0};
            mov_dst_base[1] = 0xC0 + (get_reg_index(base_reg) << 3) + get_reg_index(dst_reg);
            buffer_append(b, mov_dst_base, 2);
        }
    } else {
        // If no base register, zero out dst_reg to start
        uint8_t xor_dst_dst[] = {0x31, 0xC0};
        xor_dst_dst[1] = 0xC0 + (get_reg_index(dst_reg) << 3) + get_reg_index(dst_reg); // XOR dst, dst
        buffer_append(b, xor_dst_dst, 2);
    }

    // Handle index*scale part if present
    if (index_reg != X86_REG_INVALID && scale != 0) {
        // MOV temp_reg, index_reg
        uint8_t mov_temp_index[] = {0x89, 0xC0};
        mov_temp_index[1] = 0xC0 + (get_reg_index(index_reg) << 3) + get_reg_index(temp_reg);
        buffer_append(b, mov_temp_index, 2);

        // Apply scale using multiplication
        if (scale > 1) {
            // For known scales, use shifts for efficiency
            if (scale == 2) {
                uint8_t shl_temp_1[] = {0xC1, 0xE0 + get_reg_index(temp_reg), 1}; // SHL temp_reg, 1
                buffer_append(b, shl_temp_1, 3);
            } else if (scale == 4) {
                uint8_t shl_temp_2[] = {0xC1, 0xE0 + get_reg_index(temp_reg), 2}; // SHL temp_reg, 2
                buffer_append(b, shl_temp_2, 3);
            } else if (scale == 8) {
                uint8_t shl_temp_3[] = {0xC1, 0xE0 + get_reg_index(temp_reg), 3}; // SHL temp_reg, 3
                buffer_append(b, shl_temp_3, 3);
            } else {
                // For other scales, multiply with null-free construction
                // MOV dst_reg, scale
                generate_mov_eax_imm(b, scale);
                // MOV temp_reg, EAX (move scale to EAX)
                uint8_t mov_temp_eax[] = {0x89, 0xC0};
                mov_temp_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(temp_reg);
                buffer_append(b, mov_temp_eax, 2);

                // IMUL temp_reg, temp_reg (multiply index_reg by scale)
                uint8_t imul_temp[] = {0x0F, 0xAF, 0xC0};
                imul_temp[2] = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(temp_reg);
                buffer_append(b, imul_temp, 3);
            }
        }

        // ADD dst_reg, temp_reg (add scaled index to base)
        uint8_t add_dst_temp[] = {0x01, 0xC0};
        add_dst_temp[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(dst_reg);
        buffer_append(b, add_dst_temp, 2);
    }

    // Add displacement using null-free construction
    if (disp != 0) {
        if (is_null_free((uint32_t)disp) && (int32_t)disp >= -128 && (int32_t)disp <= 127) {
            // If displacement is null-free and fits in signed 8-bit, add it directly with ADD reg, imm8
            uint8_t add_dst_disp[] = {0x83, 0xC0, (uint8_t)disp};
            add_dst_disp[1] = 0xC0 + (get_reg_index(dst_reg) << 3) + get_reg_index(dst_reg);
            buffer_append(b, add_dst_disp, 3);
        } else {
            // If displacement has null bytes or doesn't fit in imm8, construct it with null-free approach
            // MOV temp_reg, displacement value (null-free construction)
            generate_mov_eax_imm(b, (uint32_t)disp);

            // MOV temp_reg, EAX (move the constructed value to temp_reg)
            uint8_t mov_temp_eax[] = {0x89, 0xC0};
            mov_temp_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(temp_reg);
            buffer_append(b, mov_temp_eax, 2);

            // ADD dst_reg, temp_reg (add the displacement)
            uint8_t add_dst_temp[] = {0x01, 0xC0};
            add_dst_temp[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(dst_reg);
            buffer_append(b, add_dst_temp, 2);
        }
    }

    // POP the temp register to restore its original value
    uint8_t pop_temp[] = {0x58 + get_reg_index(temp_reg)};
    buffer_append(b, pop_temp, 1);
}

/*
 * Generate alternative for LEA with problematic encoding
 */
void generate_lea_problematic_encoding(struct buffer *b, cs_insn *insn) {
    cs_x86_op *dst = &insn->detail->x86.operands[0];
    cs_x86_op *src = &insn->detail->x86.operands[1];
    
    x86_reg dst_reg = dst->reg;
    x86_reg base_reg = src->mem.base;
    uint64_t disp = src->mem.disp;
    
    // Handle addressing mode that requires displacement byte (like EBP/R13 + 0)
    if ((base_reg == X86_REG_EBP || base_reg == X86_REG_R13) && disp == 0) {
        // Instead of LEA dst, [EBP] which requires 00 displacement byte,
        // use: MOV dst_reg, base_reg
        generate_mov_reg_imm(b, &(cs_insn){
            .id = X86_INS_MOV,
            .detail = &(cs_detail){
                .x86 = {
                    .op_count = 2,
                    .operands = {{.type = X86_OP_REG, .reg = dst_reg}, {.type = X86_OP_REG, .reg = base_reg}}
                }
            }
        });
    } else {
        // Use the same approach as the general displacement handler
        generate_lea_displacement_nulls(b, insn);
    }
}

/*
 * Strategy definitions
 */
strategy_t lea_displacement_nulls_strategy = {
    .name = "lea_displacement_nulls",
    .can_handle = can_handle_lea_displacement_nulls,
    .get_size = get_size_lea_displacement_nulls,
    .generate = generate_lea_displacement_nulls,
    .priority = 82  // Medium-high priority for LEA operations
};

strategy_t lea_problematic_encoding_strategy = {
    .name = "lea_problematic_encoding",
    .can_handle = can_handle_lea_problematic_encoding,
    .get_size = get_size_lea_problematic_encoding,
    .generate = generate_lea_problematic_encoding,
    .priority = 81  // Slightly lower than displacement_nulls
};

/*
 * Register function
 */
void register_lea_displacement_optimization_strategies() {
    register_strategy(&lea_displacement_nulls_strategy);
    register_strategy(&lea_problematic_encoding_strategy);
}