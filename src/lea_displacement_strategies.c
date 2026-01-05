#include "strategy.h"
#include "utils.h"
#include "profile_aware_sib.h"
#include <stdio.h>
#include <string.h>

// Strategy 2: LEA with Complex Displacement
// Use the LEA (Load Effective Address) instruction with complex displacement values
// to construct immediate values containing nulls without directly encoding them
// in instruction immediates.

int can_handle_lea_complex_displacement(cs_insn *insn) {
    // Check if this is a LEA instruction
    if (insn->id != X86_INS_LEA) {
        return 0;
    }

    // Check if it has memory operands with displacement containing nulls
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        if (insn->detail->x86.operands[i].type == X86_OP_MEM) {
            int64_t disp = insn->detail->x86.operands[i].mem.disp;

            // Check if displacement has null bytes
            if (disp != 0) {
                uint32_t disp32 = (uint32_t)disp;

                // Check if displacement itself contains null bytes
                if (!is_bad_byte_free(disp32)) {
                    // Additional check: does the overall instruction have null bytes?
                    if (has_null_bytes(insn)) {
                        return 1; // Has null bytes in displacement AND in instruction
                    }
                }
            }
        }
    }

    return 0;
}

size_t get_size_lea_complex_displacement(__attribute__((unused)) cs_insn *insn) {
    // MOV EAX, calculated_value + LEA target_reg, [EAX]
    // MOV EAX, imm (5-15 bytes) + LEA reg, [EAX] (2-3 bytes for safe encoding)
    return 18; // Conservative estimate with buffer for complex null-free construction
}

void generate_lea_complex_displacement(struct buffer *b, cs_insn *insn) {
    // For LEA with complex addressing that might have null bytes in displacement,
    // a reliable approach is to calculate the address manually and move it to target register

    if (insn->detail->x86.op_count != 2) {
        // Fallback to original if not the expected format
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    cs_x86_op *dst_op = &insn->detail->x86.operands[0];  // destination register
    cs_x86_op *src_op = &insn->detail->x86.operands[1];  // source memory operand

    if (dst_op->type != X86_OP_REG || src_op->type != X86_OP_MEM) {
        // Fallback if not in expected format
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    x86_reg target_reg = dst_op->reg;

    // Calculate effective address step by step to avoid null bytes
    // Save EAX to use it as temporary
    uint8_t push_eax[] = {0x50};
    buffer_append(b, push_eax, 1);

    // Build effective address in EAX:
    // First handle base register
    if (src_op->mem.base != X86_REG_INVALID) {
        // MOV EAX, base_reg
        uint8_t mov_eax_base[] = {0x89, 0xC0};
        mov_eax_base[1] = 0xC0 + (get_reg_index(src_op->mem.base) << 3) + get_reg_index(X86_REG_EAX);
        buffer_append(b, mov_eax_base, 2);
    } else {
        // XOR EAX, EAX to start with 0
        uint8_t xor_eax[] = {0x31, 0xC0}; // XOR EAX, EAX
        buffer_append(b, xor_eax, 2);
    }

    // Handle index * scale
    if (src_op->mem.index != X86_REG_INVALID) {
        // Save current EAX value to ECX temporarily
        uint8_t push_ecx[] = {0x51};
        buffer_append(b, push_ecx, 1);

        // MOV EAX, index_reg
        uint8_t mov_eax_index[] = {0x89, 0xC0};
        mov_eax_index[1] = 0xC0 + (get_reg_index(src_op->mem.index) << 3) + get_reg_index(X86_REG_EAX);
        buffer_append(b, mov_eax_index, 2);

        // Scale EAX by the scale factor (SHL operations)
        if (src_op->mem.scale == 2) {
            uint8_t shl_eax[] = {0xD1, 0xE0}; // SHL EAX, 1
            buffer_append(b, shl_eax, 2);
        } else if (src_op->mem.scale == 4) {
            uint8_t shl_eax[] = {0xD1, 0xE0}; // SHL EAX, 1
            buffer_append(b, shl_eax, 2);
            buffer_append(b, shl_eax, 2); // Double shift for x4 (SHL EAX, 1 twice)
        } else if (src_op->mem.scale == 8) {
            uint8_t shl_eax[] = {0xD1, 0xE0}; // SHL EAX, 1
            buffer_append(b, shl_eax, 2);
            buffer_append(b, shl_eax, 2); // SHL EAX, 1
            buffer_append(b, shl_eax, 2); // SHL EAX, 1 (x8 = shift 3 times)
        }

        // Add the base value from ECX back to EAX
        uint8_t pop_ecx[] = {0x59};
        buffer_append(b, pop_ecx, 1);

        uint8_t add_eax_ecx[] = {0x01, 0xC1}; // ADD EAX, ECX
        buffer_append(b, add_eax_ecx, 2);
    }

    // Handle displacement
    if (src_op->mem.disp != 0) {
        uint32_t disp = (uint32_t)src_op->mem.disp;

        // Use EDX as temporary register for displacement
        uint8_t push_edx[] = {0x52};
        buffer_append(b, push_edx, 1);

        // MOV EDX, disp with null-free construction
        generate_mov_eax_imm(b, disp);
        // Now EAX contains the displacement, move it to EDX
        uint8_t mov_edx_eax[] = {0x89, 0xC2};  // MOV EDX, EAX
        buffer_append(b, mov_edx_eax, 2);

        // ADD EAX, EDX (add displacement to calculated address)
        uint8_t add_eax_edx[] = {0x01, 0xD0}; // ADD EAX, EDX
        buffer_append(b, add_eax_edx, 2);

        // Restore original EDX
        uint8_t pop_edx[] = {0x5A};
        buffer_append(b, pop_edx, 1);
    }

    // Move result to target register using safe addressing to avoid nulls
    if (target_reg != X86_REG_EAX) {
        // Use SIB addressing to avoid null ModR/M byte when target_reg == EAX
        // FIXED: Use profile-safe SIB
    if (generate_safe_mov_mem_reg(b, X86_REG_EAX, X86_REG_EAX) != 0) {
        uint8_t push[] = {0x50};
        buffer_append(b, push, 1);
        uint8_t pop[] = {0x8F, 0x00};
        buffer_append(b, pop, 2);
    }
    } else {
        // Target is EAX, already in the right place
    }

    // Restore original EAX
    uint8_t pop_eax[] = {0x58};
    buffer_append(b, pop_eax, 1);
}

strategy_t lea_complex_displacement_strategy = {
    .name = "lea_complex_displacement",
    .can_handle = can_handle_lea_complex_displacement,
    .get_size = get_size_lea_complex_displacement,
    .generate = generate_lea_complex_displacement,
    .priority = 80  // High priority for displacement handling
};

// Alternative approach: Use LEA with adjusted displacement to avoid nulls
int can_handle_lea_displacement_adjusted(cs_insn *insn) {
    if (insn->id != X86_INS_LEA) {
        return 0;
    }

    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        if (insn->detail->x86.operands[i].type == X86_OP_MEM) {
            int64_t disp = insn->detail->x86.operands[i].mem.disp;

            if (disp != 0) {
                uint32_t disp32 = (uint32_t)disp;

                // Check if displacement itself contains null bytes
                if (!is_bad_byte_free(disp32)) {
                    // Additional check: does the overall instruction have null bytes?
                    if (has_null_bytes(insn)) {
                        return 1; // Has null bytes in displacement AND in instruction
                    }
                }
            }
        }
    }

    return 0;
}

size_t get_size_lea_displacement_adjusted(__attribute__((unused)) cs_insn *insn) {
    // This approach might use arithmetic to construct the address
    return 20; // Conservative estimate with more buffer for complex instructions
}

void generate_lea_displacement_adjusted(struct buffer *b, cs_insn *insn) {
    // Extract operands
    if (insn->detail->x86.op_count != 2) {
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    cs_x86_op *src_op = &insn->detail->x86.operands[1];

    if (dst_op->type != X86_OP_REG || src_op->type != X86_OP_MEM) {
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    x86_reg target_reg = dst_op->reg;

    // To avoid nulls in LEA, compute the effective address manually
    // Save original EAX
    uint8_t push_eax[] = {0x50};
    buffer_append(b, push_eax, 1);

    // Build effective address in EAX, similar to our complex displacement function
    // Handle base register
    if (src_op->mem.base != X86_REG_INVALID) {
        // MOV EAX, base_reg
        uint8_t mov_eax_base[] = {0x89, 0xC0};
        mov_eax_base[1] = 0xC0 + (get_reg_index(src_op->mem.base) << 3) + get_reg_index(X86_REG_EAX);
        buffer_append(b, mov_eax_base, 2);
    } else {
        // XOR EAX, EAX to start with 0
        uint8_t xor_eax[] = {0x31, 0xC0};
        buffer_append(b, xor_eax, 2);
    }

    // Handle index * scale
    if (src_op->mem.index != X86_REG_INVALID) {
        // Save current EAX value to ECX temporarily
        uint8_t push_ecx[] = {0x51};
        buffer_append(b, push_ecx, 1);

        // MOV EAX, index_reg
        uint8_t mov_eax_index[] = {0x89, 0xC0};
        mov_eax_index[1] = 0xC0 + (get_reg_index(src_op->mem.index) << 3) + get_reg_index(X86_REG_EAX);
        buffer_append(b, mov_eax_index, 2);

        // Scale EAX by the scale factor (SHL operations)
        if (src_op->mem.scale == 2) {
            uint8_t shl_eax[] = {0xD1, 0xE0};
            shl_eax[1] = 0xE0 + get_reg_index(X86_REG_EAX);  // SHL EAX, 1
            buffer_append(b, shl_eax, 2);
        } else if (src_op->mem.scale == 4) {
            uint8_t shl_eax[] = {0xD1, 0xE0};
            shl_eax[1] = 0xE0 + get_reg_index(X86_REG_EAX);  // SHL EAX, 1
            buffer_append(b, shl_eax, 2);
            buffer_append(b, shl_eax, 2); // Double shift for x4 (SHL EAX, 1 twice)
        } else if (src_op->mem.scale == 8) {
            uint8_t shl_eax[] = {0xD1, 0xE0};
            shl_eax[1] = 0xE0 + get_reg_index(X86_REG_EAX);  // SHL EAX, 1
            buffer_append(b, shl_eax, 2);
            buffer_append(b, shl_eax, 2); // SHL EAX, 1
            buffer_append(b, shl_eax, 2); // SHL EAX, 1 (x8 = shift 3 times)
        }

        // Add the base value back from ECX
        uint8_t pop_ecx[] = {0x59};
        buffer_append(b, pop_ecx, 1);

        uint8_t add_eax_ecx[] = {0x01, 0xC8};
        buffer_append(b, add_eax_ecx, 2);
    }

    // Handle displacement
    if (src_op->mem.disp != 0) {
        uint32_t disp = (uint32_t)src_op->mem.disp;
        // Use EDX as temporary register for displacement
        uint8_t push_edx[] = {0x52};
        buffer_append(b, push_edx, 1);

        // MOV EDX, disp with null-free construction
        generate_mov_eax_imm(b, disp);
        // Now EAX contains the displacement, move it to EDX
        uint8_t mov_edx_eax[] = {0x89, 0xC2};  // MOV EDX, EAX
        buffer_append(b, mov_edx_eax, 2);

        // Add displacement to calculated address in EAX
        uint8_t add_eax_edx[] = {0x01, 0xD0}; // ADD EAX, EDX
        buffer_append(b, add_eax_edx, 2);

        // Restore original EDX
        uint8_t pop_edx[] = {0x5A};
        buffer_append(b, pop_edx, 1);
    }

    // Move result to target register using SIB addressing to avoid nulls in ModR/M
    if (target_reg != X86_REG_EAX) {
        // MOV target_reg, EAX using SIB addressing to avoid null ModR/M byte
        // FIXED: Use profile-safe SIB
    if (generate_safe_mov_mem_reg(b, X86_REG_EAX, X86_REG_EAX) != 0) {
        uint8_t push[] = {0x50};
        buffer_append(b, push, 1);
        uint8_t pop[] = {0x8F, 0x00};
        buffer_append(b, pop, 2);
    }
    } else {
        // Target is EAX, already in the right place
    }

    // Restore original EAX
    uint8_t pop_eax[] = {0x58};
    buffer_append(b, pop_eax, 1);
}

strategy_t lea_displacement_adjusted_strategy = {
    .name = "lea_displacement_adjusted",
    .can_handle = can_handle_lea_displacement_adjusted,
    .get_size = get_size_lea_displacement_adjusted,
    .generate = generate_lea_displacement_adjusted,
    .priority = 75  // Medium-high priority
};

// Register the LEA displacement strategies
void register_lea_displacement_strategies() {
    register_strategy(&lea_complex_displacement_strategy);
    register_strategy(&lea_displacement_adjusted_strategy);
}