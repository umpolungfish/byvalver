#include "strategy.h"
#include "utils.h"
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

                for (int j = 0; j < 4; j++) {
                    if (((disp32 >> (j * 8)) & 0xFF) == 0) {
                        return 1; // Has null bytes in displacement
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
    // Extract the target register and memory operand
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
    uint32_t disp = (uint32_t)src_op->mem.disp;

    // Calculate the effective address by using another register
    // MOV EAX, displacement (using null-free construction)
    generate_mov_eax_imm(b, disp);

    // Now generate LEA target_reg, [EAX]
    // The ModR/M byte for LEA reg, [EAX] when target_reg is EAX creates a null byte
    // So we need to handle that specially
    if (target_reg == X86_REG_EAX) {
        // Use SIB byte to avoid null: LEA EAX, [EAX]
        uint8_t code[] = {0x8D, 0x04, 0x20}; // LEA EAX, [EAX] with SIB byte (scale=0, index=ESP, base=EAX)
        buffer_append(b, code, 3);
    } else {
        // For other registers: LEA target_reg, [EAX]
        // ModR/M byte: (target_reg_idx << 3) | 0 (for [EAX])
        uint8_t modrm = (get_reg_index(target_reg) << 3) | 0;
        uint8_t code[] = {0x8D, 0x00}; // LEA reg, [EAX]
        code[1] = modrm;
        buffer_append(b, code, 2);
    }
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

                // Check if displacement has null bytes
                for (int j = 0; j < 4; j++) {
                    if (((disp32 >> (j * 8)) & 0xFF) == 0) {
                        return 1;
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
    uint32_t disp = (uint32_t)src_op->mem.disp;

    // Use arithmetic to construct the required address without nulls
    // For example, instead of LEA reg, [base + 0x00123456], use:
    // MOV EAX, base
    // ADD EAX, adjusted_value (null-free)

    // If there's a base register, we first load it
    if (src_op->mem.base != X86_REG_INVALID) {
        // MOV target_reg, base_reg
        uint8_t mov_base[] = {0x89, 0x00};
        mov_base[1] = (get_reg_index(target_reg) << 3) | get_reg_index(src_op->mem.base);
        buffer_append(b, mov_base, 2);
    } else {
        // If no base register, start with 0
        uint8_t xor_reg[] = {0x31, 0xC0}; // XOR target_reg, target_reg to zero it
        xor_reg[1] = (get_reg_index(target_reg) << 3) | get_reg_index(target_reg);
        buffer_append(b, xor_reg, 2);
    }

    // Now add the displacement using null-free construction
    if (disp != 0) {
        // Generate MOV EAX, disp (null-free) and then ADD target_reg, EAX
        // Or use a direct ADD if the displacement is small enough to be 8-bit

        // For the displacement, we'll use a temporary register approach
        generate_mov_eax_imm(b, disp);

        // ADD target_reg, EAX
        uint8_t add_code[] = {0x01, 0x00};
        add_code[1] = (get_reg_index(target_reg) << 3) | get_reg_index(X86_REG_EAX); // ADD target_reg, EAX
        buffer_append(b, add_code, 2);
    }
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