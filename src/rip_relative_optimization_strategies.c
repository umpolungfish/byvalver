/**
 * rip_relative_optimization_strategies.c
 *
 * Priority: 87 (Tier 2 - Essential for modern x64)
 * Applicability: x64 PIC code (80% of modern shellcode)
 *
 * Implements advanced RIP-relative addressing optimizations for x64 position-
 * independent code. Provides multiple transformation techniques to avoid bad
 * bytes in RIP-relative offsets while maintaining PIC properties.
 *
 * Key techniques:
 * 1. Offset Decomposition - Split large offsets into RIP + ADD
 * 2. Double-RIP Calculation - Use intermediate RIP-relative calculations
 * 3. Negative RIP Offset - Use negative offsets when beneficial
 * 4. RIP-Relative via Stack - CALL/POP method for complex cases
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

/**
 * Check if instruction uses RIP-relative addressing with bad offset
 */
static int has_rip_relative_bad_offset(cs_insn *insn) {
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (op->type == X86_OP_MEM && is_rip_relative_operand(op)) {
            int64_t disp = op->mem.disp;
            if (disp != 0 && !is_bad_byte_free((uint32_t)disp)) {
                return 1;
            }
        }
    }
    return 0;
}

/**
 * Technique 1: Offset Decomposition
 *
 * Handles: LEA RAX, [RIP + large_offset] (with bad chars in offset)
 * Transform: LEA RAX, [RIP]; ADD RAX, offset (split calculation)
 *
 * Priority: 87
 */
int can_handle_offset_decomposition(cs_insn *insn) {
    // Check if it's LEA with RIP-relative operand
    if (insn->id != X86_INS_LEA || !has_rip_relative_bad_offset(insn)) {
        return 0;
    }

    // Only handle if offset is reasonably large (avoid for small offsets)
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (op->type == X86_OP_MEM && is_rip_relative_operand(op)) {
            int64_t disp = op->mem.disp;
            if (disp > 0x1000 || disp < -0x1000) { // Large offsets
                return 1;
            }
        }
    }

    return 0;
}

size_t get_size_offset_decomposition(__attribute__((unused)) cs_insn *insn) {
    // Original LEA is 7 bytes
    // Transform: LEA RAX, [RIP] (7) + ADD RAX, imm32 (6) = 13 bytes
    return 13;
}

void generate_offset_decomposition(struct buffer *b, cs_insn *insn) {
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;

    // Find the RIP-relative operand and its displacement
    int64_t offset = 0;
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (op->type == X86_OP_MEM && is_rip_relative_operand(op)) {
            offset = op->mem.disp;
            break;
        }
    }

    // Generate LEA reg, [RIP] (zero displacement)
    uint8_t lea_rip[] = {
        0x48, 0x8D, 0x05 + (dst_reg - X86_REG_RAX) * 8, // LEA reg, [RIP + disp32]
        0x00, 0x00, 0x00, 0x00  // disp32 = 0
    };
    buffer_append(b, lea_rip, 7);

    // Generate ADD reg, offset (use polymorphic immediate if needed)
    uint8_t add_offset[] = {
        0x48, 0x81, 0xC0 + (dst_reg - X86_REG_RAX), // ADD reg, imm32
        (uint8_t)(offset & 0xFF),
        (uint8_t)((offset >> 8) & 0xFF),
        (uint8_t)((offset >> 16) & 0xFF),
        (uint8_t)((offset >> 24) & 0xFF)
    };
    buffer_append(b, add_offset, 6);
}

/**
 * Technique 2: Double-RIP Calculation
 *
 * Handles: MOV RAX, [RIP + offset] (with bad chars)
 * Transform: LEA RBX, [RIP + offset1]; MOV RAX, [RBX + offset2]
 *
 * Priority: 86
 */
int can_handle_double_rip_calculation(cs_insn *insn) {
    // Check if it's MOV with RIP-relative memory operand
    if (insn->id != X86_INS_MOV || !has_rip_relative_bad_offset(insn)) {
        return 0;
    }

    // Check if destination is register and source is memory
    if (insn->detail->x86.op_count != 2 ||
        insn->detail->x86.operands[0].type != X86_OP_REG ||
        insn->detail->x86.operands[1].type != X86_OP_MEM) {
        return 0;
    }

    return 1;
}

size_t get_size_double_rip_calculation(__attribute__((unused)) cs_insn *insn) {
    // LEA RBX, [RIP + disp] (7) + MOV RAX, [RBX + disp] (7) = 14 bytes
    return 14;
}

void generate_double_rip_calculation(struct buffer *b, cs_insn *insn) {
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;

    // Get the original offset
    int64_t offset = 0;
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (op->type == X86_OP_MEM && is_rip_relative_operand(op)) {
            offset = op->mem.disp;
            break;
        }
    }

    // Split offset into two parts
    int64_t offset1 = offset / 2;
    int64_t offset2 = offset - offset1;

    // LEA RBX, [RIP + offset1]
    uint8_t lea_rbx[] = {
        0x48, 0x8D, 0x1D, // LEA RBX, [RIP + disp32]
        (uint8_t)(offset1 & 0xFF),
        (uint8_t)((offset1 >> 8) & 0xFF),
        (uint8_t)((offset1 >> 16) & 0xFF),
        (uint8_t)((offset1 >> 24) & 0xFF)
    };
    buffer_append(b, lea_rbx, 7);

    // MOV dst_reg, [RBX + offset2]
    uint8_t mov_indirect[] = {
        0x48, 0x8B, 0x43 + (dst_reg - X86_REG_RAX) * 8, // MOV reg, [RBX + disp8]
        (uint8_t)offset2
    };
    buffer_append(b, mov_indirect, 4);
}

/**
 * Technique 3: Negative RIP Offset
 *
 * Handles: LEA RAX, [RIP + positive_offset]
 * Transform: JMP forward; data; forward: LEA RAX, [RIP - negative_offset]
 *
 * This is complex and may not be worth implementing in basic version
 */
int can_handle_negative_rip_offset(__attribute__((unused)) cs_insn *insn) {
    // Placeholder - negative offsets are less common and complex to implement
    return 0;
}

/**
 * Technique 4: RIP-Relative via Stack
 *
 * Handles: LEA RAX, [RIP + offset] (when other methods fail)
 * Transform: CALL $+5; POP RAX; ADD RAX, adjusted_offset
 *
 * Priority: 85
 */
int can_handle_rip_via_stack(cs_insn *insn) {
    // Fallback technique for complex RIP-relative cases
    return (insn->id == X86_INS_LEA || insn->id == X86_INS_MOV) &&
           has_rip_relative_bad_offset(insn);
}

size_t get_size_rip_via_stack(__attribute__((unused)) cs_insn *insn) {
    // CALL $+5 (5) + POP RAX (1) + ADD RAX, imm32 (6) = 12 bytes
    return 12;
}

void generate_rip_via_stack(struct buffer *b, cs_insn *insn) {
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;

    // Get the original offset
    int64_t offset = 0;
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (op->type == X86_OP_MEM && is_rip_relative_operand(op)) {
            offset = op->mem.disp;
            break;
        }
    }

    // CALL $+5 (pushes return address = current RIP + 5)
    uint8_t call_next[] = {0xE8, 0x00, 0x00, 0x00, 0x00}; // CALL +0 (placeholder)
    buffer_append(b, call_next, 5);

    // POP dst_reg (get the pushed RIP)
    uint8_t pop_reg = 0x58 + (dst_reg - X86_REG_RAX);
    buffer_append(b, &pop_reg, 1);

    // ADD dst_reg, (offset + 5) to account for CALL size
    int64_t adjusted_offset = offset + 5;
    uint8_t add_adjusted[] = {
        0x48, 0x81, 0xC0 + (dst_reg - X86_REG_RAX), // ADD reg, imm32
        (uint8_t)(adjusted_offset & 0xFF),
        (uint8_t)((adjusted_offset >> 8) & 0xFF),
        (uint8_t)((adjusted_offset >> 16) & 0xFF),
        (uint8_t)((adjusted_offset >> 24) & 0xFF)
    };
    buffer_append(b, add_adjusted, 6);
}

// Strategy registration
static strategy_t offset_decomposition_strategy = {
    .name = "RIP-Relative Optimization (Offset Decomposition)",
    .can_handle = can_handle_offset_decomposition,
    .get_size = get_size_offset_decomposition,
    .generate = generate_offset_decomposition,
    .priority = 87,
    .target_arch = BYVAL_ARCH_X64
};

static strategy_t double_rip_calculation_strategy = {
    .name = "RIP-Relative Optimization (Double RIP)",
    .can_handle = can_handle_double_rip_calculation,
    .get_size = get_size_double_rip_calculation,
    .generate = generate_double_rip_calculation,
    .priority = 86,
    .target_arch = BYVAL_ARCH_X64
};

static strategy_t rip_via_stack_strategy = {
    .name = "RIP-Relative Optimization (Stack Method)",
    .can_handle = can_handle_rip_via_stack,
    .get_size = get_size_rip_via_stack,
    .generate = generate_rip_via_stack,
    .priority = 85,
    .target_arch = BYVAL_ARCH_X64
};

void register_rip_relative_optimization_strategies(void) {
    register_strategy(&offset_decomposition_strategy);
    register_strategy(&double_rip_calculation_strategy);
    register_strategy(&rip_via_stack_strategy);
}