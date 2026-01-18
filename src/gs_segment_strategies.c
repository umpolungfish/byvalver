#include "strategy.h"
#include "utils.h"
#include "core.h"
#include <stdio.h>
#include <string.h>

// GS segment strategies for null bytes in GS memory operations
int can_handle_gs_segment(cs_insn *insn) {
    if (insn->id != X86_INS_MOV && insn->id != X86_INS_LEA) {
        return 0;
    }

    // Check for GS segment in memory operand
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (op->type == X86_OP_MEM && op->mem.segment == X86_REG_GS) {
            // Check if instruction has null bytes
            return has_null_bytes_in_encoding(insn->bytes, insn->size);
        }
    }

    return 0;
}

size_t get_size_gs_segment(__attribute__((unused)) cs_insn *insn) {
    // Alternative sequence: MOV reg, imm (GS base) + ADD reg, disp + MOV dest, [reg]
    return 20; // Conservative estimate
}

void generate_gs_segment(struct buffer *b, cs_insn *insn) {
    // For simplicity, try to replace GS:[disp] with equivalent flat addressing
    // This is a placeholder; real implementation would need GS base loading

    cs_x86_op *mem_op = NULL;
    cs_x86_op *reg_op = NULL;

    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];
        if (op->type == X86_OP_MEM) mem_op = op;
        else if (op->type == X86_OP_REG) reg_op = op;
    }

    if (!mem_op || !reg_op) return;

    // Assume GS base is loaded via other means; for now, use a placeholder
    // MOV reg, GS_BASE + disp
    // uint64_t gs_base_placeholder = 0; // Should be actual GS base (placeholder)

    if (insn->id == X86_INS_MOV) {
        // For MOV reg, GS:[disp] -> MOV reg, [addr]
        // But addr is not known at compile time; this is problematic
        // Use a sequence to load from memory without GS

        // For now, fallback to original (this needs proper implementation)
        buffer_append(b, insn->bytes, insn->size);
    } else {
        // For LEA, similar issue
        buffer_append(b, insn->bytes, insn->size);
    }
}

strategy_t gs_segment_strategy = {
    .name = "gs_segment",
    .can_handle = can_handle_gs_segment,
    .get_size = get_size_gs_segment,
    .generate = generate_gs_segment,
    .priority = 70  // High priority for GS operations
};

// Register GS segment strategies
void register_gs_segment_strategies(void) {
    register_strategy(&gs_segment_strategy);
}