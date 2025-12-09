/*
 * Enhanced PEB-based API Resolution Strategies
 *
 * This strategy module handles sophisticated Windows API resolution patterns
 * that involve PEB traversal and hash-based API lookups which commonly
 * contain null bytes in displacement offsets and immediate values.
 */

#include "strategy.h"
#include "utils.h"
#include "peb_api_resolution_strategies.h"
#include <stdio.h>
#include <string.h>

/*
 * Enhanced detection for PEB traversal instructions that commonly contain nulls
 * Examples: mov eax, [ebx + 0x3c], mov edx, [edx + 0x78], etc.
 */
int can_handle_enhanced_peb_traversal(cs_insn *insn) {
    // Disable this broken strategy - it introduces nulls instead of eliminating them
    (void)insn;
    return 0;
}

/*
 * Enhanced detection for hash-based API resolution patterns
 * Looks for comparisons of function names like "GetProcAddress"
 */
int can_handle_hash_based_resolution(cs_insn *insn) {
    // Disable this broken strategy - it introduces nulls instead of eliminating them
    (void)insn;
    return 0;
}

/*
 * Enhanced detection for conditional jumps in API resolution loops
 */
int can_handle_peb_conditional_jumps(cs_insn *insn) {
    // Disable this broken strategy - it introduces nulls instead of eliminating them
    (void)insn;
    return 0;
}

size_t get_size_enhanced_peb_traversal(__attribute__((unused)) cs_insn *insn) {
    // Enhanced PEB traversal might require more complex code generation
    // LEA + MOV + potential arithmetic operations to avoid nulls
    return 25;  // Conservative estimate
}

size_t get_size_hash_based_resolution(__attribute__((unused)) cs_insn *insn) {
    // Hash-based resolution might need string construction and comparison
    return 30;  // Higher estimate for complex operations
}

size_t get_size_peb_conditional_jumps(__attribute__((unused)) cs_insn *insn) {
    // Conditional jumps with modified displacement
    return 15;  // Additional instructions for displacement handling
}

/*
 * Generate null-free PEB traversal using available utilities
 */
void generate_enhanced_peb_traversal(struct buffer *b, cs_insn *insn) {
    cs_x86_op *dst = &insn->detail->x86.operands[0];
    cs_x86_op *src = &insn->detail->x86.operands[1];

    // For instruction like: mov eax, [ebx + 0x3c] where 0x3c could contain nulls
    x86_reg base_reg = src->mem.base;
    uint64_t disp = src->mem.disp;

    // Instead of: mov dst_reg, [base_reg + disp] where disp has nulls,
    // We use: mov addr_reg, base_reg; add addr_reg, disp; mov dst_reg, [addr_reg]

    x86_reg addr_reg = X86_REG_EAX;
    if (dst->reg == X86_REG_EAX) {
        addr_reg = X86_REG_ECX;  // Use ECX as address register if EAX is destination
        if (dst->reg == X86_REG_ECX) {
            addr_reg = X86_REG_EDX;  // Use EDX as fallback
        }
    }

    // MOV addr_reg, base_reg
    generate_mov_reg_imm(b, &(cs_insn){
        .id = X86_INS_MOV,
        .detail = &(cs_detail){
            .x86 = {
                .op_count = 2,
                .operands = {{.type = X86_OP_REG, .reg = addr_reg}, {.type = X86_OP_REG, .reg = base_reg}}
            }
        }
    });

    // ADD addr_reg, disp (using utilities to avoid nulls in immediate)
    generate_op_reg_imm(b, &(cs_insn){
        .id = X86_INS_ADD,
        .detail = &(cs_detail){
            .x86 = {
                .op_count = 2,
                .operands = {{.type = X86_OP_REG, .reg = addr_reg}, {.type = X86_OP_IMM, .imm = disp}}
            }
        }
    });

    // MOV dst_reg, [addr_reg] - load from calculated address
    // This needs to use utilities as well
    // We'll build: MOV EAX, addr_reg_address; MOV dst_reg, [EAX]
    generate_mov_reg_mem_imm(b, &(cs_insn){
        .id = X86_INS_MOV,
        .detail = &(cs_detail){
            .x86 = {
                .op_count = 2,
                .operands = {{.type = X86_OP_REG, .reg = dst->reg}, {.type = X86_OP_MEM, .mem = {.base = addr_reg}}}
            }
        }
    });
}

/*
 * Generate hash-based API resolution with null-free immediate values
 */
void generate_hash_based_resolution(struct buffer *b, cs_insn *insn) {
    // For instruction like: cmp [eax], 0x50746547
    // Need to avoid nulls in immediate values

    cs_x86_op *mem_op = &insn->detail->x86.operands[0];
    cs_x86_op *imm_op = &insn->detail->x86.operands[1];
    uint32_t original_imm = (uint32_t)imm_op->imm;

    if (is_null_free(original_imm)) {
        // If immediate is already null-free, use directly
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    // Create null-free comparison by loading immediate through register
    // MOV EAX, immediate_value (constructed without nulls)
    // CMP [memory], EAX

    x86_reg temp_reg = X86_REG_EAX;  // Use EAX as temp register

    // Load the immediate value into a register using null-free construction
    generate_mov_eax_imm(b, original_imm);

    // Generate CMP [mem], reg instruction
    uint8_t cmp_instr[] = {0x39, 0x00};
    if (mem_op->mem.base != X86_REG_INVALID) {
        cmp_instr[1] = (get_reg_index(temp_reg) << 3) | get_reg_index(mem_op->mem.base);
        buffer_append(b, cmp_instr, 2);
    }
    else if (mem_op->mem.disp != 0) {
        // Handle memory operand with displacement only
        generate_mov_eax_imm(b, mem_op->mem.disp); // Load memory address
        uint8_t cmp_eax[] = {0x39, 0x00}; // CMP [EAX], reg
        cmp_eax[1] = (get_reg_index(temp_reg) << 3) | 0x00; // Compare with [EAX]
        buffer_append(b, cmp_eax, 2);
    }
}

/*
 * Generate conditional jumps with null-free displacement handling
 */
void generate_peb_conditional_jumps(struct buffer *b, cs_insn *insn) {
    // For conditional jumps with potential nulls in displacement
    // Transform to: test, conditional jump to short label, or longer sequence
    
    // Check if the jump offset itself contains nulls in its encoding
    // For now, let's just pass through (this needs more complex implementation)
    // A full implementation would need to handle the displacement differently
    
    // For now, just append the original instruction
    // In a complete implementation, we would transform conditional jumps
    // to use alternative patterns that avoid null-byte displacements
    buffer_append(b, insn->bytes, insn->size);
}

/*
 * Strategy definitions
 */
strategy_t enhanced_peb_traversal_strategy = {
    .name = "enhanced_peb_traversal",
    .can_handle = can_handle_enhanced_peb_traversal,
    .get_size = get_size_enhanced_peb_traversal,
    .generate = generate_enhanced_peb_traversal,
    .priority = 88  // Medium-high priority, below critical Windows strategies
};

strategy_t hash_based_resolution_strategy = {
    .name = "hash_based_resolution",
    .can_handle = can_handle_hash_based_resolution,
    .get_size = get_size_hash_based_resolution,
    .generate = generate_hash_based_resolution,
    .priority = 89  // Medium-high priority, below critical Windows strategies
};

strategy_t peb_conditional_jump_strategy = {
    .name = "peb_conditional_jump",
    .can_handle = can_handle_peb_conditional_jumps,
    .get_size = get_size_peb_conditional_jumps,
    .generate = generate_peb_conditional_jumps,
    .priority = 87  // Medium-high priority, below critical Windows strategies
};

/*
 * Register function
 */
void register_peb_api_resolution_strategies() {
    register_strategy(&enhanced_peb_traversal_strategy);
    register_strategy(&hash_based_resolution_strategy);
    register_strategy(&peb_conditional_jump_strategy);
}