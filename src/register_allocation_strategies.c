/*
 * Register Allocation Strategies for Null Avoidance
 *
 * This strategy module handles register remapping to avoid null-byte patterns
 * by selecting alternative registers that naturally don't introduce nulls
 * when used in specific instruction contexts.
 */

#include "strategy.h"
#include "utils.h"
#include "register_allocation_strategies.h"
#include <stdio.h>
#include <string.h>

/*
 * Detection for any instruction that uses a register in a way that creates null bytes
 * This could be based on the instruction encoding itself, or based on the immediate values
 * that get combined with the register.
 */
int can_handle_register_remap_nulls(cs_insn *insn) {
    // Disable this broken strategy - it appends original instruction with nulls
    (void)insn;
    return 0;
}

/*
 * Detection for MOV instructions where source/destination registers might be problematic
 */
int can_handle_mov_register_remap(cs_insn *insn) {
    // Disable this broken strategy - it appends original instruction with nulls
    (void)insn;
    return 0;
}

size_t get_size_register_remap_nulls(__attribute__((unused)) cs_insn *insn) {
    // Register remapping might require additional instructions for transfer
    // MOV alternative_reg, original_reg or similar operation
    return 8;
}

size_t get_size_mov_register_remap(__attribute__((unused)) cs_insn *insn) {
    // Additional MOV instruction to transfer between registers
    return 6;
}

/*
 * Generate register remapping to avoid null-byte patterns in addressing
 */
void generate_register_remap_nulls(struct buffer *b, cs_insn *insn) {
    // This strategy is incomplete and introduces nulls
    // Disable it by just appending the original instruction
    // TODO: Implement proper register remapping that reconstructs the instruction
    buffer_append(b, insn->bytes, insn->size);
}

/*
 * Generate register remapping specifically for MOV instructions
 */
void generate_mov_register_remap(struct buffer *b, cs_insn *insn) {
    // This strategy is incomplete and introduces nulls
    // Disable it by just appending the original instruction
    // TODO: Implement proper register remapping that reconstructs the instruction
    buffer_append(b, insn->bytes, insn->size);
}

/*
 * More sophisticated register allocation that considers the whole instruction context
 */
int can_handle_contextual_register_swap(cs_insn *insn) {
    // Disable this broken strategy - it introduces nulls instead of eliminating them
    (void)insn;
    return 0;
}

size_t get_size_contextual_register_swap(__attribute__((unused)) cs_insn *insn) {
    return 10; // For register swapping + original instruction
}

void generate_contextual_register_swap(struct buffer *b, cs_insn *insn) {
    // Analyze if register swapping could reduce nulls
    // This is a complex transformation that depends on context
    
    // For now, we'll implement a basic version that swaps to avoid problematic
    // addressing modes
    buffer_append(b, insn->bytes, insn->size);
}

/*
 * Strategy definitions
 */
strategy_t register_remap_nulls_strategy = {
    .name = "register_remap_nulls",
    .can_handle = can_handle_register_remap_nulls,
    .get_size = get_size_register_remap_nulls,
    .generate = generate_register_remap_nulls,
    .priority = 75  // Medium priority
};

strategy_t mov_register_remap_strategy = {
    .name = "mov_register_remap",
    .can_handle = can_handle_mov_register_remap,
    .get_size = get_size_mov_register_remap,
    .generate = generate_mov_register_remap,
    .priority = 78  // Medium-high priority for MOV operations
};

strategy_t contextual_register_swap_strategy = {
    .name = "contextual_register_swap",
    .can_handle = can_handle_contextual_register_swap,
    .get_size = get_size_contextual_register_swap,
    .generate = generate_contextual_register_swap,
    .priority = 72  // Medium priority
};

/*
 * Register function
 */
void register_register_allocation_strategies() {
    register_strategy(&register_remap_nulls_strategy);
    register_strategy(&mov_register_remap_strategy);
    register_strategy(&contextual_register_swap_strategy);
}