#ifndef ARITHMETIC_DECOMPOSITION_STRATEGIES_H
#define ARITHMETIC_DECOMPOSITION_STRATEGIES_H

#include <capstone/capstone.h>
#include "core.h"

// Detection functions
int can_handle_mov_arith_decomp(cs_insn *insn);

// Size calculation functions
size_t get_size_mov_arith_decomp(cs_insn *insn);

// Generation functions
void generate_mov_arith_decomp(struct buffer *b, cs_insn *insn);

#endif
