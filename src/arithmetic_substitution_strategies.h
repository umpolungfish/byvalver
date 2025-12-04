#ifndef ARITHMETIC_SUBSTITUTION_STRATEGIES_H
#define ARITHMETIC_SUBSTITUTION_STRATEGIES_H

#include <capstone/capstone.h>
#include "core.h"

// Detection functions
int can_handle_arithmetic_substitution(cs_insn *insn);

// Size calculation functions
size_t get_size_arithmetic_substitution(cs_insn *insn);

// Generation functions
void generate_arithmetic_substitution(struct buffer *b, cs_insn *insn);

#endif
