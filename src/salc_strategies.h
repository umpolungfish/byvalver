#ifndef SALC_STRATEGIES_H
#define SALC_STRATEGIES_H

#include <capstone/capstone.h>
#include "core.h"

// Detection functions
int can_handle_salc_zero_al(cs_insn *insn);

// Size calculation functions
size_t get_size_salc_zero_al(cs_insn *insn);

// Generation functions
void generate_salc_zero_al(struct buffer *b, cs_insn *insn);

#endif
