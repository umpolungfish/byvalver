#ifndef REP_STOSB_STRATEGIES_H
#define REP_STOSB_STRATEGIES_H

#include <capstone/capstone.h>
#include "core.h"

// Detection functions
int can_handle_rep_stosb_count_setup(cs_insn *insn);

// Size calculation functions
size_t get_size_rep_stosb_count_setup(cs_insn *insn);

// Generation functions
void generate_rep_stosb_count_setup(struct buffer *b, cs_insn *insn);

#endif
