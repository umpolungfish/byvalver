#ifndef XCHG_PRESERVATION_STRATEGIES_H
#define XCHG_PRESERVATION_STRATEGIES_H

#include <capstone/capstone.h>
#include "core.h"

// Detection functions
int can_handle_push_imm_preservation(cs_insn *insn);

// Size calculation functions
size_t get_size_push_imm_preservation(cs_insn *insn);

// Generation functions
void generate_push_imm_preservation(struct buffer *b, cs_insn *insn);

#endif
