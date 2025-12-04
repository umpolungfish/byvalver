#ifndef SYSCALL_STRATEGIES_H
#define SYSCALL_STRATEGIES_H

#include <capstone/capstone.h>
#include "core.h"

// Detection functions
int can_handle_syscall_number_mov(cs_insn *insn);

// Size calculation functions
size_t get_size_syscall_number_mov(cs_insn *insn);

// Generation functions
void generate_syscall_number_mov(struct buffer *b, cs_insn *insn);

#endif
