#ifndef LOOP_STRATEGIES_H
#define LOOP_STRATEGIES_H

#include "strategy.h"

// LOOP family instruction null-byte elimination strategies
// Handles LOOP, JECXZ, LOOPE, LOOPNE instructions with null bytes in displacement

void register_loop_strategies();

#endif
