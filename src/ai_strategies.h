#ifndef AI_STRATEGIES_H
#define AI_STRATEGIES_H

// AI-generated strategies for Byvalver
// Machine learning discovers new plumbing techniques

#include "strategy.h"

// Generate strategies using AI
int generate_ai_strategies(int count);

// Register AI-generated strategies
void register_ai_strategies(void);

// Learn from successful transformations
void learn_from_transformation(const uint8_t* original, size_t original_size,
                              const uint8_t* transformed, size_t transformed_size,
                              const char* strategy_used);

// Get AI strategy recommendations
strategy_t** get_ai_recommendations(cs_insn* insn, int* count);

#endif /* AI_STRATEGIES_H */