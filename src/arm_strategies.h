#ifndef ARM_STRATEGIES_H
#define ARM_STRATEGIES_H

// ARM-specific bad-byte elimination strategies
// Plumbing-themed ARM instruction transformations

// Register all ARM strategies with the strategy system
void register_arm_strategies(void);

// Individual strategy declarations
extern strategy_t arm_mov_imm_strategy;
extern strategy_t arm_add_imm_strategy;

#endif /* ARM_STRATEGIES_H */