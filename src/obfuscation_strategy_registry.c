/*
 * BYVALVER - Biphasic Architecture Pass 1: Obfuscation Strategy Registry
 *
 * This registry manages obfuscation and complexification transformations.
 * Pass 1 focuses on increasing analytical difficulty through polymorphic
 * transformations WITHOUT concern for null bytes (Pass 2 cleans those up).
 *
 * Benefits of Biphasic Architecture:
 * - Obfuscation strategies can introduce nulls freely
 * - Null-elimination strategies don't need to consider obfuscation patterns
 * - More aggressive transformations possible
 * - Enhanced polymorphism and signature evasion
 */

#include "strategy.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Debug mode
#ifdef DEBUG
  #define DEBUG_LOG(fmt, ...) do { fprintf(stderr, "[OBFUSC] " fmt "\n", ##__VA_ARGS__); } while(0)
#else
  #define DEBUG_LOG(fmt, ...) do {} while(0)
#endif

#define MAX_OBFUSCATION_STRATEGIES 50

static strategy_t* obfuscation_strategies[MAX_OBFUSCATION_STRATEGIES];
static int obfuscation_strategy_count = 0;

void register_obfuscation_strategy(strategy_t *strategy) {
    if (obfuscation_strategy_count < MAX_OBFUSCATION_STRATEGIES) {
        obfuscation_strategies[obfuscation_strategy_count++] = strategy;
        DEBUG_LOG("Registered obfuscation strategy: %s (priority %d)",
                  strategy->name, strategy->priority);
    } else {
        fprintf(stderr, "[ERROR] Obfuscation strategy registry full! Maximum of %d strategies.\n",
                MAX_OBFUSCATION_STRATEGIES);
    }
}

// Forward declarations for obfuscation strategy registration functions
void register_test_to_and_obfuscation();           // TEST → AND transformation
void register_mov_push_pop_obfuscation();          // MOV → PUSH/POP chains
void register_arithmetic_negation_obfuscation();   // Arithmetic identity transformations
void register_junk_code_insertion();               // Dead code insertion
void register_opaque_predicate_obfuscation();      // Opaque predicates
void register_register_renaming_obfuscation();     // Register substitution
void register_instruction_reordering();            // Independent instruction reordering
void register_constant_unfolding();                // Immediate value obfuscation
void register_nop_insertion();                     // NOP padding/polymorphism
void register_stack_spill_obfuscation();           // Stack-based register hiding

// Initialize all obfuscation strategies
void init_obfuscation_strategies() {
    DEBUG_LOG("Initializing Pass 1 (Obfuscation) strategy registry...", 0); // Adding dummy arg to avoid C99 warning

    // Register obfuscation transformations (order matters - higher priority first)
    register_opaque_predicate_obfuscation();      // Priority 95 - Complex control flow
    register_junk_code_insertion();               // Priority 90 - Dead code
    register_arithmetic_negation_obfuscation();   // Priority 85 - Arithmetic identities
    register_test_to_and_obfuscation();           // Priority 80 - TEST → AND
    register_mov_push_pop_obfuscation();          // Priority 75 - MOV → PUSH/POP
    register_register_renaming_obfuscation();     // Priority 70 - Register substitution
    register_constant_unfolding();                // Priority 65 - Immediate obfuscation
    register_instruction_reordering();            // Priority 60 - Instruction shuffle
    register_stack_spill_obfuscation();           // Priority 55 - Stack hiding
    register_nop_insertion();                     // Priority 50 - Polymorphic padding

    DEBUG_LOG("Pass 1 initialized with %d obfuscation strategies", obfuscation_strategy_count);
}

// Find best matching obfuscation strategy for an instruction
strategy_t* find_obfuscation_strategy(cs_insn *insn) {
    strategy_t *best = NULL;
    int best_priority = -1;

    for (int i = 0; i < obfuscation_strategy_count; i++) {
        strategy_t *s = obfuscation_strategies[i];
        if (s->can_handle(insn)) {
            if (s->priority > best_priority) {
                best = s;
                best_priority = s->priority;
            }
        }
    }

    if (best) {
        DEBUG_LOG("Selected obfuscation strategy '%s' (priority %d) for: %s %s",
                  best->name, best->priority, insn->mnemonic, insn->op_str);
    }

    return best;
}

// Get count of registered obfuscation strategies
int get_obfuscation_strategy_count() {
    return obfuscation_strategy_count;
}

// List all registered obfuscation strategies (for debugging)
void list_obfuscation_strategies() {
    fprintf(stderr, "\n=== Pass 1: Obfuscation Strategies (%d registered) ===\n",
            obfuscation_strategy_count);
    for (int i = 0; i < obfuscation_strategy_count; i++) {
        strategy_t *s = obfuscation_strategies[i];
        fprintf(stderr, "  [%2d] Priority %3d: %s\n", i, s->priority, s->name);
    }
    fprintf(stderr, "===================================================\n\n");
}
