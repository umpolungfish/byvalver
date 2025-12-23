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

#define MAX_OBFUSCATION_STRATEGIES 100

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

// NEW: 10 Additional Obfuscation Strategies
void register_runtime_selfmod_obfuscation();                // Priority 99 - Runtime self-modifying code
void register_incremental_decoder_obfuscation();            // Priority 97 - Incremental decoding
void register_mutated_junk_insertion_obfuscation();         // Priority 93 - Mutated junk with opaque predicates
void register_semantic_equivalence_substitution();          // Priority 88 - Instruction equivalence
void register_fpu_stack_obfuscation();                      // Priority 86 - FPU instruction obfuscation
void register_overlapping_instruction_obfuscation();        // Priority 84 - Overlapping instructions
void register_register_shuffle_obfuscation();               // Priority 82 - Register shuffling
void register_syscall_instruction_substitution();           // Priority 79 - Syscall method substitution
void register_control_flow_dispatcher_obfuscation();        // Priority 77 - CFG flattening
void register_mixed_arithmetic_base_obfuscation();          // Priority 73 - Arithmetic constant hiding

// NEW: 5 Additional Obfuscation Strategies (v3.0)
void register_call_pop_pic_delta_obfuscation();             // Priority 95 - CALL/POP PIC delta retrieval
void register_peb_namelength_fingerprint_obfuscation();     // Priority 84 - PEB module name length fingerprinting
void register_partial_16bit_hash_obfuscation();             // Priority 83 - 16-bit partial hash comparison
void register_unicode_negation_encoding_obfuscation();      // Priority 81 - Unicode negation encoding
void register_loopnz_compact_search_obfuscation();          // Priority 76 - LOOPNZ compact search patterns

// Initialize all obfuscation strategies
void init_obfuscation_strategies() {
    DEBUG_LOG("Initializing Pass 1 (Obfuscation) strategy registry...");

    // Register obfuscation transformations (order matters - higher priority first)

    // HIGH PRIORITY: Advanced obfuscation (99-90)
    register_runtime_selfmod_obfuscation();           // Priority 99 - Runtime self-modification (STUB)
    register_incremental_decoder_obfuscation();       // Priority 97 - Incremental decoding (STUB)
    register_call_pop_pic_delta_obfuscation();        // Priority 95 - CALL/POP PIC delta retrieval
    register_opaque_predicate_obfuscation();          // Priority 95 - Complex control flow (DISABLED)
    register_mutated_junk_insertion_obfuscation();    // Priority 93 - Mutated junk with predicates
    register_junk_code_insertion();                   // Priority 90 - Dead code (DISABLED)

    // MEDIUM-HIGH PRIORITY: Instruction transformation (88-80)
    register_semantic_equivalence_substitution();     // Priority 88-84 - Multiple equivalences
    register_fpu_stack_obfuscation();                 // Priority 86 - FPU obfuscation
    register_arithmetic_negation_obfuscation();       // Priority 85 - Arithmetic identities
    register_peb_namelength_fingerprint_obfuscation(); // Priority 84 - PEB module name length fingerprinting
    register_overlapping_instruction_obfuscation();   // Priority 84 - Overlapping instructions (STUB)
    register_partial_16bit_hash_obfuscation();        // Priority 83 - 16-bit partial hash comparison
    register_register_shuffle_obfuscation();          // Priority 82 - Register shuffling
    register_unicode_negation_encoding_obfuscation(); // Priority 81 - Unicode negation encoding
    register_test_to_and_obfuscation();               // Priority 80 - TEST → AND

    // MEDIUM PRIORITY: Syscall & control flow (79-70)
    register_syscall_instruction_substitution();      // Priority 79-78 - Syscall substitution
    register_control_flow_dispatcher_obfuscation();   // Priority 77 - CFG flattening (STUB)
    register_loopnz_compact_search_obfuscation();     // Priority 76 - LOOPNZ compact search patterns
    register_mov_push_pop_obfuscation();              // Priority 75 - MOV → PUSH/POP
    register_mixed_arithmetic_base_obfuscation();     // Priority 73 - Constant hiding
    register_register_renaming_obfuscation();         // Priority 70 - Register substitution (STUB)

    // LOW PRIORITY: Remaining strategies (65-50)
    register_constant_unfolding();                    // Priority 65 - Immediate obfuscation (STUB)
    register_instruction_reordering();                // Priority 60 - Instruction shuffle (STUB)
    register_stack_spill_obfuscation();               // Priority 55 - Stack hiding (STUB)
    register_nop_insertion();                         // Priority 50 - Polymorphic padding (STUB)

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