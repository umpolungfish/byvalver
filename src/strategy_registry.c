#include "strategy.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h> // Added for debug prints
// #include <stdio.h> // Removed for printf

// Debug mode - compile with -DDEBUG to enable detailed logging
#ifdef DEBUG
  #define DEBUG_LOG(fmt, ...) do { fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__); } while(0)
#else
  #define DEBUG_LOG(fmt, ...) do {} while(0)
#endif

#define MAX_STRATEGIES 100

static strategy_t* strategies[MAX_STRATEGIES];
static int strategy_count = 0;

void register_strategy(strategy_t *strategy) {
    if (strategy_count < MAX_STRATEGIES) {
        strategies[strategy_count++] = strategy;
    }
}

void register_mov_strategies(); // Forward declaration
void register_arithmetic_strategies(); // Forward declaration
void register_memory_strategies(); // Forward declaration
void register_jump_strategies(); // Forward declaration
void register_general_strategies(); // Forward declaration
void register_anti_debug_strategies(); // Forward declaration
void register_shift_strategy(); // Forward declaration
void register_peb_strategies(); // Forward declaration

void init_strategies() {
    #ifdef DEBUG
    fprintf(stderr, "[DEBUG] Initializing strategies\n");
    #endif

    strategy_count = 0;
    register_mov_strategies();  // Register all MOV strategies
    register_arithmetic_strategies();  // Register all arithmetic strategies
    register_memory_strategies();  // Register all memory strategies
    register_jump_strategies();  // Register all jump strategies
    register_general_strategies();  // Register all general strategies
    // register_anti_debug_strategies();  // DISABLED - causes issues with non-NOP instructions
    register_shift_strategy();  // Register shift-based strategy
    // register_peb_strategies();  // ALSO DISABLE THIS - was causing inappropriate application to non-NOP instructions

    #ifdef DEBUG
    fprintf(stderr, "[DEBUG] Registered %d strategies\n", strategy_count);
    #endif
    // printf("init_strategies: Registered %d strategies.\n", strategy_count); // Removed debug print
}

strategy_t** get_strategies_for_instruction(cs_insn *insn, int *count) {
    DEBUG_LOG("get_strategies_for_instruction called for instruction ID: 0x%x", insn->id);
    DEBUG_LOG("Instruction: %s %s", insn->mnemonic, insn->op_str);
    
    static strategy_t* applicable_strategies[MAX_STRATEGIES];
    int applicable_count = 0;

    for (int i = 0; i < strategy_count; i++) {
        DEBUG_LOG("  Trying strategy: %s", strategies[i]->name);
        if (strategies[i]->can_handle(insn)) {
            applicable_strategies[applicable_count++] = strategies[i];
            DEBUG_LOG("    Strategy %s can handle this instruction", strategies[i]->name);
        }
    }

    // Sort strategies by priority (higher priority first)
    for (int i = 0; i < applicable_count - 1; i++) {
        for (int j = i + 1; j < applicable_count; j++) {
            if (applicable_strategies[i]->priority < applicable_strategies[j]->priority) {
                strategy_t* temp = applicable_strategies[i];
                applicable_strategies[i] = applicable_strategies[j];
                applicable_strategies[j] = temp;
            }
        }
    }
    
    DEBUG_LOG("  Found %d applicable strategies", applicable_count);
    if (applicable_count > 0) {
        DEBUG_LOG("  Using: %s (priority %d)", applicable_strategies[0]->name, applicable_strategies[0]->priority);
    }

    *count = applicable_count;
    return applicable_strategies;
}

// Utility functions
int is_mov_instruction(cs_insn *insn) {
    int result = (insn->id == X86_INS_MOV && 
            insn->detail->x86.op_count == 2 && 
            insn->detail->x86.operands[1].type == X86_OP_IMM);
    // printf("is_mov_instruction: insn->id=0x%x, op_count=%d, operand[1].type=%d, result=%d\n",
    //        insn->id, insn->detail->x86.op_count, insn->detail->x86.operands[1].type, result); // Removed debug print
    return result;
}

int is_arithmetic_instruction(cs_insn *insn) {
    return ((insn->id == X86_INS_ADD || insn->id == X86_INS_SUB || 
             insn->id == X86_INS_AND || insn->id == X86_INS_OR || 
             insn->id == X86_INS_XOR || insn->id == X86_INS_CMP) &&
            insn->detail->x86.op_count == 2 && 
            insn->detail->x86.operands[1].type == X86_OP_IMM);
}

int has_null_bytes(cs_insn *insn) {
    int has_null = 0;
    for (size_t j = 0; j < insn->size; j++) {
        if (insn->bytes[j] == 0x00) { 
            has_null = 1; 
            break; 
        }
    }
    // printf("has_null_bytes: insn->id=0x%x, has_null=%d\n", insn->id, has_null); // Removed debug print
    return has_null;
}
// Register the shift strategy
void register_shift_strategy() {
    extern strategy_t shift_based_strategy;
    register_strategy(&shift_based_strategy);
}

