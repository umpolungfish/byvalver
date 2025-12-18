#include "ml_instruction_map.h"
#include <capstone/x86.h>
#include <stddef.h>

// Top 50 most common x86 instructions in shellcode (ordered by frequency)
// Index corresponds to one-hot encoding position (0-49)
// Index 50 is reserved for "OTHER" bucket
static const unsigned int TOP_INSTRUCTIONS[TOP_N_INSTRUCTIONS] = {
    X86_INS_MOV,      // 0  - Most common: data movement
    X86_INS_PUSH,     // 1  - Stack operations
    X86_INS_POP,      // 2
    X86_INS_XOR,      // 3  - Arithmetic/logic (common for zeroing)
    X86_INS_LEA,      // 4  - Address calculation
    X86_INS_ADD,      // 5
    X86_INS_SUB,      // 6
    X86_INS_CALL,     // 7  - Control flow
    X86_INS_JMP,      // 8
    X86_INS_RET,      // 9
    X86_INS_CMP,      // 10 - Comparison
    X86_INS_TEST,     // 11
    X86_INS_AND,      // 12 - Logic operations
    X86_INS_OR,       // 13
    X86_INS_SHL,      // 14 - Shifts
    X86_INS_SHR,      // 15
    X86_INS_INC,      // 16 - Increment/decrement
    X86_INS_DEC,      // 17
    X86_INS_IMUL,     // 18 - Multiplication
    X86_INS_MUL,      // 19
    X86_INS_NOP,      // 20 - Padding/alignment
    X86_INS_INT,      // 21 - System calls (Linux int 0x80)
    X86_INS_SYSCALL,  // 22 - System calls (64-bit)
    X86_INS_CDQ,      // 23 - Sign extension
    X86_INS_XCHG,     // 24 - Exchange
    X86_INS_NEG,      // 25 - Negate
    X86_INS_NOT,      // 26 - Bitwise NOT
    X86_INS_MOVZX,    // 27 - Zero-extend move
    X86_INS_MOVSX,    // 28 - Sign-extend move
    X86_INS_JE,       // 29 - Conditional jumps (jump if equal)
    X86_INS_JNE,      // 30 - Jump if not equal
    X86_INS_JA,       // 31 - Above (unsigned)
    X86_INS_JB,       // 32 - Below (unsigned)
    X86_INS_JL,       // 33 - Less (signed)
    X86_INS_JG,       // 34 - Greater (signed)
    X86_INS_JAE,      // 35 - Above or equal
    X86_INS_JBE,      // 36 - Below or equal
    X86_INS_JLE,      // 37 - Less or equal
    X86_INS_JGE,      // 38 - Greater or equal
    X86_INS_STOSB,    // 39 - String operations
    X86_INS_LODSB,    // 40 - Load string byte
    X86_INS_SCASB,    // 41 - Scan string byte
    X86_INS_MOVSB,    // 42 - Move string byte
    X86_INS_LOOP,     // 43 - Loop
    X86_INS_LEAVE,    // 44 - Stack frame cleanup
    X86_INS_ENTER,    // 45 - Stack frame setup
    X86_INS_DIV,      // 46 - Division
    X86_INS_IDIV,     // 47 - Signed division
    X86_INS_SAR,      // 48 - Arithmetic shift right
    X86_INS_ROL       // 49 - Rotate left
};

// Instruction names for debugging/logging
static const char* TOP_INSTRUCTION_NAMES[TOP_N_INSTRUCTIONS] = {
    "MOV", "PUSH", "POP", "XOR", "LEA", "ADD", "SUB", "CALL", "JMP", "RET",
    "CMP", "TEST", "AND", "OR", "SHL", "SHR", "INC", "DEC", "IMUL", "MUL",
    "NOP", "INT", "SYSCALL", "CDQ", "XCHG", "NEG", "NOT", "MOVZX", "MOVSX", "JE",
    "JNE", "JA", "JB", "JL", "JG", "JAE", "JBE", "JLE", "JGE", "STOSB",
    "LODSB", "SCASB", "MOVSB", "LOOP", "LEAVE", "ENTER", "DIV", "IDIV", "SAR", "ROL"
};

// Lookup table for fast mapping (instruction_id -> onehot_index)
// -1 means "not in top-N, use OTHER bucket"
static int g_insn_to_onehot[1024] = {0};  // Large enough for X86_INS_ENDING
static int g_initialized = 0;

void ml_instruction_map_init(void) {
    if (g_initialized) {
        return;
    }

    // Initialize all to -1 (OTHER bucket)
    for (int i = 0; i < 1024; i++) {
        g_insn_to_onehot[i] = -1;
    }

    // Map top-N instructions to their indices
    for (int i = 0; i < TOP_N_INSTRUCTIONS; i++) {
        unsigned int insn_id = TOP_INSTRUCTIONS[i];
        if (insn_id < 1024) {
            g_insn_to_onehot[insn_id] = i;
        }
    }

    g_initialized = 1;
}

int ml_get_instruction_onehot_index(unsigned int insn_id) {
    // Ensure initialization
    if (!g_initialized) {
        ml_instruction_map_init();
    }

    // Bounds check
    if (insn_id >= 1024) {
        return TOP_N_INSTRUCTIONS;  // OTHER bucket (index 50)
    }

    // Lookup in table
    int idx = g_insn_to_onehot[insn_id];
    if (idx < 0) {
        return TOP_N_INSTRUCTIONS;  // OTHER bucket (index 50)
    }

    return idx;
}

const char* ml_get_instruction_name_by_index(int onehot_idx) {
    if (onehot_idx < 0 || onehot_idx > TOP_N_INSTRUCTIONS) {
        return "INVALID";
    }

    if (onehot_idx == TOP_N_INSTRUCTIONS) {
        return "OTHER";
    }

    return TOP_INSTRUCTION_NAMES[onehot_idx];
}
