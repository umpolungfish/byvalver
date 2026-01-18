#ifndef CORE_H
#define CORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <capstone/capstone.h>
#include "strategy.h"
#include "cli.h"  // For bad_byte_config_t
#include "batch_processing.h"  // For batch_stats_t

// Capstone architecture mode selector
void get_capstone_arch_mode(byval_arch_t arch, cs_arch *cs_arch_out, cs_mode *cs_mode_out);

#ifdef DEBUG
  // C99 compliant debug macro
  #define DEBUG_LOG(...) do { fprintf(stderr, "[DEBUG] "); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
  #define DEBUG_INSN(insn) fprintf(stderr, "[DEBUG] %s %s\n", insn->mnemonic, insn->op_str)
#else
  #define DEBUG_LOG(...) do {} while(0)
  #define DEBUG_INSN(insn) do {} while(0)
#endif

// Core data structures
struct buffer {
    uint8_t *data;
    size_t size;
    size_t capacity;
};

struct instruction_node {
    cs_insn *insn;
    size_t offset;
    size_t new_offset;
    size_t new_size;
    struct instruction_node *next;
};

// Global bad byte context (v3.0)
// Thread-local in multi-threaded scenarios (future enhancement)
typedef struct {
    bad_byte_config_t config;     // Active configuration
    int initialized;               // 0 = uninitialized, 1 = ready
} bad_byte_context_t;

// Global bad byte context instance
extern bad_byte_context_t g_bad_byte_context;

// Global batch statistics context (for tracking strategy usage during processing)
// This is used to track strategy usage and file complexity during processing
extern batch_stats_t* g_batch_stats_context;

// Bad byte context management functions
void init_bad_byte_context(bad_byte_config_t *config);
void reset_bad_byte_context(void);
bad_byte_config_t* get_bad_byte_config(void);

// Batch statistics context management functions
void set_batch_stats_context(batch_stats_t *stats);
void track_strategy_usage(const char *strategy_name, int success, size_t output_size);

// Function to count instructions and bad bytes in shellcode
void count_shellcode_stats(const uint8_t *shellcode, size_t size, int *instruction_count, int *bad_byte_count, byval_arch_t arch);

// Core functions
struct buffer remove_null_bytes(const uint8_t *shellcode, size_t size, byval_arch_t arch);
struct buffer apply_obfuscation(const uint8_t *shellcode, size_t size, byval_arch_t arch);
struct buffer biphasic_process(const uint8_t *shellcode, size_t size, byval_arch_t arch);
void buffer_init(struct buffer *b);
void buffer_free(struct buffer *b);
void buffer_append(struct buffer *b, const uint8_t *data, size_t size);
uint8_t get_reg_index(uint8_t reg);
int is_rip_relative_operand(cs_x86_op *op);
int is_relative_jump(cs_insn *insn);
int verify_null_elimination(struct buffer *processed);
void fallback_general_instruction(struct buffer *b, cs_insn *insn);
void fallback_mov_reg_imm(struct buffer *b, cs_insn *insn);
void fallback_arithmetic_reg_imm(struct buffer *b, cs_insn *insn);
void fallback_memory_operation(struct buffer *b, cs_insn *insn);
void handle_unhandled_instruction_with_nulls(struct buffer *b, cs_insn *insn);
struct buffer adaptive_processing(const uint8_t *input, size_t size, byval_arch_t arch);

#endif