/*
 * Header file for advanced shellcode transformation strategies
 * Implements sophisticated transformations to bridge 78.9% to 80%+ similarity
 */

#ifndef ADVANCED_TRANSFORMATIONS_H
#define ADVANCED_TRANSFORMATIONS_H

#include "strategy.h"

// Function prototypes for advanced transformation strategies
void register_advanced_transformations();
void init_advanced_transformations();

// Individual strategy functions
size_t get_modrm_null_bypass_size(cs_insn *insn);
void generate_modrm_null_bypass(struct buffer *b, cs_insn *insn);

size_t get_arithmetic_substitution_size(cs_insn *insn);
void generate_arithmetic_substitution(struct buffer *b, cs_insn *insn);

size_t get_flag_preserving_test_size(cs_insn *insn);
void generate_flag_preserving_test(struct buffer *b, cs_insn *insn);

size_t get_sib_addressing_size(cs_insn *insn);
void generate_sib_addressing(struct buffer *b, cs_insn *insn);

size_t get_xor_null_free_size(cs_insn *insn);
void generate_xor_null_free(struct buffer *b, cs_insn *insn);

size_t get_push_optimized_size(cs_insn *insn);
void generate_push_optimized(struct buffer *b, cs_insn *insn);

size_t get_byte_granularity_size(cs_insn *insn);
void generate_byte_granularity(struct buffer *b, cs_insn *insn);

size_t get_cond_jump_target_size(cs_insn *insn);
void generate_cond_jump_target(struct buffer *b, cs_insn *insn);

size_t get_cond_jump_target_size_enhanced(cs_insn *insn);
void generate_cond_jump_target_enhanced(struct buffer *b, cs_insn *insn);

// Utility functions
int can_use_temp_register(cs_insn *insn, uint8_t temp_reg);
int is_register_available(uint8_t reg, cs_insn *current_insn);
uint8_t get_available_temp_register(cs_insn *insn);

// Check functions for specific transformations
int can_handle_modrm_null_bypass(cs_insn *insn);
int can_handle_arithmetic_substitution(cs_insn *insn);
int can_handle_flag_preserving_test(cs_insn *insn);
int can_handle_sib_addressing(cs_insn *insn);
int can_handle_xor_null_free(cs_insn *insn);
int can_handle_push_optimized(cs_insn *insn);
int can_handle_byte_granularity(cs_insn *insn);
int can_handle_cond_jump_target(cs_insn *insn);
int can_handle_cond_jump_target_enhanced(cs_insn *insn);

#endif