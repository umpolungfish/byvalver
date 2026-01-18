#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <capstone/capstone.h>
#include "core.h"

// Utility functions that strategies need access to
size_t get_mov_eax_imm_size(uint32_t imm);
void generate_mov_eax_imm(struct buffer *b, uint32_t imm);
// void _generate_mov_eax_imm_direct(struct buffer *b, uint32_t imm); // Removed original direct version
size_t get_mov_reg_imm_size(cs_insn *insn);
void generate_mov_reg_imm(struct buffer *b, cs_insn *insn);
size_t get_op_reg_imm_size(cs_insn *insn);
void generate_op_reg_imm(struct buffer *b, cs_insn *insn);
size_t get_push_imm32_size(uint32_t imm);
void generate_push_imm32(struct buffer *b, uint32_t imm);
size_t get_push_imm8_size();
void generate_push_imm8(struct buffer *b, int8_t imm);
void generate_push_imm(struct buffer *b, uint32_t imm);
void generate_mov_eax_imm_byte(struct buffer *b, uint8_t imm);
size_t get_mov_reg_mem_imm_size(cs_insn *insn);
void generate_mov_reg_mem_imm(struct buffer *b, cs_insn *insn);
size_t get_lea_reg_mem_disp32_size(cs_insn *insn);
void generate_lea_reg_mem_disp32(struct buffer *b, cs_insn *insn);
size_t get_mov_disp32_reg_size(cs_insn *insn);
void generate_mov_disp32_reg(struct buffer *b, cs_insn *insn);
size_t get_cmp_mem32_reg_size(cs_insn *insn);
void generate_cmp_mem32_reg(struct buffer *b, cs_insn *insn);
size_t get_arith_mem32_imm32_size(cs_insn *insn);
void generate_arith_mem32_imm32(struct buffer *b, cs_insn *insn);
size_t get_xor_reg_reg_size(cs_insn *insn);
void generate_xor_reg_reg(struct buffer *b, cs_insn *insn);
size_t get_cdq_size();
void generate_cdq(struct buffer *b);
size_t get_mul_reg_size(uint8_t reg);
void generate_mul_reg(struct buffer *b, uint8_t reg);
size_t get_push_pop_size(cs_insn *insn);
void generate_push_pop(struct buffer *b, cs_insn *insn);
size_t get_get_pc_size();
void generate_get_pc(struct buffer *b, uint8_t reg);
size_t get_mov_reg_imm_get_pc_size(cs_insn *insn, struct instruction_node *current);
void generate_mov_reg_imm_get_pc(struct buffer *b, cs_insn *insn);
size_t get_find_kernel32_base_size();
void generate_find_kernel32_base(struct buffer *b);
size_t get_find_get_proc_address_size();
void generate_find_get_proc_address(struct buffer *b);
size_t get_call_imm_dynamic_size();
void generate_call_imm_dynamic(struct buffer *b, cs_insn *insn);
size_t get_call_imm_size(cs_insn *insn);
void generate_call_imm(struct buffer *b, cs_insn *insn);
size_t get_mov_reg_imm_shift_size(cs_insn *insn);
void generate_mov_reg_imm_shift(struct buffer *b, cs_insn *insn);
int find_neg_equivalent(uint32_t target, uint32_t *negated_val);
size_t get_mov_reg_imm_neg_size(cs_insn *insn);
void generate_mov_reg_imm_neg(struct buffer *b, cs_insn *insn);
size_t get_op_reg_imm_neg_size(cs_insn *insn);
void generate_op_reg_imm_neg(struct buffer *b, cs_insn *insn);
size_t get_xor_encoded_mov_size(cs_insn *insn);
void generate_xor_encoded_mov(struct buffer *b, cs_insn *insn);
size_t get_xor_encoded_arithmetic_size(cs_insn *insn);
void generate_xor_encoded_arithmetic(struct buffer *b, cs_insn *insn);

// ADD/SUB Encoding functions
int find_addsub_key(uint32_t target, uint32_t *val1, uint32_t *val2, int *is_add);
size_t get_addsub_encoded_mov_size(cs_insn *insn);
void generate_addsub_encoded_mov(struct buffer *b, cs_insn *insn);
size_t get_addsub_encoded_arithmetic_size(cs_insn *insn);
void generate_addsub_encoded_arithmetic(struct buffer *b, cs_insn *insn);

int find_not_equivalent(uint32_t target, uint32_t *not_val);
void generate_mov_reg_imm_not(struct buffer *b, cs_insn *insn);
size_t get_mov_reg_imm_not_size(cs_insn *insn);

#include "hash_utils.h" // Include hash utilities

// Buffer manipulation helper functions
void buffer_write_byte(struct buffer *b, uint8_t byte);
void buffer_write_word(struct buffer *b, uint16_t word);
void buffer_write_dword(struct buffer *b, uint32_t dword);
void buffer_resize(struct buffer *b, size_t new_size);

// Additional utility functions used in generate_mov_eax_imm
int find_xor_key(uint32_t target, uint32_t *xor_key);
int find_arithmetic_equivalent(uint32_t target, uint32_t *base, uint32_t *offset, int *operation);

// ============================================================================
// Generic Bad Character Checking Functions (v3.0)
// ============================================================================

/**
 * Check if a buffer contains any bad bytes
 * @param data: Buffer to check
 * @param size: Buffer size
 * @return: 1 if any byte is bad, 0 otherwise
 */
int has_null_bytes_in_encoding(const uint8_t *data, size_t size);

// Check if a single byte is free of bad bytes
int is_bad_byte_free_byte(uint8_t byte);

// Check if a 32-bit value is free of bad bytes
int is_bad_byte_free(uint32_t val);

// Check if a buffer is free of bad bytes
int is_bad_byte_free_buffer(const uint8_t *data, size_t size);

// ============================================================================
// Backward Compatibility Wrappers (DEPRECATED in v3.0)
// ============================================================================

// DEPRECATED: Use is_bad_byte_free() instead
int is_null_free(uint32_t val);

// DEPRECATED: Use is_bad_byte_free_byte() instead
int is_null_free_byte(uint8_t byte);

// Create parent directories for a file path if they don't exist
int create_parent_dirs(const char *filepath);

#endif