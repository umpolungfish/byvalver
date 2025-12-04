#ifndef CORE_H
#define CORE_H

#include <stdint.h>
#include <stddef.h>
#include <capstone/capstone.h>
#include "strategy.h"

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

// Core functions
struct buffer remove_null_bytes(const uint8_t *shellcode, size_t size);
struct buffer apply_obfuscation(const uint8_t *shellcode, size_t size);
struct buffer biphasic_process(const uint8_t *shellcode, size_t size);
void buffer_init(struct buffer *b);
void buffer_free(struct buffer *b);
void buffer_append(struct buffer *b, const uint8_t *data, size_t size);
uint8_t get_reg_index(uint8_t reg);
int is_relative_jump(cs_insn *insn);
int verify_null_elimination(struct buffer *processed);
void fallback_general_instruction(struct buffer *b, cs_insn *insn);
void fallback_mov_reg_imm(struct buffer *b, cs_insn *insn);
void fallback_arithmetic_reg_imm(struct buffer *b, cs_insn *insn);
struct buffer adaptive_processing(const uint8_t *input, size_t size);

#endif