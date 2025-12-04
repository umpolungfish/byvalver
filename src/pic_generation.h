/**
 * @file pic_generation.h
 * @brief Position Independent Code (PIC) generation functions for Windows shellcode
 *
 * This module provides functions to generate Windows position-independent shellcode
 * using techniques such as JMP-CALL-POP for EIP/rip register access and hash-based
 * API resolution for runtime API calls without relying on imports.
 */

#ifndef PIC_GENERATION_H
#define PIC_GENERATION_H

#include <stdint.h>
#include <stddef.h>
#include "core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Structures
 * ============================================================================ */

/**
 * @brief Options for PIC generation
 */
typedef struct {
    int use_jmp_call_pop;      /**< Use JMP-CALL-POP technique for EIP/rip access (default: 1) */
    int use_api_hashing;       /**< Use hash-based API resolution (default: 1) */
    int include_anti_debug;    /**< Include anti-debugging features in PIC (default: 0) */
    int xor_encode_payload;    /**< XOR encode the payload (default: 0) */
    uint32_t xor_key;          /**< XOR key if xor_encode_payload is enabled (default: 0x12345678) */
} PICOptions;

/**
 * @brief PIC generation result
 */
typedef struct {
    uint8_t *data;             /**< Generated PIC shellcode */
    size_t size;               /**< Size of generated shellcode */
    int api_count;             /**< Number of APIs resolved */
    int techniques_used;       /**< Number of PIC techniques applied */
} PICResult;

/* ============================================================================
 * Public API Functions
 * ============================================================================ */

/**
 * @brief Generate position-independent shellcode from assembly code
 *
 * This function takes input assembly code and converts it to position-independent
 * shellcode using various techniques like JMP-CALL-POP for EIP access and
 * hash-based API resolution.
 *
 * @param input Input shellcode or assembly bytes
 * @param input_size Size of input data
 * @param options PIC generation options
 * @param result Output result structure
 * @return 0 on success, -1 on error
 */
int pic_generate(const uint8_t *input, size_t input_size,
                 const PICOptions *options, PICResult *result);

/**
 * @brief Generate PIC shellcode and write to file
 *
 * Convenience function that generates PIC shellcode and writes directly to file.
 *
 * @param input Input shellcode or assembly bytes
 * @param input_size Size of input data
 * @param output_path Path to output file
 * @param options PIC generation options
 * @return 0 on success, -1 on error
 */
int pic_generate_to_file(const uint8_t *input, size_t input_size,
                         const char *output_path, const PICOptions *options);

/**
 * @brief Free resources allocated by PIC generation functions
 *
 * @param result PIC result structure to free
 */
void pic_free_result(PICResult *result);

/**
 * @brief Initialize default PIC options
 *
 * @param options Options structure to initialize
 */
void pic_init_options(PICOptions *options);

/**
 * @brief Generate a JMP-CALL-POP stub for getting current EIP/rip
 *
 * This function creates a stub that gets the current instruction pointer,
 * which is the foundation of many PIC techniques.
 *
 * @param buffer Buffer to append the stub to
 * @param is_64bit Flag indicating if targeting 64-bit (default: 0 for 32-bit)
 * @return 0 on success, -1 on error
 */
int pic_generate_jmp_call_pop_stub(struct buffer *b, int is_64bit);

/**
 * @brief Generate API resolution code using hash-based technique
 *
 * This function creates code that resolves Windows APIs at runtime using hash comparison
 * instead of relying on import tables.
 *
 * @param buffer Buffer to append the API resolution code to
 * @param api_name Name of the API to generate resolution code for
 * @return 0 on success, -1 on error
 */
int pic_generate_api_resolution(struct buffer *b, const char *api_name);

/**
 * @brief Generate hash for a given API function name
 *
 * Uses a simple hash algorithm to convert an API name to a 32-bit hash value.
 *
 * @param api_name Name of the API function
 * @return 32-bit hash value
 */
uint32_t pic_hash_api_name(const char *api_name);

/**
 * @brief Generate position-independent function call
 *
 * Creates a function call that works regardless of where the code is loaded.
 *
 * @param buffer Buffer to append the call to
 * @param api_hash Hash of the API name to call
 * @return 0 on success, -1 on error
 */
int pic_generate_pic_call(struct buffer *b, uint32_t api_hash);

/**
 * @brief Generate Windows-specific anti-debugging features
 *
 * Adds techniques to detect and potentially bypass debugging.
 *
 * @param buffer Buffer to append anti-debug code to
 * @return 0 on success, -1 on error
 */
int pic_generate_anti_debug(struct buffer *b);

#ifdef __cplusplus
}
#endif

#endif /* PIC_GENERATION_H */