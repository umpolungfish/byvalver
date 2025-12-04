/**
 * @file byvalver.h
 * @brief Public API for byvalver null-byte elimination library
 *
 * This header provides a simple C API for removing null bytes from
 * shellcode while preserving functional equivalence. It uses advanced
 * transformation strategies based on x86/x64 instruction semantics.
 */

#ifndef BYVALVER_H
#define BYVALVER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Error Codes
 * ============================================================================ */

/**
 * @brief Error codes returned by byvalver functions
 */
typedef enum {
    BYVAL_SUCCESS = 0,                  /**< Operation succeeded */
    BYVAL_ERROR_INVALID_INPUT = 1,      /**< Invalid input parameters */
    BYVAL_ERROR_DISASSEMBLY_FAILED = 2, /**< Disassembly failed */
    BYVAL_ERROR_NO_STRATEGY = 3,        /**< No strategy found for instruction */
    BYVAL_ERROR_MEMORY = 4,             /**< Memory allocation failed */
    BYVAL_ERROR_NULLS_REMAIN = 5,       /**< Null bytes remain after processing */
    BYVAL_ERROR_PROCESSING_FAILED = 6   /**< General processing failure */
} ByvalError;

/* ============================================================================
 * Structures
 * ============================================================================ */

/**
 * @brief Processing options
 */
typedef struct {
    int verbose;              /**< Enable verbose output (0 = off, 1 = on) */
    int verify_output;        /**< Verify null-byte elimination (0 = off, 1 = on) */
    int max_passes;           /**< Maximum number of processing passes (default: 3) */
    int xor_encode;           /**< XOR encode output with key (0 = off, 1 = on) */
    uint32_t xor_key;         /**< XOR encoding key (used if xor_encode = 1) */
} ByvalOptions;

/**
 * @brief Processing result
 *
 * Contains the cleaned shellcode and processing statistics. The caller is
 * responsible for freeing the data field using byval_free_result().
 */
typedef struct {
    uint8_t *data;            /**< Cleaned shellcode (caller must free with byval_free_result) */
    size_t size;              /**< Size of cleaned shellcode in bytes */
    int nulls_removed;        /**< Number of null bytes removed */
    int strategies_applied;   /**< Number of transformation strategies applied */
    int passes_completed;     /**< Number of processing passes completed */
} ByvalResult;

/* ============================================================================
 * Public API Functions
 * ============================================================================ */

/**
 * @brief Clean shellcode by removing null bytes
 *
 * This is the main cleaning function. It disassembles the input shellcode,
 * identifies instructions containing null bytes, and applies transformation
 * strategies to eliminate them while preserving functionality.
 *
 * @param input Input shellcode buffer (must not be NULL)
 * @param input_size Size of input shellcode in bytes
 * @param options Processing options (may be NULL for defaults)
 * @param result Output result structure (must not be NULL)
 * @return BYVAL_SUCCESS on success, error code otherwise
 */
ByvalError byval_clean(const uint8_t *input, size_t input_size,
                       const ByvalOptions *options, ByvalResult *result);

/**
 * @brief Clean shellcode and write to file
 *
 * Convenience function that cleans shellcode and writes it directly to a file.
 *
 * @param input Input shellcode buffer
 * @param input_size Size of input shellcode in bytes
 * @param output_path Path to output file
 * @param options Processing options (may be NULL for defaults)
 * @return BYVAL_SUCCESS on success, error code otherwise
 */
ByvalError byval_clean_to_file(const uint8_t *input, size_t input_size,
                               const char *output_path, const ByvalOptions *options);

/**
 * @brief Free resources allocated by byval_clean
 *
 * Frees all memory allocated in a ByvalResult structure, including the
 * data buffer.
 *
 * @param result Result structure to free (may be NULL)
 */
void byval_free_result(ByvalResult *result);

/**
 * @brief Get human-readable error string
 *
 * Returns a string description of an error code.
 *
 * @param error Error code
 * @return Pointer to static string (do not free)
 */
const char* byval_error_string(ByvalError error);

/**
 * @brief Get library version string
 *
 * Returns the version of the byvalver library.
 *
 * @return Pointer to static version string (do not free)
 */
const char* byval_version(void);

/**
 * @brief Initialize default options
 *
 * Fills a ByvalOptions structure with default values.
 *
 * @param options Options structure to initialize (must not be NULL)
 */
void byval_init_options(ByvalOptions *options);

/**
 * @brief Check if shellcode contains null bytes
 *
 * Scans shellcode for null bytes and returns count.
 *
 * @param data Shellcode buffer
 * @param size Size of shellcode in bytes
 * @return Number of null bytes found
 */
size_t byval_count_nulls(const uint8_t *data, size_t size);

/**
 * @brief Get number of registered strategies
 *
 * Returns the number of transformation strategies available in the library.
 *
 * @return Number of strategies
 */
int byval_get_strategy_count(void);

#ifdef __cplusplus
}
#endif

#endif /* BYVALVER_H */
