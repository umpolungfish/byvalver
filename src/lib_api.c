/**
 * @file lib_api.c
 * @brief Implementation of byvalver public C API
 *
 * This file implements the public API defined in byvalver.h by wrapping
 * the internal null-byte elimination functions.
 */

#include "../include/byvalver.h"
#include "../include/core.h"
#include "../include/strategy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define BYVAL_VERSION "1.0.0"

/* Global initialization flag */
static int g_strategies_initialized = 0;

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * @brief Ensure strategies are initialized (called once)
 */
static void ensure_strategies_initialized(void) {
    if (!g_strategies_initialized) {
        init_strategies();
        g_strategies_initialized = 1;
    }
}

/**
 * @brief Count null bytes in buffer
 */
static size_t count_null_bytes(const uint8_t *data, size_t size) {
    size_t count = 0;
    for (size_t i = 0; i < size; i++) {
        if (data[i] == 0x00) {
            count++;
        }
    }
    return count;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

void byval_init_options(ByvalOptions *options) {
    if (!options) return;

    options->verbose = 0;
    options->verify_output = 1;  // Default to verifying output
    options->max_passes = 3;
    options->xor_encode = 0;
    options->xor_key = 0;
    options->arch = BYVAL_ARCH_X86;  // Default to x86
}

const char* byval_error_string(ByvalError error) {
    switch (error) {
        case BYVAL_SUCCESS:
            return "Success";
        case BYVAL_ERROR_INVALID_INPUT:
            return "Invalid input parameters";
        case BYVAL_ERROR_DISASSEMBLY_FAILED:
            return "Disassembly failed";
        case BYVAL_ERROR_NO_STRATEGY:
            return "No strategy found for instruction";
        case BYVAL_ERROR_MEMORY:
            return "Memory allocation failed";
        case BYVAL_ERROR_NULLS_REMAIN:
            return "Null bytes remain after processing";
        case BYVAL_ERROR_PROCESSING_FAILED:
            return "Processing failed";
        default:
            return "Unknown error";
    }
}

const char* byval_version(void) {
    return BYVAL_VERSION;
}

void byval_free_result(ByvalResult *result) {
    if (!result) return;

    if (result->data) {
        free(result->data);
        result->data = NULL;
    }

    result->size = 0;
    result->nulls_removed = 0;
    result->strategies_applied = 0;
    result->passes_completed = 0;
}

size_t byval_count_nulls(const uint8_t *data, size_t size) {
    if (!data || size == 0) return 0;
    return count_null_bytes(data, size);
}

int byval_get_strategy_count(void) {
    ensure_strategies_initialized();
    // TODO: Implement actual strategy counting
    return 70;  // Approximate number of strategies
}

ByvalError byval_clean(const uint8_t *input, size_t input_size,
                       const ByvalOptions *options, ByvalResult *result) {
    if (!input || input_size == 0 || !result) {
        return BYVAL_ERROR_INVALID_INPUT;
    }

    // Initialize result structure
    memset(result, 0, sizeof(ByvalResult));

    // Use default options if none provided
    ByvalOptions default_opts;
    if (!options) {
        byval_init_options(&default_opts);
        options = &default_opts;
    }

    // Ensure strategies are initialized
    ensure_strategies_initialized();

    // Count original null bytes
    size_t original_nulls = count_null_bytes(input, input_size);

    if (options->verbose) {
        fprintf(stdout, "[byvalver] Input size: %zu bytes\n", input_size);
        fprintf(stdout, "[byvalver] Original null bytes: %zu\n", original_nulls);
    }

    // Process shellcode to remove null bytes
    struct buffer processed = remove_null_bytes(input, input_size, options->arch);

    // Check if processing failed
    if (processed.data == NULL || processed.size == 0) {
        if (options->verbose) {
            fprintf(stderr, "[byvalver] Processing failed\n");
        }
        return BYVAL_ERROR_PROCESSING_FAILED;
    }

    // Apply XOR encoding if requested
    struct buffer final_output;
    buffer_init(&final_output);

    if (options->xor_encode && options->xor_key != 0) {
        if (options->verbose) {
            fprintf(stdout, "[byvalver] Applying XOR encoding with key 0x%08x\n", options->xor_key);
        }

        // For now, just XOR encode the data directly
        // In the full implementation, this would include the decoder stub
        buffer_append(&final_output, processed.data, processed.size);

        // XOR encode
        for (size_t i = 0; i < final_output.size; i++) {
            final_output.data[i] ^= ((uint8_t *)&options->xor_key)[i % 4];
        }
    } else {
        // No encoding, use processed data directly
        buffer_append(&final_output, processed.data, processed.size);
    }

    // Verify null-byte elimination if requested
    if (options->verify_output) {
        size_t remaining_nulls = count_null_bytes(final_output.data, final_output.size);
        if (remaining_nulls > 0) {
            if (options->verbose) {
                fprintf(stderr, "[byvalver] Warning: %zu null bytes remain\n", remaining_nulls);
            }
            buffer_free(&processed);
            buffer_free(&final_output);
            return BYVAL_ERROR_NULLS_REMAIN;
        }
    }

    // Allocate result buffer
    result->data = (uint8_t *)malloc(final_output.size);
    if (!result->data) {
        buffer_free(&processed);
        buffer_free(&final_output);
        return BYVAL_ERROR_MEMORY;
    }

    // Copy data to result
    memcpy(result->data, final_output.data, final_output.size);
    result->size = final_output.size;
    result->nulls_removed = (int)original_nulls;
    result->strategies_applied = 0;  // TODO: Track this in core
    result->passes_completed = 1;

    if (options->verbose) {
        fprintf(stdout, "[byvalver] Output size: %zu bytes\n", result->size);
        fprintf(stdout, "[byvalver] Removed %d null bytes\n", result->nulls_removed);
        fprintf(stdout, "[byvalver] Size change: %+zd bytes\n", 
                (ssize_t)result->size - (ssize_t)input_size);
    }

    // Cleanup
    buffer_free(&processed);
    buffer_free(&final_output);

    return BYVAL_SUCCESS;
}

ByvalError byval_clean_to_file(const uint8_t *input, size_t input_size,
                               const char *output_path, const ByvalOptions *options) {
    if (!input || input_size == 0 || !output_path) {
        return BYVAL_ERROR_INVALID_INPUT;
    }

    ByvalResult result;
    ByvalError err = byval_clean(input, input_size, options, &result);
    if (err != BYVAL_SUCCESS) {
        return err;
    }

    // Write to file
    FILE *out_f = fopen(output_path, "wb");
    if (!out_f) {
        byval_free_result(&result);
        return BYVAL_ERROR_PROCESSING_FAILED;
    }

    size_t written = fwrite(result.data, 1, result.size, out_f);
    fclose(out_f);

    if (written != result.size) {
        byval_free_result(&result);
        return BYVAL_ERROR_PROCESSING_FAILED;
    }

    if (options && options->verbose) {
        fprintf(stdout, "[byvalver] Wrote %zu bytes to %s\n", result.size, output_path);
    }

    byval_free_result(&result);
    return BYVAL_SUCCESS;
}
