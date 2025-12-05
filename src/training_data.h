/**
 * @file training_data.h
 * @brief Training data collection system for ML Strategist
 * 
 * This header defines the structures and functions for collecting,
 * storing, and managing training data for the ML-based shellcode strategist.
 */

#ifndef TRAINING_DATA_H
#define TRAINING_DATA_H

#include <stdint.h>
#include <stddef.h>
#include <capstone/capstone.h>
#include "ml_strategist.h"
#include "strategy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_TRAINING_SAMPLES 10000
#define MAX_INSTRUCTION_SIZE 16
#define MAX_STRATEGY_NAME_LEN 64

/**
 * @brief Structure to represent a training sample
 */
typedef struct {
    uint8_t original_bytes[MAX_INSTRUCTION_SIZE];  // Original instruction bytes
    size_t original_size;                          // Size of original instruction
    uint8_t transformed_bytes[MAX_INSTRUCTION_SIZE * 4];  // Transformed instruction bytes (allowing larger output)
    size_t transformed_size;                       // Size of transformed instruction
    instruction_features_t features;               // Features extracted from original instruction
    char applied_strategy[MAX_STRATEGY_NAME_LEN];  // Name of strategy applied
    int strategy_success;                          // Whether strategy was successful (1) or failed (0)
    int null_eliminated;                           // Whether all nulls were eliminated (1) or not (0)
    double effectiveness_score;                    // Effectiveness score (0.0-1.0)
    uint64_t timestamp;                           // Timestamp of when sample was collected
} training_sample_t;

/**
 * @brief Training data collection context
 */
typedef struct {
    training_sample_t* samples;                    // Array of training samples
    size_t sample_count;                          // Current number of samples
    size_t max_samples;                           // Maximum number of samples
    char output_file[256];                        // File to save collected data
    int collection_enabled;                       // Whether collection is enabled
    int auto_save_interval;                       // Save every N samples
    size_t last_saved_count;                      // Number of samples at last save
} training_data_context_t;

/**
 * @brief Initialize the training data collection system
 * @param context Pointer to the training data context to initialize
 * @param max_samples Maximum number of samples to collect
 * @return 0 on success, non-zero on failure
 */
int training_data_init(training_data_context_t* context, size_t max_samples);

/**
 * @brief Add a training sample to the collection
 * @param context Training data context
 * @param original_insn Original Capstone instruction
 * @param transformed_data Transformed shellcode bytes
 * @param transformed_size Size of transformed data
 * @param applied_strategy Strategy that was applied
 * @param success Whether the transformation was successful
 * @return 0 on success, non-zero on failure
 */
int training_data_add_sample(training_data_context_t* context,
                             cs_insn* original_insn,
                             const uint8_t* transformed_data,
                             size_t transformed_size,
                             strategy_t* applied_strategy,
                             int success);

/**
 * @brief Extract and store features for an instruction
 * @param insn Instruction to extract features from
 * @param features Output features structure
 * @return 0 on success, non-zero on failure
 */
int training_data_extract_features(cs_insn* insn, instruction_features_t* features);

/**
 * @brief Save collected training data to a file
 * @param context Training data context
 * @param filename File to save data to
 * @return 0 on success, non-zero on failure
 */
int training_data_save(training_data_context_t* context, const char* filename);

/**
 * @brief Load training data from a file
 * @param context Training data context
 * @param filename File to load data from
 * @return 0 on success, non-zero on failure
 */
int training_data_load(training_data_context_t* context, const char* filename);

/**
 * @brief Process a shellcode file to extract training samples
 * @param context Training data context
 * @param shellcode_path Path to shellcode file
 * @param processed_path Path to processed shellcode output (for comparison)
 * @return Number of samples extracted, negative on error
 */
int training_data_process_shellcode(training_data_context_t* context,
                                    const char* shellcode_path,
                                    const char* processed_path);

/**
 * @brief Process all shellcodes in a directory to extract training samples
 * @param context Training data context
 * @param directory_path Path to directory containing shellcode files
 * @return Total number of samples extracted, negative on error
 */
int training_data_process_directory(training_data_context_t* context,
                                    const char* directory_path);

/**
 * @brief Get statistics about the collected training data
 * @param context Training data context
 * @param success_count Output parameter for successful transformations
 * @param failure_count Output parameter for failed transformations
 * @param null_free_count Output parameter for null-free outputs
 * @return 0 on success, non-zero on failure
 */
int training_data_get_stats(training_data_context_t* context,
                            size_t* success_count,
                            size_t* failure_count,
                            size_t* null_free_count);

/**
 * @brief Cleanup the training data collection system
 * @param context Training data context to cleanup
 */
void training_data_cleanup(training_data_context_t* context);

/**
 * @brief Enable or disable training data collection
 * @param context Training data context
 * @param enabled Whether to enable (1) or disable (0) collection
 */
void training_data_set_enabled(training_data_context_t* context, int enabled);

/**
 * @brief Get current number of collected samples
 * @param context Training data context
 * @return Number of collected samples
 */
size_t training_data_get_sample_count(training_data_context_t* context);

#ifdef __cplusplus
}
#endif

#endif /* TRAINING_DATA_H */