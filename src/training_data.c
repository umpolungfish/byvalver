/**
 * @file training_data.c
 * @brief Training data collection system implementation
 * 
 * This file implements the training data collection for the ML-based strategist.
 */

#include "training_data.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * @brief Initialize the training data collection system
 */
int training_data_init(training_data_context_t* context, size_t max_samples) {
    if (!context) {
        return -1;
    }
    
    // Initialize context
    memset(context, 0, sizeof(training_data_context_t));
    
    // Allocate memory for samples
    context->samples = (training_sample_t*)calloc(max_samples, sizeof(training_sample_t));
    if (!context->samples) {
        return -1;
    }
    
    context->max_samples = max_samples;
    context->sample_count = 0;
    context->collection_enabled = 1;
    context->auto_save_interval = 100;  // Save every 100 samples
    context->last_saved_count = 0;
    
    strncpy(context->output_file, "training_data.bin", sizeof(context->output_file) - 1);
    context->output_file[sizeof(context->output_file) - 1] = '\0';
    
    printf("[TRAINING DATA] Initialized with capacity for %zu samples\n", max_samples);
    return 0;
}

/**
 * @brief Add a training sample to the collection
 */
int training_data_add_sample(training_data_context_t* context,
                             cs_insn* original_insn,
                             const uint8_t* transformed_data,
                             size_t transformed_size,
                             strategy_t* applied_strategy,
                             int success) {
    if (!context || !original_insn || !transformed_data || !applied_strategy) {
        return -1;
    }
    
    if (!context->collection_enabled) {
        return 0;  // Collection disabled, but not an error
    }
    
    if (context->sample_count >= context->max_samples) {
        printf("[TRAINING DATA] Warning: Maximum sample capacity reached (%zu)\n", context->max_samples);
        return -1;
    }
    
    // Get current sample
    training_sample_t* sample = &context->samples[context->sample_count];
    
    // Copy original instruction bytes
    size_t copy_size = (original_insn->size > MAX_INSTRUCTION_SIZE) ? 
                        MAX_INSTRUCTION_SIZE : original_insn->size;
    memcpy(sample->original_bytes, original_insn->bytes, copy_size);
    sample->original_size = copy_size;
    
    // Copy transformed data
    size_t transform_copy_size = (transformed_size > MAX_INSTRUCTION_SIZE * 4) ? 
                                 MAX_INSTRUCTION_SIZE * 4 : transformed_size;
    memcpy(sample->transformed_bytes, transformed_data, transform_copy_size);
    sample->transformed_size = transform_copy_size;
    
    // Extract features from the original instruction
    training_data_extract_features(original_insn, &sample->features);
    
    // Copy strategy name
    strncpy(sample->applied_strategy, applied_strategy->name, MAX_STRATEGY_NAME_LEN - 1);
    sample->applied_strategy[MAX_STRATEGY_NAME_LEN - 1] = '\0';
    
    // Set success flags
    sample->strategy_success = success;
    
    // Check if nulls were eliminated
    sample->null_eliminated = 1;
    for (size_t i = 0; i < transform_copy_size; i++) {
        if (sample->transformed_bytes[i] == 0x00) {
            sample->null_eliminated = 0;
            break;
        }
    }
    
    // Calculate effectiveness score (simplified)
    // Score based on success and null elimination
    sample->effectiveness_score = success ? (sample->null_eliminated ? 1.0 : 0.5) : 0.0;
    
    // Set timestamp
    sample->timestamp = (uint64_t)time(NULL);
    
    context->sample_count++;
    
    // Auto-save if interval reached
    if ((int)(context->sample_count - context->last_saved_count) >= context->auto_save_interval) {
        printf("[TRAINING DATA] Auto-saving at %zu samples\n", context->sample_count);
        training_data_save(context, context->output_file);
        context->last_saved_count = context->sample_count;
    }
    
    return 0;
}

/**
 * @brief Extract and store features for an instruction
 */
int training_data_extract_features(cs_insn* insn, instruction_features_t* features) {
    if (!insn || !features) {
        return -1;
    }
    
    // Use the ML strategist's feature extraction function
    return ml_extract_instruction_features(insn, features);
}

/**
 * @brief Save collected training data to a file
 */
int training_data_save(training_data_context_t* context, const char* filename) {
    if (!context || !filename) {
        return -1;
    }
    
    FILE* file = fopen(filename, "wb");
    if (!file) {
        printf("[TRAINING DATA] Error: Could not open file %s for writing\n", filename);
        return -1;
    }
    
    // Write metadata
    fwrite(&context->sample_count, sizeof(size_t), 1, file);
    fwrite(&context->max_samples, sizeof(size_t), 1, file);
    
    // Write all samples
    for (size_t i = 0; i < context->sample_count; i++) {
        fwrite(&context->samples[i], sizeof(training_sample_t), 1, file);
    }
    
    fclose(file);
    printf("[TRAINING DATA] Saved %zu samples to %s\n", context->sample_count, filename);
    return 0;
}

/**
 * @brief Load training data from a file
 */
int training_data_load(training_data_context_t* context, const char* filename) {
    if (!context || !filename) {
        return -1;
    }
    
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("[TRAINING DATA] Error: Could not open file %s for reading\n", filename);
        return -1;
    }
    
    // Read metadata
    size_t sample_count, max_samples;
    if (fread(&sample_count, sizeof(size_t), 1, file) != 1) {
        fclose(file);
        return -1;
    }
    
    if (fread(&max_samples, sizeof(size_t), 1, file) != 1) {
        fclose(file);
        return -1;
    }
    
    // Check if we have enough space
    if (sample_count > context->max_samples) {
        printf("[TRAINING DATA] Error: File contains %zu samples, but buffer only supports %zu\n", 
               sample_count, context->max_samples);
        fclose(file);
        return -1;
    }
    
    // Read all samples
    for (size_t i = 0; i < sample_count; i++) {
        if (fread(&context->samples[i], sizeof(training_sample_t), 1, file) != 1) {
            fclose(file);
            return -1;
        }
    }
    
    context->sample_count = sample_count;
    
    fclose(file);
    printf("[TRAINING DATA] Loaded %zu samples from %s\n", sample_count, filename);
    return 0;
}

/**
 * @brief Process a shellcode file to extract training samples
 */
int training_data_process_shellcode(training_data_context_t* context,
                                    const char* shellcode_path,
                                    const char* processed_path __attribute__((unused))) {
    if (!context || !shellcode_path) {
        return -1;
    }
    
    // This would require implementing shellcode processing with strategy application
    // and collection of the before/after pairs with strategy information
    printf("[TRAINING DATA] Processing shellcode: %s\n", shellcode_path);
    
    // For now, return 0 as this would be complex to implement without the full processing pipeline
    return 0;
}

/**
 * @brief Process all shellcodes in a directory to extract training samples
 */
int training_data_process_directory(training_data_context_t* context,
                                    const char* directory_path) {
    if (!context || !directory_path) {
        return -1;
    }
    
    printf("[TRAINING DATA] Processing directory: %s\n", directory_path);
    // This would involve iterating through all .bin files in a directory
    // and processing each one to collect training samples
    return 0;
}

/**
 * @brief Get statistics about the collected training data
 */
int training_data_get_stats(training_data_context_t* context,
                            size_t* success_count,
                            size_t* failure_count,
                            size_t* null_free_count) {
    if (!context || !success_count || !failure_count || !null_free_count) {
        return -1;
    }
    
    *success_count = 0;
    *failure_count = 0;
    *null_free_count = 0;
    
    for (size_t i = 0; i < context->sample_count; i++) {
        if (context->samples[i].strategy_success) {
            (*success_count)++;
        } else {
            (*failure_count)++;
        }
        
        if (context->samples[i].null_eliminated) {
            (*null_free_count)++;
        }
    }
    
    return 0;
}

/**
 * @brief Cleanup the training data collection system
 */
void training_data_cleanup(training_data_context_t* context) {
    if (context && context->samples) {
        free(context->samples);
        context->samples = NULL;
        context->sample_count = 0;
        context->max_samples = 0;
    }
}

/**
 * @brief Enable or disable training data collection
 */
void training_data_set_enabled(training_data_context_t* context, int enabled) {
    if (context) {
        context->collection_enabled = enabled ? 1 : 0;
    }
}

/**
 * @brief Get current number of collected samples
 */
size_t training_data_get_sample_count(training_data_context_t* context) {
    if (context) {
        return context->sample_count;
    }
    return 0;
}