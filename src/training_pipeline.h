/**
 * @file training_pipeline.h
 * @brief Training pipeline for ML Strategist
 * 
 * This header defines the functions for generating training data,
 * training the ML model, and managing the complete training pipeline.
 */

#ifndef TRAINING_PIPELINE_H
#define TRAINING_PIPELINE_H

#include <stdint.h>
#include <stddef.h>
#include "training_data.h"
#include "ml_strategist.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SHELLCODE_FILES 1000
#define MODEL_VERSION_SIZE 32

/**
 * @brief Training pipeline configuration
 */
typedef struct {
    char training_data_dir[256];              // Directory containing training shellcode files
    char model_output_path[256];              // Path to save trained model
    char model_version[MODEL_VERSION_SIZE];   // Version string for the model
    size_t max_training_samples;              // Maximum samples to use for training
    double validation_split;                  // Fraction of data to use for validation (0.0-1.0)
    int enable_augmentation;                  // Whether to enable data augmentation
    int epochs;                              // Number of training epochs
    double learning_rate;                    // Learning rate for training
    int batch_size;                          // Batch size for training
    int verbose;                             // Verbosity level (0-2)
} training_config_t;

/**
 * @brief Training statistics
 */
typedef struct {
    int total_samples;                       // Total samples processed
    int successful_transformations;          // Transformations that removed nulls
    int failed_transformations;              // Transformations that failed
    double average_strategy_confidence;      // Average confidence of ML predictions
    double null_elimination_rate;            // Rate of successful null elimination
    double model_accuracy;                   // Model accuracy on validation set
    double processing_time;                  // Total processing time in seconds
} training_stats_t;

/**
 * @brief Initialize the training configuration with defaults
 * @param config Configuration structure to initialize
 * @return 0 on success, non-zero on failure
 */
int training_pipeline_init_config(training_config_t* config);

/**
 * @brief Process shellcode files to generate training data
 * @param config Training configuration
 * @param data_context Training data context to store results
 * @return 0 on success, non-zero on failure
 */
int training_pipeline_generate_data(training_config_t* config,
                                    training_data_context_t* data_context);

/**
 * @brief Train the ML model using the collected data
 * @param config Training configuration
 * @param data_context Training data context with samples
 * @param strategist ML strategist to train
 * @return 0 on success, non-zero on failure
 */
int training_pipeline_train_model(training_config_t* config,
                                  training_data_context_t* data_context,
                                  ml_strategist_t* strategist);

/**
 * @brief Evaluate the trained model
 * @param strategist Trained ML strategist
 * @param data_context Validation data context
 * @param stats Output statistics structure
 * @return 0 on success, non-zero on failure
 */
int training_pipeline_evaluate_model(ml_strategist_t* strategist,
                                     training_data_context_t* data_context,
                                     training_stats_t* stats);

/**
 * @brief Execute the complete training pipeline
 * @param config Training configuration
 * @return 0 on success, non-zero on failure
 */
int training_pipeline_execute(training_config_t* config);

/**
 * @brief Perform data augmentation on training samples
 * @param data_context Training data context
 * @return Number of samples after augmentation, negative on error
 */
int training_pipeline_augment_data(training_data_context_t* data_context);

/**
 * @brief Load existing training data from multiple sources
 * @param config Training configuration
 * @param data_context Training data context to fill
 * @return 0 on success, non-zero on failure
 */
int training_pipeline_load_existing_data(training_config_t* config,
                                         training_data_context_t* data_context);

/**
 * @brief Validate the quality of training data
 * @param data_context Training data context to validate
 * @return 0 on success, non-zero on failure
 */
int training_pipeline_validate_data(training_data_context_t* data_context);

/**
 * @brief Save training statistics to file
 * @param stats Training statistics to save
 * @param filepath Path to save statistics file
 * @return 0 on success, non-zero on failure
 */
int training_pipeline_save_stats(training_stats_t* stats, const char* filepath);

#ifdef __cplusplus
}
#endif

#endif /* TRAINING_PIPELINE_H */