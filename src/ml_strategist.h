/**
 * @file ml_strategist.h
 * @brief ML-based shellcode strategist for byvalver
 * 
 * This header defines the interface for the ML-based strategist that
 * intelligently suggests, reprioritizes, and discovers novel null-byte 
 * elimination and obfuscation strategies.
 */

#ifndef ML_STRATEGIST_H
#define ML_STRATEGIST_H

#include <capstone/capstone.h>
#include "strategy.h"
#include "core.h"
#include "ml_metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

// Maximum number of features for instruction representation
#define MAX_INSTRUCTION_FEATURES 128
#define MAX_STRATEGY_COUNT 200

/**
 * @brief Structure to represent instruction features for ML model
 */
typedef struct {
    double features[MAX_INSTRUCTION_FEATURES];  // Feature vector
    int feature_count;                          // Number of active features
    int instruction_type;                       // Type of instruction (MOV, ADD, etc.)
    int has_nulls;                             // Whether instruction has null bytes
    int operand_types[4];                      // Types of operands
    int immediate_value;                       // Immediate value if present
    int register_indices[4];                   // Register indices if present
} instruction_features_t;

/**
 * @brief ML model prediction result
 */
typedef struct {
    strategy_t* recommended_strategy;           // Recommended strategy
    double confidence;                         // Confidence score (0.0-1.0)
    int strategy_ranking[MAX_STRATEGY_COUNT];  // Ranked list of strategy indices
    double strategy_scores[MAX_STRATEGY_COUNT]; // Scores for each strategy
    int strategy_count;                        // Number of strategies ranked
} ml_prediction_result_t;

/**
 * @brief ML Strategist context
 */
typedef struct {
    void* model;                               // ML model handle (implementation-specific)
    int initialized;                           // Whether the strategist is initialized
    char model_path[256];                      // Path to the ML model file
    int update_model;                          // Whether to update model based on results
} ml_strategist_t;

/**
 * @brief Initialize the ML strategist
 * @param strategist Pointer to the strategist context to initialize
 * @param model_path Path to the ML model file
 * @return 0 on success, non-zero on failure
 */
int ml_strategist_init(ml_strategist_t* strategist, const char* model_path);

/**
 * @brief Extract features from an instruction for ML model input
 * @param insn Capstone instruction to extract features from
 * @param features Output structure to fill with features
 * @return 0 on success, non-zero on failure
 */
int ml_extract_instruction_features(cs_insn* insn, instruction_features_t* features);

/**
 * @brief Get ML-based strategy recommendation for an instruction
 * @param strategist The ML strategist context
 * @param insn The instruction to analyze
 * @param prediction Output prediction result
 * @return 0 on success, non-zero on failure
 */
int ml_get_strategy_recommendation(ml_strategist_t* strategist, 
                                   cs_insn* insn, 
                                   ml_prediction_result_t* prediction);

/**
 * @brief Update strategy priorities based on ML model prediction
 * @param insn The instruction to analyze
 * @param applicable_strategies Array of applicable strategies
 * @param strategy_count Number of applicable strategies
 * @return 0 on success, non-zero on failure
 */
int ml_reprioritize_strategies(ml_strategist_t* strategist,
                               cs_insn* insn,
                               strategy_t** applicable_strategies,
                               int* strategy_count);

/**
 * @brief Discover and register new strategies based on ML model
 * @param strategist The ML strategist context
 * @return Number of new strategies discovered, negative on error
 */
int ml_discover_new_strategies(ml_strategist_t* strategist);

/**
 * @brief Provide feedback to improve ML model based on processing results
 * @param strategist The ML strategist context
 * @param original_insn Original instruction
 * @param applied_strategy Strategy that was applied
 * @param success Whether the strategy application was successful
 * @param new_shellcode_size Size of transformed shellcode
 * @return 0 on success, non-zero on failure
 */
int ml_provide_feedback(ml_strategist_t* strategist,
                        cs_insn* original_insn,
                        strategy_t* applied_strategy,
                        int success,
                        size_t new_shellcode_size);

/**
 * @brief Cleanup the ML strategist resources
 * @param strategist The ML strategist context to cleanup
 */
void ml_strategist_cleanup(ml_strategist_t* strategist);

/**
 * @brief Save updated model to file
 * @param strategist The ML strategist context
 * @param path Path to save the model to
 * @return 0 on success, non-zero on failure
 */
int ml_strategist_save_model(ml_strategist_t* strategist, const char* path);

/**
 * @brief Load model from file
 * @param strategist The ML strategist context
 * @param path Path from which to load the model
 * @return 0 on success, non-zero on failure
 */
int ml_strategist_load_model(ml_strategist_t* strategist, const char* path);

/**
 * @brief Export metrics in JSON format
 * @param filepath Path to save JSON export
 */
void ml_strategist_export_metrics_json(const char* filepath);

/**
 * @brief Export metrics in CSV format
 * @param filepath Path to save CSV export
 */
void ml_strategist_export_metrics_csv(const char* filepath);

/**
 * @brief Print live metrics stats
 */
void ml_strategist_print_live_metrics(void);

// Function to get reference to metrics tracker for other modules
ml_metrics_tracker_t* get_ml_metrics_tracker(void);

#ifdef __cplusplus
}
#endif

#endif /* ML_STRATEGIST_H */