/**
 * @file evaluation_framework.h
 * @brief Evaluation and testing framework for ML Strategist
 * 
 * This header defines the functions for evaluating the ML model's performance,
 * testing the effectiveness of transformations, and validating the overall system.
 */

#ifndef EVALUATION_FRAMEWORK_H
#define EVALUATION_FRAMEWORK_H

#include <stdint.h>
#include <stddef.h>
#include "ml_strategist.h"
#include "strategy.h"
#include "training_data.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_TEST_CASES 1000
#define EVALUATION_REPORT_PATH "evaluation_report.txt"

/**
 * @brief Structure to represent an evaluation test case
 */
typedef struct {
    uint8_t original_shellcode[1024];        // Original shellcode
    size_t original_size;                    // Size of original shellcode
    uint8_t processed_shellcode[2048];       // Processed shellcode after transformation
    size_t processed_size;                   // Size of processed shellcode
    int nulls_before;                        // Number of null bytes in original
    int nulls_after;                         // Number of null bytes in processed
    int processing_success;                  // Whether processing was successful
    double processing_time;                  // Time taken for processing (seconds)
    strategy_t* applied_strategy;            // Strategy that was applied
    double ml_confidence;                    // ML model's confidence in recommendation
    char test_description[256];              // Description of the test case
} evaluation_case_t;

/**
 * @brief Evaluation metrics structure
 */
typedef struct {
    int total_test_cases;                    // Total test cases processed
    int successful_transformations;          // Cases where transformation was successful
    int failed_transformations;              // Cases where transformation failed
    int nulls_completely_eliminated;         // Cases where all nulls were eliminated
    double average_null_reduction_rate;      // Average percentage of nulls eliminated
    double average_ml_confidence;            // Average confidence of ML predictions
    double average_size_increase;            // Average size increase percentage
    double average_processing_time;          // Average time per transformation
    double overall_accuracy;                 // Overall accuracy rate
    int top_strategy_effectiveness[10];      // Effectiveness of top 10 strategies
} evaluation_metrics_t;

/**
 * @brief Evaluation configuration
 */
typedef struct {
    char test_shellcode_dir[256];            // Directory containing test shellcodes
    int run_performance_tests;               // Whether to run performance tests
    int run_correctness_tests;               // Whether to run correctness tests
    int run_ml_accuracy_tests;               // Whether to run ML accuracy tests
    int num_test_cases;                      // Number of test cases to run
    double train_test_split;                 // Train/test split ratio
    int verbose_output;                      // Verbose output level (0-2)
} evaluation_config_t;

/**
 * @brief Initialize evaluation configuration with defaults
 * @param config Configuration to initialize
 * @return 0 on success, non-zero on failure
 */
int evaluation_init_config(evaluation_config_t* config);

/**
 * @brief Run the complete evaluation suite
 * @param strategist ML strategist to evaluate
 * @param config Evaluation configuration
 * @param metrics Output metrics structure
 * @return 0 on success, non-zero on failure
 */
int evaluation_run_complete_suite(ml_strategist_t* strategist,
                                  evaluation_config_t* config,
                                  evaluation_metrics_t* metrics);

/**
 * @brief Run performance tests on the ML strategist
 * @param strategist ML strategist to test
 * @param config Evaluation configuration
 * @param metrics Output metrics structure
 * @return 0 on success, non-zero on failure
 */
int evaluation_run_performance_tests(ml_strategist_t* strategist,
                                     evaluation_config_t* config,
                                     evaluation_metrics_t* metrics);

/**
 * @brief Run correctness tests to verify functional preservation
 * @param strategist ML strategist to test
 * @param config Evaluation configuration
 * @param metrics Output metrics structure
 * @return 0 on success, non-zero on failure
 */
int evaluation_run_correctness_tests(ml_strategist_t* strategist,
                                     evaluation_config_t* config,
                                     evaluation_metrics_t* metrics);

/**
 * @brief Run ML accuracy tests to measure prediction quality
 * @param strategist ML strategist to test
 * @param config Evaluation configuration
 * @param metrics Output metrics structure
 * @return 0 on success, non-zero on failure
 */
int evaluation_run_ml_accuracy_tests(ml_strategist_t* strategist,
                                     evaluation_config_t* config,
                                     evaluation_metrics_t* metrics);

/**
 * @brief Load test cases from shellcode files
 * @param config Evaluation configuration
 * @param test_cases Array to store test cases
 * @param max_cases Maximum number of cases to load
 * @return Number of test cases loaded, negative on error
 */
int evaluation_load_test_cases(evaluation_config_t* config,
                               evaluation_case_t* test_cases,
                               int max_cases);

/**
 * @brief Evaluate a single test case
 * @param strategist ML strategist to use
 * @param test_case Test case to evaluate
 * @return 0 on success, non-zero on failure
 */
int evaluation_run_single_test(ml_strategist_t* strategist,
                               evaluation_case_t* test_case);

/**
 * @brief Calculate evaluation metrics from test results
 * @param test_cases Array of test cases
 * @param case_count Number of test cases
 * @param metrics Output metrics structure
 * @return 0 on success, non-zero on failure
 */
int evaluation_calculate_metrics(evaluation_case_t* test_cases,
                                 int case_count,
                                 evaluation_metrics_t* metrics);

/**
 * @brief Generate evaluation report
 * @param metrics Evaluation metrics
 * @param config Evaluation configuration
 * @param filepath Path to save the report
 * @return 0 on success, non-zero on failure
 */
int evaluation_generate_report(evaluation_metrics_t* metrics,
                               evaluation_config_t* config,
                               const char* filepath);

/**
 * @brief Compare ML-enhanced vs traditional approach
 * @param config Evaluation configuration
 * @param traditional_metrics Metrics for traditional approach
 * @param ml_enhanced_metrics Metrics for ML-enhanced approach
 * @return 0 on success, non-zero on failure
 */
int evaluation_compare_approaches(evaluation_config_t* config,
                                  evaluation_metrics_t* traditional_metrics,
                                  evaluation_metrics_t* ml_enhanced_metrics);

/**
 * @brief Run regression tests to ensure no functionality was broken
 * @param config Evaluation configuration
 * @return 0 on success, non-zero on failure
 */
int evaluation_run_regression_tests(evaluation_config_t* config);

#ifdef __cplusplus
}
#endif

#endif /* EVALUATION_FRAMEWORK_H */