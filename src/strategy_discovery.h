/**
 * @file strategy_discovery.h
 * @brief Novel strategy discovery module for ML Strategist
 * 
 * This header defines the functions for discovering new transformation strategies
 * using ML-based pattern analysis and genetic algorithm approaches.
 */

#ifndef STRATEGY_DISCOVERY_H
#define STRATEGY_DISCOVERY_H

#include <capstone/capstone.h>
#include "strategy.h"
#include "ml_strategist.h"

#ifdef __cplusplus
extern "C" {
#endif

// Maximum number of templates for strategy generation
#define MAX_STRATEGY_TEMPLATES 50
#define MAX_STRATEGY_NAME_LEN 64
#define MAX_INSTRUCTION_SEQUENCE 10

/**
 * @brief Structure representing a strategy template
 */
typedef struct {
    char name[MAX_STRATEGY_NAME_LEN];
    int instruction_type;                    // Type of instruction this handles
    int pattern_mask;                        // Mask defining the pattern to match
    int priority;                            // Default priority for new strategies
    int generation_count;                    // How many strategies have been generated from this template
} strategy_template_t;

/**
 * @brief Structure representing a discovered strategy
 */
typedef struct {
    strategy_t strategy;                      // The actual strategy
    char original_template[MAX_STRATEGY_NAME_LEN]; // Which template it was generated from
    double effectiveness_score;              // How effective it has been
    int usage_count;                         // How many times it has been used
    int success_count;                       // How many times it succeeded
} discovered_strategy_t;

/**
 * @brief Strategy discovery context
 */
typedef struct {
    strategy_template_t templates[MAX_STRATEGY_TEMPLATES];
    int template_count;
    discovered_strategy_t* discovered_strategies;
    int discovered_count;
    int max_discovered;
    ml_strategist_t* ml_strategist;         // Reference to ML strategist
    int enable_discovery;                    // Whether discovery is enabled
    double discovery_threshold;              // Minimum effectiveness score to consider a strategy
    int auto_register;                       // Whether to automatically register discovered strategies
} strategy_discovery_context_t;

/**
 * @brief Initialize the strategy discovery context
 * @param context Discovery context to initialize
 * @param ml_strategist Reference to the ML strategist
 * @return 0 on success, non-zero on failure
 */
int strategy_discovery_init(strategy_discovery_context_t* context, ml_strategist_t* ml_strategist);

/**
 * @brief Add a strategy template for the discovery system to use
 * @param context Discovery context
 * @param template The template to add
 * @return 0 on success, non-zero on failure
 */
int strategy_discovery_add_template(strategy_discovery_context_t* context, 
                                    strategy_template_t* template);

/**
 * @brief Discover new strategies based on successful patterns
 * @param context Discovery context
 * @param sample_data Training data to analyze for patterns
 * @return Number of new strategies discovered, negative on error
 */
int strategy_discovery_find_new_strategies(strategy_discovery_context_t* context,
                                           void* sample_data);

/**
 * @brief Generate a new strategy from an existing template
 * @param context Discovery context
 * @param template_name Name of the template to use
 * @param new_strategy Output for the new strategy
 * @return 0 on success, non-zero on failure
 */
int strategy_discovery_generate_strategy(strategy_discovery_context_t* context,
                                         const char* template_name,
                                         discovered_strategy_t* new_strategy);

/**
 * @brief Evaluate a newly discovered strategy
 * @param context Discovery context
 * @param strategy Strategy to evaluate
 * @param test_shellcode Shellcode to test the strategy on
 * @param test_size Size of test shellcode
 * @return Effectiveness score (0.0-1.0) or negative on error
 */
double strategy_discovery_evaluate_strategy(strategy_discovery_context_t* context,
                                           discovered_strategy_t* strategy,
                                           const uint8_t* test_shellcode,
                                           size_t test_size);

/**
 * @brief Register a discovered strategy in the main strategy registry
 * @param strategy The discovered strategy to register
 * @return 0 on success, non-zero on failure
 */
int strategy_discovery_register_strategy(discovered_strategy_t* strategy);

/**
 * @brief Analyze successful transformations to generate new strategy templates
 * @param context Discovery context
 * @param training_data Training data to analyze
 * @param data_count Number of training samples to analyze
 * @return 0 on success, non-zero on failure
 */
int strategy_discovery_analyze_patterns(strategy_discovery_context_t* context,
                                        void* training_data,
                                        int data_count);

/**
 * @brief Get statistics about discovery process
 * @param context Discovery context
 * @param total_templates Output for total templates
 * @param successful_strategies Output for successfully discovered strategies
 * @param registered_strategies Output for registered strategies
 * @return 0 on success, non-zero on failure
 */
int strategy_discovery_get_stats(strategy_discovery_context_t* context,
                                 int* total_templates,
                                 int* successful_strategies,
                                 int* registered_strategies);

/**
 * @brief Cleanup the strategy discovery context
 * @param context Discovery context to cleanup
 */
void strategy_discovery_cleanup(strategy_discovery_context_t* context);

/**
 * @brief Enable or disable strategy discovery
 * @param context Discovery context
 * @param enable Whether to enable (1) or disable (0) discovery
 */
void strategy_discovery_set_enabled(strategy_discovery_context_t* context, int enable);

#ifdef __cplusplus
}
#endif

#endif /* STRATEGY_DISCOVERY_H */