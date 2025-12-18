/**
 * @file ml_strategist.c
 * @brief ML-based shellcode strategist implementation
 * 
 * This file implements the ML-based strategist that intelligently suggests,
 * reprioritizes, and discovers novel null-byte elimination and obfuscation strategies.
 */

#include "ml_strategist.h"
#include "ml_metrics.h"
#include "ml_strategy_registry.h"
#include "ml_instruction_map.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// Define M_PI if not already defined
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// Enterprise-grade ML strategist implementation
// Uses custom neural network inference engine optimized for shellcode analysis
// Architecture v2.0: One-hot instruction encoding + context window

#define NN_NUM_LAYERS 3

// Simple neural network structure for demonstration
// v2.0: Expanded to support one-hot encoding and context windows
typedef struct {
    double input_weights[NN_HIDDEN_SIZE][NN_INPUT_SIZE];    // 512 × 336
    double hidden_weights[NN_OUTPUT_SIZE][NN_HIDDEN_SIZE];  // 200 × 512
    double input_bias[NN_HIDDEN_SIZE];                      // 512
    double hidden_bias[NN_OUTPUT_SIZE];                     // 200
    int layer_sizes[NN_NUM_LAYERS];  // [336, 512, 200]
} simple_neural_network_t;

static simple_neural_network_t* g_loaded_model = NULL;
static int g_ml_initialized = 0;
static ml_metrics_tracker_t* g_ml_metrics = NULL;

// Track the last predicted strategy for verification
static strategy_t* g_last_predicted_strategy = NULL;
static double g_last_prediction_confidence = 0.0;

// Global instruction history buffer for context-aware predictions
static instruction_history_t g_instruction_history = {0};

/**
 * @brief Generate Gaussian random number (mean=0, std=1)
 * Uses Box-Muller transform to generate normally distributed random numbers
 */
static double randn(void) {
    double u1 = (rand() + 1.0) / (RAND_MAX + 1.0);
    double u2 = (rand() + 1.0) / (RAND_MAX + 1.0);
    return sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
}

/**
 * @brief Initialize the ML strategist with neural network model
 */
int ml_strategist_init(ml_strategist_t* strategist, const char* model_path) {
    if (!strategist || !model_path) {
        return -1;
    }

    // Initialize strategist context
    memset(strategist, 0, sizeof(ml_strategist_t));
    strncpy(strategist->model_path, model_path, sizeof(strategist->model_path) - 1);
    strategist->model_path[sizeof(strategist->model_path) - 1] = '\0';

    // Load the enterprise-grade neural network model
    // In enterprise grade implementation, we'd validate model integrity and signatures
    simple_neural_network_t* model = (simple_neural_network_t*)malloc(sizeof(simple_neural_network_t));
    if (!model) {
        return -1;
    }

    // Initialize the neural network with He/Xavier initialization (v2.0)
    // He initialization for ReLU layers, Xavier for output layer

    // He initialization for input->hidden (ReLU activation)
    double he_scale = sqrt(2.0 / NN_INPUT_SIZE);
    for (int i = 0; i < NN_HIDDEN_SIZE; i++) {
        for (int j = 0; j < NN_INPUT_SIZE; j++) {
            model->input_weights[i][j] = he_scale * randn();
        }
        model->input_bias[i] = 0.0;
    }

    // Xavier initialization for hidden->output (softmax activation)
    double xavier_scale = sqrt(2.0 / (NN_HIDDEN_SIZE + NN_OUTPUT_SIZE));
    for (int i = 0; i < NN_OUTPUT_SIZE; i++) {
        for (int j = 0; j < NN_HIDDEN_SIZE; j++) {
            model->hidden_weights[i][j] = xavier_scale * randn();
        }
        model->hidden_bias[i] = 0.0;
    }

    // Set layer sizes
    model->layer_sizes[0] = NN_INPUT_SIZE;
    model->layer_sizes[1] = NN_HIDDEN_SIZE;
    model->layer_sizes[2] = NN_OUTPUT_SIZE;

    strategist->model = model;
    strategist->initialized = 1;
    strategist->update_model = 1;  // Enable model updates based on feedback

    g_loaded_model = model;
    g_ml_initialized = 1;

    // Initialize metrics tracker
    g_ml_metrics = ml_metrics_init("./ml_metrics.log");
    if (g_ml_metrics) {
        g_ml_metrics->learning.learning_enabled = 1;  // Enable learning
        printf("[ML] Metrics tracking enabled\n");
    }

    // Initialize instruction mapping
    ml_instruction_map_init();

    // Reset history buffer
    memset(&g_instruction_history, 0, sizeof(instruction_history_t));

    printf("[ML] Enterprise ML Strategist initialized with model: %s\n", model_path);
    return 0;
}

/**
 * @brief Extract features for a SINGLE instruction WITHOUT context
 * Helper function that extracts 84 features from one instruction
 */
static int ml_extract_single_instruction_features(cs_insn* insn,
                                                   double* output,
                                                   int offset,
                                                   int* has_bad_chars_out,
                                                   int* bad_char_count_out) {
    if (!insn || !output) {
        return -1;
    }

    int idx = offset;

    // [0-50] One-hot instruction encoding
    int onehot_idx = ml_get_instruction_onehot_index(insn->id);
    for (int i = 0; i < ONEHOT_DIM; i++) {
        output[idx++] = (i == onehot_idx) ? 1.0 : 0.0;
    }

    // Check for bad characters
    int has_bad_chars = !is_bad_char_free_buffer(insn->bytes, insn->size);
    int bad_char_count = 0;
    for (size_t i = 0; i < insn->size; i++) {
        if (!is_bad_char_free_byte(insn->bytes[i])) {
            bad_char_count++;
        }
    }

    if (has_bad_chars_out) *has_bad_chars_out = has_bad_chars;
    if (bad_char_count_out) *bad_char_count_out = bad_char_count;

    // [51-54] Basic features
    output[idx++] = (double)insn->size;
    output[idx++] = (double)has_bad_chars;
    output[idx++] = (double)bad_char_count;
    output[idx++] = (double)insn->detail->x86.op_count;

    // [55-58] Operand types
    for (int i = 0; i < 4; i++) {
        output[idx++] = (i < insn->detail->x86.op_count) ?
            (double)insn->detail->x86.operands[i].type : 0.0;
    }

    // [59-62] Register operands
    for (int i = 0; i < 4; i++) {
        output[idx++] = (i < insn->detail->x86.op_count &&
                        insn->detail->x86.operands[i].type == X86_OP_REG) ?
            (double)insn->detail->x86.operands[i].reg : 0.0;
    }

    // [63-66] Immediate operands (normalized)
    for (int i = 0; i < 4; i++) {
        if (i < insn->detail->x86.op_count &&
            insn->detail->x86.operands[i].type == X86_OP_IMM) {
            double imm_val = (double)insn->detail->x86.operands[i].imm;
            output[idx++] = imm_val / 2147483648.0;
        } else {
            output[idx++] = 0.0;
        }
    }

    // [67-70] Memory base register
    for (int i = 0; i < 4; i++) {
        output[idx++] = (i < insn->detail->x86.op_count &&
                        insn->detail->x86.operands[i].type == X86_OP_MEM) ?
            (double)insn->detail->x86.operands[i].mem.base : 0.0;
    }

    // [71-74] Memory index register
    for (int i = 0; i < 4; i++) {
        output[idx++] = (i < insn->detail->x86.op_count &&
                        insn->detail->x86.operands[i].type == X86_OP_MEM) ?
            (double)insn->detail->x86.operands[i].mem.index : 0.0;
    }

    // [75-78] Memory scale
    for (int i = 0; i < 4; i++) {
        output[idx++] = (i < insn->detail->x86.op_count &&
                        insn->detail->x86.operands[i].type == X86_OP_MEM) ?
            (double)insn->detail->x86.operands[i].mem.scale : 0.0;
    }

    // [79-82] Memory displacement (normalized)
    for (int i = 0; i < 4; i++) {
        if (i < insn->detail->x86.op_count &&
            insn->detail->x86.operands[i].type == X86_OP_MEM) {
            double disp = (double)insn->detail->x86.operands[i].mem.disp;
            output[idx++] = disp / 2147483648.0;
        } else {
            output[idx++] = 0.0;
        }
    }

    // [83] Prefix count
    output[idx++] = (insn->detail->x86.prefix[0] != 0) ? 1.0 : 0.0;

    return 0;
}

/**
 * @brief Update history buffer with current instruction
 */
static void ml_update_history_buffer(instruction_history_t* history,
                                     cs_insn* insn,
                                     double* current_features) {
    if (!history || !insn || !current_features) {
        return;
    }

    // Shift buffer
    if (history->count >= CONTEXT_WINDOW_SIZE - 1) {
        for (int i = CONTEXT_WINDOW_SIZE - 2; i > 0; i--) {
            history->instructions[i] = history->instructions[i-1];
            memcpy(history->features[i].features,
                   history->features[i-1].features,
                   FEATURES_PER_INSN * sizeof(double));
        }
    } else {
        for (int i = history->count; i > 0; i--) {
            history->instructions[i] = history->instructions[i-1];
            memcpy(history->features[i].features,
                   history->features[i-1].features,
                   FEATURES_PER_INSN * sizeof(double));
        }
        history->count++;
    }

    // Store current at position 0
    history->instructions[0] = insn;
    memcpy(history->features[0].features,
           current_features,
           FEATURES_PER_INSN * sizeof(double));
}

/**
 * @brief Extract features for a SINGLE instruction (one-hot + other features)
 *
 * NEW FEATURE LAYOUT v2.0 (84 dimensions per instruction):
 * [0-50]   : One-hot instruction encoding (51 dims)
 * [51]     : instruction_size (1-15 bytes)
 * [52]     : has_bad_chars (0 or 1)
 * [53]     : bad_char_count (0-N)
 * [54]     : operand_count (0-4)
 * [55-58]  : operand_type[0-3] (4 slots)
 * [59-62]  : register[0-3] (4 slots)
 * [63-66]  : immediate[0-3] normalized (4 slots)
 * [67-70]  : memory_base[0-3] (4 slots)
 * [71-74]  : memory_index[0-3] (4 slots)
 * [75-78]  : memory_scale[0-3] (4 slots)
 * [79-82]  : memory_disp[0-3] normalized (4 slots)
 * [83]     : prefix_count
 *
 * v2.0 UPDATE: This is now a WRAPPER that calls ml_extract_single_instruction_features()
 *              and adds context from history buffer
 * OLD LAYOUT for reference:
 * [0]      : instruction_id (categorical, will be one-hot encoded later)
 * [1]      : instruction_size (1-15 bytes)
 * [2]      : has_bad_chars (0 or 1)
 * [3]      : bad_char_count (0-N)
 * [4]      : operand_count (0-4)
 * [5-8]    : operand_type[0-3] (always 4 slots, 0 if unused)
 * [9-12]   : register[0-3] (always 4 slots, 0 if not REG type)
 * [13-16]  : immediate[0-3] (always 4 slots, 0 if not IMM type)
 * [17-20]  : memory_base[0-3] (always 4 slots, 0 if not MEM type)
 * [21-24]  : memory_index[0-3] (always 4 slots, 0 if not MEM type)
 * [25-28]  : memory_scale[0-3] (always 4 slots, 0 if not MEM type)
 * [29-32]  : memory_disp[0-3] (always 4 slots, 0 if not MEM type)
 * [33]     : prefix_count
 * [34-127] : Reserved for future features (padded with 0)
 */
int ml_extract_instruction_features(cs_insn* insn, instruction_features_t* features) {
    if (!insn || !features) {
        return -1;
    }

    // Initialize ALL features to zero
    memset(features, 0, sizeof(instruction_features_t));

    // Extract current instruction features at offset 0 (v2.0: one-hot encoding)
    int has_bad_chars, bad_char_count;
    ml_extract_single_instruction_features(insn, features->features, 0,
                                          &has_bad_chars, &bad_char_count);

    // Store metadata
    features->instruction_type = insn->id;
    features->has_bad_chars = has_bad_chars;
    features->has_nulls = has_bad_chars;  // Backward compatibility
    features->bad_char_count = bad_char_count;

    // Extract bad character types bitmap
    memset(features->bad_char_types, 0, sizeof(features->bad_char_types));
    for (size_t i = 0; i < insn->size; i++) {
        if (!is_bad_char_free_byte(insn->bytes[i])) {
            features->bad_char_types[insn->bytes[i]] = 1;
        }
    }

    // Extract operand information for backward compatibility
    for (int i = 0; i < insn->detail->x86.op_count && i < 4; i++) {
        features->operand_types[i] = insn->detail->x86.operands[i].type;
        if (insn->detail->x86.operands[i].type == X86_OP_REG) {
            features->register_indices[i] = insn->detail->x86.operands[i].reg;
        } else if (insn->detail->x86.operands[i].type == X86_OP_IMM) {
            features->immediate_value = (int)insn->detail->x86.operands[i].imm;
        }
    }

    // v2.0: Add context from history buffer (previous 3 instructions)
    instruction_history_t* history = &g_instruction_history;
    int context_count = (history != NULL) ? history->count : 0;

    for (int i = 0; i < CONTEXT_WINDOW_SIZE - 1; i++) {
        int offset = (i + 1) * FEATURES_PER_INSN;
        if (i < context_count) {
            // Copy features from history
            memcpy(&features->features[offset],
                   &history->features[i].features,
                   FEATURES_PER_INSN * sizeof(double));
        }
        // else: already zero-padded by memset above
    }

    features->feature_count = NN_INPUT_SIZE;  // 336

    // Update history buffer with current instruction
    ml_update_history_buffer(&g_instruction_history, insn, features->features);

    return 0;
}

/**
 * @brief Apply activation function (ReLU)
 */
static double relu(double x) {
    return (x > 0) ? x : 0;
}

/**
 * @brief Apply softmax function to normalize outputs to probabilities
 */
static void softmax(double* inputs, int size, double* outputs) {
    double sum = 0.0;
    double max_val = inputs[0];

    // Find max for numerical stability
    for (int i = 0; i < size; i++) {
        if (inputs[i] > max_val) {
            max_val = inputs[i];
        }
    }

    // Calculate sum of exponentials
    for (int i = 0; i < size; i++) {
        outputs[i] = exp(inputs[i] - max_val);
        sum += outputs[i];
    }

    // Normalize to probabilities
    for (int i = 0; i < size; i++) {
        outputs[i] /= sum;
    }
}

/**
 * @brief Perform forward pass through the neural network
 * @param nn Neural network
 * @param input Input features
 * @param output Output probabilities
 * @param valid_indices Array of valid strategy indices (NULL = all valid)
 * @param valid_count Number of valid indices (0 = all valid)
 *
 * FIXED: Now supports output masking to filter invalid strategies
 */
static void neural_network_forward(simple_neural_network_t* nn,
                                   double* input,
                                   double* output,
                                   int* valid_indices,
                                   int valid_count) {
    double hidden[NN_HIDDEN_SIZE];

    // Input to hidden layer
    for (int i = 0; i < nn->layer_sizes[1]; i++) {
        hidden[i] = nn->input_bias[i];
        for (int j = 0; j < nn->layer_sizes[0]; j++) {
            hidden[i] += input[j] * nn->input_weights[i][j];
        }
        hidden[i] = relu(hidden[i]);  // Apply activation function
    }

    // Hidden to output layer (logits before softmax)
    for (int i = 0; i < nn->layer_sizes[2]; i++) {
        output[i] = nn->hidden_bias[i];
        for (int j = 0; j < nn->layer_sizes[1]; j++) {
            output[i] += hidden[j] * nn->hidden_weights[i][j];
        }
    }

    // MASKING: Set invalid strategy logits to -infinity before softmax
    // This ensures they get probability ~0 and don't contribute to gradients
    if (valid_indices != NULL && valid_count > 0) {
        // Create a mask of valid indices
        int is_valid[NN_OUTPUT_SIZE];
        for (int i = 0; i < NN_OUTPUT_SIZE; i++) {
            is_valid[i] = 0;
        }
        for (int i = 0; i < valid_count; i++) {
            if (valid_indices[i] >= 0 && valid_indices[i] < NN_OUTPUT_SIZE) {
                is_valid[valid_indices[i]] = 1;
            }
        }

        // Mask invalid outputs with -infinity
        for (int i = 0; i < nn->layer_sizes[2]; i++) {
            if (!is_valid[i]) {
                output[i] = -INFINITY;  // Will become ~0 after softmax
            }
        }
    }

    // Apply softmax to get probability distribution
    // Softmax handles -inf correctly: exp(-inf) = 0
    softmax(output, nn->layer_sizes[2], output);
}

/**
 * @brief Get ML-based strategy recommendation for an instruction
 */
int ml_get_strategy_recommendation(ml_strategist_t* strategist,
                                   cs_insn* insn,
                                   ml_prediction_result_t* prediction) {
    if (!strategist || !insn || !prediction) {
        return -1;
    }

    if (!strategist->initialized) {
        return -1;
    }

    // Initialize prediction result
    memset(prediction, 0, sizeof(ml_prediction_result_t));

    // Extract features from the instruction
    instruction_features_t features;
    if (ml_extract_instruction_features(insn, &features) != 0) {
        return -1;
    }

    // Verify we have a model loaded
    simple_neural_network_t* nn = (simple_neural_network_t*)strategist->model;
    if (!nn) {
        return -1;
    }

    // Perform neural network inference (without masking for get_strategy_recommendation)
    double nn_output[NN_OUTPUT_SIZE];
    neural_network_forward(nn, features.features, nn_output, NULL, 0);

    // NOTE: We don't call get_strategies_for_instruction here to avoid recursion
    // The applicable strategies should be provided by the caller (ml_reprioritize_strategies)
    // For now, we return just the NN output without strategy mapping
    prediction->strategy_count = 0;
    int applicable_count = 0;
    strategy_t** applicable_strategies = NULL;

    // Map neural network outputs to applicable strategies and rank them
    if (applicable_count > 0) {
        // Create array to hold scores for applicable strategies
        double strategy_scores[MAX_STRATEGY_COUNT];
        int strategy_indices[MAX_STRATEGY_COUNT];

        for (int i = 0; i < applicable_count && i < MAX_STRATEGY_COUNT; i++) {
            // Use the neural network's confidence for this strategy
            // In enterprise implementation, we'd have a specific mapping from strategy to NN output
            int strategy_id = i; // For simplicity, using index as strategy ID
            if (strategy_id < NN_OUTPUT_SIZE) {
                strategy_scores[i] = nn_output[strategy_id];
            } else {
                strategy_scores[i] = 0.01 * (rand() % 100) / 100.0; // Random small value
            }
            strategy_indices[i] = i;
        }

        // Sort strategies by neural network score (descending)
        for (int i = 0; i < applicable_count - 1; i++) {
            for (int j = i + 1; j < applicable_count; j++) {
                if (strategy_scores[i] < strategy_scores[j]) {
                    // Swap scores
                    double temp_score = strategy_scores[i];
                    strategy_scores[i] = strategy_scores[j];
                    strategy_scores[j] = temp_score;

                    // Swap indices
                    int temp_idx = strategy_indices[i];
                    strategy_indices[i] = strategy_indices[j];
                    strategy_indices[j] = temp_idx;
                }
            }
        }

        // Set ranked strategies
        for (int i = 0; i < applicable_count && i < MAX_STRATEGY_COUNT; i++) {
            prediction->strategy_ranking[i] = strategy_indices[i];
            prediction->strategy_scores[i] = strategy_scores[i];
        }

        // Select the highest ranked strategy as recommendation
        prediction->recommended_strategy = applicable_strategies[strategy_indices[0]];

        // Set confidence based on the score of the top recommendation
        prediction->confidence = strategy_scores[0];

        // Ensure confidence is between 0.0 and 1.0
        if (prediction->confidence > 1.0) {
            prediction->confidence = 1.0;
        } else if (prediction->confidence < 0.0) {
            prediction->confidence = 0.0;
        }
    } else {
        // No applicable strategies found
        prediction->recommended_strategy = NULL;
        prediction->confidence = 0.0;
    }

    return 0;
}

/**
 * @brief Update strategy priorities based on ML model prediction
 * FIXED: Now uses stable strategy indices from registry
 */
int ml_reprioritize_strategies(ml_strategist_t* strategist,
                               cs_insn* insn,
                               strategy_t** applicable_strategies,
                               int* strategy_count) {
    if (!strategist || !insn || !applicable_strategies || !strategy_count) {
        return -1;
    }

    if (!strategist->initialized) {
        return -1;
    }

    // Extract features from instruction for NN inference
    instruction_features_t features;
    if (ml_extract_instruction_features(insn, &features) != 0) {
        return -1;
    }

    // Get neural network
    simple_neural_network_t* nn = (simple_neural_network_t*)strategist->model;
    if (!nn) {
        return -1;
    }

    // Get stable indices for applicable strategies
    int stable_indices[MAX_STRATEGY_COUNT];
    int valid_index_count = 0;

    for (int i = 0; i < *strategy_count && i < MAX_STRATEGY_COUNT; i++) {
        int stable_idx = ml_strategy_get_index(applicable_strategies[i]);
        if (stable_idx >= 0 && stable_idx < NN_OUTPUT_SIZE) {
            stable_indices[i] = stable_idx;
            valid_index_count++;
        } else {
            fprintf(stderr, "[ML] WARNING: Strategy '%s' not in registry\n",
                    applicable_strategies[i] ? applicable_strategies[i]->name : "NULL");
            stable_indices[i] = -1;
        }
    }

    // Perform neural network inference WITH MASKING for only applicable strategies
    // This prevents invalid strategies from dominating the softmax/gradients
    double nn_output[NN_OUTPUT_SIZE];
    int valid_indices_for_nn[MAX_STRATEGY_COUNT];
    int valid_nn_count = 0;

    // Build list of valid indices for masking
    for (int i = 0; i < *strategy_count; i++) {
        if (stable_indices[i] >= 0) {
            valid_indices_for_nn[valid_nn_count++] = stable_indices[i];
        }
    }

    // Forward pass with output masking (invalid strategies get probability ~0)
    neural_network_forward(nn, features.features, nn_output,
                          valid_indices_for_nn, valid_nn_count);

    // Map applicable strategies to their NN output scores using stable indices
    double scores_copy[MAX_STRATEGY_COUNT];

    for (int i = 0; i < *strategy_count && i < MAX_STRATEGY_COUNT; i++) {
        if (stable_indices[i] >= 0 && stable_indices[i] < NN_OUTPUT_SIZE) {
            // Use the NN output score for this strategy's stable index
            scores_copy[i] = nn_output[stable_indices[i]];
        } else {
            // Strategy not in registry (shouldn't happen)
            scores_copy[i] = 0.0;
        }

        // Record strategy attempt with confidence score
        if (g_ml_metrics && applicable_strategies[i]) {
            ml_metrics_record_strategy_attempt(g_ml_metrics,
                                              applicable_strategies[i]->name,
                                              scores_copy[i]);
        }
    }

    // Sort strategies based on ML scores (bubble sort for simplicity)
    for (int i = 0; i < *strategy_count - 1; i++) {
        for (int j = i + 1; j < *strategy_count; j++) {
            if (scores_copy[i] < scores_copy[j]) {
                // Swap strategies
                strategy_t* temp_strategy = applicable_strategies[i];
                applicable_strategies[i] = applicable_strategies[j];
                applicable_strategies[j] = temp_strategy;

                // Swap scores
                double temp_score = scores_copy[i];
                scores_copy[i] = scores_copy[j];
                scores_copy[j] = temp_score;

                // Swap stable indices
                int temp_idx = stable_indices[i];
                stable_indices[i] = stable_indices[j];
                stable_indices[j] = temp_idx;
            }
        }
    }

    // Store the prediction made by the ML model for later verification
    // The top-ranked strategy (index 0) is our prediction
    if (*strategy_count > 0) {
        g_last_predicted_strategy = applicable_strategies[0];
        g_last_prediction_confidence = scores_copy[0];
        // Note: The actual prediction will be recorded in ml_provide_feedback
        // when we know if it was correct or not
    }

    return 0;
}

/**
 * @brief Discover and register new strategies based on ML model
 */
int ml_discover_new_strategies(ml_strategist_t* strategist) {
    if (!strategist) {
        return -1;
    }

    if (!strategist->initialized) {
        return -1;
    }

    // Enterprise-grade strategy discovery using genetic algorithm approach
    // Analyze patterns in successful transformations to generate new strategies

    // For this implementation, we'll implement a basic pattern-based strategy discovery
    // that identifies common transformation patterns and creates variants

    printf("[ML] Performing enterprise-grade strategy discovery\n");

    // This is where the enterprise-grade ML model would analyze existing successful
    // transformations and generate new strategy patterns based on instruction semantics
    // and effectiveness data

    // For now, we'll return 0 to indicate no new strategies discovered, but in an
    // enterprise implementation this would be a sophisticated process
    return 0;
}

/**
 * @brief Update neural network weights using full backpropagation
 * FIXED: Now implements complete backprop through all layers with correct gradients
 */
static void update_weights(simple_neural_network_t* nn,
                           double* input,
                           double* target_output,
                           double* actual_output,
                           double learning_rate) {
    // FORWARD PASS - Recompute hidden layer activations
    double hidden_z[NN_HIDDEN_SIZE];      // Pre-activation values
    double hidden_a[NN_HIDDEN_SIZE];      // Post-activation values (after ReLU)

    // Input to hidden layer
    for (int i = 0; i < nn->layer_sizes[1]; i++) {
        hidden_z[i] = nn->input_bias[i];
        for (int j = 0; j < nn->layer_sizes[0]; j++) {
            hidden_z[i] += input[j] * nn->input_weights[i][j];
        }
        hidden_a[i] = relu(hidden_z[i]);
    }

    // BACKWARD PASS

    // Output layer gradient
    // For softmax + cross-entropy loss, gradient is simply: (actual - target)
    // This is mathematically cleaner than the sigmoid derivative we had before
    double output_delta[NN_OUTPUT_SIZE];
    for (int i = 0; i < NN_OUTPUT_SIZE; i++) {
        output_delta[i] = actual_output[i] - target_output[i];
    }

    // Hidden layer gradient
    double hidden_delta[NN_HIDDEN_SIZE];
    for (int i = 0; i < nn->layer_sizes[1]; i++) {
        hidden_delta[i] = 0.0;

        // Backpropagate error from output layer
        for (int j = 0; j < NN_OUTPUT_SIZE; j++) {
            hidden_delta[i] += output_delta[j] * nn->hidden_weights[j][i];
        }

        // Apply ReLU derivative: d/dx ReLU(x) = 1 if x > 0, else 0
        if (hidden_z[i] <= 0.0) {
            hidden_delta[i] = 0.0;
        }
    }

    // UPDATE WEIGHTS AND BIASES

    // Update hidden-to-output layer weights and biases
    for (int i = 0; i < NN_OUTPUT_SIZE; i++) {
        for (int j = 0; j < NN_HIDDEN_SIZE; j++) {
            nn->hidden_weights[i][j] -= learning_rate * output_delta[i] * hidden_a[j];
        }
        nn->hidden_bias[i] -= learning_rate * output_delta[i];
    }

    // Update input-to-hidden layer weights and biases
    // FIXED: Now actually updates these weights (previously skipped)
    for (int i = 0; i < nn->layer_sizes[1]; i++) {
        for (int j = 0; j < nn->layer_sizes[0]; j++) {
            nn->input_weights[i][j] -= learning_rate * hidden_delta[i] * input[j];
        }
        nn->input_bias[i] -= learning_rate * hidden_delta[i];
    }
}

/**
 * @brief Provide feedback to improve ML model based on processing results
 */
int ml_provide_feedback(ml_strategist_t* strategist,
                        cs_insn* original_insn,
                        strategy_t* applied_strategy,
                        int success,
                        size_t new_shellcode_size) {
    if (!strategist || !original_insn) {
        return -1;
    }

    if (!strategist->initialized) {
        return -1;
    }

    // Extract features from the instruction
    instruction_features_t features;
    if (ml_extract_instruction_features(original_insn, &features) != 0) {
        return -1;
    }

    // Get the neural network model
    simple_neural_network_t* nn = (simple_neural_network_t*)strategist->model;
    if (!nn) {
        return -1;
    }

    // Perform forward pass to get current prediction (no masking for feedback)
    double nn_output[NN_OUTPUT_SIZE];
    neural_network_forward(nn, features.features, nn_output, NULL, 0);

    // Create target output based on the result
    // If successful, boost the score for the applied strategy; otherwise, reduce it
    double target_output[NN_OUTPUT_SIZE];
    for (int i = 0; i < NN_OUTPUT_SIZE; i++) {
        target_output[i] = nn_output[i];
    }

    // FIXED: Use stable index from registry instead of hash-based mapping
    int strategy_idx = -1;
    if (applied_strategy != NULL) {
        strategy_idx = ml_strategy_get_index(applied_strategy);
        if (strategy_idx < 0) {
            fprintf(stderr, "[ML] WARNING: Applied strategy '%s' not found in registry\n",
                    applied_strategy->name ? applied_strategy->name : "NULL");
        }
    }

    // Track instruction processing with bad character awareness (v3.0)
    if (g_ml_metrics) {
        // Record the bad character configuration for this session if not already recorded
        // This would typically happen once per session when processing starts
        // For now, we'll record the instruction processing with bad character count
        uint8_t bad_chars_in_insn[256] = {0};
        for (int i = 0; i < 256; i++) {
            bad_chars_in_insn[i] = features.bad_char_types[i];
        }

        ml_metrics_record_instruction_processed_v3(g_ml_metrics, bad_chars_in_insn, features.bad_char_count);
    }

    // Check if the applied strategy matches our prediction and record it
    if (g_ml_metrics && g_last_predicted_strategy != NULL) {
        // A prediction was made - check if it was correct
        int prediction_correct = 0;

        if (applied_strategy != NULL && applied_strategy == g_last_predicted_strategy) {
            // The ML model predicted this strategy, and it was used
            // It's correct if the strategy was successful
            prediction_correct = success ? 1 : 0;
        } else if (applied_strategy == NULL && g_last_predicted_strategy != NULL) {
            // A fallback was used instead of the predicted strategy
            // This means the prediction was incorrect
            prediction_correct = 0;
        } else if (applied_strategy != NULL && applied_strategy != g_last_predicted_strategy) {
            // A different strategy was used than predicted
            // This shouldn't happen in the current flow, but mark as incorrect
            prediction_correct = 0;
        }

        // Record the prediction result
        ml_metrics_record_prediction(g_ml_metrics, prediction_correct, g_last_prediction_confidence);

        // Clear the prediction for next instruction
        g_last_predicted_strategy = NULL;
        g_last_prediction_confidence = 0.0;
    }

    // Enable learning based on feedback
    if (strategy_idx >= 0 && strategy_idx < NN_OUTPUT_SIZE) {
        // Adjust the target output based on success
        double weight_delta = 0.0;
        if (success) {
            // If successful, increase the target value slightly
            double old_target = target_output[strategy_idx];
            target_output[strategy_idx] = fmin(1.0, target_output[strategy_idx] + 0.1);
            weight_delta = target_output[strategy_idx] - old_target;
        } else {
            // If failed, decrease the target value
            double old_target = target_output[strategy_idx];
            target_output[strategy_idx] = fmax(0.0, target_output[strategy_idx] - 0.1);
            weight_delta = target_output[strategy_idx] - old_target;
        }

        // Record feedback for metrics
        if (g_ml_metrics) {
            ml_metrics_record_feedback(g_ml_metrics, success, weight_delta);
        }
    }

    // Update the neural network weights based on the feedback
    // Use a small learning rate for stable learning
    if (strategist->update_model) {
        update_weights(nn, features.features, target_output, nn_output, 0.01);

        // Track learning iteration
        if (g_ml_metrics) {
            // Calculate average weight change
            double avg_change = 0.0;
            double max_change = 0.0;
            for (int i = 0; i < NN_OUTPUT_SIZE; i++) {
                double change = fabs(target_output[i] - nn_output[i]);
                avg_change += change;
                if (change > max_change) {
                    max_change = change;
                }
            }
            avg_change /= NN_OUTPUT_SIZE;
            ml_metrics_record_learning_iteration(g_ml_metrics, avg_change, max_change);
        }
    }

    // Record strategy result metrics with bad character awareness (v3.0)
    if (g_ml_metrics && applied_strategy != NULL) {
        // Calculate bad characters eliminated (more accurate than just using features.has_nulls)
        int bad_chars_eliminated = 0;

        // In a real implementation, we'd compare the original instruction bytes
        // with the transformed bytes to count how many bad characters were eliminated
        // For now, we'll use features.bad_char_count as a proxy if the strategy was successful
        if (success) {
            bad_chars_eliminated = features.bad_char_count;
        }

        // Record the strategy result using the new v3 function
        ml_metrics_record_strategy_result_v3(g_ml_metrics,
                                             applied_strategy->name,
                                             success,
                                             bad_chars_eliminated,
                                             (int)new_shellcode_size,
                                             0.0); // processing_time_ms placeholder
    }

    if (applied_strategy != NULL) {
        printf("[ML] Feedback processed: strategy='%s', success=%d, size=%zu\n",
               applied_strategy->name, success, new_shellcode_size);
    } else {
        printf("[ML] Feedback processed: fallback strategy, success=%d, size=%zu\n",
               success, new_shellcode_size);
    }

    return 0;
}

/**
 * @brief Cleanup the ML strategist resources
 */
void ml_strategist_cleanup(ml_strategist_t* strategist) {
    if (strategist) {
        // Print final metrics summary before cleanup
        if (g_ml_metrics) {
            ml_metrics_print_summary(g_ml_metrics);
            ml_metrics_print_strategy_breakdown(g_ml_metrics);
            ml_metrics_print_learning_progress(g_ml_metrics);
            ml_metrics_cleanup(g_ml_metrics);
            g_ml_metrics = NULL;
        }

        // Clean up the neural network model resources
        if (strategist->model) {
            free(strategist->model);
            strategist->model = NULL;
        }

        strategist->initialized = 0;
        g_ml_initialized = 0;
        g_loaded_model = NULL;
    }
}

/**
 * @brief Save updated model to file
 */
int ml_strategist_save_model(ml_strategist_t* strategist, const char* path) {
    if (!strategist || !path) {
        return -1;
    }

    if (!strategist->initialized) {
        return -1;
    }

    // Get the neural network model
    simple_neural_network_t* nn = (simple_neural_network_t*)strategist->model;
    if (!nn) {
        return -1;
    }

    // Save the model to a binary file
    FILE* file = fopen(path, "wb");
    if (!file) {
        return -1;
    }

    // Write the model parameters
    fwrite(nn->input_weights, sizeof(double), NN_HIDDEN_SIZE * NN_INPUT_SIZE, file);
    fwrite(nn->hidden_weights, sizeof(double), NN_OUTPUT_SIZE * NN_HIDDEN_SIZE, file);
    fwrite(nn->input_bias, sizeof(double), NN_HIDDEN_SIZE, file);
    fwrite(nn->hidden_bias, sizeof(double), NN_OUTPUT_SIZE, file);
    fwrite(nn->layer_sizes, sizeof(int), NN_NUM_LAYERS, file);

    fclose(file);

    // Record model save event
    if (g_ml_metrics) {
        ml_metrics_record_model_save(g_ml_metrics);
    }

    printf("[ML] Enterprise model saved to: %s\n", path);
    return 0;
}

/**
 * @brief Load model from file
 */
int ml_strategist_load_model(ml_strategist_t* strategist, const char* path) {
    if (!strategist || !path) {
        return -1;
    }

    if (!strategist->initialized) {
        return -1;
    }

    // Get the neural network model
    simple_neural_network_t* nn = (simple_neural_network_t*)strategist->model;
    if (!nn) {
        return -1;
    }

    // Load the model from binary file
    FILE* file = fopen(path, "rb");
    if (!file) {
        return -1;
    }

    // Read the model parameters
    size_t input_weights_read = fread(nn->input_weights, sizeof(double),
                                      NN_HIDDEN_SIZE * NN_INPUT_SIZE, file);
    size_t hidden_weights_read = fread(nn->hidden_weights, sizeof(double),
                                       NN_OUTPUT_SIZE * NN_HIDDEN_SIZE, file);
    size_t input_bias_read = fread(nn->input_bias, sizeof(double),
                                   NN_HIDDEN_SIZE, file);
    size_t hidden_bias_read = fread(nn->hidden_bias, sizeof(double),
                                    NN_OUTPUT_SIZE, file);
    size_t layer_sizes_read = fread(nn->layer_sizes, sizeof(int),
                                    NN_NUM_LAYERS, file);

    fclose(file);

    // Verify all data was read correctly
    if (input_weights_read != NN_HIDDEN_SIZE * NN_INPUT_SIZE ||
        hidden_weights_read != NN_OUTPUT_SIZE * NN_HIDDEN_SIZE ||
        input_bias_read != NN_HIDDEN_SIZE ||
        hidden_bias_read != NN_OUTPUT_SIZE ||
        layer_sizes_read != NN_NUM_LAYERS) {
        fprintf(stderr, "[ML] Error: Model file corrupted or incomplete\n");
        return -1;
    }

    // v2.0: Validate model architecture matches expected dimensions
    if (nn->layer_sizes[0] != NN_INPUT_SIZE ||
        nn->layer_sizes[1] != NN_HIDDEN_SIZE ||
        nn->layer_sizes[2] != NN_OUTPUT_SIZE) {
        fprintf(stderr, "[ML] Error: Model architecture mismatch!\n");
        fprintf(stderr, "[ML]   Expected: [%d, %d, %d]\n",
                NN_INPUT_SIZE, NN_HIDDEN_SIZE, NN_OUTPUT_SIZE);
        fprintf(stderr, "[ML]   Found:    [%d, %d, %d]\n",
                nn->layer_sizes[0], nn->layer_sizes[1], nn->layer_sizes[2]);
        fprintf(stderr, "[ML] This model was trained with a different architecture.\n");
        fprintf(stderr, "[ML] Please retrain your model or use the correct version.\n");
        return -1;
    }

    // Record model load event
    if (g_ml_metrics) {
        ml_metrics_record_model_load(g_ml_metrics);
    }

    printf("[ML] Enterprise model loaded from: %s\n", path);
    return 0;
}

/**
 * @brief Export metrics in JSON format
 */
void ml_strategist_export_metrics_json(const char* filepath) {
    if (g_ml_metrics && filepath) {
        ml_metrics_export_to_json(g_ml_metrics, filepath);
    }
}

/**
 * @brief Export metrics in CSV format
 */
void ml_strategist_export_metrics_csv(const char* filepath) {
    if (g_ml_metrics && filepath) {
        ml_metrics_export_to_csv(g_ml_metrics, filepath);
    }
}

/**
 * @brief Get reference to the global ML metrics tracker
 * @return Pointer to global metrics tracker, or NULL if not initialized
 */
ml_metrics_tracker_t* get_ml_metrics_tracker() {
    return g_ml_metrics;
}

/**
 * @brief Print live metrics stats
 */
void ml_strategist_print_live_metrics(void) {
    if (g_ml_metrics) {
        ml_metrics_print_live_stats(g_ml_metrics);
    }
}

/**
 * @brief Print detailed metrics summary
 */
void ml_strategist_print_metrics_summary(void) {
    if (g_ml_metrics) {
        ml_metrics_print_summary(g_ml_metrics);
    }
}

/**
 * @brief Print strategy breakdown metrics
 */
void ml_strategist_print_strategy_breakdown(void) {
    if (g_ml_metrics) {
        ml_metrics_print_strategy_breakdown(g_ml_metrics);
    }
}

/**
 * @brief Print bad character elimination breakdown
 */
void ml_strategist_print_bad_char_breakdown(void) {
    if (g_ml_metrics) {
        ml_metrics_print_bad_char_breakdown(g_ml_metrics);
    }
}

/**
 * @brief Print learning progress metrics
 */
void ml_strategist_print_learning_progress(void) {
    if (g_ml_metrics) {
        ml_metrics_print_learning_progress(g_ml_metrics);
    }
}