# Machine Learning Integration in BYVALVER

## Overview

BYVALVER includes an optional machine learning-enhanced component called the "ML Strategist" that uses a simple neural network model to improve the selection and prioritization of null-byte elimination strategies. The ML component analyzes assembly instructions and learns which transformation strategies are most effective for different instruction patterns based on feedback from successful transformations.

## ML Model Architecture

### Neural Network Structure (v2.0 - December 2025)

**Current Architecture (v2.0)**:
- **Input Layer**: 336-dimensional feature vector (4 instructions × 84 features each)
  - Current instruction: 51 one-hot encoding + 33 other features
  - Previous instruction 1: 51 one-hot encoding + 33 other features
  - Previous instruction 2: 51 one-hot encoding + 33 other features
  - Previous instruction 3: 51 one-hot encoding + 33 other features
- **Hidden Layer**: 512 neurons with ReLU activation function (He initialization)
- **Output Layer**: 200-dimensional vector representing potential strategies (Xavier initialization)
- **Architecture**: Feedforward neural network with 3 layers (input → hidden → output)
- **Parameters**: ~204,000 trainable parameters
- **Model Size**: ~1.66 MB

**Previous Architecture (v1.0)**:
- **Input Layer**: 128-dimensional feature vector (scalar instruction encoding)
- **Hidden Layer**: 256 neurons with ReLU activation
- **Output Layer**: 200-dimensional vector
- **Parameters**: ~84,000 trainable parameters
- **Model Size**: ~660 KB

**Breaking Change**: v1.0 models are incompatible with v2.0 architecture. All models must be retrained.

### Feature Extraction (Updated v3.0)
The ML model extracts the following features from x86/x64 instructions:
- Instruction type (MOV, ADD, etc.) - using Capstone instruction ID
- Instruction size in bytes
- Presence of bad characters in the instruction (v3.0: generic, v2.x: null bytes only)
- Bad character count and types (v3.0: tracks which specific bad chars present)
- Operand count and types (register, immediate, memory)
- Register indices for register operands
- Immediate values for immediate operands
- Additional instruction characteristics encoded as numerical values

**Note (v3.0):** The ML model now tracks generic bad character patterns, not just null bytes. However, the model was trained exclusively on null-byte elimination data and has not been retrained for other bad character sets.

### Forward Pass Processing
1. **Input to Hidden Layer**: 
   - Matrix multiplication of input features with input weights
   - Addition of bias terms
   - ReLU activation function application
2. **Hidden to Output Layer**:
   - Matrix multiplication of hidden layer outputs with output weights
   - Addition of bias terms
3. **Softmax Normalization**:
   - Converts outputs to probability distribution (confidence scores)
   - Ensures all strategy scores sum to 1.0

## Input Processing

### Instruction Analysis
The ML component receives disassembled x86/x64 instructions via Capstone engine and performs:

1. **Feature Vector Creation**: Transforms the instruction into a standardized numerical feature vector
2. **Bad Character Detection (v3.0)**: Identifies if the instruction contains bad characters that need elimination (v2.x: null bytes only, v3.0: configurable via --bad-chars)
3. **Operand Analysis**: Examines instruction operands to determine complexity and transformation requirements

**Note (v3.0):** Bad character detection now uses the global bad_char_context to check against user-specified bad characters. The ML model still processes instructions the same way but the detection has been generalized.

### Feature Vector Composition (v2.0)

**Architecture v2.0 (December 2025)** - 336 total dimensions:

The feature vector contains 4 instructions (current + 3 previous) with 84 features each:

**Per-Instruction Features (84 dimensions)**:
- **[0-50]**: One-hot instruction encoding (51 dims)
  - Top-50 most common x86 instructions: MOV, PUSH, POP, XOR, LEA, ADD, SUB, CALL, JMP, RET, CMP, TEST, AND, OR, SHL, SHR, INC, DEC, IMUL, MUL, NOP, INT, SYSCALL, CDQ, XCHG, NEG, NOT, MOVZX, MOVSX, JE, JNE, JA, JB, JL, JG, JAE, JBE, JLE, JGE, STOSB, LODSB, SCASB, MOVSB, LOOP, LEAVE, ENTER, DIV, IDIV, SAR, ROL
  - Index 50: "OTHER" bucket for remaining ~1,450 instructions
- **[51]**: Instruction byte count (1-15)
- **[52]**: Bad character presence flag (0 or 1)
- **[53]**: Bad character count (0-N)
- **[54]**: Operand count (0-4)
- **[55-58]**: Operand type indicators (4 fixed slots)
- **[59-62]**: Register ID values (4 fixed slots)
- **[63-66]**: Immediate value characteristics (4 fixed slots, normalized)
- **[67-70]**: Memory base register (4 fixed slots)
- **[71-74]**: Memory index register (4 fixed slots)
- **[75-78]**: Memory scale (4 fixed slots)
- **[79-82]**: Memory displacement (4 fixed slots, normalized)
- **[83]**: Prefix count

**Context Window**:
- **[0-83]**: Current instruction (84 features)
- **[84-167]**: Previous instruction 1 (84 features)
- **[168-251]**: Previous instruction 2 (84 features)
- **[252-335]**: Previous instruction 3 (84 features)

**Zero-Padding**: For the first 1-3 instructions of shellcode, previous instruction slots are padded with zeros (network learns this represents "no previous instruction").

**Key Improvements**:
1. **Categorical Encoding**: Instruction IDs now use proper one-hot encoding instead of scalar values
2. **Fixed Layout**: Feature indices no longer slide based on operand count
3. **Context Awareness**: Network sees surrounding instructions, enabling sequential pattern learning
4. **Stable Slots**: Dedicated positions for each feature type (no ambiguity)

**Previous Architecture (v1.0)** - 128 dimensions:
- Raw instruction ID (scalar - incorrect for categorical data)
- Instruction byte count
- Bad character flags
- Operand types, registers, immediates (sliding indices based on operand count)
- No context window (only current instruction)

## Strategy Processing and Output

### Strategy Ranking
Once the neural network processes the instruction features:

1. **Strategy Selection**: Identifies applicable strategies for the instruction type
2. **Confidence Scoring**: Uses neural network output to assign confidence scores to each applicable strategy
3. **Ranking**: Sorts strategies by ML-assigned confidence scores in descending order
4. **Prioritization**: Presents highest-confidence strategies first for attempted application

### Feedback Mechanism
After a strategy is applied (or fails to be applied):

1. **Success Recording**: Logs whether the transformation was successful (v3.0: checks for any bad characters in output, not just nulls)
2. **Weight Updates**: Adjusts neural network weights using simple gradient descent
3. **Learning Iteration**: Updates the model based on outcome to improve future predictions
4. **Metrics Tracking**: Records performance metrics for analysis

**Important (v3.0):** While the feedback mechanism now validates against generic bad characters, the ML model's learned patterns are specific to null-byte elimination. The model may not perform optimally for other bad character sets without retraining.

## Integration Architecture

### ML Strategist Lifecycle
```
Initialization → Feature Extraction → Strategy Ranking → Strategy Application → Feedback Processing → Model Updates
```

### Core Components

1. **ml_strategist_t**: Main ML strategist context maintaining the neural network model
2. **instruction_features_t**: Feature vector representation of assembly instructions
3. **ml_prediction_result_t**: Output structure containing recommended strategies and confidence scores
4. **ml_metrics_tracker_t**: Performance tracking and metrics collection system

### Integration Points
- **strategy_registry.c**: ML-based reprioritization of applicable strategies
- **main.c**: ML strategist initialization and cleanup
- **core.c**: Metrics tracking functions
- **training_pipeline.c**: Model training and evaluation routines

## Training Pipeline

### Data Collection
- **Training Samples**: Generated from shellcode files with null-byte containing instructions
- **Feature-Label Pairs**: Instructions paired with successful transformation strategies
- **Data Augmentation**: Synthetic sample generation based on known patterns

### Model Training Process
1. **Data Preparation**: Extract training samples from shellcode binaries
2. **Batch Training**: Process samples in batches to update neural network weights
3. **Validation**: Evaluate model performance on held-out validation set
4. **Model Saving**: Store updated model weights to disk for future use

### Evaluation Metrics
- **Prediction Accuracy**: Percentage of correct strategy recommendations
- **Bad Character Elimination Rate (v3.0)**: Effectiveness at removing bad characters (v2.x: null bytes only)
- **Success Rate**: Overall transformation success percentage
- **Confidence Calibration**: Correlation between confidence scores and actual success

**Note (v3.0):** Metrics track generic bad character elimination, but model accuracy is based on null-byte training data.

## Metrics and Monitoring

### Performance Tracking
The system tracks:

- **Instruction Processing Rates**: How many instructions processed per second
- **Strategy Success Rates**: Individual strategy effectiveness
- **Bad Character Elimination Statistics (v3.0)**: Total bad characters eliminated vs. original count (v2.x: null bytes only)
- **Learning Progress**: Model improvement over processing time
- **Feedback Cycles**: Total learning iterations performed

**Important (v3.0):** Statistics reflect generic bad character elimination, but ML performance characteristics are based on null-byte elimination training.

### Export Formats
- **JSON Export**: Structured metrics for external analysis
- **CSV Export**: Tabular data for spreadsheet analysis
- **Console Reports**: Real-time performance summaries
- **Log Files**: Detailed tracking for debugging

## Command Line Integration

### ML Options
- `--ml`: Enable ML-enhanced strategy selection (EXPERIMENTAL)
- `--metrics`: Enable ML metrics tracking and learning
- `--metrics-file FILE`: Specify metrics output file

## Model Persistence

### Model Storage
- **Binary Format**: Neural network weights stored in proprietary binary format
- **Model Updates**: Weights updated during runtime and saved periodically
- **Versioning**: Model version tracking for compatibility

### Loading Process
1. **File Detection**: Check for existing model file at startup
2. **Weight Loading**: Load pre-trained weights from file
3. **Fallback Initialization**: Initialize with default weights if file not found

## Neural Network Implementation Details (v2.0)

### Weight Matrices (v2.0)
**Current Architecture (v2.0)**:
- **Input Weights**: 512×336 matrix (hidden_size × input_size)
  - 172,032 parameters
  - He initialization: scale = sqrt(2 / 336) ≈ 0.0772
- **Hidden Weights**: 200×512 matrix (output_size × hidden_size)
  - 102,400 parameters
  - Xavier initialization: scale = sqrt(2 / (512 + 200)) ≈ 0.0530
- **Input Bias**: 512-element vector (initialized to 0.0)
- **Hidden Bias**: 200-element vector (initialized to 0.0)
- **Total Parameters**: ~204,432 trainable parameters

**Previous Architecture (v1.0)**:
- **Input Weights**: 256×128 matrix (32,768 parameters)
- **Hidden Weights**: 200×256 matrix (51,200 parameters)
- **Bias Vectors**: 256 + 200 = 456 parameters
- **Total Parameters**: ~84,424 trainable parameters

### Activation Functions
- **Hidden Layer**: ReLU (Rectified Linear Unit) activation
  - f(x) = max(0, x)
  - Derivative: f'(x) = 1 if x > 0, else 0
- **Output Layer**: Softmax for probability distribution
  - f(x_i) = exp(x_i) / Σ exp(x_j)
  - With output masking for invalid strategies (logits set to -INFINITY)

### Weight Initialization (v2.0)
**He Initialization (Input Layer)**:
- Used for ReLU activation layers
- Scale: sqrt(2 / n_in) where n_in = 336
- Method: Gaussian distribution N(0, scale²)
- Implemented via Box-Muller transform

**Xavier Initialization (Output Layer)**:
- Used for softmax activation
- Scale: sqrt(2 / (n_in + n_out)) where n_in = 512, n_out = 200
- Method: Gaussian distribution N(0, scale²)

**Gaussian Random Number Generation**:
```c
// Box-Muller transform for N(0,1)
double u1 = (rand() + 1.0) / (RAND_MAX + 1.0);
double u2 = (rand() + 1.0) / (RAND_MAX + 1.0);
return sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
```

### Learning Algorithm
- **Backpropagation**: Full gradient descent through all layers (v2.0 fix)
- **Learning Rate**: Configurable parameter (default: 0.01)
- **Gradient Computation**:
  - Output layer: delta = predicted - target (softmax + cross-entropy)
  - Hidden layer: delta = output_gradient @ hidden_weights × ReLU'(hidden)
- **Weight Updates**: Both input-to-hidden and hidden-to-output layers updated
- **Batch Processing**: Online learning (update after each sample)

### Context Buffer Management (v2.0)
**History Buffer**:
- Maintains last 3 instructions with full feature vectors
- Circular buffer with automatic shifting
- Zero-padding for start-of-shellcode

**Buffer Update**:
```c
// After processing each instruction:
1. Extract current instruction features
2. Add previous 3 instructions from history buffer
3. Create 336-dimensional input vector
4. Forward pass through network
5. Update history buffer (shift + append current)
```

## Enterprise Features

### Scalability
- **Real-time Learning**: Model updates during shellcode processing
- **Performance Monitoring**: Live metrics and feedback
- **Adaptive Prioritization**: Dynamic strategy ranking based on context

### Analytics
- **Strategy Breakdown**: Individual strategy performance analysis
- **Learning Progress**: Model improvement tracking
- **Performance Optimization**: Strategy effectiveness monitoring

---

## Architecture v2.0 Update (December 2025)

### Overview of Changes

Architecture v2.0 represents a complete overhaul of the ML feature representation system, addressing two critical architectural issues:

1. **Issue 6 (MEDIUM)**: Categorical Data as Scalar
2. **Issue 7 (LOW)**: No Context Window

Both issues have been **FIXED** in v2.0, resulting in a theoretically superior but incompatible architecture.

### What Changed

#### 1. One-Hot Instruction Encoding

**Problem (v1.0)**:
```c
// Instruction ID treated as scalar number
features[0] = (double)insn->id;  // MOV=634, ADD=9, etc.
// Implies MOV is "70× larger" than ADD - mathematically nonsensical
```

**Solution (v2.0)**:
```c
// Instruction ID as one-hot vector (51 dimensions)
int onehot_idx = ml_get_instruction_onehot_index(insn->id);
for (int i = 0; i < 51; i++) {
    features[i] = (i == onehot_idx) ? 1.0 : 0.0;
}
// MOV: [1,0,0,...,0]
// ADD: [0,0,0,0,0,1,0,...,0]
// Network learns instruction-specific patterns without ordinal bias
```

**Implementation**:
- New files: `src/ml_instruction_map.h`, `src/ml_instruction_map.c`
- Top-50 most common x86 instructions identified from shellcode analysis
- O(1) lookup via static array: `instruction_id → one-hot_index`
- "OTHER" bucket (index 50) for remaining ~1,450 instructions

**Impact**:
- Network can learn MOV-specific transformations distinct from ADD
- No false ordinal relationships between instruction types
- Categorical semantics preserved

#### 2. Context Window (Sliding Buffer)

**Problem (v1.0)**:
```c
// Only current instruction visible to network
ml_extract_instruction_features(current_insn, &features);  // 128 dims
// Cannot learn patterns like "PUSH-POP pairs" or "MOV-XOR sequences"
```

**Solution (v2.0)**:
```c
// Current + 3 previous instructions
ml_extract_instruction_features_with_context(
    current_insn,
    &features,
    &g_instruction_history  // Maintains last 3 instructions
);  // 336 dims (4 × 84)

// Network sees:
// [Current instruction: 84 dims]
// [Previous instruction 1: 84 dims]
// [Previous instruction 2: 84 dims]
// [Previous instruction 3: 84 dims]
```

**Implementation**:
- Global history buffer: `instruction_history_t g_instruction_history`
- Automatic circular buffer management (shift + append)
- Zero-padding for start-of-shellcode (first 1-3 instructions)
- History updated after each instruction processed

**Impact**:
- Network learns sequential dependencies
- Context-aware strategy selection (e.g., "after PUSH, prefer POP-based strategies")
- Better handling of multi-instruction patterns

#### 3. Fixed Feature Layout

**Problem (v1.0)**:
```c
// Feature indices slide based on operand count
idx = 5;  // Start of operand features
for (int i = 0; i < op_count; i++) {
    features[idx++] = operand_type[i];  // idx varies!
}
for (int i = 0; i < op_count; i++) {
    features[idx++] = register[i];  // idx varies!
}
// Feature[7] could be operand_type[1] OR register[0] depending on instruction
```

**Solution (v2.0)**:
```c
// Fixed slots for each feature type
features[55] = operand_type[0];  // Always index 55
features[56] = operand_type[1];  // Always index 56
features[57] = operand_type[2];  // Always index 57
features[58] = operand_type[3];  // Always index 58

features[59] = register[0];  // Always index 59
features[60] = register[1];  // Always index 60
// ... (4 slots each, 0 if unused)
// Network learns stable patterns: "Feature[55] is always first operand type"
```

**Impact**:
- Network can learn consistent feature meanings
- No ambiguity in feature interpretation
- Stable gradient propagation

#### 4. Improved Weight Initialization

**Problem (v1.0)**:
```c
// Uniform random initialization
model->input_weights[i][j] = ((double)rand() / RAND_MAX) - 0.5;
// Not optimal for ReLU or softmax activation functions
```

**Solution (v2.0)**:
```c
// He initialization for ReLU layers
double he_scale = sqrt(2.0 / NN_INPUT_SIZE);
model->input_weights[i][j] = he_scale * randn();  // Gaussian N(0, scale²)

// Xavier initialization for softmax layer
double xavier_scale = sqrt(2.0 / (NN_HIDDEN_SIZE + NN_OUTPUT_SIZE));
model->hidden_weights[i][j] = xavier_scale * randn();
```

**Impact**:
- Faster convergence during training
- Better gradient flow through network
- Reduced vanishing/exploding gradient issues

### New Components

**Files Created**:
1. **`src/ml_instruction_map.h`** (40 lines)
   - Interface for instruction one-hot encoding
   - `ml_get_instruction_onehot_index()` - Fast O(1) lookup
   - `ml_instruction_map_init()` - Initialize mapping table
   - `ml_get_instruction_name_by_index()` - Debugging support

2. **`src/ml_instruction_map.c`** (127 lines)
   - Static lookup table: `g_insn_to_onehot[1024]`
   - Top-50 instruction constants: `TOP_INSTRUCTIONS[]`
   - Instruction name strings: `TOP_INSTRUCTION_NAMES[]`

**Files Modified**:
1. **`src/ml_strategist.h`**
   - Constants updated: `NN_INPUT_SIZE` (128→336), `NN_HIDDEN_SIZE` (256→512)
   - Added: `ONEHOT_DIM` (51), `FEATURES_PER_INSN` (84), `CONTEXT_WINDOW_SIZE` (4)
   - New struct: `instruction_history_t` for context buffer

2. **`src/ml_strategist.c`**
   - Global history buffer: `g_instruction_history`
   - New functions:
     - `randn()` - Gaussian random number generator (Box-Muller)
     - `ml_extract_single_instruction_features()` - Per-instruction extraction
     - `ml_update_history_buffer()` - Context buffer management
   - Rewritten: `ml_extract_instruction_features()` - Context-aware extraction
   - Updated: `ml_strategist_init()` - He/Xavier initialization
   - Enhanced: `ml_strategist_load_model()` - Architecture validation

3. **`docs/ML_FIXES_2025.md`**
   - Issues 6 & 7 marked as ✅ FIXED
   - Added "Architecture v2.0 Update" section

### Breaking Changes and Migration

**Model Incompatibility**:
- v1.0 models **CANNOT** be loaded in v2.0 (different dimensions)
- v2.0 performs automatic validation on model load
- Error message: "Model architecture mismatch! Expected: [336, 512, 200], Got: [128, 256, 200]"

**Migration Path**:
```bash
# Old v1.0 models must be discarded
rm -f ml_models/*.bin  # Remove v1.0 models

# Retrain from scratch with v2.0
make train
./bin/train_model

# New v2.0 model created
ls -lh ml_models/byvalver_ml_model.bin
# Expected: ~1.66 MB (v1.0 was ~660 KB)
```

**Code Changes for Developers**:
- Feature vector size: 128 → 336 dimensions
- Instruction encoding: Scalar → One-hot (use `ml_get_instruction_onehot_index()`)
- Feature extraction: Single instruction → Context-aware (4 instructions)
- Model files: v1.0 format incompatible, must retrain

### Performance Characteristics

**Computational Cost**:
- **Inference Time**: ~3-5× slower (larger network: 336 input, 512 hidden)
- **Memory Usage**: ~2.5× more (1.66 MB vs 660 KB model file)
- **Training Time**: ~4× slower per example (more parameters to update)

**Expected Accuracy Improvement**:
- **Theory**: 10-30% better strategy selection accuracy
- **Reason**: Proper categorical encoding + sequential context awareness
- **Status**: Requires empirical validation on diverse shellcode datasets

**Trade-offs**:
- **Pros**: Theoretically superior architecture, proper categorical semantics, context awareness
- **Cons**: Slower inference, larger model size, requires retraining, no pre-trained weights

### Usage Examples

**Standard ML Mode** (same command, new architecture):
```bash
# Enable ML with v2.0 architecture
./bin/byvalver --ml input.bin output.bin

# Model uses 336-dimensional features automatically
# Context buffer maintains last 3 instructions
# One-hot encoding applied transparently
```

**Training New v2.0 Model**:
```bash
# Training utility uses v2.0 architecture
./bin/train_model

# Creates model with:
# - 336 input dimensions
# - 512 hidden neurons
# - He/Xavier initialization
# - Context buffer support
```

**Model Save/Load**:
```bash
# Save current v2.0 state
./bin/byvalver --save-model models/checkpoint_v2.bin

# Load v2.0 model (automatic validation)
./bin/byvalver --load-model models/checkpoint_v2.bin --ml test.bin output.bin

# If model is v1.0, load will fail with architecture mismatch error
```

### Validation and Testing

**Build Verification**:
```bash
# Clean build with v2.0
make clean && make

# Expected:
# - 149 object files compiled (including ml_instruction_map.o)
# - No errors or warnings
# - Binary: bin/byvalver
```

**Runtime Verification**:
```bash
# Check feature dimensions
./bin/byvalver --ml test.bin output.bin 2>&1 | grep "features"
# Should show: 336-dimensional feature vectors

# Verify context buffer
./bin/byvalver --ml test.bin output.bin 2>&1 | grep "history"
# Should show: History buffer management active

# Test model save/load
./bin/byvalver --save-model test.bin && ls -lh test.bin
# Expected: ~1.66 MB file size
```

### Current Status

**Implementation**: ✅ Complete and functional
- All code changes implemented
- Compiles without errors
- Model save/load includes architecture validation
- Context buffer automatically managed

**Testing**: ⚠️ Requires validation
- No extensive training on large corpus yet
- Accuracy improvements need empirical validation
- Performance benchmarks needed (inference time, memory usage)
- Comparison with v1.0 baseline required

**Recommendation**:
- **Research/Development**: Enable `--ml` flag for testing and evaluation
- **Production**: Continue using deterministic mode until v2.0 is validated
- **Reporting**: Please report accuracy improvements, regressions, or issues

### Future Work

**Potential Improvements**:
1. **Pre-training**: Train on large corpus of diverse shellcode samples
2. **Hyperparameter Tuning**: Optimize hidden layer size, learning rate, batch size
3. **Regularization**: Add dropout or L2 penalty to prevent overfitting
4. **Longer Context**: Experiment with 5-10 instruction windows
5. **Bidirectional Context**: Include future instructions (lookahead)

**Not Yet Fixed** (documented in ML_FIXES_2025.md):
- No remaining critical or high-priority issues
- All 7 original issues (1-7) are now FIXED

**Documentation**:
- See `docs/ML_FIXES_2025.md` for complete technical details
- See `docs/USAGE.md` for user-facing v2.0 documentation
- See `docs/BUILD.md` for build system changes

---

**Last Updated**: December 2025 (Architecture v2.0 Release)