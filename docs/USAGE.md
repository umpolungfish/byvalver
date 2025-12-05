# BYVALVER Usage Guide

## Overview

BYVALVER is an advanced command-line tool for automated removal of null bytes from shellcode while preserving functional equivalence. The tool leverages the Capstone disassembly framework to analyze x86/x64 assembly instructions and applies sophisticated transformation strategies.

## What's New in v2.1.1

### Automatic Output Directory Creation

BYVALVER now automatically creates parent directories for output files, eliminating the need for manual directory setup:

**Features:**
- **Recursive Creation**: Automatically creates entire directory paths as needed
- **Deep Nesting Support**: Handles complex directory structures like `data/experiments/2025/batch_001/output.bin`
- **mkdir -p Behavior**: Works similar to Unix `mkdir -p` command
- **Improved Error Messages**: Shows exact file paths and specific error reasons when failures occur

**Example:**
```bash
# These commands now work without pre-creating directories
byvalver input.bin results/processed/output.bin
byvalver input.bin experiments/2025/december/run_042/shellcode.bin
```

**Benefits:**
- No more "No such file or directory" errors for output files
- Streamlines batch processing workflows
- Reduces manual directory management
- Ideal for automated scripts and pipelines

## What's New in v2.2

### Batch Directory Processing

**New in v2.2**: BYVALVER now includes comprehensive batch directory processing with full compatibility for all existing options.

#### New Command-Line Options

- `-r, --recursive` - Process directories recursively
- `--pattern PATTERN` - File pattern to match (default: *.bin)
- `--no-preserve-structure` - Flatten output (don't preserve directory structure)
- `--continue-on-error` - Continue processing even if some files fail

#### Auto-Detection

Batch mode is automatically enabled when the input is a directory:

```bash
# Single file mode (automatic)
byvalver input.bin output.bin

# Batch mode (automatic)
byvalver input_dir/ output_dir/
```

#### Compatibility with All Existing Options

All options work seamlessly with batch processing:
- `--biphasic` - Applies biphasic processing to all files
- `--pic` - Generates PIC code for all files
- `--ml` - Uses ML strategy selection for all files
- `--xor-encode KEY` - XOR encodes all processed files
- `--metrics, --metrics-json, --metrics-csv` - Aggregates metrics across all files
- `--quiet, --verbose` - Controls output level for batch operations
- `--dry-run` - Validates all files without processing

#### Usage Examples

Process all .bin files in a directory (non-recursive):
```bash
byvalver shellcodes/ output/
```

Process recursively with all subdirectories:
```bash
byvalver -r shellcodes/ output/
```

Process only .txt files recursively:
```bash
byvalver -r --pattern "*.txt" input/ output/
```

Process with biphasic mode and XOR encoding:
```bash
byvalver -r --biphasic --xor-encode 0x12345678 input/ output/
```

Flatten output (don't preserve directory structure):
```bash
byvalver -r --no-preserve-structure input/ output/
```

Continue processing even if some files fail:
```bash
byvalver -r --continue-on-error input/ output/
```

#### Implementation Details

**New Files:**
- `src/batch_processing.h` - Batch processing API
- `src/batch_processing.c` - Directory traversal, file discovery, and statistics

**Key Features:**
- **Automatic directory creation** - Parent directories created automatically (preserves existing functionality)
- **Pattern matching** - Uses fnmatch for flexible file pattern matching
- **Directory structure preservation** - Optional preservation of input directory hierarchy
- **Comprehensive statistics** - Tracks total files, processed, failed, skipped, and size metrics
- **Progress reporting** - Shows progress as [N/Total] filename
- **Error handling** - Configurable error handling (stop or continue on errors)

#### Tested Scenarios

✅ Non-recursive batch processing
✅ Recursive batch processing
✅ Directory structure preservation
✅ Flattened output (--no-preserve-structure)
✅ Custom file patterns (--pattern)
✅ Compatibility with --biphasic
✅ Compatibility with --xor-encode
✅ Error handling with --continue-on-error
✅ Empty file handling

All existing single-file functionality remains unchanged and fully compatible!

## What's New in v2.2.1

### ML Prediction Tracking System

**New in v2.2.1**: BYVALVER now properly tracks and records ML predictions with outcome-based accuracy metrics.

#### Problem Fixed

Previous versions showed "Predictions Made: 0" in ML metrics even when the neural network was actively reprioritizing strategies. The ML model was performing inference and learning from feedback, but predictions were never being recorded in the metrics system.

**Root Cause:** The `ml_reprioritize_strategies()` function performed neural network inference to reorder strategies but never called `ml_metrics_record_prediction()`. Learning happened (feedback iterations were tracked), but prediction counts remained at zero.

#### Solution Implemented

A comprehensive three-component prediction tracking system:

##### 1. **Prediction State Tracking**
Global state variables track the ML model's prediction for each instruction:
```c
static strategy_t* g_last_predicted_strategy = NULL;
static double g_last_prediction_confidence = 0.0;
```

##### 2. **Prediction Storage**
When the ML model reprioritizes strategies (`ml_reprioritize_strategies()`):
- The top-ranked strategy (index 0) is stored as the prediction
- The ML confidence score for that strategy is saved
- Prediction is held in pending state until outcome is known

##### 3. **Outcome-Based Recording**
When strategy application completes (`ml_provide_feedback()`):
- Compares applied strategy against stored prediction
- Determines if prediction was correct:
  - **Correct**: Predicted strategy was used AND succeeded
  - **Incorrect**: Different strategy used OR predicted strategy failed
- Records prediction with actual outcome via `ml_metrics_record_prediction()`
- Clears prediction state for next instruction

#### Implementation Architecture

**Key Files Modified:**
- `src/ml_strategist.c:39-41` - Added prediction state variables
- `src/ml_strategist.c:398-407` - Store predictions in `ml_reprioritize_strategies()`
- `src/ml_strategist.c:537-562` - Verify and record predictions in `ml_provide_feedback()`

**Processing Flow:**
```
Instruction Analysis
       ↓
ML Neural Network Inference (reprioritize)
       ↓
Store Top Strategy + Confidence
       ↓
Apply Strategy
       ↓
Compare Outcome vs Prediction
       ↓
Record Prediction (correct/incorrect)
       ↓
Update Accuracy Metrics
```

#### Before vs After

**Before Fix:**
```
=== ML STRATEGIST PERFORMANCE SUMMARY ===
Instructions Processed: 3702
Strategies Applied: 3693
Null Bytes Eliminated: 3693 / 3702 (99.76%)

--- Model Performance ---
Predictions Made: 0          ← No predictions recorded
Current Accuracy: 0.00%      ← No accuracy tracking
Avg Prediction Confidence: 0.0000

--- Learning Progress ---
Learning Enabled: YES
Total Feedback Iterations: 7395  ← Learning WAS happening
Positive Feedback: 3693
```

**After Fix:**
```
=== ML STRATEGIST PERFORMANCE SUMMARY ===
Instructions Processed: 4
Strategies Applied: 4
Null Bytes Eliminated: 4 / 4 (100.00%)

--- Model Performance ---
Predictions Made: 4          ← Predictions now tracked
Current Accuracy: 100.00%    ← Real accuracy metrics
Avg Prediction Confidence: 0.0062  ← Actual confidence values

--- Learning Progress ---
Learning Enabled: YES
Total Feedback Iterations: 8
Positive Feedback: 4
```

#### Benefits

- **Accurate Metrics**: Prediction counts now reflect actual ML model usage
- **Real Accuracy**: Accuracy percentages based on actual prediction outcomes
- **Confidence Tracking**: Average confidence reflects true ML model confidence scores
- **Learning Validation**: Confirms ML model is making predictions, not just learning
- **Performance Analysis**: Enables evaluation of ML model effectiveness over time
- **Debugging Support**: Provides visibility into ML decision-making process

## Installation

### Global Installation
After building the project, you can install byvalver globally:

```bash
# Install the binary to /usr/local/bin
sudo make install

# Install the man page to /usr/local/share/man/man1
sudo make install-man

# Verify installation
byvalver --version
```

### Direct Usage
If not installed globally, run from the project directory:
```bash
./bin/byvalver [OPTIONS] <input_file> [output_file]
```

## Command-Line Interface

### Basic Syntax
```bash
byvalver [OPTIONS] <input_file> [output_file]
```

### Parameters

- `input_file`: Path to the input binary file containing shellcode to process
- `output_file`: Optional. Path to the output binary file. Defaults to `output.bin`

## Options

### General Options
- `-h, --help`: Show help message and exit
- `-v, --version`: Show version information and exit
- `-V, --verbose`: Enable verbose output
- `-q, --quiet`: Suppress non-essential output
- `--config FILE`: Use custom configuration file
- `--no-color`: Disable colored output

### Batch Processing Options
- `-r, --recursive`: Process directories recursively
- `--pattern PATTERN`: File pattern to match (default: *.bin)
- `--no-preserve-structure`: Flatten output (don't preserve directory structure)
- `--continue-on-error`: Continue processing even if some files fail

### Processing Options
- `--biphasic`: Enable biphasic processing (obfuscation + null-byte elimination)
- `--pic`: Generate position-independent code
- `--ml`: Enable ML-powered strategy prioritization (experimental)
- `--xor-encode KEY`: XOR encode output with 4-byte key (hex)
- `--format FORMAT`: Output format: raw, c, python, powershell, hexstring

### Advanced Options
- `--strategy-limit N`: Limit number of strategies to consider per instruction
- `--max-size N`: Maximum output size (in bytes)
- `--timeout SECONDS`: Processing timeout (default: no timeout)
- `--dry-run`: Validate input without processing
- `--stats`: Show detailed statistics after processing

### Output Options
- `-o, --output FILE`: Output file (alternative to positional argument)
- `--validate`: Validate output is null-byte free

### ML Metrics Options (requires --ml)
- `--metrics`: Enable ML metrics tracking and learning
- `--metrics-file FILE`: Metrics output file (default: ./ml_metrics.log)
- `--metrics-json`: Export metrics in JSON format
- `--metrics-csv`: Export metrics in CSV format
- `--metrics-live`: Show live metrics during processing

## Processing Modes

### 1. Standard Mode
Basic null-byte elimination without additional obfuscation:
```bash
byvalver input.bin output.bin
```

This mode applies transformation strategies to remove null bytes from the shellcode while preserving functionality.

### 2. Biphasic Mode
Two-pass processing that first obfuscates the shellcode then eliminates null bytes:
```bash
byvalver --biphasic input.bin output.bin
```

This mode:
- Pass 1: Applies obfuscation strategies to increase analytical difficulty
- Pass 2: Eliminates null bytes from the obfuscated code

### 3. Position Independent Code (PIC) Mode
Generates position-independent code with API resolution:
```bash
byvalver --pic input.bin output.bin
```

Features:
- JMP-CALL-POP technique for position-independent access
- API hashing and runtime resolution
- PEB-based API discovery
- Anti-debugging features

### 4. XOR Encoding Mode
Adds a decoder stub and XOR-encodes the output with a specified key:
```bash
byvalver --biphasic --xor-encode 0x12345678 input.bin output.bin
```

This mode prepends a JMP-CALL-POP decoder stub that will decode the shellcode at runtime using the provided key.

### 5. Machine Learning Mode (Experimental)
Enables ML-powered strategy prioritization using neural network inference:
```bash
byvalver --ml input.bin output.bin
```

**Overview:**

ML mode uses a custom neural network to intelligently select and prioritize transformation strategies based on instruction context. Instead of using fixed priority values, the neural network analyzes instruction features and ranks strategies dynamically.

**How It Works:**

1. **Feature Extraction**:
   - Extracts 128 features from each instruction (opcode, operands, size, registers, etc.)
   - Encodes instruction characteristics into numerical feature vectors
   - Detects null-byte presence and operand types

2. **Neural Network Inference**:
   - 3-layer feedforward network (128→256→200 nodes)
   - ReLU activation in hidden layer
   - Softmax normalization in output layer
   - Forward pass inference for each instruction

3. **Strategy Re-ranking**:
   - Maps neural network outputs to applicable strategies
   - Re-sorts strategies by ML confidence scores
   - Falls back to traditional priority if needed
   - Selects highest-scoring strategy first

4. **Model Persistence**:
   - Model stored in `./ml_models/byvalver_ml_model.bin`
   - Binary format with weights and biases
   - Automatic fallback to random weights if missing

**Combining ML with Other Modes:**

```bash
# ML with biphasic processing
byvalver --ml --biphasic input.bin output.bin

# ML with PIC generation
byvalver --ml --pic input.bin output.bin

# ML with all features
byvalver --ml --pic --biphasic --xor-encode 0xABCD1234 input.bin output.bin
```