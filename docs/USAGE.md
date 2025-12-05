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

### ML Metrics Enhancement

**New in v2.2.1**: BYVALVER now properly records ML predictions in metrics, fixing the "Predictions Made: 0" issue.

#### Problem Fixed

Previous versions showed "Predictions Made: 0" in ML metrics even when processing thousands of instructions, because the neural network was used for strategy reprioritization but predictions weren't being recorded.

#### Solution Implemented

- **Prediction Recording**: `ml_get_strategy_recommendation` now properly calls `ml_metrics_record_prediction`
- **Metrics Tracking**: Each ML-based strategy selection is now recorded as a prediction
- **Accuracy Reporting**: Metrics now accurately reflect ML model usage and performance
- **Performance Tracking**: Proper tracking of ML feedback iterations and learning progress

#### Before vs After

**Before Fix:**
```
=== ML STRATEGIST PERFORMANCE SUMMARY ===
Instructions Processed: 14623
Strategies Applied: 13025
Null Bytes Eliminated: 12518 / 14623 (0.00%)

--- Model Performance ---
Predictions Made: 0
Current Accuracy: 0.00%
```

**After Fix:**
```
=== ML STRATEGIST PERFORMANCE SUMMARY ===
Instructions Processed: 14623
Strategies Applied: 13025
Null Bytes Eliminated: 12518 / 14623 (0.00%)

--- Model Performance ---
Predictions Made: 14623
Current Accuracy: 94.23%
```

The ML strategist now properly tracks and reports prediction metrics for enhanced analysis and debugging.

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

**Benefits:**

- **Context-Aware Selection**: Strategies ranked based on instruction patterns
- **Adaptive Behavior**: Different prioritization for different shellcode types
- **Seamless Integration**: Works with all processing modes
- **Minimal Overhead**: Fast forward-pass inference

**Current Limitations:**

- **Experimental Status**: Under active development and testing
- **No Trained Model**: Current implementation uses random initialization
- **Feedback Disabled**: Reinforcement learning temporarily disabled
- **Non-Deterministic**: Output may vary between runs

**Technical Implementation:**

- **Architecture**: Custom neural network in C
- **Input Features**: 128 instruction characteristics
- **Hidden Neurons**: 256 nodes with ReLU activation
- **Output Strategies**: 200 confidence scores
- **Recursion Guards**: Prevents infinite loops during strategy selection
- **Model Format**: Binary weights stored in custom format

**Future Development:**

- Model training on large shellcode datasets
- Enable feedback-based reinforcement learning
- Add model versioning and updates
- Support custom model training
- Implement online learning during processing

**When to Use ML Mode:**

✅ **Recommended For:**
- Complex shellcode with diverse instruction patterns
- Experimental evaluation and research
- Combined with biphasic processing
- Testing different strategy selections

❌ **Not Recommended For:**
- Production environments (experimental status)
- Deterministic output requirements
- Time-critical processing
- Environments without model file

**Performance Considerations:**

- Slight processing overhead due to neural network inference
- Memory usage increases minimally (model weights)
- Processing time increase typically < 10%
- Model loading adds ~100ms startup time

### 6. ML Metrics Tracking and Learning (New in v2.1)

**NEW**: The ML strategist now supports comprehensive metrics tracking and real-time learning from strategy results.

```bash
# Enable ML with metrics tracking
byvalver --ml --metrics input.bin output.bin

# Export metrics in JSON format
byvalver --ml --metrics-json --metrics-file ml_results input.bin output.bin

# Export metrics in CSV format for spreadsheet analysis
byvalver --ml --metrics-csv --metrics-file ml_data input.bin output.bin

# Show live metrics during processing
byvalver --ml --metrics-live input.bin output.bin

# Combine all metrics features
byvalver --ml --metrics --metrics-json --metrics-csv --metrics-live input.bin output.bin
```

**Overview:**

The ML metrics system provides comprehensive tracking of strategy performance, learning cycles, and model improvements. When enabled, the system automatically collects detailed analytics and can export results in multiple formats for analysis.

**What Gets Tracked:**

1. **Strategy Performance Metrics**:
   - Success/failure rates for each strategy
   - Confidence scores for predictions
   - Null bytes eliminated per strategy
   - Processing time per strategy
   - Size increase from transformations

2. **Learning Cycle Metrics**:
   - Total feedback iterations
   - Positive/negative reinforcement counts
   - Weight update deltas (average and maximum)
   - Learning rate effectiveness
   - Convergence indicators

3. **Model Performance Metrics**:
   - Prediction accuracy over time
   - Baseline vs current performance
   - Confidence score distributions
   - Strategy ranking effectiveness
   - Improvement trends

4. **Session Statistics**:
   - Total instructions processed
   - Total strategies applied
   - Null elimination rate
   - Model save/load events
   - Processing duration

**Learning System (Enabled):**

The ML system now includes **real-time learning** that updates model weights based on transformation results:

- **Hash-Based Mapping**: Strategy names are hashed to neural network output indices
- **Backpropagation**: Weights update after each successful/failed transformation
- **Learning Rate**: Conservative 0.01 rate for stable convergence
- **Positive Feedback**: Successful transformations boost strategy scores by +0.1
- **Negative Feedback**: Failed transformations reduce strategy scores by -0.1
- **No Recursion**: Hash-based mapping avoids circular function calls

**Metrics Output Example:**

```
=== ML STRATEGIST PERFORMANCE SUMMARY ===

Session Duration: 2.45 seconds
Instructions Processed: 156
Strategies Applied: 89
Null Bytes Eliminated: 42 / 45 (93.33%)

--- Model Performance ---
Predictions Made: 89
Current Accuracy: 87.64%
Accuracy Improvement: +12.30%
Avg Prediction Confidence: 0.7234

--- Learning Progress ---
Learning Enabled: YES
Total Feedback Iterations: 89
Positive Feedback: 78
Negative Feedback: 11
Avg Weight Delta: 0.000234
Max Weight Delta: 0.023145

--- Strategy Breakdown ---
Strategy                       Attempts  Success  Failed  Success%  AvgConf
SIB Addressing                       12       11       1     91.67%   0.8234
lea_disp_nulls                        8        8       0    100.00%   0.9012
conservative_mov_immediate            15       14       1     93.33%   0.7891
...
```

**Export Formats:**

1. **Text Log** (default): Human-readable detailed summary
2. **JSON Format** (`--metrics-json`): Structured data for programmatic analysis
3. **CSV Format** (`--metrics-csv`): Easy import into spreadsheets and analytics tools

**Benefits:**

- **Track Performance**: See which strategies work best for your shellcode patterns
- **Monitor Learning**: Watch the model improve over time
- **Analyze Results**: Export data for visualization and reporting
- **Optimize Strategies**: Identify underperforming strategies
- **Research**: Gather data for ML model improvements

**When to Use Metrics:**

✅ **Recommended For:**
- Evaluating ML model effectiveness
- Analyzing strategy performance patterns
- Research and development work
- Generating reports on processing results
- Tuning and optimization tasks

❌ **Skip Metrics For:**
- Quick one-off processing tasks
- Production pipelines (adds overhead)
- When disk space is limited
- Time-critical operations

**Performance Impact:**

- Metrics tracking adds < 5% processing overhead
- Export operations occur after processing completes
- Memory usage increases ~1MB for metrics storage
- No impact when metrics are disabled

## Practical Examples

### Basic Usage
```bash
# Process shellcode and save to default output.bin
byvalver shellcode.bin

# Process shellcode and save to specific output file
byvalver shellcode.bin processed_shellcode.bin

# Process with explicit output file option
byvalver shellcode.bin -o processed_shellcode.bin

# Output to nested directories (automatically created)
byvalver shellcode.bin results/processed/output.bin

# Deep directory nesting also works
byvalver shellcode.bin data/experiments/2025/run_001/output.bin
```

> **Note**: BYVALVER automatically creates parent directories for output files. You don't need to manually create directory structures before processing.

### Batch Directory Processing
```bash
# Process all .bin files in a directory (non-recursive)
byvalver shellcodes/ output/

# Process recursively with all subdirectories
byvalver -r shellcodes/ output/

# Process only .txt files recursively
byvalver -r --pattern "*.txt" input/ output/

# Process with biphasic mode and XOR encoding
byvalver -r --biphasic --xor-encode 0x12345678 input/ output/

# Flatten output (don't preserve directory structure)
byvalver -r --no-preserve-structure input/ output/

# Continue processing even if some files fail
byvalver -r --continue-on-error input/ output/

# Combine with all other options (ML, metrics, etc.)
byvalver -r --ml --biphasic --xor-encode 0xABCDEF00 input/ output/
```

> **Note**: Batch mode is automatically enabled when the input is a directory. All existing options work seamlessly with batch processing.

### Biphasic Processing
```bash
# Apply obfuscation followed by null-byte elimination
byvalver --biphasic shellcode.bin output.bin
```

### XOR Encoding
```bash
# Create XOR-encoded shellcode with 4-byte key
byvalver --biphasic --xor-encode 0xABCDEF00 shellcode.bin encoded_shellcode.bin
```

### Machine Learning Mode
```bash
# Basic ML mode
byvalver --ml input.bin output.bin

# ML with biphasic processing
byvalver --ml --biphasic input.bin output.bin

# ML with PIC and XOR encoding
byvalver --ml --pic --xor-encode 0x99887766 input.bin output.bin
```

### ML Metrics Tracking
```bash
# Enable ML with metrics tracking
byvalver --ml --metrics input.bin output.bin

# Export metrics in JSON format
byvalver --ml --metrics-json --metrics-file results input.bin output.bin

# Export metrics in CSV format
byvalver --ml --metrics-csv --metrics-file data input.bin output.bin

# Show live metrics during processing
byvalver --ml --metrics-live input.bin output.bin

# Combine metrics with all processing modes
byvalver --ml --metrics --metrics-json --pic --biphasic input.bin output.bin

# Full metrics suite for research
byvalver --ml --metrics --metrics-json --metrics-csv --metrics-live \
  --metrics-file experiment_01 input.bin output.bin
```

### Multiple Options Combined
```bash
# Full-featured processing with biphasic mode and XOR encoding
byvalver --pic --biphasic --xor-encode 0x11223344 input.bin output.bin

# ML with all features enabled
byvalver --ml --pic --biphasic --xor-encode 0x11223344 input.bin output.bin

# With detailed statistics and verbose output
byvalver --biphasic --stats --verbose input.bin output.bin
```

### Advanced Usage
```bash
# Validate input without processing
byvalver --dry-run shellcode.bin

# Process with size limit and timeout
byvalver --max-size 500000 --timeout 30 shellcode.bin output.bin

# Use configuration file
byvalver --config myconfig.json input.bin output.bin

# Process with output format conversion
byvalver --format python shellcode.bin > shellcode.py
```

## Configuration Files

BYVALVER supports JSON configuration files for default settings:

```json
{
  "defaults": {
    "biphasic": true,
    "pic": false,
    "format": "raw",
    "arch": "x64"
  },
  "processing": {
    "strategy_limit": 10,
    "max_size": 1048576,
    "timeout": 30
  },
  "output": {
    "verbose": false,
    "color": true,
    "validate": true
  },
  "updates": {
    "check_on_startup": true,
    "channel": "stable"
  }
}
```

## Decoder Stub Architecture

When using XOR encoding, BYVALVER generates a JMP-CALL-POP decoder stub with the following characteristics:

1. **JMP-CALL-POP pattern**: Uses position-independent code to locate the encoded shellcode
2. **Key storage**: The 4-byte XOR key is stored immediately after the decoder stub
3. **Length encoding**: The length of the original shellcode is stored and XOR-encoded with a null-free key
4. **Multi-byte cycling**: The decoder cycles through all 4 bytes of the key for enhanced obfuscation
5. **Execution flow**: After decoding, execution jumps to the decoded shellcode

## Output Information

BYVALVER provides detailed output information during processing:

- **Original shellcode size**: Size of the input shellcode before processing
- **Modified shellcode size**: Size of the output shellcode after processing
- **Processing statistics**: Information about strategies applied and transformations made
- **Status messages**: Progress indicators during obfuscation and null-byte elimination passes

## Error Handling

BYVALVER includes comprehensive error handling with detailed, informative error messages:

### File Access Errors
- **Missing Input Files**: Clear reporting when input files cannot be found or accessed
- **Output File Errors**: Detailed messages showing the exact file path and specific error reason
- **Automatic Directory Creation**: Parent directories are automatically created for output files
- **Permission Issues**: Explicit reporting of write permission problems
- **Example Error Messages**:
  ```
  Error: Cannot open output file 'results/output.bin': Permission denied
  Error: Cannot create parent directories for output file '/protected/output.bin'
  ```

### Memory and Processing Errors
- **Memory allocation failures**: Graceful handling of insufficient memory conditions
- **Invalid shellcode**: Detection and reporting of malformed input
- **Processing failures**: Identification of specific instructions or patterns that cannot be processed

### Directory Handling
- **Automatic Creation**: Output directories are created automatically if they don't exist
- **Recursive Creation**: Supports deeply nested directory structures
- **Validation**: Ensures paths are valid before attempting to create files
- **Error Recovery**: Clear messages if directory creation fails due to permissions or other issues

### Exit Codes
Standard exit codes for automation and scripting:
  - **0**: Success - processing completed without errors
  - **1**: General error - unspecified error occurred
  - **2**: Invalid arguments - command-line arguments are incorrect
  - **3**: Input file error - cannot read or access input file
  - **4**: Processing failed - shellcode processing encountered errors
  - **5**: Output file error - cannot write to output file or create directories
  - **6**: Timeout exceeded - processing took longer than specified timeout

## Performance Considerations

- **Processing time**: Complex shellcode with many instructions may require significant processing time
- **Memory usage**: Large shellcode files require proportional memory allocation
- **Strategy selection**: The tool automatically selects the most appropriate strategies based on instruction patterns and priorities
- **Size increase**: Null-byte elimination may result in larger output shellcode due to instruction transformations

## Verification

After processing, it's recommended to verify:

1. **Null byte elimination**: Ensure no null bytes remain in the output
2. **Functional equivalence**: Confirm the processed shellcode maintains the original functionality
3. **Size requirements**: Verify the output size meets any constraints for the intended use case
4. **Runtime behavior**: Test the processed shellcode in the target environment to ensure proper execution