# BYVALVER Usage Guide

## Overview

BYVALVER is an advanced command-line tool for automated removal of null bytes from shellcode while preserving functional equivalence. The tool leverages the Capstone disassembly framework to analyze x86/x64 assembly instructions and applies sophisticated transformation strategies.

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

## Practical Examples

### Basic Usage
```bash
# Process shellcode and save to default output.bin
byvalver shellcode.bin

# Process shellcode and save to specific output file
byvalver shellcode.bin processed_shellcode.bin

# Process with explicit output file option
byvalver shellcode.bin -o processed_shellcode.bin
```

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

BYVALVER includes comprehensive error handling:

- **File access errors**: Proper reporting of missing input files or write permissions
- **Memory allocation failures**: Graceful handling of insufficient memory conditions
- **Invalid shellcode**: Detection and reporting of malformed input
- **Processing failures**: Identification of specific instructions or patterns that cannot be processed
- **Exit codes**: 
  - 0: Success
  - 1: General error
  - 2: Invalid arguments
  - 3: Input file error
  - 4: Processing failed
  - 5: Output file error
  - 6: Timeout exceeded

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