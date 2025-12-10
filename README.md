<div align="center">
  <h1>byvalver</h1>
  <p><b>NULL-BYTE ELIMINATION FRAMEWORK</b></p>

  <img src="./images/byvalver_logo.png" alt="byvalver logo" width="400">
</div>

<div align="center">

  ![C](https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white)
  &nbsp;
  ![Shellcode](https://img.shields.io/badge/Shellcode-Analysis-%23FF6B6B.svg?style=for-the-badge)
  &nbsp;
  ![Cross-Platform](https://img.shields.io/badge/Cross--Platform-Windows%20%7C%20Linux%20%7C%20macOS-%230071C5.svg?style=for-the-badge)
  &nbsp;
  ![Security](https://img.shields.io/badge/Security-Hardened-%23000000.svg?style=for-the-badge)

</div>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#building-and-setup">Building</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage-guide">Usage</a> •
  <a href="#ml-training">ML Training</a> •
  <a href="#development">Development</a> •
  <a href="#troubleshooting">Troubleshooting</a>
</p>

<hr>

## OVERVIEW

**byvalver** is a C-based command-line tool designed for automated denulling (removal of null bytes) of shellcode while preserving functional equivalence. The tool leverages the Capstone disassembly framework to analyze x86/x64 assembly instructions and applies a library of ranked transformation strategies to replace null-containing instructions with functionally equivalent, denulled alternatives.

**Primary Function:** Remove null bytes (`\x00`) from binary shellcode that would otherwise cause issues with string-based operations or memory management routines.

**Technology Stack:**
- C language implementation for performance and low-level control
- Capstone Disassembly Framework for instruction analysis
- NASM assembler for building decoder stubs
- x86/x64 assembly and instruction set knowledge
- Modular strategy pattern for extensible transformations
- Machine Learning integration for intelligent strategy selection

`byvalver` prioritizes `security`, `robustness`, and `portability`, running seamlessly on Windows, Linux, and macOS.

## FEATURES

### Advanced Transformation Engine
BYVALVER includes 120+ instruction transformation strategies that handle complex instructions including arithmetic, MOV, conditional jumps, and API calls. The engine uses sophisticated instruction rewriting to eliminate null bytes while preserving functionality.

**New Windows-Specific Features (v2.5):**
- **CALL/POP Immediate Loading**: Use CALL/POP technique to load immediate values without encoding nulls in instructions
- **PEB API Hashing Strategy**: Use PEB traversal to find kernel32.dll and hash-based API resolution for stealthy function calls
- **SALC + Conditional Flag Manipulation**: Use SALC (Set AL on Carry) instruction for efficient AL register zeroing without MOV AL, 0x00
- **LEA Arithmetic Substitution**: Use LEA instruction to perform arithmetic operations without immediate null bytes
- **Shift-Based Value Construction**: Use bit shift operations combined with arithmetic to build values containing null bytes
- **Stack-Based String Construction**: Construct strings using multiple PUSH operations to avoid null-laden string literals
- **Enhanced Immediate Encoding**: Advanced immediate construction methods for Windows-specific patterns
- **Enhanced PEB API Resolution**: Sophisticated Windows API resolution patterns with null-byte displacement handling
- **Conditional Jump Displacement Strategies**: Advanced conditional jump handling with null-byte displacement resolution
- **Register Allocation Strategies**: Dynamic register remapping to avoid null-byte patterns
- **LEA Displacement Optimization**: Specialized LEA instruction handling for displacement values containing null bytes

**Critical Bug Fixes and Improvements (v2.6-v2.8):**
- **Disabled Broken Strategies**: Fixed critical bugs where several strategies were introducing null bytes instead of eliminating them
- **mov_register_remap**: Fixed bug where this strategy would append original instruction with nulls instead of transforming
- **contextual_register_swap**: Fixed bug where this strategy would introduce nulls instead of eliminating them
- **hash_based_resolution**: Fixed incomplete implementation causing null introduction
- **enhanced_peb_traversal**: Fixed incomplete implementation causing null introduction
- **peb_conditional_jumps**: Fixed incomplete implementation causing null introduction
- **Fixed Top 5 Impact Strategies**: Enhanced the following high-impact strategies significantly improving null elimination success rate:
  - **generic_mem_null_disp_enhanced**: Improved generic memory displacement null elimination
  - **lea_displacement_nulls**: Enhanced LEA instruction displacement handling
  - **SIB Addressing Null Elimination**: Improved SIB addressing null detection and handling
  - **conditional_jump_displacement**: Implemented proper conditional jump transformation
  - **mov_mem_imm**: Enhanced MOV memory immediate handling
- **PUSH 0 Bug Fix (v2.8)**: Fixed critical bug in xchg_preservation_strategies.c where `PUSH 0` was encoded as `6A 00` (contains null byte) instead of using the null-free MOV+PUSH construction. This affected 2/3 failing files (skeeterspit.bin, wingaypi.bin).
- **SIB ARPL Bug Fix (v2.8)**: Fixed critical bug in sib_strategies.c where the strategy claimed to handle ANY instruction with SIB addressing but only implemented transformations for MOV, PUSH, LEA, CMP, ADD, SUB, AND, OR, XOR. The ARPL instruction fell through to default case which copied original bytes with nulls. Added instruction type filter to only accept supported instructions. This affected 1/3 failing files (SSIWML.bin).
- **Achievement: 100% Success Rate**: These fixes brought the success rate from 16/19 (84.2%) to **19/19 (100%)** on the full test suite.

**Key Features:**
- **Strategy Registration**: Comprehensive registration system for all transformation strategies
- **Fallback Mechanisms**: Robust fallback systems when primary transformation methods fail
- **Complex Instruction Handling**: Advanced handling of instructions with null bytes in operands, displacements, and immediate values
- **Enhanced MOV Strategies**: Multiple new approaches for MOV operations with null-containing immediate values
- **Enhanced Arithmetic Strategies**: Multiple arithmetic decomposition techniques (ADD/SUB, XOR, NOT, NEG)
- **Memory Displacement Improvements**: Advanced techniques for handling LEA/MOV/CMP with null-containing displacements
- **Immediate Value Encoding**: Multiple encoding methods (XOR, shift-based, arithmetic decomposition)
- **Register Chaining**: Enhanced register-based transformations to avoid null bytes
- **Multi-Pass Processing**: Biphasic architecture with obfuscation pass followed by null-byte elimination
- **SIB Addressing Enhancements**: Sophisticated SIB addressing mode handling to avoid null bytes
- **Conditional Jump Optimization**: Advanced conditional jump displacement handling for improved success rates

### Batch Directory Processing
Process multiple shellcode files in batch mode with directory processing capabilities.

- `-r, --recursive`: Process directories recursively.
- `--pattern PATTERN`: File pattern to match (default: `*.bin`).
- `--no-preserve-structure`: Flatten output directory structure.
- `--no-continue-on-error`: Stop processing on the first error.

### ML-Powered Strategy Selection
Intelligently prioritizes transformation strategies based on instruction context using neural network inference.

- **Feature Extraction**: Extracts 128 features from each instruction.
- **Neural Network Inference**: A 3-layer feedforward network ranks strategies dynamically.
- **Prediction Tracking**: Tracks the ML model's prediction accuracy with real-time feedback.
- **Adaptive Learning**: Model updates strategy rankings based on success/failure feedback.
- **Path Resolution**: Enhanced model loading with dynamic path resolution based on executable location.

### Comprehensive Verification Tools
A suite of Python-based tools to validate the output of byvalver.

- **`verify_denulled.py`**: Verifies that output files contain zero null bytes.
- **`verify_functionality.py`**: Verifies that processed shellcode maintains basic functional instruction patterns.
- **`verify_semantic.py`**: Verifies semantic equivalence between original and processed shellcode, accounting for expected transformations.

## ARCHITECTURE

BYVALVER follows a modular architecture based on the Strategy pattern, with components designed for extensibility and maintainability.

<div align="center">
  <img src="./images/bv1.png" alt="MAIN FRAMEWORK" width="800">
  <img src="./images/bv5.png" alt="ML INTEGRATION" width="800">
</div>

## BUILDING AND SETUP

### Dependencies

- A C compiler (`gcc`, `clang`, or MSVC)
- [Capstone disassembly library](http://www.capstone-engine.org/) with development headers
- NASM assembler (`nasm`)
- `xxd` utility (usually part of `vim-common` package)
- Make

### Installation of Dependencies

```bash
# Ubuntu/Debian
sudo apt install build-essential nasm xxd pkg-config libcapstone-dev

# macOS with Homebrew
brew install capstone nasm
```

### Building from Source

The project uses a standard `Makefile`.

```bash
# Build the main executable (default)
make

# Build with debug symbols and sanitizers
make debug

# Build optimized release version
make release

# Build static executable
make static

# Build the ML model training utility
make train

# Clean build artifacts
make clean
```

## INSTALLATION

### 1. From Source
After building the project, you can install byvalver globally using the Makefile.

```bash
# Install the binary to /usr/local/bin and the man page
sudo make install
```

### 2. Using the Install Script
You can also use the provided shell script to install the latest release from GitHub or build from local sources.

```bash
# Download and run the script
curl -sSL https://raw.githubusercontent.com/mrnob0dy666/byvalver/main/install.sh | bash

# Or, to install from your local source clone:
chmod +x install.sh
./install.sh
```

## USAGE GUIDE

### Basic Syntax
```bash
byvalver [OPTIONS] <input_file> [output_file]
```
- `input_file`: Path to the input binary file containing shellcode.
- `output_file`: Optional. Path to the output binary file. Defaults to `output.bin`.

### Command-Line Options

- `-h, --help`: Show help message.
- `-v, --version`: Show version information.
- `-V, --verbose`: Enable verbose output.
- `-q, --quiet`: Suppress non-essential output.
- `--biphasic`: Enable biphasic processing (obfuscation + null-byte elimination).
- `--pic`: Generate position-independent code.
- `--ml`: Enable ML-powered strategy prioritization.
- `--xor-encode KEY`: XOR encode output with a 4-byte hex key (e.g., 0xDEADBEEF).
- `--format FORMAT`: Set output format (`raw`, `c`, `python`, `hexstring`).
- `-r, --recursive`: Process directories recursively.
- `--pattern PATTERN`: File pattern to match for batch processing.

### Processing Modes

1.  **Standard Mode**: Basic null-byte elimination.
    ```bash
    byvalver input.bin output.bin
    ```
2.  **Biphasic Mode**: Obfuscates the shellcode then eliminates null bytes.
    ```bash
    byvalver --biphasic input.bin output.bin
    ```
3.  **PIC Mode**: Generates position-independent code.
    ```bash
    byvalver --pic input.bin output.bin
    ```
4.  **XOR Encoding Mode**: Adds a decoder stub and XOR-encodes the output.
    ```bash
    byvalver --xor-encode 0xDEADBEEF input.bin output.bin
    ```

## ML TRAINING

### Training the ML Model

BYVALVER includes a dedicated training utility to create and update the ML model used for strategy selection.

#### Building the Training Utility
```bash
# Build the standalone training utility
make train
```

This creates `bin/train_model` which can be used to train the ML model on your own shellcode datasets.

#### Training Process
```bash
# Run training (defaults to shellcodes/ directory and ml_models/ output)
./bin/train_model

# The training process includes:
# - Data generation from shellcode files in ./shellcodes/
# - ML model training with configurable epochs and parameters
# - Model evaluation and statistics generation
# - Model saving to the default location
```

#### Training Configuration
The training utility uses the following defaults which can be modified in `training_pipeline.c`:
- **Training Data Directory**: `./shellcodes/`
- **Model Output Path**: `./ml_models/byvalver_ml_model.bin` (with path resolution)
- **Max Training Samples**: 10,000
- **Training Epochs**: 50
- **Validation Split**: 20%
- **Learning Rate**: 0.001
- **Batch Size**: 32

#### ML Model Path Resolution
BYVALVER includes enhanced path resolution for the ML model file:
- The main executable dynamically resolves the model path based on its own location
- This ensures the application works when moved to different directories
- The training utility follows the same path resolution logic

## DEVELOPMENT

### Code Style
The project follows modern C conventions with a focus on modularity and clarity.

### Testing
The project includes a Python-based test suite. To run the tests, execute the main test script:
```bash
python3 test_all_bins.py
```

## TROUBLESHOOTING
For issues with null-byte elimination, ensure your input file format is correct and verify that your system has the required dependencies installed. Check that the shellcode doesn't contain instructions that are particularly difficult to transform without null bytes.

If using the ML functionality, verify that the model file exists at the expected location. The application will fall back to default weights if the model file is not found.

## LICENSE

`byvalver` is freely sicced upon the world under the ![UNLICENSE](./UNLICENSE)