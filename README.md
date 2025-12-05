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
  <a href="#building-and-setup">Setup</a> •
  <a href="#usage-guide">Usage</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#development">Development</a> •
  <a href="#troubleshooting">Troubleshooting</a>
</p>

<hr>

<br>

## OVERVIEW

**byvalver** is an advanced C-based command-line tool designed for automated removal of null bytes from shellcode while preserving functional equivalence. The tool leverages the Capstone disassembly framework to analyze x86/x64 assembly instructions and applies sophisticated transformation strategies to replace null-containing instructions with functionally equivalent alternatives.

**Primary Function:** Remove null bytes (`\\x00`) from binary shellcode that would otherwise cause issues with string-based operations or memory management routines.

**Technology Stack:**
- C language implementation for performance and low-level control
- Capstone Disassembly Framework for instruction analysis
- NASM assembler for building decoder stubs
- x86/x64 assembly and instruction set knowledge
- Modular strategy pattern for extensible transformations

---

**byvalver**:

1. **ANALYZES** x86/x64 assembly instructions with Capstone
2. **IDENTIFIES** instructions containing null bytes
3. **TRANSFORMS** instructions to null-byte-free equivalents
4. **OUTPUTS** clean shellcode in multiple formats (binary, XOR-encoded, PIC)

`byvalver` tool prioritizes `security`, `robustness`, and `portability`, running seamlessly on Windows, Linux, and macOS.

### 🔧 Advanced Architecture (v2.0)

**byvalver v2.0** features a sophisticated architecture with **comprehensive strategy registry** for improved maintainability, testability, and extensibility:

- ✅ **100+ transformation strategies** for diverse instruction types
- ✅ **ML-powered strategy prioritization** with neural network inference
- ✅ **Biphase processing** (obfuscation + null-byte elimination)
- ✅ **Position Independent Code (PIC) generation** capability
- ✅ **XOR encoding with decoder stubs**
- ✅ **Enhanced null-byte elimination** with specialized MOV and ADD strategies
- ✅ **Disassembly validation** for improved error handling
- ✅ **Professional-grade code organization**

See [ARCHITECTURE.md](ARCHITECTURE.md) for complete architecture documentation.

<br>

## NEW STRATEGIES

### MOV reg, [reg] Null-Byte Elimination Strategy

**New in v2.1**: BYVALVER now includes specialized transformation strategies for the common `mov reg, [reg]` pattern that produces null bytes, such as `mov eax, [eax]` (opcode `8B 00`). This instruction pattern creates null bytes in the ModR/M byte, which our new strategy eliminates by using a temporary register with displacement arithmetic:

```assembly
push temp_reg      ; Save temporary register
lea temp_reg, [src_reg - 1]  ; Load effective address with non-null displacement
mov dest_reg, [temp_reg + 1] ; Dereference the correct address
pop temp_reg       ; Restore temporary register
```

This transformation preserves all registers (except flags) and eliminates the null-byte ModR/M encoding.

### ADD [mem], reg8 Null-Byte Elimination Strategy

**New in v2.1**: BYVALVER now handles the `add [mem], reg8` pattern that creates null bytes, such as `add [eax], al` (opcode `00 00`). This instruction encodes null bytes in both the opcode and ModR/M byte. The new strategy replaces it with a null-byte-free sequence:

```assembly
push temp_reg                 ; Save temporary register
movzx temp_reg, byte ptr [mem] ; Load the byte from memory into temp register
add temp_reg, src_reg8        ; Perform the addition
mov byte ptr [mem], temp_reg  ; Store the result back into memory
pop temp_reg                  ; Restore temporary register
```

This transformation uses null-byte-free instructions to achieve the same result.

### Disassembly Validation Enhancement

**New in v2.1**: Added robust validation to detect invalid shellcode input. If Capstone disassembler returns zero instructions, BYVALVER now provides a clear error message instead of proceeding with invalid data.

<br>

## BUILDING AND SETUP

### DEPENDENCIES

- A C compiler (`gcc`, `clang`, or MSVC)
- [Capstone disassembly library](http://www.capstone-engine.org/) with development headers
- NASM assembler (`nasm`)
- `xxd` utility (usually part of `vim-common` package)
- Make

### INSTALLATION OF DEPENDENCIES

```bash
# Ubuntu/Debian
sudo apt install build-essential nasm xxd pkg-config libcapstone-dev

# macOS with Homebrew
brew install capstone nasm

# Or manually install Capstone from https://github.com/capstone-engine/capstone
```

### BUILDING

**RECOMMENDED: Makefile Build**

```bash
# Build the main executable (default)
make

# Build with debug symbols and sanitizers
make debug

# Build optimized release version
make release

# Build static executable
make static

# Clean build artifacts
make clean

# Show build information
make info
```

### GLOBAL INSTALLATION

**1. QUICK INSTALLATION**

```bash
# Install using the installation script
curl -sSL https://raw.githubusercontent.com/mrnob0dy666/byvalver/main/install.sh | bash

# Or download and run the script manually
curl -O https://raw.githubusercontent.com/mrnob0dy666/byvalver/main/install.sh
chmod +x install.sh
./install.sh
```

**2. FROM SOURCE**

```bash
# Clone the repository
git clone https://github.com/mrnob0dy666/byvalver.git
cd byvalver

# Install dependencies (Ubuntu/Debian)
sudo apt install build-essential nasm xxd pkg-config libcapstone-dev

# Build and install
make release
sudo make install  # This will install to /usr/local/bin
```

**3. VERIFICATION**

After installation, verify byvalver is working:
```bash
byvalver --version
byvalver --help
```

<br>

### BASIC USAGE

> **Note**: After installation, you can run `byvalver` from anywhere in your system.

**1. PROCESS INPUT SHELLCODE TO REMOVE NULL BYTES**

```bash
# Basic usage: process input.bin and output to output.bin
byvalver input.bin output.bin

# Enable biphasic processing (obfuscation + null-byte elimination)
byvalver --biphasic input.bin output.bin

# XOR encode output with 4-byte key (hex)
byvalver --biphasic --xor-encode 0x12345678 input.bin output.bin
```

**2. GENERATE POSITION INDEPENDENT CODE**

```bash
# Generate position-independent code (new feature)
byvalver --pic input.bin output.bin

# Generate PIC code with XOR encoding
byvalver --pic --xor-encode 0x12345678 input.bin output.bin

# Generate PIC code with biphasic processing (obfuscation + null-byte elimination)
byvalver --pic --biphasic input.bin output.bin
```

**3. PROCESS WITH DETAILED OUTPUT**

```bash
# Process shellcode with only null-byte elimination
byvalver input.bin output.bin
```

**4. COMBINE MULTIPLE OPTIONS**

```bash
byvalver --pic --biphasic --xor-encode 0x12345678 input.bin output.bin
```

Success output:
```
[+] Success: Processed shellcode with 0 null bytes remaining.
```

**5. MACHINE LEARNING MODE (EXPERIMENTAL)**

```bash
# Enable ML-powered strategy prioritization
byvalver --ml input.bin output.bin

# Combine with other processing modes
byvalver --ml --biphasic input.bin output.bin
byvalver --ml --pic input.bin output.bin
byvalver --ml --pic --biphasic input.bin output.bin
```

ML mode uses a neural network to intelligently prioritize transformation strategies based on instruction patterns, potentially improving null-byte elimination effectiveness.

### ADVANCED USAGE EXAMPLES

**PROCESS WITH DETAILED OUTPUT:**

```bash
byvalver --biphasic input.bin output.bin
```

**CREATE XOR-ENCODED SHELLCODE WITH CUSTOM KEY:**

```bash
byvalver --biphasic --xor-encode 0xDEADBEEF shellcode.bin encoded.bin
```

**PROCESS WITHOUT OBFUSCATION BUT WITH XOR ENCODING:**

```bash
byvalver --xor-encode 0x12345678 input.bin output.bin
```

**USE CONFIGURATION FILE:**

```bash
byvalver --config ~/.config/byvalver/config input.bin output.bin
```

**VALIDATE INPUT WITHOUT PROCESSING:**

```bash
byvalver --dry-run shellcode.bin
```

**VIEW DETAILED PROCESSING STATISTICS:**

```bash
byvalver --stats --biphasic shellcode.bin output.bin
```

<br>

### COMMAND-LINE OPTIONS

#### GENERAL OPTIONS

```
-h, --help                    Show help message and exit
-v, --version                 Show version information and exit
-V, --verbose                 Enable verbose output
-q, --quiet                   Suppress non-essential output
--config FILE                 Use custom configuration file
--no-color                    Disable colored output
```

#### PROCESSING OPTIONS

```
--biphasic                    Enable biphasic processing (obfuscation + null-elimination)
--pic                         Generate position-independent code
--ml                          Enable ML-powered strategy prioritization (experimental)
--xor-encode KEY              XOR encode output with 4-byte key (hex)
--format FORMAT               Output format: raw, c, python, powershell, hexstring
```

#### ADVANCED OPTIONS

```
--strategy-limit N            Limit number of strategies to consider per instruction
--max-size N                  Maximum output size (in bytes)
--timeout SECONDS             Processing timeout (default: no timeout)
--dry-run                     Validate input without processing
--stats                       Show detailed statistics after processing
```

#### OUTPUT OPTIONS

```
-o, --output FILE             Output file (alternative to positional argument)
--validate                    Validate output is null-byte free
```

<br>

<br>

## FEATURES

<table>
<tr>
<td width="50%">

### CORE CAPABILITIES

- **Cross-platform compatibility** (Windows, Linux, macOS)
- **x86/x64 architecture support** with Capstone framework
- **Intelligent instruction analysis** via Capstone disassembly
- **100+ transformation strategies** for diverse instruction types
- **ML-powered strategy prioritization** (experimental)
- **Biphase processing** (obfuscation + null-byte elimination)
- **Position Independent Code (PIC) generation**
- **XOR encoding with decoder stubs**

</td>
<td width="50%">

### Security & ANALYSIS

- **PEB-based debugger detection**
- **Timing-based anti-debugging using RDTSC**
- **INT3-based debugger identification**
- **VM and sandbox detection capabilities**
- **Position-independent API resolution**
- **Modified djb2 hashing for API names**
- **Runtime kernel32.dll discovery**

</td>
</tr>
</table>

<br>

## ARCHITECTURE

`byvalver` features a sophisticated, maintainable codebase with enhanced security and performance:

### CORE PROCESSING COMPONENTS

| Component | Function | Description |
|-----------|----------|-------------|
| **Capstone Integration** | Disassembly | Analyzes x86/x64 assembly instructions for null-byte detection |
| **Strategy Registry System** | Transformation | 100+ strategies handle different instruction types (MOV, arithmetic, jumps, etc.) |
| **ML Strategist** | Prioritization | Neural network-based strategy selection and ranking (experimental) |
| **Biphase Processing** | Obfuscation & Elimination | Two-pass approach: first obfuscates, then removes null bytes |
| **PIC Generation** | Position Independence | Windows-specific PIC with JMP-CALL-POP and API hashing |
| **XOR Encoding** | Obfuscation | Prepending of decoder stub with 4-byte key support |

### ARCHITECTURE BENEFITS

<table>
<tr>
<td><b>MAINTAINABILITY</b></td>
<td>Strategy pattern design reduces complexity</td>
</tr>
<tr>
<td><b>EXTENSIBILITY</b></td>
<td>Easy to add new transformation strategies</td>
</tr>
<tr>
<td><b>FUNCTIONAL PRESERVATION</b></td>
<td>All transformations maintain semantic equivalence</td>
</tr>
<tr>
<td><b>NULL-FREE GUARANTEE</b></td>
<td>All strategies produce null-byte free output</td>
</tr>
<tr>
<td><b>ANTI-ANALYSIS</b></td>
<td>Multiple techniques to deter reverse engineering</td>
</tr>
</table>

<br>

## USAGE GUIDE

`byvalver` supports multiple processing modes for seamless integration:

### NULL-BYTE ELIMINATION MODE

<details>
<summary><b>Click to expand basic null-byte elimination</b></summary>

Basic null-byte removal - perfect for direct shellcode usage:

```bash
./bin/byvalver input.bin output.bin
```

</details>

### BIPHASIC PROCESSING MODE

<details>
<summary><b>Click to expand biphasic processing</b></summary>

Two-pass approach with obfuscation and null-byte elimination:

```bash
./bin/byvalver --biphasic input.bin output.bin
```

**Process:**
- **Pass 1**: Obfuscation & complexification of shellcode to increase analytical difficulty
- **Pass 2**: Null-byte elimination on the obfuscated code (clear separation of concerns)

</details>

### XOR ENCODING MODE

<details>
<summary><b>Click to expand XOR encoding</b></summary>

XOR encoding with JMP-CALL-POP decoder stub:

```bash
./bin/byvalver --biphasic --xor-encode 0x12345678 input.bin output.bin
```

**Features:**
- Automatic prepending of JMP-CALL-POP decoder stub
- 4-byte XOR key support with encoded length information
- Multi-byte XOR key cycling for enhanced obfuscation
- Null-free decoder stub implementation

</details>

### POSITION INDEPENDENT CODE (PIC) MODE

<details>
<summary><b>Click to expand PIC generation</b></summary>

Generate position-independent code with API resolution:

```bash
./bin/byvalver --pic input.bin output.bin
```

**Capabilities:**
- **JMP-CALL-POP technique**: Get current EIP/RIP register value for position-independent access
- **API Hash Resolution**: Runtime resolution of Windows APIs using hash-based name lookup
- **PEB-based API Discovery**: Locate kernel32.dll base address and enumerate exported functions
- **Anti-Debugging Features**: Built-in checks to detect debugging environments
- **PIC Shellcode Generation**: Convert regular shellcode to position-independent format

</details>

### MACHINE LEARNING MODE (EXPERIMENTAL)

<details>
<summary><b>Click to expand ML-powered strategy prioritization</b></summary>

Enable intelligent strategy selection using neural network inference:

```bash
# Basic ML mode
./bin/byvalver --ml input.bin output.bin

# ML with biphasic processing
./bin/byvalver --ml --biphasic input.bin output.bin

# ML with PIC generation
./bin/byvalver --ml --pic input.bin output.bin

# Full-featured ML processing
./bin/byvalver --ml --pic --biphasic --xor-encode 0x12345678 input.bin output.bin
```

**How It Works:**

The ML strategist uses a custom neural network to analyze instruction features and intelligently prioritize transformation strategies:

1. **Feature Extraction**: For each instruction, the system extracts features including:
   - Instruction opcode and type (MOV, ADD, JMP, etc.)
   - Operand types (register, immediate, memory)
   - Instruction size and null-byte presence
   - Register indices and immediate values

2. **Neural Network Inference**: A 3-layer neural network (128→256→200 nodes) processes these features:
   - **Input Layer**: 128 instruction features
   - **Hidden Layer**: 256 nodes with ReLU activation
   - **Output Layer**: 200 strategy confidence scores with softmax normalization

3. **Strategy Prioritization**: The network's output scores are mapped to applicable strategies:
   - Strategies are re-ranked based on ML confidence scores
   - Higher-scoring strategies are attempted first
   - Falls back to traditional priority-based selection if ML is unavailable

4. **Model Persistence**: The neural network model is stored in `./ml_models/byvalver_ml_model.bin`:
   - Pre-trained weights loaded at startup
   - Lightweight binary format for fast loading
   - Falls back to default random weights if model file is missing

**Benefits:**

- **Intelligent Selection**: Neural network learns patterns in successful transformations
- **Adaptive Prioritization**: Strategies are ranked based on instruction context
- **Performance**: Minimal overhead with efficient forward-pass inference
- **Compatibility**: Seamlessly integrates with all processing modes (--biphasic, --pic, --xor-encode)

**Technical Details:**

- **Architecture**: Custom neural network with backpropagation support
- **Recursion Prevention**: Guard mechanisms prevent infinite recursion during strategy selection
- **Feedback Loop**: System tracks strategy success/failure (currently disabled to prevent recursion)
- **Thread-Safe**: Recursion guards ensure single-threaded ML operations

**Current Limitations:**

- **Experimental Status**: ML mode is under active development and testing
- **Feedback Learning Disabled**: Reinforcement learning temporarily disabled due to recursion issues
- **Model Training**: Current model uses random initialization; future updates will include trained weights
- **Performance Impact**: Slight processing overhead due to neural network inference

**Future Development:**

- Enable feedback-based learning with proper recursion handling
- Train models on large shellcode datasets for improved accuracy
- Add model versioning and automatic updates
- Implement adaptive learning during processing
- Support for custom model training and fine-tuning

**When to Use ML Mode:**

- ✅ Complex shellcode with diverse instruction patterns
- ✅ When traditional strategies produce suboptimal results
- ✅ Experimental evaluation and research purposes
- ✅ Combined with biphasic processing for maximum effectiveness
- ❌ Not recommended for production use (experimental)
- ❌ Avoid if deterministic output is required

</details>

<br>

## STRATEGY REGISTRY SYSTEM

BYVALVER implements a comprehensive registry of 80+ transformation strategies that handle different types of x86/x64 instructions:

### MOV INSTRUCTION STRATEGIES

- Direct register-to-register MOV transformations
- MOV with immediate value decomposition
- MOV through arithmetic operations
- Memory-based MOV transformations
- Conditional MOV handling

### ARITHMETIC INSTRUCTION STRATEGIES

- ADD/SUB instruction substitution
- MUL/IMUL transformations
- AND/OR/XOR equivalent operations
- INC/DEC replacement patterns
- Complex arithmetic decomposition

### JUMP AND CONTROL FLOW STRATEGIES

- Conditional jump rewrites
- Direct jump replacements
- Call instruction transformations
- Loop instruction modifications
- Relative/absolute jump handling

### SPECIALIZED STRATEGIES

- API hashing and resolution patterns
- PEB (Process Environment Block) access transformations
- Anti-debugging instruction handling
- FPU (Floating Point Unit) instruction replacement
- System call instruction modifications

<br>

## DEVELOPMENT

### ANTI-ANALYSIS FEATURES

BYVALVER includes several anti-analysis techniques:

**PEB-based Debugger Detection:**
- Checks the PEB (Process Environment Block) for debugger flags
- Uses direct memory access to detect debugging artifacts
- Implements stealthy checking that doesn't trigger alerts

**Timing-based Anti-Debugging:**
- Uses RDTSC instructions to measure execution time
- Detects when execution is being stepped through
- Includes checks that are difficult to bypass

**VM and Sandbox Detection:**
- Checks for virtualized environments
- Detects common sandbox characteristics
- Adjusts behavior in potentially monitored environments

### EXTENSIBLE ARCHITECTURE

- Easy addition of new transformation strategies
- Priority-based strategy selection system
- Modular codebase for maintainability
- Comprehensive error handling and reporting

### ARCHITECTURE PRINCIPLES

- **Strategy Pattern**: Each transformation follows a common interface (`can_handle`, `get_size`, `generate`)
- **Modular Design**: Separate source files for different instruction types and strategies
- **Null-free Guarantee**: All strategies must produce null-byte free output
- **Functional Preservation**: All transformations must maintain semantic equivalence

### STRATEGY DEVELOPMENT

- New strategies must implement the `strategy_t` interface
- Strategies are registered in `strategy_registry.c` or `obfuscation_strategy_registry.c`
- Priority system (higher numbers = higher priority) for conflict resolution
- Strategies must be thoroughly tested for null-byte introduction

<br>

</details>

### SAFE USAGE PRACTICES

<table>
<tr>
<td><b>ISOLATION</b></td>
<td>Run only in VMs or sandboxed environments</td>
</tr>
<tr>
<td><b>NEVER EXECUTE</b></td>
<td>Do not execute shellcode without analysis</td>
</tr>
<tr>
<td><b>STAY UPDATED</b></td>
<td>Keep tool updated for security patches</td>
</tr>
<tr>
<td><b>ANALYZE FIRST</b></td>
<td>Understand transformations before deployment</td>
</tr>
</table>

<br>

## GLOBAL INSTALLATION

### QUICK INSTALLATION

**Unix/Linux/macOS:**
```bash
# Install using the installation script
curl -sSL https://raw.githubusercontent.com/mrnob0dy666/byvalver/main/install.sh | bash

# Or download and run the script manually
curl -O https://raw.githubusercontent.com/mrnob0dy666/byvalver/main/install.sh
chmod +x install.sh
./install.sh
```

**From Source:**
```bash
# Clone the repository
git clone https://github.com/mrnob0dy666/byvalver.git
cd byvalver

# Install dependencies (Ubuntu/Debian)
sudo apt install build-essential nasm xxd pkg-config libcapstone-dev

# Build and install
make release
sudo make install  # This will install to /usr/local/bin
```

### PACKAGE MANAGERS

**Homebrew (macOS):**
```bash
brew install byvalver  # Coming soon
```

**AUR (Arch Linux):**
```bash
yay -S byvalver  # Coming soon
```

### VERIFICATION

After installation, verify byvalver is working:
```bash
byvalver --version
byvalver --help
```

<br>

## COMMAND-LINE OPTIONS

### GENERAL OPTIONS

```
-h, --help                    Show help message and exit
-v, --version                 Show version information and exit
-V, --verbose                 Enable verbose output
-q, --quiet                   Suppress non-essential output
--config FILE                 Use custom configuration file
--no-color                    Disable colored output
```

### PROCESSING OPTIONS

```
--biphasic                    Enable biphasic processing (obfuscation + null-elimination)
--pic                         Generate position-independent code
--xor-encode KEY              XOR encode output with 4-byte key (hex)
--format FORMAT               Output format: raw, c, python, powershell, hexstring
```

### ADVANCED OPTIONS

```
--strategy-limit N            Limit number of strategies to consider per instruction
--max-size N                  Maximum output size (in bytes)
--timeout SECONDS             Processing timeout (default: no timeout)
--dry-run                     Validate input without processing
--stats                       Show detailed statistics after processing
```

### OUTPUT OPTIONS

```
-o, --output FILE             Output file (alternative to positional argument)
--validate                    Validate output is null-byte free
```

<br>

## TESTING AND VERIFICATION

### Python-Based Verification

The project includes a comprehensive test suite in `test_all_bins.py` that:
- Processes all .bin files in a specified directory
- Collects detailed statistics on processing results
- Verifies null-byte elimination
- Reports execution times and strategy usage
- Generates detailed assessment reports

### Batch Processing Capabilities

The verification system can handle large sets of shellcode files:
```bash
python3 test_all_bins.py
```

This will process all .bin files in the BIG_BIN directory and generate detailed reports.

<br>

## TROUBLESHOULDING

### COMMON ISSUES

<details>
<summary><b>Click to expand troubleshooting guide</b></summary>

#### Missing Dependencies
- Run `make check-deps` to verify dependencies
- Install Capstone library as described in the setup section

#### Build Failures
- Check that all dependencies are properly installed
- Verify the Capstone library is accessible
- Ensure NASM and xxd utilities are available

#### Null Byte Detection
- Check that your output file has been properly processed
- Use hexdump to verify null byte elimination

#### API Resolution Issues
- Ensure your PIC shellcode targets the correct Windows APIs
- Verify the hashing algorithm matches your target system

</details>

### VERIFICATION OF RESULTS

After processing, you can verify that null bytes have been eliminated:

```bash
# Check for null bytes in output
hexdump -C output.bin | grep "00 "
```

<br>

## CONTRIBUTING

### ADDING NEW STRATEGIES

To add a new transformation strategy:

1. Create a new source file with your strategy implementation
2. Implement the `strategy_t` interface functions
3. Register your strategy in the appropriate registry file
4. Test thoroughly to ensure no null bytes are introduced
5. Verify functional equivalence is maintained

### TESTING NEW CODE

- Always test new strategies against multiple input shellcode samples
- Verify null-byte elimination is complete
- Check that functionality is preserved
- Test with both simple and complex shellcode

<br>

## PERFORMANCE CONSIDERATIONS

### PROCESSING TIME

- Simple shellcode: < 1 second
- Complex shellcode: Up to several seconds
- Large shellcode files: May require several minutes

### MEMORY USAGE

- Memory usage scales with input size
- Recommended to have at least 10x input size in available RAM
- Some complex transformations may require additional temporary memory

### OUTPUT SIZE

- Output shellcode may be larger than input due to transformations
- Size increase depends on the complexity of null-byte elimination required
- Typically 10-50% size increase for heavily null-contaminated input

<br>

## PROJECT CONTEXT

BYVALVER is part of a larger offensive toolchain that includes `purl_diver` (shellcode extraction from PE files) and `toxoglosser` (stealthy process injection on Windows). This toolchain represents a modular approach to payload preparation and execution, addressing critical challenges in modern offensive operations including payload generation, obfuscation, integrity preservation, and stealthy execution against advanced defenses.

The tool is specifically designed for cybersecurity professionals working in penetration testing, red team operations, and malware research contexts. It enables rapid iteration on payloads by automating the tedious and error-prone process of manual null-byte elimination in shellcode.

<br>

<div align="center">
  <hr>
  <p><i>null-byte free and ready!</i></p>
  <p><b>byvalver</b> - eliminating null bytes since inception!</p>
</div>