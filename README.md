<DOCUMENT filename="README.md">
  
# byvalver (·𐑚𐑲𐑝𐑨𐑤𐑝𐑼)

## THE SHELLCODE NULL-BYTE ELIMINATOR / 𐑞 𐑖𐑧𐑤𐑒𐑴𐑛 𐑯𐑫𐑤–𐑚𐑲𐑑 𐑧𐑤𐑦𐑥𐑦𐑯𐑱𐑑𐑼

<div align="center">
  <img src="./images/byvalver_logo.png" alt="byvalver logo" width="750">
</div>

<div align="center">
  <img src="https://img.shields.io/badge/C-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white" alt="C">
  <img src="https://img.shields.io/badge/Shellcode-Analysis-%23FF6B6B.svg?style=for-the-badge" alt="Shellcode Analysis">
  <img src="https://img.shields.io/badge/Cross--Platform-Windows%20%7C%20Linux%20%7C%20macOS-%230071C5.svg?style=for-the-badge" alt="Cross-Platform">
  <img src="https://img.shields.io/badge/Security-Hardened-%23000000.svg?style=for-the-badge" alt="Security Hardened">
</div>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#system-requirements">System Requirements</a> •
  <a href="#dependencies">Dependencies</a> •
  <a href="#building">Building</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#obfuscation-strategies">Obfuscation Strategies</a> •
  <a href="#denullification-strategies">Denullification Strategies</a> •
  <a href="#ml-training">ML Training</a> •
  <a href="#development">Development</a> •
  <a href="#troubleshooting">Troubleshooting</a> •
  <a href="#license">License</a>
</p>

<hr>

## Overview

**byvalver** is a CLI tool built in `C` for automatically eliminating null-bytes (`\x00`) from x86/x64 shellcode while maintaining complete functional equivalence  

It achieves a high success rate in producing null-free output across diverse, real-world shellcode test suites, including complex Windows payloads.

The tool uses the `Capstone` disassembly framework to analyze instructions and applies over 120 ranked transformation strategies to replace null-containing code with equivalent alternatives  

Supports Windows, Linux, and macOS

**Core Technologies:**
- Pure `C` implementation for efficiency and low-level control
- `Capstone` for precise disassembly
- `NASM` for generating decoder stubs
- Modular strategy pattern for extensible transformations
- Neural network integration for intelligent strategy selection
- Biphasic processing: Obfuscation followed by denullification

While it has demonstrated 100% success on a comprehensive test corpus representing a wide variety of null-byte sources, some specialized shellcode may require additional strategies to achieve full denulling —-> our extensible registry makes it easy to add new transformations as needed

## Features

### High Denulling Success Rate
<div align="center">
  <strong>Achieved 100% null-byte elimination on a diverse test corpus representing common and complex null sources.</strong>
</div>

### Advanced Transformation Engine
120+ strategies covering virtually all common null-byte sources:
- `CALL/POP` and stack-based immediate loading
- `PEB` traversal with hashed API resolution
- Advanced hash-based API resolution with complex algorithms
- Multi-stage `PEB` traversal for multiple DLL loading
- `SALC`, `XCHG`, and flag-based zeroing
- `LEA` for arithmetic substitution
- `Shift` and arithmetic value construction
- Multi-`PUSH` string building
- Stack-based structure construction for Windows structures
- Stack-based string construction with advanced patterns
- `SIB` and displacement rewriting
- Conditional jump displacement handling
- Register remapping and chaining
- Enhanced `SALC`+`REP STOSB` for buffer initialization
- Comprehensive support for `MOV`, `ADD/SUB`, `XOR`, `LEA`, `CMP`, `PUSH`, and more

The engine employs multi-pass processing (obfuscation → denulling) with robust fallback mechanisms for edge cases

*While highly effective, certain edge-case shellcodes may still contain nulls → these can most always be addressed by extending the strategy registry*

### DENULLING IN ACTION

![byvalver batch processing](./images/denulling.gif)

### Performance Metrics

Real-world performance data from processing 179 diverse shellcode samples:

```
📊 Batch Processing Statistics:

Success Rate:            179/179             █████████████████████████   100.00%
Files Processed:         179                 █████████████████████████   100.00%
Failed:                  0                   ░░░░░░░░░░░░░░░░░░░░░░░░░   00.00%
Skipped:                 0                   ░░░░░░░░░░░░░░░░░░░░░░░░░   00.00%

💾 Size Optimization:

Input Size:              65.69 MB            █████████████████████████   100.00%
Output Size:             0.58 MB             ░░░░░░░░░░░░░░░░░░░░░░░░░   00.88%
Compression Ratio:       0.01x               Size reduced by 99.12%
```

```
🧠 ML Strategy Selection Performance:

Processing Speed:
Instructions/sec:        19.3 inst/sec       ████████████░░░░░░░░░░░░░
Total Instructions:      20,535
Session Duration:        1,065 seconds

Null-Byte Elimination:
Eliminated:              17,087/20,535       █████████████████████░░░░   83.21%
Strategies Applied:      19,904
Success Rate:            85.84%              █████████████████████░░░░   85.84%

Learning Progress:
Positive Feedback:       17,087              ████████████████████░░░░░   85.84%
Negative Feedback:       2,817               ███░░░░░░░░░░░░░░░░░░░░░░   14.16%
Total Iterations:        40,439
Avg Confidence:          0.1307              ███░░░░░░░░░░░░░░░░░░░░░░   13.07%
```

```
🏆 Top Performing Denullification Strategies:

Strategy                                  Attempts    Success%    Confidence
--------                                  --------    --------    ----------
ret_immediate                                  134    ████████████░░░░░░░░░░░░░   50.00%
transform_add_mem_reg8                        2012    ██████████░░░░░░░░░░░░░░░   43.69%
cmp_mem_reg_null                                96    ██████████░░░░░░░░░░░░░░░   45.83%
MOVZX/MOVSX Null-Byte Elimination              162    █████████░░░░░░░░░░░░░░░░   45.06%
Unicode STOSW Byte-by-Byte                      86    ███████░░░░░░░░░░░░░░░░░░   34.88%
lea_disp_null                                 3850    ███████░░░░░░░░░░░░░░░░░░   30.36%
cmp_reg_imm_null                               796    █████░░░░░░░░░░░░░░░░░░░░   23.49%
generic_mem_null_disp_enhanced              21880    █████░░░░░░░░░░░░░░░░░░░░   20.34%
ModRM Byte Null Bypass                          82    ████░░░░░░░░░░░░░░░░░░░░░   17.07%
SALC with Flag Setup                          1654    ████░░░░░░░░░░░░░░░░░░░░░   16.87%
Shift-Based Value Construction                2830    ███░░░░░░░░░░░░░░░░░░░░░░   15.62%
conservative_arithmetic                       5142    ███░░░░░░░░░░░░░░░░░░░░░░   15.95%
Stack-Based Structure Construction            7558    ███░░░░░░░░░░░░░░░░░░░░░░   12.70%
Multi-Stage PEB Traversal                     9936    ██░░░░░░░░░░░░░░░░░░░░░░░   11.36%
LEA with Complex Addressing                   3568    ██░░░░░░░░░░░░░░░░░░░░░░░   11.35%
```

```
⚡ Processing Efficiency:

Learning Rate:           1.97 feedback/instruction
Weight Update Avg:       0.042650
Weight Update Max:       0.100000
Total Weight Updates:    1724.68

Strategy Coverage:
Total Strategies:        120+
Strategies Activated:    115                 ████████████████████████░   95.83%
Zero-Attempt:            5                   █░░░░░░░░░░░░░░░░░░░░░░░░   04.17%
```

### Obfuscation Layer
`--biphasic` mode adds anti-analysis obfuscation prior to denulling:
- Control flow flattening
- Dispatcher patterns
- Register reassignment
- State obfuscation
- Dead code insertion
- NOP sleds
- Instruction substitution
- Equivalent operations
- Stack frame manipulation
- API resolution hiding
- String Encoding
- Constant Encoding
- Anti-debugging
- VM detection techniques

### ML-Powered Strategy Selection (Experimental)
- Extracts 128 features per instruction
- 3-layer feedforward neural network for dynamic ranking
- Adaptive learning from success/failure feedback
- Tracks predictions, accuracy, and confidence
- Graceful fallback to deterministic ordering
- **Note**: ML mode is experimental and may reduce success rate; use `--ml` flag to enable (disabled by default)

### Batch Processing
- Recursive directory traversal (`-r`)
- Custom file patterns (`--pattern "*.bin"`)
- Structure preservation or flattening
- Continue-on-error or strict modes
- Compatible with all options (biphasic, PIC, `XOR`, etc.)

### Output Options
- Formats: raw binary, `C` array, Python bytes, hex string
- `XOR` encoding with decoder stub (`--xor-encode 0xDEADBEEF`)
- Position-independent code (`--pic`)
- Automatic output directory creation

### Verification Suite
Python tools for validation:
- `verify_denulled.py`: Ensures zero null bytes
- `verify_functionality.py`: Checks execution patterns
- `verify_semantic.py`: Validates equivalence

## Architecture

byvalver employs a modular strategy-pattern design:
- Pass 1: (Optional) Obfuscation for anti-analysis
- Pass 2: Denullification for null-byte removal
- ML layer for strategy optimization
- Batch system for scalable processing

<div align="center">
  <img src="./images/bv1.png" alt="Main Framework" width="800">
</div>

<div align="center">
  <img src="./images/bv5.png" alt="ML Integration" width="800">
</div>

## System Requirements

- **OS**: Linux (Ubuntu/Debian/Fedora), macOS (with Homebrew), Windows (via WSL/MSYS2)
- **CPU**: x86/x64 with modern instructions
- **RAM**: 1GB free
- **Disk**: 50MB free
- **Tools**: `C` compiler, Make, Git (recommended)

## Dependencies

- **Core**: GCC/Clang, GNU Make, `Capstone` (v4.0+), `NASM` (v2.13+), xxd
- **Optional**: Clang-Format, Cppcheck, Valgrind
- **ML Training**: Math libraries (included)

### Installation Commands

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install build-essential `NASM` xxd pkg-config lib`Capstone`-dev clang-format cppcheck valgrind
```

**macOS (Homebrew):**
```bash
brew install `Capstone` `NASM` vim
```

**Windows (WSL):**
Same as Ubuntu/Debian.

## Building

Use the Makefile for builds:

- Default: `make` (optimized executable)
- Debug: `make debug` (symbols, sanitizers)
- Release: `make release` (-O3, native)
- Static: `make static` (self-contained)
- ML Trainer: `make train` (bin/train_model)
- Clean: `make clean` or `make clean-all`

Customization:
```bash
make CC=clang CFLAGS="-O3 -march=native"
```

View config: `make info`

## Installation

Global install:
```bash
sudo make install
sudo make install-man
```

Uninstall:
```bash
sudo make uninstall
```

From GitHub:
```bash
curl -sSL https://raw.githubusercontent.com/umpolungfish/byvalver/main/install.sh | bash
```

## Usage

```bash
byvalver [OPTIONS] <input> [output]
```

- Input/output can be files or directories (auto-batch)

**Key Options:**
- `-h, --help`: Help
- `-v, --version`: Version
- `-V, --verbose`: Verbose
- `-q, --quiet`: Quiet
- `--biphasic`: Obfuscate + denull
- `--pic`: Position-independent
- `--ml`: ML strategy selection
- `--xor-encode KEY`: `XOR` with stub
- `--format FORMAT`: raw|c|python|hexstring
- `-r, --recursive`: Recursive batch
- `--pattern PATTERN`: File glob
- `--no-preserve-structure`: Flatten output
- `--no-continue-on-error`: Stop on error

**Examples:**
```bash
byvalver shellcode.bin clean.bin
byvalver --biphasic --ml --`xor`-encode 0xCAFEBABE input.bin output.bin
byvalver -r --pattern "*.bin" shellcodes/ output/
```

## Obfuscation Strategies

byvalver's obfuscation pass (enabled via `--biphasic`) applies anti-analysis techniques:

### Core Obfuscation Techniques

- **`MOV Register Exchange`**: `XCHG`/push-pop patterns
- **`MOV Immediate`**: Arithmetic decomposition
- **`Arithmetic Substitution`**: Complex equivalents
- **`Memory Access`**: Indirection and `LEA`
- **`Stack Operations`**: Manual `ESP` handling
- **`Conditional Jumps`**: `SETcc` and moves
- **`Unconditional Jumps`**: Indirect mechanisms
- **`Calls`**: `PUSH` + `JMP`
- **`Control Flow Flattening`**: Dispatcher states
- **`Instruction Substitution`**: Equivalent ops
- **`Dead Code`**: Harmless insertions
- **`Register Reassignment`**: Data flow hiding
- **`Multiplication by One`**: `IMUL` patterns
- **`NOP Sleds`**: Variable padding
- **`Jump Decoys`**: Fake targets
- **`Relative Offsets`**: Calculated jumps
- **`Switch-Based`**: Computed flow
- **`Boolean Expressions`**: De Morgan equivalents
- **`Variable Encoding`**: Reversible transforms
- **`Timing Variations`**: Delays
- **`Register State`**: Complex manipulations
- **`Stack Frames`**: Custom management
- **`API Resolution`**: Complex hashing
- **`String Encoding`**: Runtime decoding
- **`Constants`**: Expression generation
- **`Debugger Detection`**: Obfuscated checks
- **`VM Detection`**: Concealed methods

Priorities favor anti-analysis (high) over simple substitutions (low).

See ![OBFUSCATION_STRATS](docs/OBFUSCATION_STRATS.md) for detailed strategy documentation.

## Denullification Strategies

The core denull pass uses over 120 strategies:

### `MOV` Strategies
- Original pass-through
- `NEG`, `NOT`, `XOR`, `Shift`, `ADD/SUB` decompositions

### Arithmetic
- Original, `NEG`, `XOR`, `ADD/SUB`

### Jumps/Control
- `CALL/JMP` indirects
- Generic memory displacement
- Conditional offset elimination

### Advanced
- ModR/M bypass
- Flag-preserving `TEST`
- `SIB` addressing
- `PUSH` optimizations
- Windows-specific: `CALL/POP`, `PEB` hashing, `SALC`, `LEA` arithmetic, `shifts`, stack strings, etc.

### Memory/Displacement
- Displacement null handling
- `LEA` alternatives

Strategies are prioritized and selected via ML or deterministic order  

The modular registry allows easy addition of new strategies to handle emerging shellcode patterns.

See ![DENULL_STRATS](docs/DENULL_STRATS.md) for detailed strategy documentation.

## ML Training

Build trainer: `make train`

Run: `./bin/train_model`

- Data: `./shellcodes/`
- Output: `./ml_models/byvalver_ml_model.bin`
- Config: 10k samples, 50 epochs, 20% validation, LR 0.001, batch 32

Model auto-loaded at runtime with path resolution.

## Development

- Modern `C` with modularity
- Test suite: `python3 test_all_bins.py`
- Code style: Clang-Format
- Analysis: Cppcheck, Valgrind

## Troubleshooting

- Dependencies: Verify `Capstone`/`NASM`/xxd
- Builds: Check PATH_MAX, headers
- ML: Ensure model path
- Nulls: Confirm input format, dependencies

For persistent issues, use verbose mode and check logs  

If denulling fails on specific shellcode, consider adding targeted strategies to the registry.

## License

byvalver is sicced freely upon the Earth under the ![UNLICENSE](./UNLICENSE).

</DOCUMENT>