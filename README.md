<DOCUMENT filename="README.md">
# byvalver

## NULL-BYTE ELIMINATION FRAMEWORK

<div align="center">
  <img src="./images/byvalver_logo.png" alt="byvalver logo" width="400">
</div>

<div align="center">
  <img src="https://img.shields.io/badge/C-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white" alt="C">
  <img src="https://img.shields.io/badge/Shellcode-Analysis-%23FF6B6B.svg?style=for-the-badge" alt="Shellcode Analysis">
  <img src="https://img.shields.io/badge/Cross--Platform-Windows%20%7C%20Linux%20%7C%20macOS-%230071C5.svg?style=for-the-badge" alt="Cross-Platform">
  <img src="https://img.shields.io/badge/Security-Hardened-%23000000.svg?style=for-the-badge" alt="Security Hardened">
  <img src="https://img.shields.io/badge/Denulling%20Success-100%25-brightgreen.svg?style=for-the-badge" alt="100% Denulling Success">
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

**byvalver** is a x-platform command-line tool built in C for automatically eliminating null bytes (`\x00`) from x86/x64 shellcode while maintaining complete functional equivalence  

It achieves **~100% null-free output across diverse, real-world shellcode test suites**, including complex Windows payloads that challenge simpler tools

The tool uses the Capstone disassembly framework to analyze instructions and applies over 120 ranked transformation strategies to replace null-containing code with equivalent alternatives  

**Core Technologies:**
- Pure C implementation for efficiency and low-level control
- Capstone for precise disassembly
- NASM for generating decoder stubs
- Modular strategy pattern for extensible transformations
- Neural network integration for intelligent strategy selection
- Biphasic processing: Obfuscation followed by denullification

byvalver is ideal for working with shellcode that must avoid null bytes for string operations or memory constraints.

## Features

### ~100% Denulling Success
<div align="center">
  <strong>Perfect null-byte elimination on the entire test corpus – no remaining nulls, no functionality loss, no compromises.</strong>
</div>

byvalver delivers **100% success** on production-grade shellcode samples, handling PEB walking, hashed API resolution, SIB addressing, and intricate immediate/displacement patterns without fail.

### Advanced Transformation Engine
Over 120 meticulously crafted strategies covering all common null-byte sources:
- CALL/POP and stack-based immediate loading
- PEB traversal with hashed API resolution
- SALC, XCHG, and flag-based zeroing
- LEA for arithmetic substitution
- Shift and arithmetic value construction
- Multi-PUSH string building
- SIB and displacement rewriting
- Conditional jump displacement handling
- Register remapping and chaining
- Comprehensive support for MOV, ADD/SUB, XOR, LEA, CMP, PUSH, and more

The engine employs multi-pass processing (obfuscation → denulling) with robust fallback mechanisms for edge cases.

### Obfuscation Layer
Optional biphasic mode adds anti-analysis obfuscation before denulling:
- Control flow flattening and dispatcher patterns
- Register reassignment and state obfuscation
- Dead code insertion and NOP sleds
- Instruction substitution and equivalent operations
- Stack frame manipulation and API resolution hiding
- String and constant encoding
- Anti-debugging and VM detection techniques

### ML-Powered Strategy Selection
- Extracts 128 features per instruction
- 3-layer feedforward neural network for dynamic ranking
- Adaptive learning from success/failure feedback
- Tracks predictions, accuracy, and confidence
- Graceful fallback to deterministic ordering

### Batch Processing
- Recursive directory traversal (`-r`)
- Custom file patterns (`--pattern "*.bin"`)
- Structure preservation or flattening
- Continue-on-error or strict modes
- Compatible with all options (biphasic, PIC, XOR, etc.)

### Output Options
- Formats: raw binary, C array, Python bytes, hex string
- XOR encoding with decoder stub (`--xor-encode 0xDEADBEEF`)
- Position-independent code (`--pic`)
- Automatic output directory creation

### Verification Suite
Python tools for validation:
- `verify_denulled.py`: Ensures zero null bytes
- `verify_functionality.py`: Checks execution patterns
- `verify_semantic.py`: Validates equivalence

## Architecture

byvalver employs a modular strategy-pattern design:

<div align="center">
  <img src="./images/bv1.png" alt="Main Framework" width="800">
  <img src="./images/bv5.png" alt="ML Integration" width="800">
</div>

- Pass 1 (Optional): Obfuscation for anti-analysis
- Pass 2: Denullification for null-byte removal
- ML layer for strategy optimization
- Batch system for scalable processing

## System Requirements

- **OS**: Linux (Ubuntu/Debian/Fedora), macOS (with Homebrew), Windows (via WSL/MSYS2)
- **CPU**: x86/x64 with modern instructions
- **RAM**: 1GB free
- **Disk**: 50MB free
- **Tools**: C compiler, Make, Git (recommended)

## Dependencies

- **Core**: GCC/Clang, GNU Make, Capstone (v4.0+), NASM (v2.13+), xxd
- **Optional**: Clang-Format, Cppcheck, Valgrind
- **ML Training**: Math libraries (included)

### Installation Commands

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install build-essential nasm xxd pkg-config libcapstone-dev clang-format cppcheck valgrind
```

**macOS (Homebrew):**
```bash
brew install capstone nasm vim
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
curl -sSL https://raw.githubusercontent.com/mrnob0dy666/byvalver/main/install.sh | bash
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
- `--xor-encode KEY`: XOR with stub
- `--format FORMAT`: raw|c|python|hexstring
- `-r, --recursive`: Recursive batch
- `--pattern PATTERN`: File glob
- `--no-preserve-structure`: Flatten output
- `--no-continue-on-error`: Stop on error

**Examples:**
```bash
byvalver shellcode.bin clean.bin
byvalver --biphasic --ml --xor-encode 0xCAFEBABE input.bin output.bin
byvalver -r --pattern "*.bin" shellcodes/ output/
```

## Obfuscation Strategies

byvalver's obfuscation pass (enabled via `--biphasic`) applies anti-analysis techniques:

- **MOV Register Exchange**: XCHG/push-pop patterns
- **MOV Immediate**: Arithmetic decomposition
- **Arithmetic Substitution**: Complex equivalents
- **Memory Access**: Indirection and LEA
- **Stack Operations**: Manual ESP handling
- **Conditional Jumps**: SETcc and moves
- **Unconditional Jumps**: Indirect mechanisms
- **Calls**: PUSH + JMP
- **Control Flow Flattening**: Dispatcher states
- **Instruction Substitution**: Equivalent ops
- **Dead Code**: Harmless insertions
- **Register Reassignment**: Data flow hiding
- **Multiplication by One**: IMUL patterns
- **NOP Sleds**: Variable padding
- **Jump Decoys**: Fake targets
- **Relative Offsets**: Calculated jumps
- **Switch-Based**: Computed flow
- **Boolean Expressions**: De Morgan equivalents
- **Variable Encoding**: Reversible transforms
- **Timing Variations**: Delays
- **Register State**: Complex manipulations
- **Stack Frames**: Custom management
- **API Resolution**: Complex hashing
- **String Encoding**: Runtime decoding
- **Constants**: Expression generation
- **Debugger Detection**: Obfuscated checks
- **VM Detection**: Concealed methods

Priorities favor anti-analysis (high) over simple substitutions (low).

## Denullification Strategies

The core denull pass uses over 120 strategies:

### MOV Strategies
- Original pass-through
- NEG, NOT, XOR, Shift, ADD/SUB decompositions

### Arithmetic
- Original, NEG, XOR, ADD/SUB

### Jumps/Control
- CALL/JMP indirects
- Generic memory displacement
- Conditional offset elimination

### Advanced
- ModR/M bypass
- Flag-preserving TEST
- SIB addressing
- PUSH optimizations
- Windows-specific: CALL/POP, PEB hashing, SALC, LEA arithmetic, shifts, stack strings, etc.

### Memory/Displacement
- Displacement null handling
- LEA alternatives

Strategies are prioritized and selected via ML or deterministic order.

## ML Training

Build trainer: `make train`

Run: `./bin/train_model`

- Data: `./shellcodes/`
- Output: `./ml_models/byvalver_ml_model.bin`
- Config: 10k samples, 50 epochs, 20% validation, LR 0.001, batch 32

Model auto-loaded at runtime with path resolution.

## Development

- Modern C with modularity
- Test suite: `python3 test_all_bins.py`
- Code style: Clang-Format
- Analysis: Cppcheck, Valgrind

## Troubleshooting

- Dependencies: Verify Capstone/NASM/xxd
- Builds: Check PATH_MAX, headers
- ML: Ensure model path
- Nulls: Confirm input format, dependencies

For persistent issues, use verbose mode and check logs.

## License

byvalver is released into the public domain under the Unlicense.

</DOCUMENT>