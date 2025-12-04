# BYVALVER - Null-Byte Elimination Framework

## Project Overview

BYVALVER is an advanced C-based command-line tool designed for automated removal of null bytes from shellcode while preserving functional equivalence. The tool leverages the Capstone disassembly framework to analyze x86/x64 assembly instructions and applies sophisticated transformation strategies to replace null-containing instructions with functionally equivalent alternatives.

**Primary Function:** Remove null bytes (`\\x00`) from binary shellcode that would otherwise cause issues with string-based operations or memory management routines.

**Technology Stack:**
- C language implementation for performance and low-level control
- Capstone Disassembly Framework for instruction analysis
- NASM assembler for building decoder stubs
- x86/x64 assembly and instruction set knowledge
- Modular strategy pattern for extensible transformations

**Architecture:**
- Biphase processing: obfuscation pass followed by null-byte elimination pass
- Strategy registry system with 80+ transformation strategies
- XOR-encoding capability with decoder stubs
- Anti-analysis features for resilience against debugging

## Building and Running

### Dependencies
- C compiler (e.g., `gcc`)
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

# Or manually install Capstone from https://github.com/capstone-engine/capstone
```

### Build Commands
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

### Usage Examples
```bash
# Basic usage: process input.bin and output to output.bin
./bin/byvalver input.bin output.bin

# Enable biphasic processing (obfuscation + null-byte elimination)
./bin/byvalver --biphasic input.bin output.bin

# XOR encode output with 4-byte key (hex)
./bin/byvalver --biphasic --xor-encode 0x12345678 input.bin output.bin

# Process shellcode with only null-byte elimination
./bin/byvalver input.bin output.bin
```

### Testing
```bash
# Run basic functionality test
make test

# Check dependencies
make check-deps

# Format code (if clang-format is available)
make format

# Run static analysis (if cppcheck is available)
make lint
```

## Development Conventions

### Architecture Principles
- **Strategy Pattern**: Each transformation follows a common interface (`can_handle`, `get_size`, `generate`)
- **Modular Design**: Separate source files for different instruction types and strategies
- **Null-free Guarantee**: All strategies must produce null-byte free output
- **Functional Preservation**: All transformations must maintain semantic equivalence

### Code Structure
- `src/`: Main source files organized by instruction strategy type
- `src/main.c`: Command-line interface and argument parsing
- `src/core.c`: Core processing engine with disassembly and instruction handling
- `src/byvalver.h`: Public API header file
- `src/strategy_registry.c`: Registry for null-elimination strategies
- `src/obfuscation_strategy_registry.c`: Registry for obfuscation strategies
- `decoder.asm`: Assembly source for XOR decoder stub
- `decoder.h`: Generated header containing decoder binary
- `tests/`: Verification scripts
- `shellcodes/`: Example shellcode files for testing

### Strategy Development
- New strategies must implement the `strategy_t` interface
- Strategies are registered in `strategy_registry.c` or `obfuscation_strategy_registry.c`
- Priority system (higher numbers = higher priority) for conflict resolution
- Strategies must be thoroughly tested for null-byte introduction

### Testing and Verification
- Python scripts available for verification of null-byte elimination
- Comprehensive test suite in `test_all_bins.py` for batch processing
- Semantic verification through CPU state comparison (not implemented in this basic version)

## Key Features

### Advanced Transformation Engine
- 80+ instruction transformation strategies
- Handles complex instructions including arithmetic, MOV, conditional jumps, and API calls
- Support for Windows API resolution patterns with SIB addressing
- Sophisticated instruction rewriting to eliminate null bytes

### Biphase Processing
- **Pass 1**: Obfuscation & complexification of shellcode to increase analytical difficulty
- **Pass 2**: Null-byte elimination on the obfuscated code
- Clear separation of obfuscation and sanitization concerns

### XOR Encoding with Decoder Stub
- Automatic prepending of JMP-CALL-POP decoder stub
- 4-byte XOR key support with encoded length information
- Multi-byte XOR key cycling for enhanced obfuscation

### Anti-Analysis Features
- PEB-based debugger detection
- Timing-based anti-debugging using RDTSC
- INT3-based debugger identification
- VM and sandbox detection capabilities

### Extensible Architecture
- Easy addition of new transformation strategies
- Priority-based strategy selection system
- Modular codebase for maintainability
- Comprehensive error handling and reporting

### Verification Tools
- Python-based verification scripts for null-byte detection
- Batch processing capabilities with detailed statistics
- Performance monitoring and execution time tracking

## Project Context

BYVALVER is part of a larger offensive toolchain that includes `purl_diver` (shellcode extraction from PE files) and `toxoglosser` (stealthy process injection on Windows). This toolchain represents a modular approach to payload preparation and execution, addressing critical challenges in modern offensive operations including payload generation, obfuscation, integrity preservation, and stealthy execution against advanced defenses.

The tool is specifically designed for cybersecurity professionals working in penetration testing, red team operations, and malware research contexts. It enables rapid iteration on payloads by automating the tedious and error-prone process of manual null-byte elimination in shellcode.