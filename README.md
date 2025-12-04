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

## Architecture

### Biphase Processing
- **Pass 1**: Obfuscation & complexification of shellcode to increase analytical difficulty
- **Pass 2**: Null-byte elimination on the obfuscated code
- Clear separation of obfuscation and sanitization concerns

### Strategy Registry System
BYVALVER implements a comprehensive registry of 80+ transformation strategies that handle different types of x86/x64 instructions:

#### MOV Instruction Strategies
- Direct register-to-register MOV transformations
- MOV with immediate value decomposition
- MOV through arithmetic operations
- Memory-based MOV transformations
- Conditional MOV handling

#### Arithmetic Instruction Strategies
- ADD/SUB instruction substitution
- MUL/IMUL transformations
- AND/OR/XOR equivalent operations
- INC/DEC replacement patterns
- Complex arithmetic decomposition

#### Jump and Control Flow Strategies
- Conditional jump rewrites
- Direct jump replacements
- Call instruction transformations
- Loop instruction modifications
- Relative/absolute jump handling

#### Specialized Strategies
- API hashing and resolution patterns
- PEB (Process Environment Block) access transformations
- Anti-debugging instruction handling
- FPU (Floating Point Unit) instruction replacement
- System call instruction modifications

### Position Independent Code (PIC) Generation
BYVALVER now features Windows-specific Position Independent Code generation with the following capabilities:

- **JMP-CALL-POP technique**: Get current EIP/RIP register value for position-independent access
- **API Hash Resolution**: Runtime resolution of Windows APIs using hash-based name lookup
- **PEB-based API Discovery**: Locate kernel32.dll base address and enumerate exported functions
- **Anti-Debugging Features**: Built-in checks to detect debugging environments
- **PIC Shellcode Generation**: Convert regular shellcode to position-independent format

#### API Hashing Algorithm
The PIC generation module implements a robust hash algorithm for Windows API resolution:
- Uses modified djb2 hash function for API names
- Runtime lookup from kernel32.dll export table
- No dependency on import address table (IAT)

#### Generated PIC Stub Structure
When using `--pic`, the tool generates:
1. **JMP-CALL-POP stub** for EIP access
2. **PEB traversal code** to find kernel32.dll
3. **Hash-based API resolver** for runtime function calls
4. **Position-independent payload** with null-byte elimination

#### PIC Generation Strategies
- Automated EIP-relative addressing
- Hash-based API resolution (no import table dependencies)
- Runtime kernel32.dll base address discovery
- Stack-based string construction for API names
- Self-contained PIC stubs with minimal dependencies

### Position Independent Code (PIC) Integration
The PIC generation feature seamlessly integrates with existing functionality:

- Works with biphasic processing (obfuscation + null-byte elimination)
- Compatible with XOR encoding and decoder stubs
- Maintains all existing null-byte elimination guarantees
- Preserves functional equivalence while adding position independence

### XOR-Encoding Capability
- Automatic prepending of JMP-CALL-POP decoder stub
- 4-byte XOR key support with encoded length information
- Multi-byte XOR key cycling for enhanced obfuscation
- Null-free decoder stub implementation

### Anti-Analysis Features
- PEB-based debugger detection
- Timing-based anti-debugging using RDTSC
- INT3-based debugger identification
- VM and sandbox detection capabilities

## Installation and Setup

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

## Usage Guide

### Basic Usage
```bash
# Basic usage: process input.bin and output to output.bin
./bin/byvalver input.bin output.bin

# Enable biphasic processing (obfuscation + null-byte elimination)
./bin/byvalver --biphasic input.bin output.bin

# XOR encode output with 4-byte key (hex)
./bin/byvalver --biphasic --xor-encode 0x12345678 input.bin output.bin

# Generate position-independent code (new feature)
./bin/byvalver --pic input.bin output.bin

# Generate PIC code with XOR encoding
./bin/byvalver --pic --xor-encode 0x12345678 input.bin output.bin

# Generate PIC code with biphasic processing (obfuscation + null-byte elimination)
./bin/byvalver --pic --biphasic input.bin output.bin

# Generate PIC code with biphasic processing and XOR encoding
./bin/byvalver --pic --biphasic --xor-encode 0x12345678 input.bin output.bin

# Process shellcode with only null-byte elimination
./bin/byvalver input.bin output.bin
```

### Advanced Usage Examples
```bash
# Process with detailed output
./bin/byvalver --biphasic input.bin output.bin

# Create XOR-encoded shellcode with custom key
./bin/byvalver --biphasic --xor-encode 0xDEADBEEF shellcode.bin encoded.bin

# Process without obfuscation but with XOR encoding
./bin/byvalver --xor-encode 0x12345678 input.bin output.bin
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

## Key Features Explained

### Advanced Transformation Engine
- 80+ instruction transformation strategies
- Handles complex instructions including arithmetic, MOV, conditional jumps, and API calls
- Support for Windows API resolution patterns with SIB addressing
- Sophisticated instruction rewriting to eliminate null bytes

Each transformation strategy implements a standard interface:

```c
typedef struct {
    const char* name;                           // Strategy name for identification
    int (*can_handle)(cs_insn *insn);          // Function to check if strategy can handle instruction
    size_t (*get_size)(cs_insn *insn);         // Function to calculate new size
    void (*generate)(struct buffer *b, cs_insn *insn);  // Function to generate new code
    int priority;                              // Priority for strategy selection (higher = more preferred)
} strategy_t;
```

The system automatically selects the most appropriate strategy based on priority and applicability.

### Biphase Processing Architecture
The two-pass approach provides enhanced obfuscation:

**Pass 1 - Obfuscation:**
- Applies complex patterns to obscure the original intent
- Increases analytical difficulty for reverse engineers
- Implements anti-analysis features
- Adds noise and complexity without changing functionality

**Pass 2 - Null-byte Elimination:**
- Processes the obfuscated code to remove null bytes
- Maintains all obfuscation benefits from Pass 1
- Applies transformation strategies to eliminate nulls
- Preserves functional equivalence throughout

### XOR Encoding Implementation
The XOR encoding feature includes a sophisticated decoder stub:

```assembly
; JMP-CALL-POP Multi-byte XOR decoder stub
; This stub will be prepended to the encoded shellcode.
; The XOR key (4 bytes) and encoded shellcode length (4 bytes) will immediately follow the 'call decoder' instruction.

BITS 32

%define NULL_FREE_LENGTH_XOR_KEY 0x11223344

_start:
    jmp short call_decoder

decoder:
    pop esi             ; ESI = address of XOR key and encoded length
    mov ebx, dword [esi] ; Load 4-byte key into EBX
    mov ecx, dword [esi+4] ; Load encoded shellcode length into ECX
    xor ecx, NULL_FREE_LENGTH_XOR_KEY ; Decode actual length
    add esi, 8          ; ESI = start of actual encoded shellcode

    xor edx, edx        ; EDX = 0 (counter for key bytes)

decode_loop:
    mov eax, ebx        ; Copy key to EAX
    mov cl, dl          ; CL = DL (current key byte index)
    shl cl, 3           ; CL = DL * 8
    shr eax, cl         ; Shift right by (dl * 8) bits

    xor byte [esi], al  ; XOR current shellcode byte with AL
    inc esi             ; Move to next shellcode byte
    inc edx             ; Increment key byte counter
    and edx, 0x03       ; EDX = EDX % 4 (to cycle through 4-byte key)
    dec ecx             ; Decrement shellcode length counter
    jnz decode_loop     ; Loop until all bytes are decoded

    jmp esi             ; Jump to decoded shellcode

call_decoder:
    call decoder
    ; Encoded shellcode follows here
```

### Anti-Analysis Features
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

### Extensible Architecture
- Easy addition of new transformation strategies
- Priority-based strategy selection system
- Modular codebase for maintainability
- Comprehensive error handling and reporting

## Testing and Verification

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

## Project Context

BYVALVER is part of a larger offensive toolchain that includes `purl_diver` (shellcode extraction from PE files) and `toxoglosser` (stealthy process injection on Windows). This toolchain represents a modular approach to payload preparation and execution, addressing critical challenges in modern offensive operations including payload generation, obfuscation, integrity preservation, and stealthy execution against advanced defenses.

The tool is specifically designed for cybersecurity professionals working in penetration testing, red team operations, and malware research contexts. It enables rapid iteration on payloads by automating the tedious and error-prone process of manual null-byte elimination in shellcode.

## Troubleshooting

### Common Issues
If you encounter issues during build:

**Missing Dependencies:**
```bash
make check-deps
```

**Build Failures:**
- Check that all dependencies are properly installed
- Verify the Capstone library is accessible
- Ensure NASM and xxd utilities are available

### Verification of Results
After processing, you can verify that null bytes have been eliminated:
```bash
# Check for null bytes in output
hexdump -C output.bin | grep "00 "
```

## Contributing

### Adding New Strategies
To add a new transformation strategy:

1. Create a new source file with your strategy implementation
2. Implement the `strategy_t` interface functions
3. Register your strategy in the appropriate registry file
4. Test thoroughly to ensure no null bytes are introduced
5. Verify functional equivalence is maintained

### Testing New Code
- Always test new strategies against multiple input shellcode samples
- Verify null-byte elimination is complete
- Check that functionality is preserved
- Test with both simple and complex shellcode

## Performance Considerations

### Processing Time
- Simple shellcode: < 1 second
- Complex shellcode: Up to several seconds
- Large shellcode files: May require several minutes

### Memory Usage
- Memory usage scales with input size
- Recommended to have at least 10x input size in available RAM
- Some complex transformations may require additional temporary memory

### Output Size
- Output shellcode may be larger than input due to transformations
- Size increase depends on the complexity of null-byte elimination required
- Typically 10-50% size increase for heavily null-contaminated input