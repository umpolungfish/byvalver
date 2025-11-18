# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**byvalver** is an automated shellcode null-byte elimination framework built on the Capstone disassembly library. It removes null bytes (`\x00`) from x86/x86_64 shellcode while preserving functional compatibility through sophisticated instruction-level transformations.

This is a **security research and educational tool** for:
- Authorized penetration testing engagements
- CTF competitions
- Security research
- Defensive security analysis
- Shellcode analysis and understanding

**IMPORTANT**: This is an analysis and defensive security tool. When working with this codebase, you can analyze, fix bugs, add features, and improve the null-byte elimination strategies. However, maintain awareness that this handles shellcode and should only be used in authorized contexts.

## Build System

### Primary Commands

```bash
# Build the main executable
make                    # Standard build → bin/byvalver
make clean             # Remove build artifacts
make all               # Build including decoder.h generation

# Build configurations
make debug             # Build with debug symbols and sanitizers
make release           # Optimized release build
make static            # Static linking

# Testing and verification
make test              # Build and run test suite
python3 verify_nulls.py <file.bin>              # Check for null bytes
python3 verify_functionality.py <in> <out>       # Verify functionality preservation

# Development tools
make format            # Format code with clang-format or astyle
make lint              # Static analysis with cppcheck
make check-deps        # Verify build dependencies

# Build options
make VERBOSE=1         # Enable verbose build output
make DEBUG=1           # Alternative debug build
```

### Build Dependencies

- C compiler (gcc)
- Capstone disassembly library with development headers
- NASM assembler (for decoder stub generation)
- GNU Binutils (objcopy, for extracting shellcode from executables)
- xxd (for generating decoder.h from decoder.bin)

### Build Process Details

The build system has a special two-step process for the XOR decoder:
1. `decoder.asm` → `decoder.bin` (assembled with NASM)
2. `decoder.bin` → `decoder.h` (converted to C header with xxd)

The Makefile includes rules for backward compatibility with `fix_*.c` files that override main strategy files when present.

## Usage

### Basic Usage

```bash
# Process shellcode to remove null bytes
./bin/byvalver <input_shellcode.bin> [output.bin]

# Process with XOR encoding
./bin/byvalver --xor-encode 0x12345678 <input.bin> [output.bin]
```

### Working with Executables

byvalver works with **raw binary shellcode**. Extract code sections from executables first:

```bash
# Extract .text section from PE/ELF
objcopy -O binary --only-section=.text executable.exe shellcode.bin

# Process the extracted shellcode
./bin/byvalver shellcode.bin
```

### XOR Encoding Feature

The `--xor-encode` flag adds an XOR decoder stub to the output:
- Takes a 32-bit hexadecimal key (e.g., `0x12345678`)
- Prepends a JMP-CALL-POP decoder stub from `decoder.asm`
- Encodes the processed shellcode with the XOR key
- Decoder stub retrieves the key and decodes at runtime

## Architecture

### Core Design Pattern: Strategy-Based Transformation

byvalver uses a **strategy pattern** with priority-based selection for instruction transformations. Each strategy implements a consistent interface:

```c
typedef struct {
    const char* name;
    int (*can_handle)(cs_insn *insn);      // Can this strategy handle this instruction?
    size_t (*get_size)(cs_insn *insn);     // Calculate replacement size
    void (*generate)(struct buffer *b, cs_insn *insn);  // Generate null-free code
    int priority;                           // Higher = more preferred
} strategy_t;
```

### Processing Pipeline (Multi-Pass Architecture)

1. **Disassembly Pass**: Capstone disassembles shellcode into linked list of instruction nodes
2. **Sizing Pass**: For each instruction, select strategy and calculate `new_size`
3. **Offset Calculation Pass**: Compute `new_offset` for each instruction (critical for patching relative jumps/calls)
4. **Generation & Patching Pass**: Generate null-free replacements, patch relative jumps/calls with new offsets
5. **Output**: Write null-free shellcode to file

### Core Components

| Component | File | Purpose |
|-----------|------|---------|
| **Main Entry** | `src/main.c` | CLI, file I/O, XOR encoding integration |
| **Core Engine** | `src/core.c` | Multi-pass processing, strategy selection |
| **Strategy Registry** | `src/strategy_registry.c` | Strategy collection management, `init_strategies()` |
| **Utilities** | `src/utils.c` | Shared helpers (register manipulation, buffer operations) |

### Strategy Modules (40+ strategies across 20+ modules)

- `src/mov_strategies.c` - MOV instruction replacements
- `src/arithmetic_strategies.c` - ADD, SUB, AND, OR, XOR, CMP
- `src/memory_strategies.c` - Memory operations with null-byte displacements
- `src/jump_strategies.c` - Jump and call transformations
- `src/general_strategies.c` - PUSH, general instructions
- `src/shift_strategy.c` - Shift-based immediate value construction
- `src/getpc_strategies.c` - Byte-by-byte construction for null-heavy immediates
- `src/anti_debug_strategies.c` - PEB checks, timing detection, INT3 detection
- `src/peb_strategies.c` - PEB traversal for kernel32.dll resolution
- `src/hash_utils.c` - ROR13 hash for API resolution
- `src/advanced_transformations.c` - Sophisticated ModR/M null-bypass, flag preservation
- `src/conservative_strategies.c` - Conservative transformations
- `src/lea_strategies.c` - LEA-based optimizations
- `src/context_preservation_strategies.c` - Context-aware transformations
- `src/sequence_preservation_strategies.c` - Multi-instruction pattern preservation

### Key Data Structures

```c
struct buffer {
    uint8_t *data;
    size_t size;
    size_t capacity;
};

struct instruction_node {
    cs_insn *insn;          // Capstone instruction
    size_t offset;          // Original offset
    size_t new_offset;      // Offset after transformation
    size_t new_size;        // Size after transformation
    struct instruction_node *next;
};
```

## Adding New Strategies

When implementing new transformation strategies:

1. **Create strategy module**: `src/new_strategy.c` and `src/new_strategy.h`
2. **Implement strategy interface**:
   - `can_handle(cs_insn *insn)` - Detection logic
   - `get_size(cs_insn *insn)` - Calculate replacement size
   - `generate(struct buffer *b, cs_insn *insn)` - Generate null-free bytes
3. **Define strategy struct** with name and priority
4. **Create registration function**: `register_new_strategy()`
5. **Register in strategy_registry.c**:
   - Forward declare `register_new_strategy()`
   - Call in `init_strategies()`
6. **Add to Makefile**: Add source file to `MAIN_SRCS`
7. **Test thoroughly**: Create test shellcode with `.tests/` scripts

### Strategy Priority Guidelines

- **100+**: Critical optimizations, context-aware transformations
- **50-99**: Standard null-byte elimination strategies
- **25-49**: Fallback strategies for edge cases
- **1-24**: Low-priority experimental techniques

**Example**: The byte-by-byte construction strategy (`getpc_strategies.c`) has priority 25 because it's a fallback that works universally but produces larger code (2-3x expansion for null-heavy immediates).

## Key Transformation Techniques

### Immediate Value Construction

When `MOV reg, imm32` contains null bytes, byvalver tries (in priority order):
1. **Arithmetic equivalents**: Find `val1 ± val2 = imm` where both are null-free
2. **NEG operations**: Load `-imm`, then negate
3. **NOT operations**: Load `~imm`, then bitwise NOT
4. **XOR encoding**: Load `imm XOR key`, then XOR with key
5. **ADD/SUB encoding**: Load `imm + offset`, then subtract offset
6. **Shift-based**: Load shifted value, then shift back
7. **Byte-by-byte construction**: Build value using `SHL` + `OR AL, byte` (fallback, always works)

### Control Flow Preservation

- **Relative jumps/calls**: Automatically recalculated based on `new_offset` values
- **Conditional jumps**: All conditional jump types supported (JE, JNE, JZ, JL, JG, etc.)
- **Jump/call with null displacement**: Transformed to register-based indirect jumps

### Advanced Techniques

- **ModR/M null-bypass**: Use temporary registers when ModR/M byte would contain nulls
- **Flag preservation**: Ensure transformations maintain ZF, SF, PF flags (e.g., `TEST` → `OR`)
- **Register availability analysis**: Track which registers are safe to use as temporaries
- **SIB addressing**: Avoid null ModR/M bytes using SIB (Scale-Index-Base) addressing modes

## Testing

### Running Tests

```bash
# Run the built-in test suite
make test

# Strategy-specific testing (example: getpc strategy)
python3 .tests/test_getpc.py                    # Generate test shellcode
./bin/byvalver .test_bins/getpc_test.bin        # Process
python3 verify_nulls.py .test_bins/getpc_test_processed.bin  # Verify nulls removed
python3 verify_functionality.py .test_bins/getpc_test.bin .test_bins/getpc_test_processed.bin  # Verify logic preserved
```

### Verification Tools

- `verify_nulls.py`: Checks for null bytes in output
  - `--detailed` flag for comprehensive analysis
- `verify_functionality.py`: Compares logical operations between original and processed shellcode
  - Disassembles both and compares instruction semantics

## Known Limitations & Future Work

### Current Limitations

- **Relative jump/call size changes**: Assumes size doesn't change during transformation (e.g., `EB rel8` → `E9 rel32`)
- **Instruction coverage**: Many x86 instructions and addressing modes not yet covered
- **8-bit/16-bit focus**: Primarily optimized for 32-bit operations

### Future Enhancements

- Dynamic jump instruction size adjustment
- Expanded instruction coverage (especially x64-specific instructions)
- Enhanced 8-bit and 16-bit register support
- FNSTENV-based GET PC for true position-independent code
- Per-strategy performance benchmarking

## Important Notes for Development

### Code Quality Standards

- **Zero warnings**: All strategy modules compile with zero warnings (`-Wall -Wextra -Wpedantic`)
- **Strategy pattern consistency**: All strategies follow the same interface
- **Comprehensive testing**: Test new strategies with custom shellcode before integration

### Security Considerations

- byvalver is designed for authorized security testing and research
- The tool processes potentially malicious code but should only be used in controlled environments
- XOR encoding provides obfuscation, not cryptographic security

### Performance Characteristics

- **Expansion ratio**: Typically ~3.3x for mixed shellcode
- **Processing speed**: ~100ms for 150KB shellcode
- **Scalability**: Successfully handles shellcode up to 150KB+

## Documentation

- `README.md`: User-facing documentation, features, usage examples
- `DOCS/ADVANCED_STRATEGY_DEVELOPMENT.md`: Detailed strategy analysis, exploit-db research, implementation details
- `.qwen/PROJECT_SUMMARY.md`: Development history and current status

## Common Development Workflows

### Adding a New Transformation Strategy

1. Study real-world shellcode for inspiration (exploit-db collection analysis in DOCS/)
2. Implement strategy following the pattern in existing modules
3. Register in `src/strategy_registry.c`
4. Add to Makefile `MAIN_SRCS`
5. Create test case in `.tests/`
6. Verify with `verify_nulls.py` and `verify_functionality.py`
7. Update `DOCS/ADVANCED_STRATEGY_DEVELOPMENT.md`

### Debugging Transformation Issues

1. Build with `make debug` (enables sanitizers)
2. Use `VERBOSE=1` for detailed build output
3. Check `verify_functionality.py` to understand semantic differences
4. Examine the multi-pass architecture: sizing → offset calculation → generation
5. Ensure relative jump/call patching considers new offsets

### Optimizing Strategy Selection

- Higher priority strategies are tried first
- Strategy `can_handle()` should be fast (checked for every instruction)
- `get_size()` must accurately predict generated code size (critical for offset calculation)
- `generate()` must produce exactly the size predicted by `get_size()`
