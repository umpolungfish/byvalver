# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**byvalver** is an automated framework for removing null bytes from x86/x86-64 shellcode while significantly increasing analytical difficulty through obfuscation. It operates on a **biphasic (two-pass) processing model** that decouples obfuscation from null-byte elimination.

The framework uses the Capstone disassembly engine and a modular strategy pattern architecture with 80+ transformation strategies across two processing passes.

## Build Commands

### Basic Build
```bash
# Default build (optimized release)
make

# Build with verbose output
make VERBOSE=1

# Debug build with sanitizers
make debug

# Optimized release build
make release

# Static build
make static
```

### Testing
```bash
# Build and run test suite
make test

# Verify null-byte elimination on processed shellcode
python3 verify_nulls.py <processed.bin>
python3 verify_nulls.py <processed.bin> --detailed

# Pattern-based functionality verification (fast)
python3 verify_functionality.py <original.bin> <processed.bin>

# Semantic verification using concrete execution (comprehensive, authoritative)
python3 verify_semantic.py <original.bin> <processed.bin>
python3 verify_semantic.py <original.bin> <processed.bin> --verbose
python3 verify_semantic.py <original.bin> <processed.bin> --progress
python3 verify_semantic.py <original.bin> <processed.bin> --format json

# Unified verification (complete workflow)
python3 verify/unified_verification.py <original.bin> <processed.bin>
```

### Code Quality
```bash
# Format code with clang-format or astyle
make format

# Static analysis with cppcheck
make lint

# Check build dependencies
make check-deps
```

### Cleanup
```bash
# Remove build artifacts
make clean

# Remove all artifacts including backups
make clean-all
```

## Running byvalver

### Basic Usage
```bash
# Process single shellcode file
./bin/byvalver input.bin output.bin

# Process directory of files (batch mode)
./bin/byvalver --directory ./shellcodes --output-dir ./processed

# With XOR encoding (adds decoder stub)
./bin/byvalver --xor-encode 0x12345678 input.bin output.bin
```

### Windows PIC Generation
```bash
# Generate Windows Position Independent Code with API resolution
./bin/byvalver --win-pic calc --arch x86 -o calc_shellcode.bin
./bin/byvalver --win-pic WinExec --pic-params "cmd.exe" --arch x86 -o cmd_shellcode.bin
./bin/byvalver --win-pic calc --arch x86 --xor-encode 0x12345678 -o encoded_calc.bin
```

### Working with PE/ELF Files
```bash
# Extract .text section from PE/ELF
objcopy -O binary --only-section=.text executable.exe shellcode.bin

# Process with byvalver
./bin/byvalver shellcode.bin output.bin
```

## Architecture

### Biphasic Processing Model

The core innovation of byvalver is its **two-pass architecture** that separates concerns:

1. **Pass 1: Obfuscation & Complexification** (`src/obfuscation_strategy_registry.c`)
   - Increases analytical difficulty through polymorphic transformations
   - Transforms simple instructions into convoluted but functionally equivalent sequences
   - NOT concerned with null bytes - focuses purely on complexity
   - Examples: TEST→AND, MOV→PUSH/POP, arithmetic negation, junk code insertion, opaque predicates

2. **Pass 2: Null-Byte Elimination** (`src/strategy_registry.c`)
   - Takes obfuscated output from Pass 1 and eliminates all null bytes
   - Uses 75+ specialized transformation strategies
   - Cleans up any nulls introduced by obfuscation pass
   - Maintains functional equivalence while ensuring null-free output

**Benefits**:
- Obfuscation strategies can introduce nulls without concern (Pass 2 cleans them)
- Null-elimination strategies don't need to consider obfuscation patterns
- More aggressive transformations possible
- Enhanced polymorphism and signature evasion

See `BIPHASIC.md` for detailed architecture documentation.

### Core Processing Pipeline

1. **Disassembly Pass** (`src/core.c`)
   - Disassemble input shellcode using Capstone
   - Build linked list of instruction nodes

2. **Pass 1: Obfuscation**
   - For each instruction, query obfuscation strategy registry
   - Apply highest-priority matching obfuscation strategy
   - Generate more complex replacement sequences

3. **Pass 2: Null-Elimination**
   - For each instruction from Pass 1, check for null bytes
   - Query null-elimination strategy registry
   - Select highest-priority matching strategy
   - Calculate new instruction sizes

4. **Offset Calculation**
   - Compute new offsets for relative jumps/calls based on new sizes
   - Track external targets requiring patching

5. **Generation & Patching**
   - Generate null-free replacement sequences
   - Patch relative jump/call displacements
   - Write final output

### Strategy Pattern Implementation

**Core Interface** (`src/strategy.h`):
```c
typedef struct {
    const char* name;
    int (*can_handle)(cs_insn *insn);          // Returns 1 if applicable
    size_t (*get_size)(cs_insn *insn);         // Calculates replacement size
    void (*generate)(struct buffer *b, cs_insn *insn);  // Generates code
    int priority;                               // Higher = more preferred
} strategy_t;
```

**Strategy Selection Algorithm**:
1. Evaluate all registered strategies via `can_handle()`
2. Collect applicable strategies
3. Sort by priority (descending)
4. Use highest-priority match
5. If no strategy matches, copy instruction as-is

### Source Organization

#### Core Engine
- `src/main.c` - Entry point, CLI parsing, file I/O, batch processing
- `src/core.c/h` - Main processing logic, multi-pass orchestration, offset patching
- `src/utils.c/h` - Shared helper functions (buffer management, register indexing, encoding)
- `src/obfuscation_strategy_registry.c/h` - Pass 1 strategy management
- `src/strategy_registry.c` - Pass 2 (null-elimination) strategy management

#### Pass 1: Obfuscation Strategies
- `src/obfuscation_strategies.c/h` - TEST→AND, MOV→PUSH/POP, arithmetic negation, junk code, opaque predicates
- See `docs/NEW_OBFUSCATION_STRATEGIES.md` for complete list

#### Pass 2: Null-Elimination Strategies (75+ strategies across 60+ modules)

**Critical Priority (100+)**:
- `src/indirect_call_strategies.c` - Priority 100: CALL/JMP through IAT (Windows API resolution)
- `src/sldt_replacement_strategy.c` - Priority 95: Complete SLDT opcode replacement (hardware fix)
- `src/multi_byte_nop_strategies.c` - Priority 90: Multi-byte NOP elimination

**High Priority (80-99)**:
- `src/conditional_jump_offset_strategies.c` - Priority 150: Conditional jumps with null offsets
- `src/cmp_strategies.c` - Priority 85-88: CMP immediate/memory/displacement
- `src/relative_jump_strategies.c` - Priority 85: Relative CALL/JMP displacement
- `src/retf_strategies.c` - Priority 85: Far return immediate elimination
- `src/rip_relative_strategies.c` - Priority 80: x86-64 RIP-relative addressing

**Medium Priority (50-79)**:
- `src/movzx_strategies.c` - Priority 75: MOVZX/MOVSX for PE export table reads
- `src/arpl_strategies.c` - Priority 75: ARPL ModR/M null bypass
- `src/small_immediate_strategies.c` - Priority 75: Optimized immediate construction
- `src/setcc_strategies.c` - Priority 70-75: Conditional set byte (all 16 variants)
- `src/ror_rol_strategies.c` - Priority 70: ROR/ROL for ROR13 hash API resolution
- `src/bound_strategies.c` - Priority 70: BOUND ModR/M null bypass
- `src/adc_strategies.c` - Priority 69-72: Add with carry + SIB addressing
- `src/sbb_strategies.c` - Priority 69-70: Subtract with borrow (8-bit, 32-bit)
- `src/imul_strategies.c` - Priority 71-72: Signed multiply
- `src/ret_strategies.c` - Priority 78: RET immediate cleanup
- `src/fpu_strategies.c` - Priority 60-65: x87 FPU with SIB addressing
- `src/lea_strategies.c` - Priority 65: LEA null ModR/M bypass

**Standard (1-49)**:
- `src/mov_strategies.c` - MOV transformations
- `src/arithmetic_strategies.c` - ADD, SUB, AND, OR, XOR
- `src/memory_strategies.c` - Memory operation replacements
- `src/jump_strategies.c` - Jump and call replacements
- `src/loop_strategies.c` - LOOP family (LOOP, JECXZ, LOOPE, LOOPNE)
- `src/general_strategies.c` - PUSH and general instructions
- `src/byte_construct_strategy.c` - Priority 25: Byte-by-byte immediate construction (fallback)
- `src/getpc_strategies.c` - Byte construction for null immediates
- `src/advanced_transformations.c` - NEG, NOT, ADD/SUB encoding, XOR null-free

**Specialized Modules**:
- `src/ror13_hash_strategies.c` - ROR13 hash-based API resolution (most common, 3,237 applications in testing)
- `src/stack_string_strategies.c` - Stack-based string construction
- `src/unicode_string_strategies.c` - Unicode (UTF-16) string handling
- `src/socket_address_strategies.c` - Socket address structure handling
- `src/peb_strategies.c` - PEB traversal for Windows API resolution
- `src/anti_debug_strategies.c` - Anti-debugging/analysis detection
- `src/hash_utils.c/h` - Hash utilities for API resolution
- `src/pic_generation.c/h` - Windows PIC generation with PEB traversal
- `src/xor_decrypt_strategies.c` - XOR decryption obfuscation (Pass 1)
- `src/immediate_split_strategies.c` - Immediate value splitting (Pass 2)

## Adding New Strategies

### For Obfuscation (Pass 1)

1. **Create module**: `src/new_obfuscation.c` and `.h`
2. **Implement interface**:
   ```c
   int can_handle_new_obfuscation(cs_insn *insn) {
       // Return 1 if this obfuscation applies
   }

   size_t get_size_new_obfuscation(cs_insn *insn) {
       // Return size of obfuscated sequence (may be larger)
   }

   void generate_new_obfuscation(struct buffer *b, cs_insn *insn) {
       // Generate complex but functionally equivalent code
       // Don't worry about null bytes - Pass 2 will clean them
   }
   ```
3. **Define strategy**:
   ```c
   static strategy_t new_obfuscation_strategy = {
       .name = "New Obfuscation Strategy",
       .can_handle = can_handle_new_obfuscation,
       .get_size = get_size_new_obfuscation,
       .generate = generate_new_obfuscation,
       .priority = 80  // Higher priority = more aggressive obfuscation
   };
   ```
4. **Register in `src/obfuscation_strategy_registry.c`**:
   - Add forward declaration
   - Call `register_strategy(&new_obfuscation_strategy)` in `init_obfuscation_strategies()`
5. **Add to Makefile** `MAIN_SRCS`

### For Null-Elimination (Pass 2)

1. **Create module**: `src/new_denull.c` and `.h`
2. **Implement interface** (same as above but MUST ensure null-free output)
3. **Define strategy with appropriate priority**:
   - 150+: Context-aware optimizations
   - 100+: Critical API resolution patterns
   - 80-99: Hardware fixes, x64 support
   - 50-79: High-impact transformations
   - 25-49: Standard replacements
   - 1-24: Experimental fallbacks
4. **Register in `src/strategy_registry.c`**
5. **Add to Makefile** `MAIN_SRCS`

### Testing New Strategies

```bash
# 1. Create test shellcode in .tests/
python3 .tests/test_new_strategy.py

# 2. Process with byvalver
./bin/byvalver .test_bins/new_test.bin .test_bins/new_test_processed.bin

# 3. Verify null elimination
python3 verify_nulls.py .test_bins/new_test_processed.bin

# 4. Deep semantic verification (authoritative)
python3 verify_semantic.py .test_bins/new_test.bin .test_bins/new_test_processed.bin --verbose
```

**The semantic verifier is the authoritative test** - it executes both versions with multiple test vectors and compares CPU states (registers, flags, memory).

## Critical Implementation Notes

### Null-Byte Safety (Pass 2 Strategies Only)

When implementing null-elimination strategies:
- **CRITICAL**: Ensure all helper functions are null-safe
- Use `generate_mov_eax_imm()` for null-containing immediates (not `generate_mov_reg_imm()`)
- Avoid direct immediate operations that might contain nulls
- Always verify output with `verify_nulls.py`

### SIB Addressing Pattern

`MOV EAX, [EAX]` encodes as `8B 00` (contains null!). Use SIB addressing instead:
```
8B 04 20  # MOV EAX, [EAX] - completely null-free
```
- ModR/M: `04` = mod=00, reg=000 (EAX), r/m=100 (SIB follows)
- SIB: `20` = scale=00, index=100 (ESP/none), base=000 (EAX)

### Register Selection

- Strategies often need temporary registers
- Cascade through ECX → EDX → EBX → ESI → EDI to avoid conflicts
- Always preserve with PUSH/POP when using temporarily
- Check target register to avoid using it as temporary

### Verification Workflow

1. **Process**: `./bin/byvalver input.bin output.bin`
2. **Verify nulls**: `python3 verify_nulls.py output.bin`
3. **Quick check**: `python3 verify_functionality.py input.bin output.bin`
4. **Deep verification**: `python3 verify_semantic.py input.bin output.bin --verbose`

## Code Style

- **C99 Standard**: All code uses `-std=c99`
- **No Warnings**: Clean compilation with `-Wall -Wextra -Wpedantic`
- **Debug Mode**: Use `DEBUG` macro for conditional logging
- **Error Handling**: Check for NULL, validate sizes, log errors to stderr
- **Capstone API**: Link with `-lcapstone`

## Dependencies

- **GCC** or compatible C compiler
- **Capstone** disassembly library with development headers (`libcapstone-dev`)
- **NASM** assembler (for decoder stub generation)
- **xxd** (for generating decoder header from binary)
- **GNU Binutils** (`objcopy` for extracting PE/ELF sections)
- **Python 3** with `capstone`, `unicorn` modules (for verification scripts)

## Testing Results

**Comprehensive Binary Testing** (87-file corpus, 56.11 MB):
- **Success Rate**: 98.9% (86/87 files with 100% null elimination)
- **Null Bytes Eliminated**: 21,151 across 88,044 instructions
- **Most Applied Strategy**: ROR13 Hash API Resolution (3,237 applications)
- **Top Strategies**: mov_mem_disp_null (2,968), lea_disp_null (1,768), Multi-Byte NOP (891)

## Context: Security Research Tool

This is a defensive security tool for analyzing and transforming shellcode. The codebase contains:
- Real-world shellcode samples in `.binzzz/` for testing
- Pattern recognition for Windows API resolution (ROR13 hashing, PEB traversal, IAT calls)
- Anti-debugging pattern understanding
- Educational value for understanding x86/x86-64 instruction encoding

## Additional Documentation

- `BIPHASIC.md` - Detailed biphasic architecture documentation with examples
- `docs/NEW_OBFUSCATION_STRATEGIES.md` - Complete obfuscation strategy catalog
- `docs/NEW_DENULL_STRATEGIES.md` - Complete null-elimination strategy catalog
- `docs/ADVANCED_STRATEGY_DEVELOPMENT.md` - Strategy development guide
- `verify_semantic/README.md` - Semantic verification documentation
- `README.md` - User-facing documentation with features and usage
