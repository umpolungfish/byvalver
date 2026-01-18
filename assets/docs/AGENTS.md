# AGENTS.md - Guidelines for AI Coding Agents

This document provides comprehensive guidelines for AI coding agents working on the `byvalver` codebase. `byvalver` is a C-based shellcode transformation tool that eliminates bad bytes while maintaining functional equivalence.

## Build Commands

### Standard Builds
- `make` - Default optimized build with automatic TUI detection
- `make debug` - Debug build with sanitizers and symbols (`-g -O0 -fsanitize=address -fsanitize=undefined`)
- `make release` - Highly optimized build (`-O3 -march=native -DNDEBUG`)
- `make static` - Static binary for distribution (`-static`)

### Specialized Builds
- `make train` - Build ML training utility (`bin/train_model`)
- `make with-tui` - Force TUI build (requires ncurses)
- `make no-tui` - Build without TUI support (smaller binary)
- `make clean` - Remove build artifacts
- `make clean-all` - Remove all generated files

### Build Information
- `make info` - Display current build configuration and flags

## Testing Commands

### Individual Test Execution
Run specific verification tests on individual files:

```bash
# Check for remaining bad bytes after transformation
python3 verify_denulled.py --bad-bytes "00,0a,0d" output.bin

# Verify functional preservation (instruction patterns)
python3 verify_functionality.py input.bin output.bin --arch x64

# Validate semantic equivalence
python3 verify_semantic.py input.bin output.bin --method pattern

# Test specific transformation strategies
python3 assets/tests/test_new_strategies.py
```

### Batch Testing
```bash
# Run comprehensive test suite
python3 test_all_bins.py

# Test bad-byte profile handling
./assets/tests/test_bad_bytes.sh

# Test HTTP whitespace profile specifically
./assets/tests/test_http_whitespace_profile.sh
```

### Build Verification
```bash
# Quick build test
make test
```

## Code Quality

### Formatting
```bash
# Format all C source and header files
make format  # Runs clang-format -i on src/*.c and src/*.h
```

### Static Analysis
```bash
# Run static analysis with cppcheck
make lint    # Checks for common C issues and potential bugs
```

## Code Style Guidelines

### Language Standard
- **C99** (`-std=c99`) - Use C99 features and syntax
- **Compiler flags**: `-Wall -Wextra -pedantic` for maximum warnings
- **Optimization**: `-O2` default, `-O3` for release builds

### Formatting
- **Tool**: clang-format (enforced via `make format`)
- **Style**: Follow clang-format defaults with project-specific rules
- **Consistency**: Run `make format` before commits

### Code Organization
- **Headers**: Function prototypes in `.h` files, implementations in `.c` files
- **File scope**: Move includes to file scope (not function scope)
- **Modularity**: Strategy pattern with clear separation of concerns
- **Comments**: None required (avoid unless absolutely necessary)

## Naming Conventions

### Functions
- **snake_case**: `remove_null_bytes()`, `get_capstone_arch_mode()`, `register_strategy()`

### Variables
- **snake_case**: `shellcode`, `file_size`, `new_shellcode`, `strategy_count`
- **Local scope**: Short, descriptive names
- **Global scope**: Prefix with module name if needed

### Types and Structs
- **snake_case**: `struct buffer`, `strategy_t`, `bad_byte_config_t`
- **Enums**: `byval_arch_t` (architecture enumeration)
- **Typedefs**: `_t` suffix for public types

### Files
- **snake_case**: `core.c`, `cli.c`, `strategy.h`, `obfuscation_strategy_registry.c`
- **Extensions**: `.c` for sources, `.h` for headers

### Constants
- **UPPER_SNAKE_CASE**: `MAX_STRATEGIES`, `EXIT_SUCCESS`

## Import/Export Patterns

### Header Includes
```c
// System headers first
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// External libraries
#include <capstone/capstone.h>

// Local headers
#include "core.h"
#include "utils.h"
#include "strategy.h"
```

### Function Declarations
- Full prototypes in header files:
```c
void register_strategy(strategy_t *strategy);
struct buffer remove_null_bytes(const uint8_t *shellcode, size_t size, byval_arch_t arch);
```

### Module Organization
- **Core modules**: `core.c/h`, `utils.c/h`, `cli.c/h`
- **Strategy modules**: Individual `.c` files per strategy family
- **Registry**: Central registration in `*_strategy_registry.c` files

## Error Handling

### Logging Patterns
```c
// Error messages with context
fprintf(stderr, "[ERROR] shellcode pointer is NULL!\n");
fprintf(stderr, "[ERROR] cs_open failed!\n");
fprintf(stderr, "[ERROR] Capstone disassembly error at offset 0x%lx\n", offset);
```

### Validation
```c
// Input validation at function boundaries
if (!shellcode) {
    fprintf(stderr, "[ERROR] shellcode pointer is NULL!\n");
    return new_shellcode;
}

// Memory allocation checks
buffer_t *buf = buffer_create(size);
if (!buf) {
    fprintf(stderr, "[ERROR] Failed to allocate buffer!\n");
    return NULL;
}
```

### Return Codes
- **Standard codes**: `EXIT_SUCCESS`, `EXIT_FAILURE`
- **Custom codes**: `EXIT_INPUT_FILE_ERROR`, `EXIT_PROCESSING_FAILED`
- **Error propagation**: Functions return error indicators, callers handle appropriately

## Type Usage

### Primitive Types
- **Fixed-width**: `uint8_t`, `uint32_t`, `uint64_t` for precise sizing
- **Size types**: `size_t` for memory operations and counts
- **Standard**: `int` for return codes and general integers
- **Strings**: `char` arrays, null-terminated

### Capstone Types
- **Handle**: `csh` for Capstone instances
- **Instructions**: `cs_insn*` for disassembled instructions
- **Enums**: `cs_arch`, `cs_mode` for architecture specification

### Custom Types
- **Buffers**: `struct buffer` for dynamic byte arrays
- **Strategies**: `strategy_t` function pointer structs
- **Configuration**: `bad_byte_config_t` for transformation settings
- **Architecture**: `byval_arch_t` enum (X86, X64, ARM, ARM64)

### Memory Management
- **Manual**: `malloc`/`free` pairs with error checking
- **Custom allocators**: Buffer management functions for shellcode
- **Ownership**: Clear ownership semantics in function documentation

## Best Practices

### Security
- **Input validation**: Always validate inputs before processing
- **Memory safety**: Check allocations, avoid buffer overflows
- **No secrets**: Never commit credentials, keys, or sensitive data
- **Safe defaults**: Conservative behavior over permissive

### Development
- **Testing**: Run verification scripts after changes
- **Code review**: Format and lint before commits
- **Documentation**: Update README for new features
- **Compatibility**: Test builds across supported platforms

### Performance
- **Profiling**: Use debug builds for performance analysis
- **Optimization**: Profile-guided optimization for critical paths
- **Memory**: Efficient data structures for large shellcode processing

### Cross-Platform
- **POSIX compliance**: Use standard C functions
- **Path handling**: Platform-appropriate path separators
- **Dependencies**: Clear documentation of required libraries

---

*Last updated: January 2026*
*For questions about this document, see project maintainers.*</content>
<parameter name="filePath">AGENTS.md