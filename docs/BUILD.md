# BYVALVER Build Guide

## System Requirements

### Operating Systems
- **Linux** (Ubuntu, Debian, Fedora, etc.)
- **macOS** with Homebrew package manager
- **Windows** with WSL or MSYS2 (not directly supported but possible)

### Minimum System Specifications
- **CPU**: x86/x64 processor with support for modern instruction sets
- **RAM**: 1GB free memory (for processing typical shellcode files)
- **Disk Space**: 50MB free space for build and dependencies
- **Build Tools**: Standard C development environment

## Dependencies

### Core Dependencies
- **C Compiler**: GCC or Clang (C99 compliant)
- **Make**: GNU Make for build automation
- **Git**: For version control (recommended)

### Required Libraries and Tools
- **Capstone Disassembly Framework**: Version 4.0 or higher
- **NASM Assembler**: Version 2.13 or higher for decoder stub generation
- **xxd utility**: Part of Vim package, for binary-to-hex conversion

### Optional Dependencies for Advanced Features
- **Clang-Format**: For automatic code formatting
- **Cppcheck**: For static analysis
- **Valgrind**: For memory leak detection (in debug builds)

## Installation of Dependencies

### On Ubuntu/Debian
```bash
sudo apt update
sudo apt install build-essential nasm xxd pkg-config libcapstone-dev
```

Optional packages:
```bash
sudo apt install clang-format cppcheck valgrind
```

### On macOS with Homebrew
```bash
brew install capstone nasm
```

Note: On macOS, `xxd` is usually available as part of the `vim` package. If not, you can install it with:
```bash
brew install vim
```

### On Windows (WSL)
```bash
sudo apt update
sudo apt install build-essential nasm xxd pkg-config libcapstone-dev
```

## Build Process

### Default Build
To build the main executable with standard optimizations:
```bash
make
```

This will:
- Create the `bin/` directory if it doesn't exist
- Assemble the decoder stub (`decoder.asm`)
- Generate the header file (`decoder.h`) from the binary
- Compile all source files
- Link the final executable (`bin/byvalver`)

The build process follows this sequence:
1. **Decoder Generation**: `decoder.asm` is assembled to `decoder.bin` using NASM
2. **Header Generation**: `decoder.bin` is converted to C header `decoder.h` using xxd
3. **Source Compilation**: All C source files in `src/` are compiled to object files
4. **Linking**: Object files are linked together with Capstone library to create the final executable

### Build Variants

#### Debug Build
For development and debugging with debug symbols and sanitizers:
```bash
make debug
```

This includes:
- Debug symbols (`-g`)
- No optimizations (`-O0`)
- AddressSanitizer and UndefinedBehaviorSanitizer (`-fsanitize=address -fsanitize=undefined`)
- Debug mode defines (`-DDEBUG`)
- No optimizations to preserve variable information

#### Release Build
For optimized production builds:
```bash
make release
```

This includes:
- Maximum optimizations (`-O3`)
- Native architecture optimizations (`-march=native`)
- Release mode defines (`-DNDEBUG`)
- All optimizations enabled for performance

#### Static Build
To create a statically linked executable:
```bash
make static
```

This links all dependencies statically, creating a self-contained executable that does not require external libraries at runtime.

### Clean Build
To remove all generated files:
```bash
make clean
```

This removes:
- All object files in `bin/`
- Generated `decoder.bin` and `decoder.h`
- Preserves the source code and build configuration

To remove everything including the bin directory:
```bash
make clean-all
```

## Build Configuration

### Makefile Structure
The build system is configured through the Makefile with the following detailed components:

#### Compiler and Flags
```makefile
CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c99 -O2
LDFLAGS = -lcapstone
```

- `-Wall -Wextra`: Enable all warnings to catch potential issues
- `-pedantic`: Strict adherence to C99 standard
- `-std=c99`: Use C99 standard for maximum portability
- `-O2`: Optimize for performance (changed to `-O0` for debug builds)

#### Source Management
The Makefile automatically includes all `.c` files in `src/` with specific exclusions:
- Obsolete files: `lib_api.c`, `fix_*.c`, `conservative_mov_original.c`
- Duplicate implementations: `arithmetic_substitution_strategies.c`
- Test-only code: `test_strategies.c`

The system filters these out to avoid linking conflicts and maintain build consistency.

#### Obfuscation Modules
For the biphasic architecture, specific obfuscation modules are included:
- `obfuscation_strategy_registry.c`
- `obfuscation_strategies.c`

These are used during Pass 1 of the processing pipeline.

#### Dependency Generation
All source files that depend on the decoder stub automatically have `decoder.h` as a dependency, ensuring proper rebuild when the decoder changes.

### Build Information
To view current build configuration details:
```bash
make info
```

This displays:
- Compiler and flags being used
- Target executable path
- Number of source files being compiled
- Number of object files to be generated
- Strategy modules included
- Excluded files count

### Custom Build Parameters
The build system can be customized by setting environment variables:

```bash
# Use a different compiler
make CC=clang

# Add custom flags
make CFLAGS="-O2 -march=native -Wall -Werror"

# Set custom output directory
make BIN_DIR=custom_bin
```

## Troubleshooting Common Build Issues

### Missing Dependencies
If you encounter an error about missing libcapstone-dev:
```bash
# On Ubuntu/Debian
sudo apt install libcapstone-dev

# On macOS
brew install capstone

# Verify installation
pkg-config --exists capstone && echo "Found" || echo "Missing"
```

### NASM Issues
If you get NASM-related errors:
```bash
# Verify NASM installation
nasm --version

# On some systems, you might need nasm specifically
sudo apt install nasm  # Ubuntu/Debian
brew install nasm     # macOS

# Check that NASM is in your PATH
which nasm
```

### xxd Utility Missing
If `xxd` is not found:
```bash
# Ubuntu/Debian
sudo apt install vim-common

# macOS (usually available with vim)
brew install vim

# Check availability
which xxd
```

### Capstone Installation Issues
If pkg-config can't find capstone:
```bash
# Check if capstone is properly installed
pkg-config --exists capstone && echo "Found" || echo "Not found"

# Check the library path
ldconfig -p | grep capstone

# On macOS, you might need to specify the library path explicitly:
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"
```

### Permission Issues
If you encounter permission errors during build:
```bash
# Ensure you have write permissions to the project directory
ls -la

# If needed, change ownership or permissions
chmod -R u+w /path/to/byvalver
```

### Architecture Mismatch
If you get architecture-related build errors:
```bash
# For cross-compilation, specify the target architecture
make CFLAGS="-m32" LDFLAGS="-m32 -lcapstone"  # For 32-bit build
make CFLAGS="-m64" LDFLAGS="-m64 -lcapstone"  # For 64-bit build
```

## Development Workflow

### Verification
After building, verify the build was successful:
```bash
make test
```

This runs a quick verification that the executable was built correctly and can be executed.

### Dependency Check
Before building, verify all dependencies are available:
```bash
make check-deps
```

This checks for the presence of all required tools and libraries.

### Formatting Code
To format the codebase (if clang-format is available):
```bash
make format
```

### Static Analysis
To run static analysis (if cppcheck is available):
```bash
make lint
```

## Cross-Platform Considerations

### Linux
Full build support with all features enabled. Most distributions have the required packages available through their package managers.

### macOS
Build works correctly but may require additional configuration for some sanitizer options. Homebrew is the recommended package manager.

### Windows
Use WSL (Windows Subsystem for Linux) for best results. Native Windows builds would require significant modifications to the build system and may need MinGW or Cygwin.

## Advanced Build Topics

### Adding New Source Files
The Makefile automatically includes all `.c` files in the `src/` directory. No manual updates to the build system are required when adding new source files, but they must be properly referenced in header files or registry systems.

### Exclusion of Files
The Makefile specifically excludes:
- Test files: `test_strategies.c`
- Obsolete files: various `fix_*.c` and `*_original.c` files
- Library-specific files: `lib_api.c` (for CLI build)
- Duplicate implementations: `arithmetic_substitution_strategies.c`

### Strategy Module Registration
New strategy modules automatically get compiled as part of the build process, but they must be registered in the appropriate registry files (`strategy_registry.c` or `obfuscation_strategy_registry.c`).

### Build Artifacts Location
All build artifacts are placed in the `bin/` directory:
- Compiled object files: `bin/*.o`
- Final executable: `bin/byvalver`
- Temporary files: `decoder.bin`, `decoder.h` (in project root)

### Decoder Stub Generation
The decoder stub (`decoder.asm`) is automatically assembled to binary format and converted to a C header file during the build process. Any changes to `decoder.asm` will trigger regeneration of the header.

## Deployment Build
For creating a distribution-ready build:
```bash
make release
```

The resulting `bin/byvalver` executable can then be copied to other systems with compatible architectures that have Capstone library installed.

For a completely self-contained version:
```bash
make static
```

This creates a statically linked executable that doesn't require external libraries.

## Performance Tuning
### Compiler Optimizations
The build system supports various optimization levels:
- `-O0`: No optimization (debug builds)
- `-O1`: Basic optimization
- `-O2`: Standard optimization (default)
- `-O3`: Aggressive optimization (release builds)
- `-Os`: Optimize for size

### Architecture-Specific Optimizations
Use `-march=native` to optimize for the build machine's architecture:
```bash
make release CFLAGS="-O3 -march=native -DNDEBUG"
```

## Debugging Build Issues
### Verbose Build Output
To see detailed build commands:
```bash
make V=1
```

### Incremental Build Debugging
If the build fails, you can build single files to identify the issue:
```bash
make bin/core.o    # Compile only core.c
make bin/main.o    # Compile only main.c
```

### Clean Rebuild
To ensure a completely clean rebuild:
```bash
make clean-all
make
```

## Build Verification Checklist
Before deploying or sharing the build, verify:

- [ ] All dependencies are installed and accessible
- [ ] Basic build completes successfully
- [ ] Debug build compiles without errors
- [ ] Executable runs and shows help message
- [ ] Simple test case processes correctly
- [ ] All optional features compile properly
- [ ] Clean and rebuild work correctly