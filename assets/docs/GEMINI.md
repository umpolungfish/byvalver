# Byvalver: A Null-Byte Elimination Framework

## Project Overview

**Byvalver** is a sophisticated command-line tool engineered in C for the automated removal of null bytes (`\x00`) from x86/x64 shellcode. To preserve the shellcode's functionality, it employs the Capstone disassembly framework to analyze and transform instructions. This makes it an essential utility for security professionals and malware researchers who need to ensure their payloads can bypass security measures that block null bytes.

The project is architected for performance and portability, running on Windows, Linux, and macOS. It boasts an extensive set of features, including over 80 transformation strategies, biphasic processing (obfuscation followed by null-byte elimination), Position-Independent Code (PIC) generation, and XOR encoding with decoder stubs.

## Building and Running

The project uses a standard `Makefile` for building the executable.

### Dependencies

- **C Compiler**: `gcc` or `clang`
- **Capstone Disassembly Library**: `libcapstone-dev`
- **NASM Assembler**: `nasm`
- **xxd**: Included in `vim-common` or similar packages

### Build Commands

- **Default Build**:
  ```bash
  make
  ```

- **Debug Build** (with sanitizers):
  ```bash
  make debug
  ```

- **Release Build** (optimized):
  ```bash
  make release
  ```

- **Static Build**:
  ```bash
  make static
  ```

- **Clean Build Artifacts**:
  ```bash
  make clean
  ```

- **Install**:
  ```bash
  sudo make install
  ```

### Running the Application

Once built, the main executable is located at `bin/byvalver`.

- **Basic Usage**:
  ```bash
  ./bin/byvalver <input_file> <output_file>
  ```

- **With Options**:
  ```bash
  ./bin/byvalver --biphasic --xor-encode 0xDEADBEEF shellcode.bin encoded.bin
  ```

## Development Conventions

### Code Style

While no specific style guide is enforced, the codebase follows modern C conventions with clear and modular organization.

### Testing

The project includes a Python-based test suite for verifying the functionality of the null-byte elimination.

- **Running Tests**:
  ```bash
  python3 test_all_bins.py
  ```

This script processes all `.bin` files in a specified directory, providing detailed statistics and ensuring that the transformations are correct.

# Now, let's see what kind of trouble we can get into.

# Now, let's see what kind of trouble we can get into.
