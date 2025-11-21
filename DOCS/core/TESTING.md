# BYVALVER Testing Guide

This document provides comprehensive instructions for testing BYVALVER with various shellcode samples and evaluating its performance.

## Directory Structure

BYVALVER uses an organized directory structure for testing:
- `.tests/` - Contains Python test scripts
- `.test_bins/` - Stores binary shellcode files (input/output)
- `.test_asms/` - Assembly source files for test cases

## Basic Testing

### Simple Test
```bash
# Create sample shellcode
python3 create_shellcode.py

# Process with BYVALVER
./bin/byvalver shellcode.bin output.bin

# Verify functionality
python3 verify_functionality.py shellcode.bin output.bin
```

### Performance Testing
```bash
# Generate test shellcode of specific size
python3 generate_test_shellcode.py test_1000.bin 1000

# Process with BYVALVER
./bin/byvalver test_1000.bin test_1000_processed.bin

# Check expansion rate
ls -la test_1000.bin test_1000_processed.bin
```

## Advanced Testing

### Testing with Exploit-DB Shellcodes
```bash
# Copy shellcode binaries from exploit-db collection
cp .shellcodes/linux_x86/*.bin .test_bins/

# Test individual files
./bin/byvalver .test_bins/13309.bin .test_bins/13309_processed.bin
python3 verify_functionality.py .test_bins/13309.bin .test_bins/13309_processed.bin
```

### Large-Scale Performance Tests
```bash
# Generate large test files
python3 generate_test_shellcode.py .test_bins/test_50000.bin 50000

# Process large files
./bin/byvalver .test_bins/test_50000.bin .test_bins/test_50000_processed.bin

# Verify large outputs
python3 verify_functionality.py .test_bins/test_50000.bin .test_bins/test_50000_processed.bin
```

## Expansion Rate Analysis

### Checking Expansion Rates
```bash
# For a specific file:
ORIGINAL_SIZE=$(stat -c%s input_file.bin)
PROCESSED_SIZE=$(stat -c%s output_file.bin)
EXPANSION=$(echo "scale=3; $PROCESSED_SIZE / $ORIGINAL_SIZE" | bc)
echo "Expansion rate: $EXPANSION x"
```

### Common Expansion Rates
- Simple null-free shellcode: 1.0x (no change)
- Mixed shellcode with some nulls: ~2.0x to ~3.0x
- Complex shellcode with many nulls: ~3.3x (typical for large files)

## Testing Different Shellcode Patterns

### Creating Custom Test Shellcodes
```python
# Create shellcode with specific null-byte patterns
import struct

shellcode = bytearray()
# MOV EAX, 0x00112233 (contains nulls)
shellcode.extend(b'\xb8\x33\x22\x11\x00')
# ADD EBX, 0x00445566 (contains nulls)
shellcode.extend(b'\x81\xc3\x66\x55\x44\x00')

with open("custom_test.bin", "wb") as f:
    f.write(shellcode)
```

### Testing Specific Instructions
```bash
# Test MOV instructions with immediate values
./bin/byvalver .test_asms/mov_mem_test.bin .test_bins/mov_mem_processed.bin

# Test LEA instructions
./bin/byvalver .test_asms/lea_test.bin .test_bins/lea_processed.bin

# Test CMP instructions  
./bin/byvalver .test_asms/cmp_test.bin .test_bins/cmp_processed.bin
```

## Verification Tests

### Functionality Verification
```bash
# Verify that processed shellcode maintains logical equivalence
python3 verify_functionality.py original.bin processed.bin

# Output interpretation:
# - "SUCCESS: Null bytes successfully removed!" - Null byte removal confirmed
# - "VERIFICATION: PASSED" - Functional equivalence maintained
# - "Potential issue" - Instruction not matched (may be expected due to expansion)
```

### Null Byte Verification
```bash
# Double-check that output has no null bytes
hexdump -C processed.bin | grep "00 "
# If this returns no results, no null bytes are present
```

## Performance Benchmarking

### Timing Tests
```bash
# Measure processing time
time ./bin/byvalver large_shellcode.bin output.bin
```

### Memory Usage Tests
```bash
# Monitor memory usage during processing
/usr/bin/time -v ./bin/byvalver large_shellcode.bin output.bin
```

## Regression Testing

### Standard Test Suite
```bash
# Run all standard tests
for file in .test_bins/test_*.bin; do
    ./bin/byvalver "$file" "${file%.bin}_processed.bin"
    python3 verify_functionality.py "$file" "${file%.bin}_processed.bin"
done
```

### Batch Performance Tests
```bash
# Test multiple file sizes
for size in 100 500 1000 5000 10000 25000 50000; do
    python3 generate_test_shellcode.py ".test_bins/test_$size.bin" $size
    ./bin/byvalver ".test_bins/test_$size.bin" ".test_bins/test_${size}_processed.bin"
    echo "Size $size: $(stat -c%s .test_bins/test_$size.bin) -> $(stat -c%s .test_bins/test_${size}_processed.bin)"
done
```

## Troubleshooting Tests

### Debug Mode
```bash
# Compile with debug symbols
make clean
gcc -g -Wall -Wextra -pedantic -c -o bin/main.o src/main.c
gcc -g -Wall -Wextra -pedantic -c -o bin/core.o src/core.c
gcc -g -Wall -Wextra -pedantic -c -o bin/utils.o src/utils.c
gcc -g -Wall -Wextra -pedantic -c -o bin/strategy_registry.o src/strategy_registry.c
gcc -g -Wall -Wextra -pedantic -c -o bin/mov_strategies.o src/mov_strategies.c
gcc -g -Wall -Wextra -pedantic -c -o bin/arithmetic_strategies.o src/arithmetic_strategies.c
gcc -g -Wall -Wextra -pedantic -c -o bin/memory_strategies.o src/memory_strategies.c
gcc -g -Wall -Wextra -pedantic -c -o bin/jump_strategies.o src/jump_strategies.c
gcc -g -Wall -Wextra -pedantic -c -o bin/general_strategies.o src/general_strategies.c
gcc -g -o bin/byvalver_debug bin/main.o bin/core.o bin/utils.o bin/strategy_registry.o bin/mov_strategies.o bin/arithmetic_strategies.o bin/memory_strategies.o bin/jump_strategies.o bin/general_strategies.o -lcapstone

# Debug with GDB if needed
gdb ./bin/byvalver_debug
```

### Verbose Output
The current version of BYVALVER outputs basic information about processing to the console. For more detailed analysis, you can add debug prints to specific transformation functions.

## Test Results Documentation

### Logging Results
```bash
# Log test results to a file
./bin/byvalver test.bin output.bin 2>&1 | tee test_results.log
python3 verify_functionality.py test.bin output.bin 2>&1 | tee -a test_results.log
```

### Creating Performance Reports
```bash
# For documentation of results
echo "BYVALVER Performance Report - $(date)" > performance_report.txt
echo "==========================" >> performance_report.txt
for file in .test_bins/test_*.bin; do
    original_size=$(stat -c%s "$file")
    processed_file="${file%.bin}_processed.bin"
    if [ -f "$processed_file" ]; then
        processed_size=$(stat -c%s "$processed_file")
        expansion=$(echo "scale=3; $processed_size / $original_size" | bc)
        echo "$file: $original_size -> $processed_size bytes (expansion: $expansion x)" >> performance_report.txt
    fi
done
```

## Testing Individual Strategies

With the new modular architecture, you can also test individual strategy modules:

```bash
# Since strategies are now in separate modules, you can test specific instruction types
# by creating shellcode samples that target specific strategy modules:

# MOV instruction tests (uses src/mov_strategies.c)
./bin/byvalver .test_bins/mov_nulls.bin .test_bins/mov_nulls_processed.bin

# Arithmetic instruction tests (uses src/arithmetic_strategies.c)
./bin/byvalver .test_bins/arithmetic_nulls.bin .test_bins/arithmetic_nulls_processed.bin

# Memory instruction tests (uses src/memory_strategies.c)
./bin/byvalver .test_bins/memory_nulls.bin .test_bins/memory_nulls_processed.bin

# Jump instruction tests (uses src/jump_strategies.c)
./bin/byvalver .test_bins/jump_nulls.bin .test_bins/jump_nulls_processed.bin

# General instruction tests (uses src/general_strategies.c)
./bin/byvalver .test_bins/general_nulls.bin .test_bins/general_nulls_processed.bin
```

## Continuous Testing

For ongoing development, maintain test files in the designated directories and regularly run:
```bash
# Quick functionality test
./bin/byvalver .test_bins/shellcode.bin .test_bins/shellcode_test.bin
python3 verify_functionality.py .test_bins/shellcode.bin .test_bins/shellcode_test.bin

# Performance check
./bin/byvalver .test_bins/test_1000.bin .test_bins/test_1000_test.bin
```

This testing framework allows for comprehensive validation of BYVALVER's functionality, performance, and expansion characteristics across different shellcode samples and sizes.