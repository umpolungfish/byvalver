# BYVALVER Flag Compatibility Guide

## Overview

BYVALVER supports multiple command-line flags that can be combined for powerful shellcode transformation capabilities. This guide documents all compatible flag combinations and provides examples for each use case.

## Core Processing Flags

### `--biphasic`
Enables two-pass processing:
- **Pass 1**: Obfuscation & complexification (adds anti-analysis features)
- **Pass 2**: Null-byte elimination (removes all 0x00 bytes)

**Recommended**: Use this flag for production shellcode that needs both obfuscation and null-byte elimination.

### `--pic`
Generates position-independent code (PIC) that can execute from any memory location.
- Uses CALL/POP techniques to obtain current EIP
- Implements API hashing for dynamic function resolution
- Includes optional anti-debugging checks

### `--xor-encode <KEY>`
XOR encodes the final shellcode with a 4-byte key and prepends a decoder stub.
- **Key format**: Hexadecimal value (e.g., `0x12345678`)
- **Decoder**: Automatically prepended to the output
- **Output**: `[decoder_stub][4-byte_key][4-byte_encoded_length][xor_encoded_shellcode]`

### `--ml`
Enables machine learning-based strategy selection.
- Uses trained models to select optimal transformation strategies
- Tracks metrics and learns from processing results
- **Note**: Experimental feature that may impact performance

### `--format <FORMAT>`
Specifies output format for the processed shellcode.

Supported formats:
- **`raw`** (default): Binary output
- **`c`**: C array format (`unsigned char shellcode[] = {...}`)
- **`python`**: Python bytes format (`shellcode = b"\x31\xc0..."`)
- **`powershell`**: PowerShell array format (`$shellcode = @(0x31,0xc0,...)`)
- **`hexstring`**: Plain hexadecimal string (`31c083c001cd80`)

## Batch Processing Flags

### `-r, --recursive`
Process directories recursively.

### `--pattern <PATTERN>`
File pattern to match (default: `*.bin`).
- Example: `--pattern "*.shellcode"`

### `--no-preserve-structure`
Flatten output directory structure (don't preserve input subdirectories).

### `--no-continue-on-error`
Stop processing on first error (default is to continue).

### `--failed-files <FILE>`
Write list of failed files to specified file.

## ML Metrics Flags

### `--metrics`
Enable ML metrics tracking and learning.
- Requires: `--ml` flag
- Generates: `./ml_metrics.log`

### `--metrics-file <FILE>`
Specify metrics output file (default: `./ml_metrics.log`).

### `--metrics-json`
Export metrics in JSON format.

### `--metrics-csv`
Export metrics in CSV format.

### `--metrics-live`
Show live metrics during processing.

## Flag Compatibility Matrix

| Flag | Compatible With | Notes |
|------|----------------|-------|
| `--biphasic` | All flags | ✅ Recommended for most use cases |
| `--pic` | `--biphasic`, `--ml`, `--format` | ✅ Can be combined with all processing flags |
| `--xor-encode` | `--biphasic`, `--pic`, `--ml`, `--format` | ✅ Applied after all other processing |
| `--ml` | `--biphasic`, `--pic`, `--xor-encode`, `--format`, batch flags | ✅ Fully compatible |
| `--format` | All flags | ✅ Controls output format only |
| Batch flags | All processing flags | ✅ Batch mode compatible with all flags |

## Tested Flag Combinations

All combinations below have been tested and verified to work correctly:

### ✅ Basic Combinations

```bash
# Biphasic processing with ML
./bin/byvalver --biphasic --ml input.bin output.bin

# Biphasic with PIC generation
./bin/byvalver --biphasic --pic input.bin output.bin

# Biphasic with XOR encoding
./bin/byvalver --biphasic --xor-encode 0x12345678 input.bin output.bin

# Biphasic with custom output format
./bin/byvalver --biphasic --format c input.bin output.c
./bin/byvalver --biphasic --format python input.bin output.py
./bin/byvalver --biphasic --format powershell input.bin output.ps1
./bin/byvalver --biphasic --format hexstring input.bin output.hex
```

### ✅ Advanced Combinations

```bash
# Full stack: Biphasic + PIC + XOR + C format
./bin/byvalver --biphasic --pic --xor-encode 0xDEADBEEF --format c input.bin output.c

# ML-enhanced biphasic with metrics
./bin/byvalver --biphasic --ml --metrics --metrics-live input.bin output.bin

# Biphasic with all ML metrics options
./bin/byvalver --biphasic --ml --metrics --metrics-json --metrics-csv \
  --metrics-file custom_metrics input.bin output.bin
```

### ✅ Batch Processing Combinations

```bash
# Basic batch with biphasic
./bin/byvalver --biphasic input_dir/ output_dir/

# Recursive batch with biphasic and ML
./bin/byvalver --biphasic --ml -r input_dir/ output_dir/

# Batch with biphasic, pattern matching, and C format output
./bin/byvalver --biphasic --format c -r --pattern "*.shellcode" \
  input_dir/ output_dir/

# Full batch: Biphasic + ML + format + metrics + error tracking
./bin/byvalver --biphasic --ml --format c -r \
  --metrics --metrics-live --failed-files failed.txt \
  input_dir/ output_dir/
```

## Processing Order

When multiple flags are specified, BYVALVER processes them in the following order:

1. **Input Reading**: Read shellcode from file
2. **PIC Generation** (`--pic`): If specified, generate position-independent code
3. **Biphasic Processing** (`--biphasic`): If specified, apply obfuscation then denullification
   - Pass 1: Obfuscation strategies
   - Pass 2: Null-byte elimination strategies
4. **XOR Encoding** (`--xor-encode`): If specified, XOR encode and prepend decoder stub
5. **Format Conversion** (`--format`): Convert to specified output format
6. **Output Writing**: Write to file

## ML Mode Considerations

When using `--ml`:
- Strategy selection is optimized based on learned patterns
- Metrics are tracked for continuous improvement
- Performance may be slightly impacted by ML overhead
- Works seamlessly with `--biphasic` and other flags
- ML mode is applied during Pass 2 (denullification) strategy selection

## Batch Mode Considerations

Batch processing:
- Applies all specified flags to each file independently
- Preserves directory structure by default (use `--no-preserve-structure` to flatten)
- Continues on error by default (use `--no-continue-on-error` to stop on first failure)
- Full compatibility with `--biphasic`, `--ml`, `--format`, and `--xor-encode`

## Examples

### Example 1: Production Shellcode Generation
```bash
# Generate obfuscated, null-free, position-independent shellcode with XOR encoding
./bin/byvalver --biphasic --pic --xor-encode 0x41424344 \
  original.bin weaponized.bin
```

### Example 2: C Header Generation for Development
```bash
# Convert shellcode to C header file with obfuscation
./bin/byvalver --biphasic --format c shellcode.bin shellcode.h
```

### Example 3: Batch Processing with ML
```bash
# Process entire directory with ML-enhanced strategy selection
./bin/byvalver --biphasic --ml --metrics -r \
  --pattern "*.bin" --failed-files failures.log \
  shellcode_samples/ processed_output/
```

### Example 4: Python Integration
```bash
# Generate Python-compatible shellcode
./bin/byvalver --biphasic --format python payload.bin payload.py

# Then use in Python:
# from payload import shellcode
# ctypes.string_at(ctypes.addressof(ctypes.create_string_buffer(shellcode)), len(shellcode))
```

### Example 5: PowerShell Payload
```bash
# Generate PowerShell-compatible payload
./bin/byvalver --biphasic --pic --format powershell payload.bin payload.ps1

# Then use in PowerShell:
# . .\payload.ps1
# $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($shellcode.Count)
# [System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $ptr, $shellcode.Count)
```

## Performance Notes

- **`--biphasic`**: Adds ~20-40% to processing time (two-pass architecture)
- **`--ml`**: Adds ~5-15% overhead for strategy selection
- **`--pic`**: Increases output size by ~30-50% (PIC stub + API hashing)
- **`--xor-encode`**: Adds ~50 bytes (decoder stub + key + length)
- **Batch mode**: Processing is parallelizable in future versions

## Troubleshooting

### XOR Decoding Issues
If XOR-encoded shellcode doesn't decode properly:
- Verify the key is correct
- Ensure the decoder stub wasn't modified
- Check that the encoded length matches actual shellcode size

### Format Output Issues
If formatted output doesn't compile/execute:
- Verify format matches target language syntax
- Check for proper null-termination in strings
- Ensure output file extension matches format

### ML Mode Not Learning
If ML mode doesn't improve over time:
- Enable `--metrics` to track learning progress
- Use `--metrics-live` to monitor real-time updates
- Process more samples to provide more training data

## Version

This documentation applies to BYVALVER v3.0+

Last Updated: 2025-12-11
