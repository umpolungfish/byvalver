# BYVALVER Usage Guide

## Command-Line Interface

BYVALVER provides a flexible command-line interface for processing shellcode with different processing modes and options.

### Basic Syntax
```bash
./bin/byvalver [OPTIONS] <input_file> [output_file]
```

### Parameters

- `input_file`: Path to the input binary file containing shellcode to process
- `output_file`: Optional. Path to the output binary file. Defaults to `output.bin`

### Options

- `--biphasic`: Enable biphasic processing mode (obfuscation + null-byte elimination)
- `--xor-encode <key>`: XOR encode output with specified 4-byte key (in hex format)

### Processing Modes

#### 1. Standard Mode
Basic null-byte elimination without additional obfuscation:
```bash
./bin/byvalver input.bin output.bin
```

This mode applies transformation strategies to remove null bytes from the shellcode while preserving functionality.

#### 2. Biphasic Mode
Two-pass processing that first obfuscates the shellcode then eliminates null bytes:
```bash
./bin/byvalver --biphasic input.bin output.bin
```

This mode:
- Pass 1: Applies obfuscation strategies to increase analytical difficulty
- Pass 2: Eliminates null bytes from the obfuscated code

#### 3. XOR Encoding Mode
Adds a decoder stub and XOR-encodes the output with a specified key:
```bash
./bin/byvalver --biphasic --xor-encode 0x12345678 input.bin output.bin
```

This mode prepends a JMP-CALL-POP decoder stub that will decode the shellcode at runtime using the provided key.

### Examples

#### Basic Usage
```bash
# Process shellcode and save to default output.bin
./bin/byvalver shellcode.bin

# Process shellcode and save to specific output file
./bin/byvalver shellcode.bin processed_shellcode.bin
```

#### Biphasic Processing
```bash
# Apply obfuscation followed by null-byte elimination
./bin/byvalver --biphasic shellcode.bin output.bin
```

#### XOR Encoding
```bash
# Create XOR-encoded shellcode with 4-byte key
./bin/byvalver --biphasic --xor-encode 0xABCDEF00 shellcode.bin encoded_shellcode.bin
```

#### Multiple Options Combined
```bash
# Full-featured processing with biphasic mode and XOR encoding
./bin/byvalver --biphasic --xor-encode 0x11223344 input.bin output.bin
```

### Decoder Stub Architecture

When using XOR encoding, BYVALVER generates a JMP-CALL-POP decoder stub with the following characteristics:

1. **JMP-CALL-POP pattern**: Uses position-independent code to locate the encoded shellcode
2. **Key storage**: The 4-byte XOR key is stored immediately after the decoder stub
3. **Length encoding**: The length of the original shellcode is stored and XOR-encoded with a null-free key
4. **Multi-byte cycling**: The decoder cycles through all 4 bytes of the key for enhanced obfuscation
5. **Execution flow**: After decoding, execution jumps to the decoded shellcode

### Output Information

BYVALVER provides detailed output information during processing:

- **Original shellcode size**: Size of the input shellcode before processing
- **Modified shellcode size**: Size of the output shellcode after processing
- **Processing statistics**: Information about strategies applied and transformations made
- **Status messages**: Progress indicators during obfuscation and null-byte elimination passes

### Error Handling

BYVALVER includes comprehensive error handling:

- **File access errors**: Proper reporting of missing input files or write permissions
- **Memory allocation failures**: Graceful handling of insufficient memory conditions
- **Invalid shellcode**: Detection and reporting of malformed input
- **Processing failures**: Identification of specific instructions or patterns that cannot be processed

### Performance Considerations

- **Processing time**: Complex shellcode with many instructions may require significant processing time
- **Memory usage**: Large shellcode files require proportional memory allocation
- **Strategy selection**: The tool automatically selects the most appropriate strategies based on instruction patterns and priorities
- **Size increase**: Null-byte elimination may result in larger output shellcode due to instruction transformations

### Verification

After processing, it's recommended to verify:

1. **Null byte elimination**: Ensure no null bytes remain in the output
2. **Functional equivalence**: Confirm the processed shellcode maintains the original functionality
3. **Size requirements**: Verify the output size meets any constraints for the intended use case
4. **Runtime behavior**: Test the processed shellcode in the target environment to ensure proper execution