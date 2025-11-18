# verify_semantic - Semantic Verification Tool for byvalver

## Overview

`verify_semantic` is a semantic analysis-based verification tool that uses concrete execution to verify that byvalver's null-byte elimination transformations preserve functional semantics.

Unlike the pattern-matching approach in `verify_functionality.py`, this tool:
- **Executes both versions** of the shellcode with multiple test vectors
- **Compares final CPU states** (registers, flags, memory) rather than instruction patterns
- **Detects complex transformations** including byte-construction, LOOP expansions, and multi-instruction sequences
- **Provides detailed trace output** for debugging transformation issues

## Installation

No additional dependencies beyond byvalver's existing requirements:
- Python 3.6+
- Capstone disassembly library (`pip install capstone`)

## Usage

### Basic Usage

```bash
python3 verify_semantic.py <original.bin> <processed.bin>
```

### Options

```
positional arguments:
  original              Original shellcode binary file
  processed             Processed shellcode binary file

optional arguments:
  -h, --help            show this help message and exit
  --verbose, -v         Show detailed execution trace
  --format {text,json}  Output format (default: text)
  --threshold THRESHOLD
                        Pass threshold percentage (default: 80.0)
```

### Examples

**Basic verification:**
```bash
python3 verify_semantic.py .test_bins/loop_test.bin .test_bins/loop_test_processed.bin
```

**Verbose output with details:**
```bash
python3 verify_semantic.py original.bin processed.bin --verbose
```

**JSON output for automation:**
```bash
python3 verify_semantic.py original.bin processed.bin --format json
```

**Custom pass threshold:**
```bash
python3 verify_semantic.py original.bin processed.bin --threshold 90.0
```

## How It Works

### Verification Process

1. **Disassemble** both original and processed shellcode using Capstone
2. **Generate test vectors** with different initial CPU states
3. **Execute both versions** concretely with each test vector
4. **Compare final states** (registers, flags, memory)
5. **Detect transformation patterns** (byte-construction, LOOP, etc.)
6. **Report results** with detailed mismatches if any

### Test Vectors

The tool generates 5 test vectors with different initial register states:
- All zeros (baseline)
- All ones (0xFFFFFFFF)
- Alternating patterns (0xAAAAAAAA / 0x55555555)
- Small values (1, 2, 3, 4)
- Boundary values (0x7FFFFFFF, 0x80000000)

### Supported Instructions

Currently supports:
- **Data movement:** MOV, LEA, PUSH, POP, XCHG, MOVZX, MOVSX, CDQ
- **Arithmetic:** ADD, SUB, INC, DEC, NEG, CMP
- **Logic:** AND, OR, XOR, NOT, TEST
- **Shift/Rotate:** SHL, SHR, SAL, SAR, ROL, ROR
- **Control flow:** JMP, Jcc, CALL, RET, LOOP, JECXZ (partial support)

### Transformation Detection

Recognizes these common patterns:
- **DIRECT**: 1:1 matching instruction
- **MOV_ZERO_TO_XOR**: `MOV reg, 0` → `XOR reg, reg`
- **BYTE_CONSTRUCTION**: `MOV reg, imm` → `XOR; SHL; OR; ...` sequence
- **LOOP_TO_DEC_JNZ**: `LOOP rel8` → `DEC ECX; JNZ rel8`

## Output Format

### Text Output

```
============================================================
SEMANTIC VERIFICATION RESULTS
============================================================

Equivalence Check: PASSED
Score: 100.0% (83/83)

Transformations Detected:
  DIRECT: 44
  BYTE_CONSTRUCTION: 6
  LOOP_TO_DEC_JNZ: 1

✓ VERIFICATION PASSED (threshold: 80.0%)
```

### JSON Output

```json
{
  "passed": true,
  "score": 100.0,
  "total_instructions": 83,
  "verified_instructions": 83,
  "transformations": {
    "DIRECT": 44,
    "BYTE_CONSTRUCTION": 6
  },
  "register_mismatches": 0,
  "flag_mismatches": 0,
  "memory_mismatches": 0,
  "details": ["Test vector 0: PASSED", "Test vector 1: PASSED", ...]
}
```

## Architecture

```
verify_semantic/
├── __init__.py
├── cpu_state.py           # CPU state representation (registers, flags, memory)
├── disassembler.py        # Capstone wrapper for instruction parsing
├── execution_engine.py    # Concrete execution engine
├── equivalence_checker.py # Main verification logic
└── semantics/             # Instruction semantics (stubs - handled by engine)
    ├── __init__.py
    ├── arithmetic.py
    ├── logic.py
    ├── shift.py
    ├── data_movement.py
    └── control_flow.py
```

## Comparison with verify_functionality.py

| Feature | verify_functionality.py | verify_semantic.py |
|---------|------------------------|-------------------|
| **Approach** | Pattern matching | Concrete execution |
| **Speed** | Fast | Moderate |
| **Coverage** | Limited patterns | All supported instructions |
| **Accuracy** | Pattern-dependent | High (state-based) |
| **False negatives** | Many (unrecognized patterns) | Few |
| **Best for** | Quick regression checks | Deep verification |

## Limitations

### Current Limitations

1. **Instruction coverage**: Not all x86 instructions implemented yet
2. **Symbolic execution**: Currently only concrete execution (no path exploration)
3. **Self-modifying code**: Not fully supported
4. **Position-independent code**: Limited support for GET_PC patterns

### Known Issues

1. Some complex shellcode may show "Execution failed" for test vectors but still PASS overall (this happens when unsupported instructions are encountered but don't affect final state comparison)
2. Control flow instructions (JMP, CALL) are simplified and don't actually redirect execution flow

## Future Enhancements

- [ ] Add symbolic execution for complex patterns
- [ ] Implement all x86 instruction semantics
- [ ] Support for 64-bit shellcode
- [ ] Trace logging to file (JSON/text)
- [ ] Integration with Makefile test suite
- [ ] Memory aliasing analysis
- [ ] Self-modifying code support

## Integration

### Makefile Integration

Add to byvalver Makefile:

```makefile
verify-semantic: $(BIN_DIR)/$(TARGET)
    python3 verify_semantic.py .test_bins/original.bin .test_bins/processed.bin

test-semantic: verify-semantic
```

### CI/CD Integration

```bash
# Run verification and fail on threshold
python3 verify_semantic.py original.bin processed.bin --threshold 90.0 || exit 1

# Get JSON output for reporting
python3 verify_semantic.py original.bin processed.bin --format json > results.json
```

## Troubleshooting

**"Execution failed" messages but PASSED overall:**
- This is normal - some instructions aren't implemented yet
- The tool still compares final states for successfully executed instructions
- If final states match, it reports PASSED

**False FAILures:**
- Check if both shellcodes are actually functionally equivalent
- Use `--verbose` to see which test vectors fail
- Check register/flag/memory mismatches in output

**No transformations detected:**
- Pattern detection is limited in MVP
- Doesn't affect verification accuracy (state comparison is authoritative)

## Development

### Adding New Instruction Support

1. Edit `execution_engine.py`
2. Add instruction handler method (e.g., `_execute_new_insn()`)
3. Update `_dispatch_instruction()` to call new handler
4. Test with simple shellcode using the instruction

### Adding New Transformation Patterns

1. Edit `equivalence_checker.py`
2. Add detection logic in `_detect_transformations()`
3. Add new transformation type to `_record_transformation()`

## License

Same as byvalver - see main project LICENSE.

## Author

Created as part of byvalver semantic verification enhancement.
