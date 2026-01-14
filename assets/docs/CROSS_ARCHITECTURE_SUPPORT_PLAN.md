# Cross-Architecture Support Implementation Plan

> **Status**: Planning Phase
> **Target Version**: v4.0
> **Estimated Effort**: ~1500-2000 LOC changes over 6 weeks
> **Risk Level**: Medium

---

## Executive Summary

This document outlines the implementation plan for comprehensive multi-architecture support in Byvalver, extending the **bad-byte elimination engine** to support:

- **x86** (32-bit Intel/AMD)
- **x64** (64-bit Intel/AMD)
- **ARM** (32-bit ARM)
- **ARM64** (AArch64 64-bit ARM)

Currently, the `--arch` flag is parsed but **completely ignored** during processing. All Capstone disassembly is hardcoded to `CS_MODE_32`, and all 400+ strategies are x86-specific.

---

## Current State Analysis

### Bad-Byte System (v3.0+)

Byvalver uses a **profile-aware bad-byte elimination system** (not just null bytes):

```c
typedef struct {
    uint8_t bad_bytes[256];      // Bitmap: O(1) lookup
    int bad_byte_count;           // Number of distinct bad bytes
    uint8_t bad_byte_list[256];   // Ordered list of bad byte values
} bad_byte_config_t;
```

**Supported bad-byte profiles**:
- Null bytes only (`\x00`)
- Common shellcode bad bytes (`\x00\x0a\x0d\x20`)
- Custom user-defined profiles
- Alphanumeric-only encoding
- Printable-ASCII only

### Critical Issues

1. **Architecture flag is ignored**: `--arch` flag accepted but never used
2. **Hardcoded 32-bit mode**: All core functions use `CS_MODE_32`
   - `src/core.c:535` - `remove_null_bytes()`
   - `src/core.c:1093` - `adaptive_processing()`
   - `src/core.c:1286` - `apply_obfuscation()`
   - `src/core.c:1407` - `count_shellcode_stats()`
3. **No architecture context**: Core functions don't receive architecture parameter
4. **x86-only strategies**: All 400+ strategies use `X86_INS_*` and `X86_REG_*` constants
5. **Type-unsafe handling**: String comparison instead of enum

### What Works

- ✅ CLI accepts `--arch x86` and `--arch x64`
- ✅ Configuration structure has `target_arch` field
- ✅ 400+ strategies registered for bad-byte elimination
- ✅ Capstone disassembly framework integrated
- ✅ Profile-aware bad-byte system (v3.0)
- ✅ ML-enhanced strategy selection
- ✅ Batch processing pipeline

---

## Architecture Goals

### Primary Objective

Enable Byvalver to process shellcode for **multiple architectures** with proper Capstone mode selection and architecture-specific bad-byte elimination strategies.

### Key Features

1. **Architecture Detection & Selection**
   - Automatic architecture detection from shellcode (future enhancement)
   - Manual selection via `--arch` flag
   - Type-safe architecture enumeration

2. **Architecture-Aware Strategy System**
   - Conditional strategy registration per architecture
   - Architecture-specific instruction handling
   - Proper instruction encoding for each architecture

3. **ARM/ARM64 Support**
   - ARM instruction disassembly (Capstone ARM mode)
   - ARM-specific bad-byte elimination strategies
   - ARM immediate encoding helpers
   - Thumb mode support (future enhancement)

4. **Backward Compatibility**
   - No breaking changes to CLI interface
   - Default behavior unchanged (x64)
   - All existing x86/x64 strategies continue to work

---

## Implementation Plan

### Phase 1: Type-Safe Architecture Infrastructure

**Goal**: Create architecture enumeration and helper functions

**Changes**:

1. **Add architecture enum** (`src/core.h`):
```c
typedef enum {
    BYVAL_ARCH_X86 = 0,    // 32-bit x86
    BYVAL_ARCH_X64 = 1,    // 64-bit x86-64
    BYVAL_ARCH_ARM = 2,    // 32-bit ARM
    BYVAL_ARCH_ARM64 = 3   // 64-bit ARM (AArch64)
} byval_arch_t;
```

2. **Implement Capstone mode selector** (`src/core.c`):
```c
void get_capstone_arch_mode(byval_arch_t arch,
                            cs_arch *cs_arch_out,
                            cs_mode *cs_mode_out);
```

3. **Update CLI configuration** (`src/cli.h`):
   - Change `char *target_arch` → `byval_arch_t target_arch`

4. **Update CLI parsing** (`src/cli.c`):
   - Parse `"x86"`, `"x64"`, `"arm"`, `"arm64"`/`"aarch64"` to enum
   - Set default to `BYVAL_ARCH_X64`

**Files Modified**:
- `src/core.h` - Add enum and function declaration
- `src/core.c` - Implement helper function
- `src/cli.h` - Change field type
- `src/cli.c` - Parse to enum

---

### Phase 2: Core Function Signature Updates

**Goal**: Thread architecture parameter through all processing functions

**Changes**:

1. **Update function signatures** (`src/core.h`):
```c
struct buffer remove_null_bytes(const uint8_t *shellcode, size_t size,
                                byval_arch_t arch);
struct buffer apply_obfuscation(const uint8_t *shellcode, size_t size,
                                byval_arch_t arch);
struct buffer biphasic_process(const uint8_t *shellcode, size_t size,
                               byval_arch_t arch);
struct buffer adaptive_processing(const uint8_t *input, size_t size,
                                  byval_arch_t arch);
void count_shellcode_stats(const uint8_t *shellcode, size_t size,
                          int *instruction_count, int *bad_byte_count,
                          byval_arch_t arch);
```

2. **Update implementations** (`src/core.c`):

Replace hardcoded:
```c
// OLD (WRONG):
if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
```

With dynamic selection:
```c
// NEW (CORRECT):
cs_arch cs_arch;
cs_mode cs_mode;
get_capstone_arch_mode(arch, &cs_arch, &cs_mode);
if (cs_open(cs_arch, cs_mode, &handle) != CS_ERR_OK) {
```

Apply to:
- Line 535: `remove_null_bytes()`
- Line 1093: `adaptive_processing()`
- Line 1286: `apply_obfuscation()`
- Line 1407: `count_shellcode_stats()`

3. **Update call sites** (`src/main.c`):

Pass `config->target_arch` to all core function calls:
- Lines 197, 199, 205, 207: Processing calls
- Lines 574, 615: Statistics calls

**Files Modified**:
- `src/core.h` - Function signatures
- `src/core.c` - 5 function implementations
- `src/main.c` - 6+ call sites

---

### Phase 3: Strategy System Architecture Awareness

**Goal**: Make strategy selection architecture-aware

**Changes**:

1. **Add architecture field to strategy** (`src/strategy.h`):
```c
typedef struct {
    char name[64];
    int (*can_handle)(cs_insn *insn);
    size_t (*get_size)(cs_insn *insn);
    void (*generate)(struct buffer *b, cs_insn *insn);
    int priority;
    byval_arch_t target_arch;  // NEW: Target architecture
} strategy_t;
```

2. **Update strategy initialization** (`src/strategy.h`):
```c
void init_strategies(int use_ml, byval_arch_t arch);
```

3. **Architecture-aware filtering** (`src/strategy.c`):
```c
strategy_t** get_strategies_for_instruction(cs_insn *insn, int *count,
                                           byval_arch_t arch) {
    // Filter strategies by architecture
    // Only return strategies where strategy->target_arch == arch
}
```

4. **Conditional registration** (`src/strategy_registry.c`):
```c
void init_strategies(int use_ml, byval_arch_t arch) {
    if (arch == BYVAL_ARCH_X86 || arch == BYVAL_ARCH_X64) {
        register_mov_strategies();
        register_arithmetic_strategies();
        // ... all existing x86 strategies
    }

    if (arch == BYVAL_ARCH_ARM) {
        register_arm_strategies();
    }

    if (arch == BYVAL_ARCH_ARM64) {
        register_arm64_strategies();
    }
}
```

5. **Bulk update existing strategies**:

Add `.target_arch = BYVAL_ARCH_X86` to all 400+ strategy structures.

**Automated approach**:
```bash
find src -name "*_strategies.c" -exec sed -i \
  's/\.priority = \([0-9]*\)$/&,\n    .target_arch = BYVAL_ARCH_X86/' {} \;
```

**Files Modified**:
- `src/strategy.h` - Add field, update signatures
- `src/strategy.c` - Architecture filtering
- `src/strategy_registry.c` - Conditional registration
- `src/*_strategies.c` (~40 files) - Add architecture field

---

### Phase 4: ARM Strategy Implementation

**Goal**: Implement ARM-specific bad-byte elimination strategies

#### 4.1 ARM Strategy Infrastructure

**New Files**:
- `src/arm_strategies.h` - ARM strategy declarations
- `src/arm_strategies.c` - ARM strategy implementations
- `src/arm_immediate_encoding.h` - ARM encoding helpers declarations
- `src/arm_immediate_encoding.c` - ARM encoding helper implementations
- `src/arm64_strategies.h` - ARM64 strategy declarations
- `src/arm64_strategies.c` - ARM64 strategy implementations

#### 4.2 Core ARM Strategies

**Priority 1 (Must Implement)**:

1. **arm_mov_original**
   - Pass through MOV instructions without bad bytes
   - Priority: 10
   - Example: `MOV R0, #255` (no bad bytes) → keep as-is

2. **arm_mov_mvn**
   - Transform MOV using MVN (bitwise NOT)
   - Priority: 12
   - Example: `MOV R0, #0x00FF` → `MVN R0, #0xFF00`

3. **arm_mov_multi_instruction**
   - Build values using ADD/SUB sequences
   - Priority: 8
   - Example: `MOV R0, #0x100` → `MOV R0, #0x80; ADD R0, R0, #0x80`

4. **arm_add_original**
   - Pass through ADD instructions without bad bytes
   - Priority: 10

5. **arm_sub_original**
   - Pass through SUB instructions without bad bytes
   - Priority: 10

**Priority 2 (Important)**:

6. Logical operations: `AND`, `ORR`, `EOR`
7. Load/store with adjusted offsets: `LDR`, `STR`
8. Branch instruction handling: `B`, `BL`, conditional branches
9. Stack operations: `PUSH`/`POP` alternatives using `STM`/`LDM`

**Priority 3 (Future Enhancements)**:

10. Floating-point instructions
11. SIMD/NEON instructions
12. Coprocessor instructions
13. Thumb mode support

#### 4.3 ARM Instruction Encoding Helpers

**Key Functions**:

```c
// Check if value can be encoded as ARM immediate (8-bit value + 4-bit rotation)
int is_arm_immediate_encodable(uint32_t value);

// Encode value as ARM immediate (returns encoding or -1)
int encode_arm_immediate(uint32_t value);

// Find MVN equivalent without bad bytes
int find_arm_mvn_immediate(uint32_t target, uint32_t *mvn_val_out);

// Map ARM registers to indices (0-15)
uint8_t get_arm_reg_index(arm_reg reg);

// Check if ARM instruction has bad bytes
int arm_has_bad_bytes(cs_insn *insn, const bad_byte_config_t *profile);
```

**ARM Immediate Encoding Rules**:
- ARM immediates: 8-bit value rotated right by even number of bits (0-30)
- Not all 32-bit values can be encoded as immediates
- Alternative approaches:
  - Use MVN (bitwise NOT)
  - Multi-instruction sequences
  - LDR from literal pool

#### 4.4 ARM Strategy Example

```c
// Strategy: ARM MOV with MVN transformation
int can_handle_arm_mov_mvn(cs_insn *insn) {
    if (insn->id != ARM_INS_MOV) return 0;

    if (insn->detail->arm.op_count != 2) return 0;

    if (insn->detail->arm.operands[0].type != ARM_OP_REG ||
        insn->detail->arm.operands[1].type != ARM_OP_IMM) {
        return 0;
    }

    // Only handle if has bad bytes
    if (!arm_has_bad_bytes(insn, &g_bad_byte_context)) return 0;

    // Check if MVN transformation produces bad-byte-free instruction
    uint32_t imm = (uint32_t)insn->detail->arm.operands[1].imm;
    uint32_t mvn_val;
    return find_arm_mvn_immediate(imm, &mvn_val);
}

size_t get_size_arm_mov_mvn(cs_insn *insn) {
    (void)insn;
    return 4;  // ARM instructions are 4 bytes
}

void generate_arm_mov_mvn(struct buffer *b, cs_insn *insn) {
    uint8_t rd = get_arm_reg_index(insn->detail->arm.operands[0].reg);
    uint32_t imm = (uint32_t)insn->detail->arm.operands[1].imm;
    uint32_t mvn_val;

    find_arm_mvn_immediate(imm, &mvn_val);

    // Encode MVN instruction: MVN Rd, #imm
    // Condition: AL (0xE), Opcode: MVN (0xF), I=1
    int encoded_imm = encode_arm_immediate(mvn_val);
    uint32_t instruction = 0xE3E00000 | (rd << 12) | encoded_imm;

    // Verify no bad bytes
    if (!is_bad_byte_free_value(instruction, &g_bad_byte_context)) {
        // Fallback: use original (will be caught by validation)
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    buffer_append(b, (uint8_t*)&instruction, 4);
}

strategy_t arm_mov_mvn_strategy = {
    .name = "arm_mov_mvn",
    .can_handle = can_handle_arm_mov_mvn,
    .get_size = get_size_arm_mov_mvn,
    .generate = generate_arm_mov_mvn,
    .priority = 12,
    .target_arch = BYVAL_ARCH_ARM
};
```

#### 4.5 ARM64 Considerations

ARM64 (AArch64) differs significantly from ARM:

**Differences**:
- 64-bit registers (X0-X30, W0-W30 for 32-bit)
- Different immediate encoding (more flexible)
- MOVZ/MOVK instructions for wide immediates
- No condition codes on most instructions
- Fixed 4-byte instruction size (like ARM)

**Strategy Adaptations**:
- Use MOVN (move NOT) instead of MVN
- Use MOVZ/MOVK pairs for 64-bit values
- Different register encoding scheme

---

### Phase 5: Testing & Validation

**Goal**: Ensure correctness across all architectures

#### 5.1 x86/x64 Regression Testing

**Test Cases**:
1. Process existing x86 shellcode with `--arch x86`
2. Process existing x64 shellcode with `--arch x64`
3. Verify all existing bad-byte profiles still work
4. Performance benchmarking (should be no regression)

**Expected Results**:
- All existing test shellcode processes correctly
- Output is functionally equivalent
- Bad bytes are eliminated according to profile
- No performance degradation

#### 5.2 ARM Testing Without Real Shellcode

Since ARM shellcode samples may not be available, use these approaches:

**Approach 1: Synthetic Instructions**
```c
// Create minimal ARM test cases
uint8_t test_mov_safe[] = {0xFF, 0x00, 0xA0, 0xE3};  // MOV R0, #255 (safe)
uint8_t test_mov_bad[] = {0x00, 0x00, 0xA0, 0xE3};   // MOV R0, #0 (has null)
uint8_t test_add[] = {0x01, 0x10, 0x80, 0xE2};       // ADD R1, R0, #1

// Process with Byvalver
./byvalver --arch arm test_arm_mov_bad.bin output.bin
```

**Approach 2: Cross-Compilation**
```bash
# Create simple C program
echo 'int main() { return 42; }' > test.c

# Compile for ARM
arm-linux-gnueabi-gcc -static -nostdlib -c test.c -o test.o

# Extract .text section
objcopy -O binary -j .text test.o test_arm.bin

# Process with Byvalver
./byvalver --arch arm --bad-bytes "00 0a 0d" test_arm.bin output.bin

# Verify output
arm-linux-gnueabi-objdump -D -b binary -m arm output.bin
```

**Approach 3: Unit Tests**

Create unit tests (`tests/test_arm_support.c`):

```c
void test_arm_capstone_mode_selection() {
    cs_arch arch;
    cs_mode mode;
    get_capstone_arch_mode(BYVAL_ARCH_ARM, &arch, &mode);
    assert(arch == CS_ARCH_ARM);
    assert(mode == CS_MODE_ARM);
}

void test_arm_strategy_registration() {
    init_strategies(0, BYVAL_ARCH_ARM);
    // Verify ARM strategies are registered
    // Verify x86 strategies are NOT registered
}

void test_arm_mov_mvn_strategy() {
    // Create instruction with bad byte
    uint8_t insn_bytes[] = {0x00, 0x00, 0xA0, 0xE3};  // MOV R0, #0

    // Disassemble
    csh handle;
    cs_insn *insn;
    cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_disasm(handle, insn_bytes, sizeof(insn_bytes), 0, 0, &insn);

    // Test strategy
    assert(can_handle_arm_mov_mvn(insn) == 1);

    struct buffer output;
    buffer_init(&output);
    generate_arm_mov_mvn(&output, insn);

    // Verify no bad bytes in output
    assert(is_bad_byte_free_buffer(output.data, output.size));

    cs_free(insn, 1);
    cs_close(&handle);
    buffer_free(&output);
}
```

#### 5.3 Validation & Error Handling

**Architecture Mismatch Detection**:

Add validation in `remove_null_bytes()`:

```c
// After disassembly, check instruction set matches architecture
if ((arch == BYVAL_ARCH_ARM || arch == BYVAL_ARCH_ARM64) && count > 0) {
    // Check first instruction ID range
    if (insn_array[0].id >= X86_INS_INVALID &&
        insn_array[0].id < ARM_INS_INVALID) {
        fprintf(stderr, "[ERROR] x86 instruction detected in ARM shellcode\n");
        fprintf(stderr, "[ERROR] Verify --arch parameter matches input\n");
        cs_free(insn_array, count);
        cs_close(&handle);
        return new_shellcode;
    }
}
```

**Strategy Availability Warning**:

```c
if (strategy_count == 0) {
    fprintf(stderr, "[WARNING] No strategy available for %s %s (arch: %d)\n",
            current->insn->mnemonic, current->insn->op_str, arch);
    fprintf(stderr, "[WARNING] Using fallback - may introduce bad bytes\n");
    fallback_general_instruction(&new_shellcode, current->insn);
}
```

**Bad-Byte Profile Validation**:

```c
if ((arch == BYVAL_ARCH_ARM || arch == BYVAL_ARCH_ARM64) &&
    config->bad_bytes->bad_byte_count > 128) {
    fprintf(stderr, "[WARNING] Bad-byte profile may be too restrictive for ARM\n");
    fprintf(stderr, "[WARNING] ARM instructions may naturally contain many bytes\n");
    fprintf(stderr, "[WARNING] Consider using a more permissive profile\n");
}
```

---

### Phase 6: Documentation & User Experience

**Goal**: Ensure users can effectively use multi-architecture support

#### 6.1 Update Help Text

**File**: `src/cli.c` (line 232)

```c
fprintf(stream, "  Architecture Options:\n");
fprintf(stream, "      --arch ARCH              Target architecture\n");
fprintf(stream, "                               Values: x86, x64, arm, arm64 (default: x64)\n");
fprintf(stream, "                               NOTE: ARM/ARM64 support is experimental\n");
fprintf(stream, "\n");
```

#### 6.2 Architecture Status Messages

**File**: `src/main.c` (before processing)

```c
if (!config->quiet) {
    const char *arch_name;
    switch (config->target_arch) {
        case BYVAL_ARCH_X86: arch_name = "x86 (32-bit)"; break;
        case BYVAL_ARCH_X64: arch_name = "x64 (64-bit)"; break;
        case BYVAL_ARCH_ARM: arch_name = "ARM (32-bit)"; break;
        case BYVAL_ARCH_ARM64: arch_name = "ARM64 (AArch64)"; break;
        default: arch_name = "Unknown"; break;
    }
    fprintf(stderr, "╔════════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║  BYVALVER BAD-BYTE ELIMINATION ENGINE                 ║\n");
    fprintf(stderr, "╚════════════════════════════════════════════════════════╝\n");
    fprintf(stderr, "Target Architecture: %s\n", arch_name);
    fprintf(stderr, "Bad Bytes: %d distinct values\n", config->bad_bytes->bad_byte_count);
}
```

#### 6.3 Update README

Add section documenting cross-architecture support:

```markdown
## Cross-Architecture Support

Byvalver supports shellcode processing for multiple architectures:

### Supported Architectures

- **x86** (32-bit Intel/AMD) - Fully supported
- **x64** (64-bit Intel/AMD) - Fully supported
- **ARM** (32-bit ARM) - Experimental
- **ARM64** (AArch64) - Experimental

### Usage

Specify target architecture with `--arch` flag:

```bash
# x86 shellcode
./byvalver --arch x86 --bad-bytes "00 0a 0d" input_x86.bin output.bin

# x64 shellcode (default)
./byvalver --arch x64 --bad-bytes "00 0a 0d 20" input_x64.bin output.bin

# ARM shellcode
./byvalver --arch arm --bad-bytes "00" input_arm.bin output.bin

# ARM64 shellcode
./byvalver --arch arm64 --bad-bytes "00 0a" input_arm64.bin output.bin
```

### Architecture-Specific Notes

**x86/x64**:
- Comprehensive strategy coverage (400+ strategies)
- All bad-byte profiles supported
- Highly optimized

**ARM/ARM64** (Experimental):
- Limited strategy coverage (~20-30 core strategies)
- Some complex instructions may not be transformable
- Fixed 4-byte instruction size constraints
- Immediate encoding limitations

### Bad-Byte Profile Considerations

ARM architectures have more restrictive immediate encoding:
- Use simpler bad-byte profiles when possible
- Highly restrictive profiles (>128 bad bytes) may fail
- Consider using null-byte-only profile (`--bad-bytes "00"`)
```

#### 6.4 Add Architecture Examples

Create example directory: `examples/cross_arch/`

Files:
- `x86_example.asm` - x86 shellcode example
- `x64_example.asm` - x64 shellcode example
- `arm_example.s` - ARM shellcode example
- `arm64_example.s` - ARM64 shellcode example
- `build_and_test.sh` - Script to build and test all examples

---

## Critical Files Summary

### Core Infrastructure (Phase 1-2)
| File | Changes | LOC |
|------|---------|-----|
| `src/core.h` | Add enum, update signatures | +50 |
| `src/core.c` | Implement helper, update functions | +150 |
| `src/cli.h` | Change field type | +5 |
| `src/cli.c` | Parse to enum | +30 |
| `src/main.c` | Pass architecture | +20 |

### Strategy System (Phase 3)
| File | Changes | LOC |
|------|---------|-----|
| `src/strategy.h` | Add architecture field | +10 |
| `src/strategy.c` | Architecture filtering | +50 |
| `src/strategy_registry.c` | Conditional registration | +30 |
| `src/*_strategies.c` (40 files) | Add architecture field | +400 |

### ARM Support (Phase 4)
| File | Changes | LOC |
|------|---------|-----|
| `src/arm_strategies.h` | NEW: ARM strategy declarations | +50 |
| `src/arm_strategies.c` | NEW: ARM strategies | +500 |
| `src/arm_immediate_encoding.h` | NEW: ARM helpers declarations | +30 |
| `src/arm_immediate_encoding.c` | NEW: ARM helpers | +200 |
| `src/arm64_strategies.h` | NEW: ARM64 declarations | +50 |
| `src/arm64_strategies.c` | NEW: ARM64 strategies | +300 |

### Testing (Phase 5)
| File | Changes | LOC |
|------|---------|-----|
| `tests/test_arm_support.c` | NEW: ARM unit tests | +300 |
| `tests/test_cross_arch.c` | NEW: Cross-arch tests | +200 |

**Total Estimated Changes**: ~2,375 LOC

---

## Implementation Timeline

### Week 1: Foundation (Phase 1)
- **Days 1-2**: Add architecture enum and helper function
- **Days 3-4**: Update CLI configuration and parsing
- **Day 5**: Test compilation, verify enum usage
- **Deliverable**: Type-safe architecture selection working

### Week 2: Core Threading (Phase 2)
- **Days 1-2**: Update core function signatures
- **Days 3-4**: Replace hardcoded Capstone calls
- **Day 5**: Update call sites in main.c
- **Deliverable**: x86/x64 mode selection working via --arch flag

### Week 3: Strategy System (Phase 3.1-3.3)
- **Days 1-2**: Add architecture field to strategy structure
- **Days 3-4**: Implement architecture-aware filtering
- **Day 5**: Update init_strategies() signature
- **Deliverable**: Strategy system architecture-aware

### Week 4: Strategy Updates (Phase 3.4-3.5)
- **Days 1-3**: Bulk update 400+ strategies (automated)
- **Day 4**: Verify all strategies compile
- **Day 5**: Regression testing for x86/x64
- **Deliverable**: All existing strategies marked with architecture

### Week 5: ARM Infrastructure (Phase 4.1-4.3)
- **Days 1-2**: Create ARM strategy files and headers
- **Days 3-4**: Implement ARM immediate encoding helpers
- **Day 5**: Create ARM testing framework
- **Deliverable**: ARM infrastructure ready for strategies

### Week 6: ARM Strategies (Phase 4.2, 4.4)
- **Days 1-3**: Implement 20-30 core ARM strategies
- **Day 4**: Basic ARM64 infrastructure
- **Day 5**: Testing and validation
- **Deliverable**: Working ARM support (experimental)

### Week 7: Polish & Documentation (Phase 5-6)
- **Days 1-2**: Comprehensive testing across architectures
- **Day 3**: Performance benchmarking
- **Days 4-5**: Documentation updates, examples
- **Deliverable**: Production-ready cross-architecture support

---

## Potential Risks & Mitigation

### Risk 1: ARM Immediate Encoding Complexity
**Impact**: Medium
**Probability**: High
**Mitigation**:
- Focus on simple cases first (MOV with small immediates)
- Use multi-instruction fallbacks when immediate is not encodable
- Implement MOVW/MOVT pairs for ARM
- Document limitations clearly

### Risk 2: Strategy Explosion (400+ Files to Update)
**Impact**: High
**Probability**: Low
**Mitigation**:
- Automated bulk update using sed/awk scripts
- Version control for easy rollback
- Incremental compilation to catch errors early

### Risk 3: Testing Without Real Shellcode
**Impact**: Medium
**Probability**: High
**Mitigation**:
- Synthetic test cases (manually crafted instructions)
- Cross-compilation from C code
- Unit tests for individual strategies
- Collaboration with security community for real samples

### Risk 4: Performance Regression
**Impact**: Low
**Probability**: Low
**Mitigation**:
- Benchmark each phase against baseline
- Profile hot paths if slowdown detected
- Optimize architecture filtering if needed
- No performance-critical changes in phase 1-2

### Risk 5: ARM Instruction Encoding Errors
**Impact**: High
**Probability**: Medium
**Mitigation**:
- Extensive validation of generated bytecode
- Compare against Capstone's assembler (if available)
- Unit test each strategy thoroughly
- Disassemble output and verify correctness

### Risk 6: Bad-Byte Profile Incompatibility
**Impact**: Medium
**Probability**: Medium
**Mitigation**:
- Warn users when profile is too restrictive for ARM
- Document architecture-specific limitations
- Provide example profiles for each architecture

---

## Success Criteria

### Minimum Viable Product (MVP)

- ✅ x86 and x64 modes work correctly via --arch flag
- ✅ Architecture parameter threaded through all core functions
- ✅ Capstone mode selection is dynamic
- ✅ No regression in existing x86/x64 functionality
- ✅ Clear error messages when processing fails
- ✅ Architecture mismatch detection working

### Full Implementation

- ✅ MVP criteria
- ✅ 20+ ARM strategies implemented and tested
- ✅ ARM instruction encoding helpers functional
- ✅ ARM can process basic instructions (MOV, ADD, SUB, logical ops)
- ✅ Validation detects architecture mismatches
- ✅ Documentation updated with ARM examples
- ✅ Basic ARM64 infrastructure in place

### Stretch Goals

- ✅ 50+ ARM strategies
- ✅ Thumb mode support
- ✅ ARM64 strategies implemented
- ✅ Performance optimization for ARM
- ✅ Comprehensive test suite with real ARM shellcode samples
- ✅ Automatic architecture detection from shellcode headers

---

## Backward Compatibility Guarantees

1. **Default Behavior**: Architecture defaults to x64 (unchanged)
2. **CLI Interface**: No breaking changes to existing flags
3. **Strategy System**: All existing strategies continue to work
4. **Output Format**: No changes to output format or encoding
5. **Bad-Byte Profiles**: All existing profiles continue to work on x86/x64
6. **Performance**: No regression for x86/x64 processing

---

## Performance Expectations

### x86/x64
- **Impact**: Negligible (<1% overhead from parameter passing)
- **Memory**: Minimal increase (<1KB per strategy structure)
- **Strategy Selection**: No measurable difference

### ARM/ARM64
- **Impact**: Unknown (initial implementation may be slower)
- **Memory**: Minimal increase (same as x86/x64)
- **Strategy Selection**: May be faster (fewer strategies to evaluate)

### Optimization Opportunities
- **Strategy Caching**: Cache filtered strategies per architecture
- **Lazy Initialization**: Only initialize strategies for target architecture
- **Fast Path**: Skip architecture checks for single-arch builds

---

## Verification Checklist

After implementation, verify:

- [ ] Compiles without warnings on GCC and Clang
- [ ] All existing tests pass
- [ ] Process x86 shellcode with `--arch x86`
- [ ] Process x64 shellcode with `--arch x64`
- [ ] Process ARM test cases with `--arch arm`
- [ ] Architecture mismatch detection works
- [ ] Performance benchmarks show no regression
- [ ] Memory leak check with valgrind passes
- [ ] Documentation is complete and accurate
- [ ] Examples build and run successfully

---

## Future Enhancements

After initial implementation:

1. **Automatic Architecture Detection**
   - Detect architecture from ELF headers
   - Detect architecture from instruction patterns
   - Heuristic-based architecture guessing

2. **Thumb Mode Support**
   - Thumb/ARM mode switching
   - Thumb-2 instruction support
   - IT block handling

3. **MIPS Support**
   - MIPS 32-bit and 64-bit
   - MIPS-specific strategies

4. **PowerPC Support**
   - PowerPC 32-bit and 64-bit
   - Big-endian handling

5. **RISC-V Support**
   - RV32I and RV64I
   - Compressed instruction support

---

## References

### Capstone Documentation
- [Capstone Engine](https://www.capstone-engine.org/)
- [ARM/ARM64 Support](https://www.capstone-engine.org/lang_c.html)

### ARM Architecture
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation)
- [ARM Instruction Set](https://developer.arm.com/documentation/ddi0406/latest)
- [ARM Immediate Encoding](https://developer.arm.com/documentation/dui0489/latest/arm-and-thumb-instructions/immediate-constants)

### Bad-Byte Elimination Techniques
- Existing Byvalver strategy documentation
- [Shellcode Encoding Techniques](https://www.exploit-db.com/papers/13211)

---

**Document Version**: 1.0
**Last Updated**: 2026-01-13
**Status**: Planning Phase - Implementation Not Started
