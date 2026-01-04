# Generic Bad-Byte Elimination Framework (v3.0)

## Overview

**Version:** 3.0.0
**Status:** Functional, newly implemented (experimental for non-null characters)

BYVALVER v3.0 introduces a generic bad-byte elimination framework that extends the tool's capabilities beyond null-byte removal. Users can now specify arbitrary bytes to eliminate via the `--bad-bytes` command-line option.

**Important:** The 122+ transformation strategies were originally designed, tested, and optimized specifically for null-byte elimination. While they now support generic bad bytes at the implementation level, their effectiveness for non-null byte scenarios has not been comprehensively validated.

## Architecture

### Core Data Structures

#### Bad Character Configuration (`bad_byte_config_t`)

```c
typedef struct {
    uint8_t bad_chars[256];      // Bitmap: 1=bad, 0=ok (O(1) lookup)
    int bad_char_count;           // Number of bad bytes
    uint8_t bad_char_list[256];   // List of bad byte values
} bad_byte_config_t;
```

**Design Rationale:**
- **Bitmap Array**: O(1) constant-time lookup for any byte value
- **256-byte Size**: Covers entire byte space (0x00-0xFF)
- **Memory Efficient**: Only 512 bytes total (256 bitmap + 256 list)
- **Cache Friendly**: Fits in L1 cache for optimal performance

#### Global Context (`bad_char_context_t`)

```c
typedef struct {
    bad_byte_config_t config;
    int initialized;
} bad_char_context_t;

extern bad_char_context_t g_bad_char_context;
```

**Design Rationale:**
- **Global Access**: Avoids threading configuration through 100+ functions
- **Zero Overhead**: No function parameter changes required
- **Initialization Flag**: Tracks whether context has been set
- **Single Source of Truth**: All strategies reference same configuration

### API Functions

#### Core Checking Functions

```c
// Check if single byte is free of bad bytes
int is_bad_char_free_byte(uint8_t byte);

// Check if 32-bit value contains bad bytes
int is_bad_char_free(uint32_t val);

// Check if buffer contains bad bytes
int is_bad_char_free_buffer(const uint8_t *data, size_t size);
```

**Implementation:**
```c
int is_bad_char_free_byte(uint8_t byte) {
    if (!g_bad_char_context.initialized) {
        return byte != 0x00;  // Default: null-only
    }
    return g_bad_char_context.config.bad_chars[byte] == 0;
}
```

#### Context Management Functions

```c
// Initialize bad byte context with configuration
void init_bad_char_context(bad_byte_config_t *config);

// Reset context to default state
void reset_bad_char_context(void);

// Get current bad byte configuration
bad_byte_config_t* get_bad_char_config(void);
```

### Configuration Flow

**Propagation Path:**
1. `main()` → `parse_arguments()` → populates `config->bad_chars`
2. `main()` → `process_single_file()` → calls `init_bad_char_context(config->bad_chars)`
3. All strategies access via global context: `is_bad_char_free()`

**Initialization:**
```c
// In core.c
void init_bad_char_context(bad_byte_config_t *config) {
    if (config) {
        memcpy(&g_bad_char_context.config, config, sizeof(bad_byte_config_t));
        g_bad_char_context.initialized = 1;
    } else {
        // Default: null byte only
        memset(&g_bad_char_context, 0, sizeof(bad_char_context_t));
        g_bad_char_context.config.bad_chars[0x00] = 1;
        g_bad_char_context.config.bad_char_list[0] = 0x00;
        g_bad_char_context.config.bad_char_count = 1;
        g_bad_char_context.initialized = 1;
    }
}
```

## Command-Line Interface

### `--bad-bytes` Option

**Syntax:**
```bash
byvalver --bad-bytes "XX,YY,ZZ" input.bin output.bin
```

**Format:**
- Comma-separated hexadecimal byte values
- Each value must be 2 hex digits (00-FF)
- No `0x` prefix required
- Whitespace is trimmed

**Examples:**
```bash
# Null bytes only (default)
byvalver input.bin output.bin
byvalver --bad-bytes "00" input.bin output.bin

# Null + newlines (network protocols)
byvalver --bad-bytes "00,0a,0d" input.bin output.bin

# Null + space + tab (string safety)
byvalver --bad-bytes "00,20,09" input.bin output.bin

# Multiple bad bytes
byvalver --bad-bytes "00,0a,0d,20,09" input.bin output.bin
```

### Parsing Implementation

**File:** `src/cli.c`

```c
bad_byte_config_t* parse_bad_chars_string(const char *input) {
    // Parse comma-separated hex: "00,0a,0d" → {0x00, 0x0a, 0x0d}
    // Build bitmap and list
    // Default to {0x00} if empty
    // Validate: no duplicates, valid hex, 0x00-0xFF range
}
```

**Validation:**
- Checks for valid hex format
- Validates range (0x00-0xFF)
- Automatically deduplicates values
- Returns NULL on parse error

**Error Handling:**
```c
if (!config->bad_chars) {
    fprintf(stderr, "Error: Invalid --bad-bytes format: %s\n", optarg);
    fprintf(stderr, "Expected format: \"00,0a,0d\" (comma-separated hex bytes)\n");
    return EXIT_INVALID_ARGUMENTS;
}
```

## Strategy Integration

### Strategy Updates

All 122+ strategies have been updated to use the generic API:

**Before (v2.x):**
```c
// Null-specific checking
if (insn->bytes[i] == 0x00) {
    // handle null byte
}

if (has_null_bytes(insn)) {
    // instruction contains nulls
}
```

**After (v3.0):**
```c
// Generic bad-byte checking
if (!is_bad_char_free_byte(insn->bytes[i])) {
    // handle bad byte
}

if (has_bad_chars_insn(insn)) {
    // instruction contains bad bytes
}
```

### Backward Compatibility

**Deprecated Wrappers:**
```c
// Kept for compatibility with legacy code
int is_null_free_byte(uint8_t byte) {
    return is_bad_char_free_byte(byte);
}

int is_null_free(uint32_t val) {
    return is_bad_char_free(val);
}
```

**Function Rename:**
```c
// In strategy_registry.c
int has_null_bytes(cs_insn *insn) {
    // Updated in v3.0: Now checks for generic bad bytes
    // Function name kept for backward compatibility with 100+ strategy files
    return !is_bad_char_free_buffer(insn->bytes, insn->size);
}
```

## How It Differs from Null-Byte Elimination

### Conceptual Differences

| Aspect | Null-Byte Elimination (v2.x) | Generic Bad-Byte (v3.0) |
|--------|------------------------------|------------------------------|
| **Target** | Single byte: 0x00 | Arbitrary set of bytes |
| **Configuration** | Hardcoded | User-specified via `--bad-bytes` |
| **Default** | Always null-only | Null-only if not specified |
| **Testing** | Extensively tested, 100% success | Functional but not validated |
| **Optimization** | Strategies optimized for null patterns | Strategies apply generically |
| **Use Case** | String safety, buffer overflows | Network protocols, input filters |

### Technical Differences

**Null-Byte Elimination:**
- Hardcoded check: `if (byte == 0x00)`
- Single byte to avoid
- Well-defined patterns (trailing zeros, ModR/M null bytes, etc.)
- Predictable transformation requirements

**Generic Bad-Byte Elimination:**
- Bitmap check: `if (bad_chars[byte] == 1)`
- Configurable set of bytes to avoid
- Patterns vary based on bad byte set
- Transformation requirements depend on character distribution

### Strategy Applicability

**Strategies Designed for Null Bytes:**
- MOV reg, 0x00000000 → strategies optimize for trailing zeros
- ModR/M byte 0x00 → strategies handle register encoding nulls
- Displacement 0x00000000 → strategies use SIB or register-based addressing

**Generic Bad Characters:**
- MOV reg, 0x0A0D0000 → may require different transformations
- ModR/M byte 0x0A → different register encoding constraints
- Displacement 0x0A0D0000 → may need different addressing strategies

## Use Cases

### Network Protocol Safety

Eliminate bytes that terminate network input:

```bash
# TCP protocol (null, newline, carriage return)
byvalver --bad-bytes "00,0a,0d" payload.bin output.bin

# HTTP headers (null, newline, carriage return, space)
byvalver --bad-bytes "00,0a,0d,20" payload.bin output.bin
```

**Common Bad Characters:**
- `0x00` - Null terminator
- `0x0a` - Line feed (LF, \n)
- `0x0d` - Carriage return (CR, \r)
- `0x20` - Space character

### C String Safety

Eliminate characters that C input functions treat specially:

```bash
# gets() safety (null, newline)
byvalver --bad-bytes "00,0a" payload.bin output.bin

# scanf() safety (null, whitespace)
byvalver --bad-bytes "00,20,09,0a,0d" payload.bin output.bin
```

### Custom Input Filters

Eliminate bytes filtered by custom input validation:

```bash
# Alphanumeric-only filter (eliminate non-alphanum)
# (Note: This would require listing all non-alphanum bytes)

# Custom application filter
byvalver --bad-bytes "00,0a,0d,1a,00" payload.bin output.bin
```

## Current Limitations

### Strategy Optimization

**Null-Byte Patterns:**
- Strategies check for trailing zeros in immediate values
- Optimizations for common null patterns (0x00000000, 0x00000001, etc.)
- Special handling for ModR/M byte 0x00

**Generic Patterns:**
- Strategies apply same transformations regardless of which byte
- May not optimize for non-null specific patterns
- May generate longer output for some bad byte combinations

### Testing Coverage

**Null-Byte Elimination:**
- 100% success rate on test suite (19/19 files)
- Tested across 116+ shellcode samples
- Validated against diverse real-world payloads
- Comprehensive edge case coverage

**Generic Bad-Byte Elimination:**
- Framework is functional and operational
- Strategies updated to use generic API
- Limited testing with non-null bad byte sets
- Real-world effectiveness not comprehensively validated

### ML Model Training

**Current State:**
- ML model trained exclusively on null-byte elimination data
- Feature extraction updated to track generic bad bytes
- Model has not been retrained with diverse bad byte datasets

**Impact:**
- ML mode may not perform optimally for non-null characters
- Strategy selection based on null-byte patterns
- Confidence scores calibrated for null elimination

**Recommendation:**
- Use standard mode (without `--ml`) for generic bad bytes
- ML mode should only be used with default null-byte elimination

## Performance Characteristics

### Memory Usage

**Per-Process Overhead:**
- 512 bytes for bad_byte_config_t (256 bitmap + 256 list)
- Negligible compared to typical shellcode processing

### Time Complexity

**Bad Character Checking:**
- O(1) for single byte check via bitmap
- O(n) for buffer check (n = buffer size)
- No degradation compared to null-byte checking

**Expected Performance Impact:**
- <5% overhead compared to null-byte only mode
- Actual measurements: 2-3% worst case
- Bitmap lookup is cache-friendly

### Output Size

**Null-Byte Elimination:**
- Typical expansion: 1.5x-3x original size
- Highly optimized transformations

**Generic Bad-Byte Elimination:**
- Expansion depends on bad byte distribution
- May be larger if many bad bytes present
- Strategies not optimized for specific non-null patterns

## Validation and Verification

### C Verification

**File:** `src/core.c`

```c
int verify_bad_char_elimination(struct buffer *processed) {
    return is_bad_char_free_buffer(processed->data, processed->size);
}

// Backward compatibility
int verify_null_elimination(struct buffer *processed) {
    return verify_bad_char_elimination(processed);
}
```

### Python Verification

**File:** `verify_denulled.py`

```python
def parse_bad_chars(bad_chars_str):
    """Parse comma-separated hex string into set of bad byte values."""
    bad_chars = set()
    if not bad_chars_str:
        return {0x00}
    for part in bad_chars_str.split(','):
        part = part.strip()
        byte_val = int(part, 16)
        if 0 <= byte_val <= 255:
            bad_chars.add(byte_val)
    return bad_chars if bad_chars else {0x00}

def analyze_shellcode_for_bad_chars(shellcode_data, bad_chars=None):
    """
    Args:
        bad_chars: set of bad byte values (default: {0x00})
    Returns:
        {
            'total_bytes': total size,
            'bad_char_count': number of bad chars,
            'bad_char_percentage': percentage,
            'bad_char_positions': {byte_val: [positions]},
            'bad_char_sequences': [(start, length, bytes)],
            'bad_chars_used': bad_chars set
        }
    """
```

**Usage:**
```bash
python3 verify_denulled.py output.bin --bad-bytes "00,0a,0d"
```

## Recommendations

### For Production Use

**✅ Recommended:**
- Use default mode (null-byte elimination only)
- No `--bad-bytes` option or `--bad-bytes "00"`
- Well-tested, 100% success rate
- Optimized transformations
- Proven effectiveness

**⚠️ Experimental:**
- Use `--bad-bytes` with non-null values
- Test thoroughly before production deployment
- Validate output with verification tools
- Report any issues encountered

### For Testing

**Best Practices:**
1. Start with null-byte only mode to validate baseline
2. Add one bad byte at a time
3. Verify output after each addition
4. Test with verification script
5. Compare output size and functionality

**Example Workflow:**
```bash
# Step 1: Baseline (null-only)
byvalver input.bin output1.bin
python3 verify_denulled.py output1.bin --bad-bytes "00"

# Step 2: Add newline
byvalver --bad-bytes "00,0a" input.bin output2.bin
python3 verify_denulled.py output2.bin --bad-bytes "00,0a"

# Step 3: Add carriage return
byvalver --bad-bytes "00,0a,0d" input.bin output3.bin
python3 verify_denulled.py output3.bin --bad-bytes "00,0a,0d"
```

### For Development

**Contributing Strategy Improvements:**
1. Identify patterns specific to your bad byte set
2. Design transformations optimized for those patterns
3. Implement as new strategies or enhance existing ones
4. Test with diverse shellcode samples
5. Submit pull requests with comprehensive documentation

## Strategy Coverage Analysis

### Current Strategy Count

**Total Strategies:** 163+ (after implementing Tier 1, additional high-priority strategies, and 30 new strategies including 10 general bad-byte strategies)

**Strategy Categories:**
- MOV instruction strategies: 20+ variants
- Arithmetic strategies: 30+ variants (ADD, SUB, XOR, AND, OR, etc.)
- Stack operations: 15+ variants (PUSH, POP)
- LEA addressing: 18+ variants
- Jumps: 12+ variants (conditional, unconditional)
- Windows API hashing: 8+ variants
- CMOV conditional elimination: 1 variant (Strategy 11, Priority 92)
- Advanced string operations: 1 variant (Strategy 12, Priority 85)
- Atomic operation encoding: 1 variant (Strategy 13, Priority 78)
- FPU stack immediate encoding: 1 variant (Strategy 15, Priority 76)
- XLAT table lookup: 1 variant (Strategy 16, Priority 72)
- BSF/BSR bit scanning: 1 variant (Strategy 17, Priority 80)
- Partial register optimization: 1 variant (Strategy 19, Priority 89)
- LAHF/SAHF flag preservation: 1 variant (Strategy 20, Priority 83)
- PUSHF/POPF bit manipulation: 1 variant (Strategy 21, Priority 81)
- LOOP comprehensive variants: 1 variant (Strategy 22, Priority 79)
- BSWAP endianness transformation: 1 variant (Strategy 24, Priority 85)
- Segment register TEB/PEB access: 1 variant (Strategy 14, Priority 94)

## New Strategy Documentation

### Strategy 11: CMOV Conditional Move Elimination (Priority 92)

**Problem:** CMOV instructions (CMOVcc family: CMOVZ, CMOVNZ, CMOVG, CMOVL, etc.) often encode with null bytes in ModR/M or displacement bytes, and current strategies didn't specifically handle them.

**Solution:** Replace CMOV with equivalent logic using SETcc + arithmetic operations to maintain branchless execution semantics while avoiding bad bytes.

**Implementation:**
```c
// Original: cmp eax, ebx; cmovz ecx, edx
// Transform to:
cmp eax, ebx          ; Set flags
setz al               ; AL = 1 if zero, 0 otherwise
movzx eax, al         ; EAX = 0 or 1
dec eax               ; EAX = -1 or 0 (0xFFFFFFFF or 0x00000000)
mov esi, ecx          ; Save original ECX
mov edi, edx          ; Save EDX
and esi, eax          ; If zero: ESI = 0, else: ESI = ECX
not eax               ; EAX = 0 or -1 (inverted)
and edi, eax          ; If zero: EDI = EDX, else: EDI = 0
or ecx, edi           ; ECX = EDX (if zero) or ECX (if not zero)
```

### Strategy 12: Advanced String Operation Transformation (Priority 85)

**Problem:** String instructions (MOVSB/MOVSW/MOVSD, LODSB/LODSW/LODSD, STOSB/STOSW/STOSD) with REP prefix often encode with bad bytes in REP prefixes, operand size overrides, or displacement bytes.

**Solution:** Replace REP-prefixed string operations with manual loops that avoid bad bytes in prefixes.

**Implementation:**
```c
// Original: mov ecx, 100; lea esi, [source]; lea edi, [dest]; rep movsb
// Transform to:
mov ecx, 100          ; Count (use null-free immediate strategy)
lea esi, [source]     ; Source (use displacement strategies)
lea edi, [dest]       ; Destination
copy_loop:
  mov al, [esi]       ; Load byte
  mov [edi], al       ; Store byte
  inc esi             ; Advance source
  inc edi             ; Advance dest
  dec ecx             ; Decrement counter
  jnz copy_loop       ; Loop if not zero (use offset strategies)
```

### Strategy 13: Atomic Operation Encoding Chains (Priority 78)

**Problem:** Atomic operations (XADD, CMPXCHG, LOCK prefix) may encode with bad bytes in LOCK prefix, ModR/M bytes, or memory displacements.

**Solution:** Decompose atomic operations into non-atomic equivalents for single-threaded contexts.

**Implementation:**
```c
// Original: lock xadd [counter], eax
// Transform to (single-threaded context):
mov temp, [counter]   ; Load current value
add temp, eax         ; Add to it
mov [counter], temp   ; Store back
mov eax, temp         ; Return old value
```

### Strategy 15: FPU Stack Immediate Encoding (Priority 76)

**Problem:** Immediate values that contain bad bytes can't be loaded directly. FPU instructions can be used to load and manipulate values in alternative ways that may avoid bad bytes.

**Solution:** Use FPU stack operations (FLD, FISTP, etc.) to load immediate values indirectly.

**Implementation:**
```c
// Original: mov eax, 0x12345678 (contains bad chars)
// Transform to:
push 0x12345678       ; Push immediate to stack
fild dword [esp]      ; Load integer to FPU stack
fistp dword [esp]     ; Store integer back from FPU stack
pop eax               ; Pop to register
```

### Strategy 16: XLAT Table Lookup Strategy (Priority 72)

**Problem:** XLAT instruction is commonly used in shellcode for byte translation but the table address may contain bad bytes in displacement bytes.

**Solution:** Replace XLAT with equivalent logic using MOV from memory with alternative addressing modes that avoid bad bytes.

**Implementation:**
```c
// Original: XLATB (translates AL using table at EBX+AL)
// Transform: MOVZX EAX, AL; ADD EAX, EBX; MOV AL, [EAX]
movzx eax, al         ; Zero-extend AL to EAX
add eax, ebx          ; Add base address (EBX) to index (EAX)
mov al, [eax]         ; Load the byte from calculated address
```

### Strategy 20: LAHF/SAHF Flag Preservation Strategy (Priority 83)

**Problem:** LAHF/SAHF instructions (Load/Store AH from/to flags) may contain bad bytes in their opcodes or may need to be replaced when working with shellcode that has bad byte restrictions.

**Solution:** Replace LAHF/SAHF with PUSHF/POPF or manual flag manipulation that avoids bad bytes.

**Implementation:**
```c
// Original: LAHF (loads SF, ZF, AF, PF, CF to AH)
// Transform: PUSHF; POP EAX; MOV AH, AL (where AL contains the flags)
pushf                 ; Save flags to stack
pop eax               ; Get flags into EAX
mov ah, al            ; Move low byte of flags to AH
```

### Strategy XX: Partial Register Optimization Strategy (Priority 89)

**Problem:** Instructions using partial registers (AL, AH, BL, BH, etc.) may result in encodings that contain bad bytes, particularly in ModR/M bytes or as immediate values.

**Solution:** Replace partial register operations with equivalent full register operations or alternative encodings that avoid bad bytes.

**Implementation:**
```c
// Original: mov al, 0x00 (contains null byte)
// Transform: xor eax, eax (then use AL)
xor eax, eax          ; Zero the full register
```

### Strategy XX: Segment Register TEB/PEB Access Strategy (Priority 94)

**Problem:** Direct access to TEB (FS:[0x30]) and PEB (FS:[0x34] on x86, GS:[0x60] on x64) may contain bad bytes in displacement bytes.

**Solution:** Replace segment register access with equivalent memory access that avoids bad bytes in displacement, or use alternative API resolution.

**Implementation:**
```c
// Original: mov eax, fs:[0x30] (PEB on x86, contains 0x30 which may be bad)
// Transform: Alternative approach to get PEB/TEB address
```
- String operations: 5+ variants (including Advanced String Operation Transformation)
- Atomic operations: 3+ variants (Atomic Operation Encoding Chains)
- FPU operations: 2+ variants (FPU Stack-Based Immediate Encoding)
- XLAT operations: 1+ variant (XLAT Table-Based Byte Translation)
- Flag preservation: 2+ variants (LAHF/SAHF Flag Preservation Chains)
- Segment register access: 1+ variant (Segment Register TEB/PEB Access)
- Conditional moves: 1+ variant (CMOV Conditional Move Elimination)
- Partial register optimization: 1+ variant (Partial Register Optimization)
- Bit shifts/rotates: 6+ variants
- String instructions: 4+ variants
- **NEW: Conditional logic strategies: 3+ variants (CMOV, SETcc)**
- **NEW: Register optimization strategies: 3+ variants (Partial registers)**
- **NEW: Advanced String Operation Transformation: 1+ variant**
- **NEW: Atomic Operation Encoding Chains: 1+ variant**
- **NEW: FPU Stack-Based Immediate Encoding: 1+ variant**
- **NEW: XLAT Table-Based Byte Translation: 1+ variant**
- **NEW: LAHF/SAHF Flag Preservation Chains: 1+ variant**

### Detailed Strategy Documentation

#### Strategy 12: Advanced String Operation Transformation (Priority 85)

**File:** `src/advanced_string_operation_strategies.c`
**File:** `src/advanced_string_operation_strategies.h`

**Problem Statement:**
String instructions (MOVSB/MOVSW/MOVSD, LODSB/LODSW/LODSD, STOSB/STOSW/STOSD) with REP prefix often encode with bad bytes in:
- REP prefix combinations (F3h for REP/REPE, F2h for REPNE)
- Operand size overrides (66h prefix)
- Register-based addressing displacement bytes

**Target Patterns:**
```asm
; Pattern 1: REP MOVSB memory copy with bad displacement
mov ecx, 100          ; Count
lea esi, [source]     ; Source (displacement may have nulls)
lea edi, [dest]       ; Destination
rep movsb             ; Copy ECX bytes from ESI to EDI

; Pattern 2: LODSD for data loading with bad displacement
lea esi, [data+0x100] ; Source pointer (offset contains bad chars)
lodsd                 ; Load DWORD from [ESI] into EAX

; Pattern 3: Direction flag manipulation with bad prefixes
cld                   ; Clear direction flag (FC) - may have bad chars in encoding
std                   ; Set direction flag (FD) - may have bad chars in encoding
```

**Transformation Strategy:**

**Technique 1: REP MOVSB to Manual Loop**
```c
// Original: mov ecx, 100; lea esi, [source]; lea edi, [dest]; rep movsb
// Transform to:
mov ecx, 100          ; Count (use null-free immediate strategy)
lea esi, [source]     ; Source (use displacement strategies)
lea edi, [dest]       ; Destination
copy_loop:
  mov al, [esi]       ; Load byte
  mov [edi], al       ; Store byte
  inc esi             ; Advance source
  inc edi             ; Advance dest
  dec ecx             ; Decrement counter
  jnz copy_loop       ; Loop if not zero (use offset strategies)
```

**Technique 2: LODSD to MOV + ADD**
```c
// Original: lodsd  (AC - may have issues in certain contexts)
// Transform to:
mov eax, [esi]        ; Load DWORD from [ESI]
add esi, 4            ; Advance ESI by 4 (use null-free immediate)
```

**Implementation Considerations:**
- Size overhead: 10-20 bytes vs 2-4 bytes (original)
- Performance: Significantly slower (10-100x for large copies)
- Register usage: Preserves ESI/EDI/ECX semantics
- Flag impact: Manual loops may affect flags differently
- Applicability: Medium (string operations in 30-40% of shellcode)

**Expected Benefits:**
- Null elimination: Avoids REP prefix and instruction encoding nulls
- Flexibility: Can use null-free addressing modes

#### Strategy 13: Atomic Operation Encoding Chains (Priority 78)

**File:** `src/atomic_operation_encoding_strategies.c`
**File:** `src/atomic_operation_encoding_strategies.h`

**Problem Statement:**
Atomic operations (XADD, CMPXCHG, LOCK prefix) are used in multi-threaded shellcode and rootkits for synchronization. These instructions:
- Use LOCK prefix (F0h) which may combine with opcodes to form bad bytes
- Encode with complex ModR/M bytes
- Often operate on memory with displacements containing nulls

**Target Patterns:**
```asm
; Pattern 1: LOCK XADD for atomic increment
lock xadd [counter], eax    ; Atomic add EAX to [counter], return old value

; Pattern 2: CMPXCHG for compare-and-swap
mov eax, expected           ; Expected value
mov ebx, new_value          ; New value
lock cmpxchg [ptr], ebx     ; If [ptr]==EAX, set [ptr]=EBX

; Pattern 3: LOCK INC/DEC
lock inc dword [counter]    ; Atomic increment
```

**Transformation Strategy:**

**Technique 1: XADD Decomposition (Non-Atomic)**
```c
// Original: lock xadd [mem], reg
// Transform to (single-threaded context):
mov temp, [mem]       ; Load old value
add [mem], reg        ; Add reg to memory
mov reg, temp         ; Return old value
// Note: Loses atomicity, only valid for single-threaded shellcode
```

**Technique 2: CMPXCHG Simulation**
```c
// Original: lock cmpxchg [mem], reg
// Transform to:
push ebx              ; Save EBX
mov ebx, [mem]        ; Load current value
cmp eax, ebx          ; Compare with expected
jnz cmpxchg_fail      ; If not equal, fail
mov [mem], reg        ; Store new value
mov eax, ebx          ; Return old value
pop ebx
jmp cmpxchg_done
cmpxchg_fail:
  mov eax, ebx        ; Return actual value
  pop ebx
cmpxchg_done:
```

**Implementation Considerations:**
- Atomicity: Transformations break atomicity (only valid for single-threaded contexts)
- Detection: Heuristics to detect multi-threaded vs single-threaded shellcode
- Safety: Must warn user if atomicity is lost
- Size: 8-15 bytes vs 3-6 bytes (original)
- Applicability: Low (atomic ops rare in shellcode, ~5%)

**Expected Benefits:**
- Null elimination: Removes LOCK prefix and complex encodings
- Compatibility: Works for single-threaded payloads

#### Strategy 15: FPU Stack-Based Immediate Encoding (Priority 76)

**File:** `src/fpu_stack_immediate_encoding_strategies.c`
**File:** `src/fpu_stack_immediate_encoding_strategies.h`

**Problem Statement:**
The x87 Floating-Point Unit (FPU) stack provides an alternative data storage mechanism that can be exploited for encoding integer values and avoiding bad bytes in GPR operations.

FPU operations:
- Use ST(0)-ST(7) register stack
- Can store 80-bit extended precision values
- Conversion between FPU and GPR via memory

**Target Patterns:**
```asm
; Pattern 1: Large immediate with nulls
mov eax, 0x12345678       ; May have null bytes in encoding

; Pattern 2: Multi-value loading
mov eax, value1           ; Value 1 (nulls)
mov ebx, value2           ; Value 2 (nulls)
mov ecx, value3           ; Value 3 (nulls)
```

**Transformation Strategy:**

**Technique 1: FILD (Float Integer Load) from Memory**
```c
// Original: mov eax, 0x12345678
// Transform to:
//   1. Store value in memory (use stack or data section)
//   2. Load into FPU stack: fild dword [mem]
//   3. Store back to GPR: fistp dword [temp]; mov eax, [temp]

// Example:
push 0x12345678           ; Push value to stack (use null-free PUSH strategy)
fild dword [esp]          ; Load from stack into ST(0)
fistp dword [esp]         ; Store from ST(0) back to stack
pop eax                   ; Pop into EAX
```

**Implementation Considerations:**
- Complexity: High - requires FPU state management
- Size: 15-25 bytes vs 5 bytes (MOV immediate)
- Performance: Slow (FPU ops are 10-100x slower than GPR)
- Compatibility: x87 FPU present on all x86 CPUs since 486
- FPU State: Must not corrupt existing FPU stack
- Applicability: Very low (5-10%, niche cases)

**Expected Benefits:**
- Alternative encoding: Completely different encoding path
- Obfuscation: FPU operations are uncommon in shellcode, evades signatures
- Null-free: Can construct values without null bytes via stack operations

#### Strategy 16: XLAT Table-Based Byte Translation (Priority 72)

**File:** `src/xlat_table_lookup_strategies.c`
**File:** `src/xlat_table_lookup_strategies.h`

**Problem Statement:**
The XLAT (translate byte) instruction provides table-based byte translation:
- `xlat` or `xlatb`: `AL = [EBX + AL]`
- Can be used for byte remapping, encoding, and obfuscation

**Use Cases:**
1. **Byte Remapping:** Remap bad bytes to safe characters, translate back at runtime
2. **Encoding:** Use XLAT as a substitution cipher
3. **Compact Lookups:** Replace switch statements with table lookups

**Target Patterns:**
```asm
; Pattern: Byte needs translation
mov al, 0x00              ; Load byte (has null)
; Need: Remap 0x00 to non-null value
```

**Transformation Strategy:**

**Technique 1: Byte Substitution via XLAT**
```c
// Build translation table at runtime
//   table[bad_char] = safe_char
//   table[safe_char] = bad_char (inverse)

// Example: Remap 0x00 to 0x42
// 1. Build table:
lea ebx, [translation_table]
mov byte [ebx + 0x00], 0x42   ; Map 0x00 -> 0x42
mov byte [ebx + 0x42], 0x00   ; Map 0x42 -> 0x00

// 2. Encode value:
mov al, 0x42              ; Use safe value 0x42 instead of 0x00
xlat                      ; Translate: AL = table[AL] = 0x00
// Now AL contains the actual value 0x00
```

**Implementation Considerations:**
- Table Size: 256 bytes for full translation table
- Table Location: Must store table in shellcode or build dynamically
- Overhead: Table construction + XLAT instructions
- Complexity: High - requires inverse mapping generation
- Applicability: Low (10%, niche encoding scenarios)

**Expected Benefits:**
- Flexible encoding: Can remap any byte to any other byte
- Compact: XLAT is 1 byte (D7)
- Obfuscation: Table-based encoding is uncommon

#### Strategy 20: LAHF/SAHF Flag Preservation Chains (Priority 83)

**File:** `src/lahf_sahf_flag_preservation_strategies.c`
**File:** `src/lahf_sahf_flag_preservation_strategies.h`

**Problem Statement:**
Flag preservation is critical when transforming instructions. Current strategies use PUSHF/POPF, but LAHF/SAHF provide alternative lightweight flag save/restore:
- **LAHF** (Load AH from Flags) - 9Fh: Loads SF, ZF, AF, PF, CF into AH
- **SAHF** (Store AH into Flags) - 9Eh: Restores SF, ZF, AF, PF, CF from AH

Benefits:
1. Single-byte instructions (PUSHF/POPF are 1-2 bytes, but stack-based)
2. Don't modify stack (useful when ESP is constrained)
3. Only preserve arithmetic flags (SF, ZF, AF, PF, CF), not OF/DF/IF

**Target Patterns:**
```asm
; Pattern 1: Flag preservation across transformation
cmp eax, ebx              ; Set flags
; Transform some instruction that may modify flags
; Need flags preserved for subsequent conditional

; Pattern 2: Lightweight flag save
test eax, eax             ; Set ZF
; Need to preserve ZF across complex transformation
```

**Transformation Strategy:**

**Technique 1: LAHF/SAHF instead of PUSHF/POPF**
```c
// Original: pushf; ...; popf  (3+ bytes, modifies stack)
// Transform to:
lahf                      ; Save flags to AH (1 byte)
// ... transformation code ...
sahf                      ; Restore flags from AH (1 byte)
// Savings: 1 byte, no stack modification
```

**Implementation Considerations:**
- Flag Coverage: LAHF/SAHF only handle SF, ZF, AF, PF, CF (not OF, DF, IF)
- x64 Compatibility: LAHF/SAHF valid in x64 (unlike some legacy instructions)
- Size: 1 byte each (LAHF: 9Fh, SAHF: 9Eh)
- Stack Impact: None (unlike PUSHF/POPF)
- Applicability: High (flag preservation needed in 40%+ of transformations)

**Expected Benefits:**
- Compact: 2 bytes total vs 2-4 bytes (PUSHF/POPF)
- No Stack: Useful when stack is constrained
- Fast: Single-cycle instructions on modern CPUs
- Generic Bad-Char: LAHF/SAHF opcodes (9E, 9F) unlikely to be bad chars
- **NEW: Segment register strategies: 1+ variants (FS/GS access)**

### Recently Added High-Priority Strategies (v3.1+)

#### Strategy 11: CMOV Conditional Move Elimination (Priority 92)

**Purpose:** Eliminate CMOV instructions that may contain bad bytes in ModR/M encoding bytes or displacement.

**Implementation Files:**
- `src/cmov_conditional_elimination_strategies.c`
- `src/cmov_conditional_elimination_strategies.h`

**Transformation Techniques:**
1. **SETcc + Conditional Multiplication:** Replace CMOV with SETcc + arithmetic operations
2. **XOR-Based Selection:** Use XOR masking to achieve conditional move semantics
3. **Arithmetic Blending:** Combine values using AND/OR operations with condition masks

**Example:**
```asm
; Original: CMOVZ ECX, EDX (may contain bad chars in ModR/M)
cmp eax, ebx
cmovz ecx, edx

; Transformed: SETcc + arithmetic
cmp eax, ebx          ; Set flags
setz al               ; AL = 1 if zero, 0 otherwise
movzx eax, al         ; EAX = 0 or 1
dec eax               ; EAX = -1 or 0 (0xFFFFFFFF or 0x00000000)
mov esi, ecx          ; Save original ECX
mov edi, edx          ; Save EDX
and esi, eax          ; If zero: ESI = 0, else: ESI = ECX
not eax               ; EAX = 0 or -1 (inverted)
and edi, eax          ; If zero: EDI = EDX, else: EDI = 0
or ecx, edi           ; ECX = EDX (if zero) or ECX (if not zero)
```

**Applicability:** Common in modern shellcode for branchless conditional logic, anti-debugging, and Spectre/Meltdown mitigation patterns.

#### Strategy 14: Segment Register TEB/PEB Access (Priority 94)

**Purpose:** Exploit FS/GS segment registers to access Thread Environment Block (TEB) and Process Environment Block (PEB) without using immediate values that contain bad bytes.

**Implementation Files:**
- `src/segment_register_teb_peb_strategies.c`
- `src/segment_register_teb_peb_strategies.h`

**Transformation Techniques:**
1. **Register Indirect Addressing:** Use register instead of immediate offset
2. **Offset Calculation:** Load offset into register and use indirect addressing
3. **Alternative Access Patterns:** Replace direct segment access with multi-step approaches

**Example:**
```asm
; Original: mov eax, fs:[0x30] (contains nulls in encoding)
mov eax, fs:[0x30]    ; 64 A1 30 00 00 00 - contains 3 null bytes

; Transformed: Register indirect
xor ebx, ebx          ; Clear temporary register
mov bl, 0x30          ; Load offset 0x30 into BL (no nulls)
mov eax, fs:[ebx]     ; Access FS:[EBX] - no immediate offset with bad chars
```

**Applicability:** Critical for Windows shellcode that accesses TEB/PEB for API resolution, process information, or anti-debugging techniques.

#### Strategy 19: Partial Register Optimization (Priority 89)

**Purpose:** Optimize immediate value loading by using 8-bit and 16-bit register portions instead of full 32/64-bit registers to avoid null bytes.

**Implementation Files:**
- `src/partial_register_optimization_strategies.c`
- `src/partial_register_optimization_strategies.h`

**Transformation Techniques:**
1. **8-bit Low Register (AL/BL/CL/DL):** Load values 0x00-0xFF
2. **8-bit High Register (AH/BH/CH/DH):** Load values into bits 8-15
3. **16-bit Register (AX/BX/CX/DX):** Load values 0x0000-0xFFFF

**Examples:**
```asm
; Strategy 1: 8-bit low register
; Original: mov eax, 0x00000042 (B8 42 00 00 00) - 3 null bytes
; Transformed: xor eax, eax; mov al, 0x42 (31 C0 B0 42) - 0 null bytes

; Strategy 2: 8-bit high register
; Original: mov eax, 0x00004200 (B8 00 42 00 00) - 3 null bytes
; Transformed: xor eax, eax; mov ah, 0x42 (31 C0 B4 42) - 0 null bytes

; Strategy 3: 16-bit register
; Original: mov eax, 0x00001234 (B8 34 12 00 00) - 2 null bytes
; Transformed: xor eax, eax; mov ax, 0x1234 (31 C0 66 B8 34 12) - 0 null bytes
```

**Applicability:** Very high (80%+ of shellcode loads small immediate values), foundational optimization.

## Future Enhancements

### Planned Improvements

1. **Strategy Optimization:**
   - Identify common non-null bad byte patterns
   - Optimize transformations for newline elimination
   - Special handling for common bad byte sets

2. **ML Model Retraining:**
   - Collect training data with varied bad byte sets
   - Retrain neural network with diverse patterns
   - Improve strategy selection for generic cases

3. **Advanced Strategy Families:**
   - **Conditional Logic Enhancement:** Expand CMOV family support to include more conditional instructions
   - **Segment Register Expansion:** Add support for additional segment register patterns
   - **Register Optimization:** Extend partial register techniques to more complex scenarios
   - **Multi-Instruction Analysis:** Implement window-based analysis for better optimization decisions

3. **Expanded Testing:**
   - Comprehensive test suite for non-null characters
   - Real-world payload validation
   - Edge case identification and coverage

4. **Performance Tuning:**
   - Profile performance with various bad byte sets
   - Optimize hot paths for generic checking
   - Reduce output size expansion

### Research Directions

1. **Automated Strategy Discovery:**
   - Analyze shellcode for pattern-specific transformations
   - Automatically generate strategies for common bad bytes
   - Machine learning for optimal strategy selection

2. **Hybrid Approaches:**
   - Combine multiple encoding techniques
   - Adaptive strategy selection based on bad byte distribution
   - Context-aware transformations

## Technical Reference

### Files Modified in v3.0

**Core Infrastructure:**
- `src/cli.h` - Added bad_byte_config_t structure
- `src/core.h` - Added global context declarations
- `src/core.c` - Implemented context management
- `src/utils.h` - Added generic function prototypes
- `src/utils.c` - Implemented checking functions
- `src/cli.c` - Added parsing logic
- `src/main.c` - Added context initialization
- `src/strategy_registry.c` - Updated has_null_bytes()

**Strategy Updates:**
- 122+ strategy files updated to use generic API
- Bulk update: `is_null_free()` → `is_bad_char_free()`
- All inline null checks updated to generic checks

**Verification:**
- `verify_denulled.py` - Complete rewrite for generic support

### Key Commits

Reference implementation commits:
- Infrastructure (Phase 1): Core data structures and API
- CLI Integration (Phase 2): Parsing and configuration
- Core System (Phase 3): Processing pipeline updates
- Strategy Updates (Phase 4): Bulk strategy refactoring
- Verification (Phase 5): Python tool updates
- ML Integration (Phase 6): Feature extraction updates

---

## v3.7 General Bad-Byte Elimination Strategies (2026-01-03)

The following 10 strategies were added specifically to enhance general bad-byte elimination capabilities beyond null-byte-only scenarios. These strategies target instruction encoding elements (opcodes, ModR/M bytes, SIB bytes, prefixes) that may contain arbitrary bad bytes.

### Strategy: Conditional Jump Opcode Bad-Byte Elimination (Priority 92)

**File:** `src/conditional_jump_opcode_badbyte_strategies.c`
**File:** `src/conditional_jump_opcode_badbyte_strategies.h`

**Problem Statement:**
Conditional jump instructions (JE, JNE, JG, JL, etc.) use opcodes in the range 0x70-0x7F which may themselves be bad bytes in certain contexts.

**Target Patterns:**
```asm
je target     ; 0x74 XX - opcode 0x74 may be bad byte
jne target    ; 0x75 XX - opcode 0x75 may be bad byte
jg target     ; 0x7F XX - opcode 0x7F may be bad byte
```

**Transformation Strategy:**
```c
// Original: JE target (0x74 XX)
// Transform to:
jne skip      ; Inverse condition (0x75 02)
jmp target    ; Unconditional jump (0xEB XX)
skip:
```

**Implementation:**
- Detects conditional jumps with bad opcodes
- Uses inverse condition lookup table (JE→JNE, JG→JLE, etc.)
- Replaces with inverse conditional + unconditional jump pattern
- Size: 2 bytes → 4 bytes

**Applicability:**
- Common in shellcode with restrictive bad-byte sets
- Essential for profile-based elimination (http-newline, sql-injection)
- Priority 92 (highest of the new strategies)

---

### Strategy: Register-to-Register Transfer Bad-Byte Opcodes (Priority 90)

**File:** `src/reg_to_reg_badbyte_strategies.c`
**File:** `src/reg_to_reg_badbyte_strategies.h`

**Problem Statement:**
MOV and XCHG register-to-register operations may encode with bad bytes in their opcodes (0x89, 0x8B, 0x90-0x97 for XCHG).

**Target Patterns:**
```asm
mov eax, ebx  ; 0x89 D8 - opcode 0x89 may be bad
xchg eax, ecx ; 0x91 - opcode 0x91 may be bad
```

**Transformation Strategy:**
```c
// Original: MOV EAX, EBX (0x89 D8)
// Transform to:
push ebx      ; 0x53
pop eax       ; 0x58

// Original: XCHG EAX, ECX (0x91)
// Transform to:
push eax      ; 0x50
push ecx      ; 0x51
pop eax       ; 0x58
pop ecx       ; 0x59
```

**Applicability:**
- Very common operation in shellcode
- PUSH/POP opcodes (0x50-0x5F) unlikely to be bad bytes
- Size overhead: 2 bytes → 2-4 bytes

---

### Strategy: Stack Frame Pointer Bad-Byte Elimination (Priority 89)

**File:** `src/stack_frame_badbyte_strategies.c`
**File:** `src/stack_frame_badbyte_strategies.h`

**Problem Statement:**
PUSH EBP (0x55) and POP EBP (0x5D) are common prologue/epilogue instructions whose opcodes may be bad bytes.

**Target Patterns:**
```asm
push ebp      ; 0x55 - common function prologue
pop ebp       ; 0x5D - common function epilogue
```

**Transformation Strategy:**
```c
// Original: PUSH EBP (0x55)
// Transform to:
sub esp, 4    ; 0x83 EC 04
mov [esp], ebp ; 0x89 2C 24

// Original: POP EBP (0x5D)
// Transform to:
mov ebp, [esp] ; 0x8B 2C 24
add esp, 4    ; 0x83 C4 04
```

**Applicability:**
- Essential for function prologue/epilogue patterns
- Common in compiler-generated shellcode
- Size: 1 byte → 6 bytes

---

### Strategy: ModR/M and SIB Byte Bad-Byte Elimination (Priority 88)

**File:** `src/modrm_sib_badbyte_strategies.c`
**File:** `src/modrm_sib_badbyte_strategies.h`

**Problem Statement:**
Memory operations encode addressing information in ModR/M and SIB bytes which may contain bad bytes based on register combinations and addressing modes.

**Target Patterns:**
```asm
mov [eax], ebx  ; ModR/M byte depends on registers
mov [esp+4], eax ; SIB byte may contain bad bytes
```

**Transformation Strategy:**
```c
// Original: MOV [EAX], EBX (ModR/M byte is bad)
// Transform to:
push ebx       ; Save source
push eax       ; Save address
pop edi        ; Address to EDI
pop eax        ; Source to EAX
mov [edi], eax ; Use different register combination
```

**Implementation Considerations:**
- Requires calculation of ModR/M byte for each instruction
- Must find alternative register combinations
- SIB byte handling for complex addressing modes
- Size: 2-3 bytes → 8-12 bytes

**Applicability:**
- Critical for memory operations
- Common in data manipulation shellcode
- May require temporary register allocation

---

### Strategy: Multi-Byte Immediate Partial Bad-Byte (Priority 87)

**File:** `src/partial_immediate_badbyte_strategies.c`
**File:** `src/partial_immediate_badbyte_strategies.h`

**Problem Statement:**
32-bit immediate values where only specific bytes are bad can be optimized using rotation instead of full reconstruction.

**Target Patterns:**
```asm
mov eax, 0x12340056  ; Only byte at offset 2 is bad (0x00)
mov ebx, 0x78005634  ; Only byte at offset 1 is bad (0x00)
```

**Transformation Strategy:**
```c
// Original: MOV EAX, 0x12340056 (byte 2 is 0x00)
// Rotate to: 0x00561234 → Load → Rotate back
mov eax, 0x00561234  ; Load rotated value (may still have bad byte)
ror eax, 16          ; Rotate right 16 bits → 0x12340056

// Better: Find rotation with no bad bytes
mov eax, 0x34005612  ; Rotated left 8 bits
rol eax, 24          ; Rotate left 24 bits → 0x12340056
```

**Implementation:**
- Tests all 4 rotation positions (0, 8, 16, 24 bits)
- Selects rotation with fewest bad bytes
- Only applies if rotated value has fewer bad bytes than original
- Size: 5 bytes → 10 bytes (MOV + ROR/ROL)

**Applicability:**
- Optimizes partial bad-byte immediates (common case)
- More efficient than full reconstruction
- Particularly effective for network byte order values

---

### Strategy: Bitwise Operation Immediate Bad-Byte (Priority 86)

**File:** `src/bitwise_immediate_badbyte_strategies.c`
**File:** `src/bitwise_immediate_badbyte_strategies.h`

**Problem Statement:**
Bitwise operations (AND, OR, XOR, TEST) with immediate values may encode with bad bytes in the immediate operand.

**Target Patterns:**
```asm
and eax, 0x00FFFF00  ; Immediate contains bad bytes
or ebx, 0x12005678   ; Immediate contains bad bytes
xor ecx, 0x00000001  ; Immediate contains bad bytes
test edx, 0xFF000000 ; Immediate contains bad bytes
```

**Transformation Strategy:**
```c
// Original: AND EAX, 0x00FFFF00
// Transform to:
push ecx             ; Save temp register
mov ecx, 0x00FFFF00  ; Load immediate (using null-free MOV strategy)
and eax, ecx         ; Perform operation with register
pop ecx              ; Restore temp register
```

**Implementation:**
- Uses temporary register (ECX or EDX based on destination)
- Leverages existing MOV immediate bad-byte strategies
- Preserves flags (except for TEST which only reads)
- Size: 6 bytes → 15 bytes

**Applicability:**
- Common in bitmask operations
- Essential for flag manipulation
- Frequently used in shellcode arithmetic

---

### Strategy: One-Byte Opcode Substitution (Priority 85)

**File:** `src/one_byte_opcode_sub_strategies.c`
**File:** `src/one_byte_opcode_sub_strategies.h`

**Problem Statement:**
Single-byte opcodes in the 0x40-0x5F range (INC/DEC/PUSH/POP registers) may themselves be bad bytes.

**Target Patterns:**
```asm
inc eax       ; 0x40 - may be bad byte
dec ebx       ; 0x4B - may be bad byte
push ecx      ; 0x51 - may be bad byte
pop edx       ; 0x5A - may be bad byte
```

**Transformation Strategy:**
```c
// Original: INC EAX (0x40)
// Transform to:
add eax, 1    ; 0x83 C0 01

// Original: DEC EBX (0x4B)
// Transform to:
sub ebx, 1    ; 0x83 EB 01

// Original: PUSH ECX (0x51)
// Transform to:
sub esp, 4    ; 0x83 EC 04
mov [esp], ecx ; 0x89 0C 24

// Original: POP EDX (0x5A)
// Transform to:
mov edx, [esp] ; 0x8B 14 24
add esp, 4    ; 0x83 C4 04
```

**Applicability:**
- Extremely common operations
- Simple transformations with predictable results
- Size: 1 byte → 3-6 bytes

---

### Strategy: String Instruction Length Prefix Bad-Byte (Priority 84)

**File:** `src/string_prefix_badbyte_strategies.c`
**File:** `src/string_prefix_badbyte_strategies.h`

**Problem Statement:**
String instructions with REP prefix (0xF3 for REP/REPE, 0xF2 for REPNE) may contain bad bytes in the prefix.

**Target Patterns:**
```asm
rep stosb     ; 0xF3 0xAA - REP prefix may be bad
rep movsb     ; 0xF3 0xA4 - REP prefix may be bad
repne scasb   ; 0xF2 0xAE - REPNE prefix may be bad
```

**Transformation Strategy:**
```c
// Original: REP STOSB (0xF3 0xAA)
// Transform to loop:
loop_start:
  stosb       ; 0xAA - Store AL to [EDI], increment EDI
  dec ecx     ; 0x49 or 0x83 0xE9 0x01 (if 0x49 is bad)
  jnz loop_start ; 0x75 XX - Jump if not zero
```

**Implementation:**
- Replaces REP prefix with manual loop
- Checks if DEC ECX opcode (0x49) is bad, uses SUB ECX, 1 alternative
- Loop offset calculated based on instruction size
- Size: 2 bytes → 5-8 bytes

**Performance Impact:**
- Significantly slower for large counts (10-100x)
- Acceptable for shellcode (typically small counts)

**Applicability:**
- Common in memory initialization (REP STOSB)
- Common in memory copying (REP MOVSB)
- Essential for string operations

---

### Strategy: Operand Size Prefix Bad-Byte (Priority 83)

**File:** `src/operand_size_prefix_badbyte_strategies.c`
**File:** `src/operand_size_prefix_badbyte_strategies.h`

**Problem Statement:**
16-bit operations use operand-size prefix 0x66 which may be a bad byte.

**Target Patterns:**
```asm
push ax       ; 0x66 0x50 - 16-bit PUSH
mov ax, 0x1234 ; 0x66 0xB8 0x34 0x12 - 16-bit MOV
```

**Transformation Strategy:**
```c
// Original: PUSH AX (0x66 0x50)
// Transform to:
push eax      ; 0x50 - Use 32-bit version

// Original: MOV AX, 0x1234
// Transform to:
xor eax, eax  ; Zero full register
mov ax, 0x1234 ; Would still have 0x66 prefix...
// Better approach: Use 32-bit with masking
mov eax, 0x1234 ; 0xB8 0x34 0x12 0x00 0x00
and eax, 0xFFFF ; Mask to 16 bits
```

**Implementation:**
- Converts 16-bit register operations to 32-bit equivalents
- Maps AX→EAX, CX→ECX, DX→EDX, BX→EBX, etc.
- Adds masking for value-preserving operations
- Size: 2-3 bytes → 5-10 bytes

**Applicability:**
- Less common in modern shellcode
- More common in legacy or size-optimized code

---

### Strategy: Segment Register Bad-Byte (Priority 81)

**File:** `src/segment_prefix_badbyte_strategies.c`
**File:** `src/segment_prefix_badbyte_strategies.h`

**Problem Statement:**
Segment override prefixes (FS: 0x64, GS: 0x65) may be bad bytes. These are commonly used for TEB/PEB access on Windows.

**Target Patterns:**
```asm
mov eax, fs:[0x30]  ; 0x64 0xA1 0x30 0x00 0x00 0x00 - FS prefix
mov ebx, gs:[0x60]  ; 0x65 0x8B 0x1D 0x60 0x00 0x00 0x00 - GS prefix
```

**Transformation Strategy:**
```c
// For FS:[offset], detecting is implemented
// Full transformation requires TEB base calculation:
// 1. Get FS base from TEB
// 2. Add offset to base
// 3. Access via normal memory operation

// Current implementation: Detection only
// Returns true if FS/GS prefix is bad byte
// Actual transformation is a limitation (noted in comments)
```

**Current Status:**
- **Detection**: Fully implemented
- **Transformation**: Placeholder (copies original)
- **Reason**: TEB/PEB base calculation is architecture-specific and complex

**Future Enhancement:**
- Implement TEB base retrieval on Windows
- Use alternative register-based addressing
- Priority for Windows shellcode optimization

**Applicability:**
- Critical for Windows shellcode (PEB walking)
- Common in API resolution techniques
- Currently limited (transformation TODO)

---

## Strategy Summary Table (New Additions)

| Priority | Strategy Name | File | Purpose | Size Impact |
|----------|--------------|------|---------|-------------|
| 92 | Conditional Jump Opcode Bad-Byte | `conditional_jump_opcode_badbyte_strategies.c` | Replace bad jump opcodes | 2B → 4B |
| 90 | Register-to-Register Transfer | `reg_to_reg_badbyte_strategies.c` | Replace MOV/XCHG bad opcodes | 2B → 2-4B |
| 89 | Stack Frame Pointer | `stack_frame_badbyte_strategies.c` | Replace PUSH/POP EBP | 1B → 6B |
| 88 | ModR/M and SIB Byte | `modrm_sib_badbyte_strategies.c` | Alternative register combinations | 2-3B → 8-12B |
| 87 | Multi-Byte Immediate Partial | `partial_immediate_badbyte_strategies.c` | Rotation optimization | 5B → 10B |
| 86 | Bitwise Operation Immediate | `bitwise_immediate_badbyte_strategies.c` | AND/OR/XOR/TEST with register | 6B → 15B |
| 85 | One-Byte Opcode Substitution | `one_byte_opcode_sub_strategies.c` | INC/DEC/PUSH/POP alternatives | 1B → 3-6B |
| 84 | String Instruction Prefix | `string_prefix_badbyte_strategies.c` | REP prefix to loop | 2B → 5-8B |
| 83 | Operand Size Prefix | `operand_size_prefix_badbyte_strategies.c` | 16-bit to 32-bit conversion | 2-3B → 5-10B |
| 81 | Segment Register | `segment_prefix_badbyte_strategies.c` | FS/GS prefix detection | Detection only |

---

## v3.5 Additional Strategies (2025-12-22)

### Strategy 24: BSWAP Endianness Transformation (Priority 85)

**File:** `src/bswap_endianness_transformation_strategies.c`
**File:** `src/bswap_endianness_transformation_strategies.h`

**Problem Statement:**
MOV instructions with immediate values often contain bad bytes, particularly when encoding IP addresses or port numbers in network byte order. Traditional strategies may not recognize that byte-swapping can eliminate bad bytes.

**Target Patterns:**
```asm
; Pattern: MOV with network byte order values containing bad chars
mov eax, 0x00007F01    ; 127.0.0.1 in network byte order (contains nulls)
mov ebx, 0x00005000    ; Port 80 in network byte order (contains nulls)
```

**Transformation Strategy:**
```c
// Check if byte-swapped version has fewer bad bytes
uint32_t original = 0x00007F01;      // Has 2 null bytes
uint32_t swapped = 0x017F0000;       // Has 2 null bytes at end

// Transform to:
mov eax, 0x017F0000    ; Byte-swapped immediate (bad chars moved)
bswap eax              ; Reverse byte order to get original value
```

**Implementation:**
- Check if value is bad-byte-free after byte swap
- Only apply if swapped version has fewer bad bytes
- Uses BSWAP instruction (2 bytes: 0F C8+r)
- Total: 7 bytes (MOV=5 + BSWAP=2) vs original 5 bytes

**Use Cases:**
- Socket programming: IP addresses, port numbers
- Network protocols: Endianness conversions
- Data structures with embedded addresses

---

### Strategy 21: PUSHF/POPF Bit Manipulation (Priority 81)

**File:** `src/pushf_popf_bit_manipulation_strategies.c`
**File:** `src/pushf_popf_bit_manipulation_strategies.h`

**Problem Statement:**
Flag-setting instructions (STC, CLC, STD, CLD, CMC) are single-byte opcodes that may themselves be bad bytes. Current strategies don't transform these simple instructions.

**Target Patterns:**
```asm
stc    ; F9h - Set Carry Flag (may be bad char)
clc    ; F8h - Clear Carry Flag
std    ; FDh - Set Direction Flag
cld    ; FCh - Clear Direction Flag
cmc    ; F5h - Complement Carry Flag
```

**Transformation Strategy:**
```c
// Original: STC (1 byte: F9)
// Transform to:
pushf               ; 9C - Push EFLAGS
pop eax             ; 58 - Pop into EAX
or eax, 0x01        ; 0D 01 00 00 00 - Set carry bit
push eax            ; 50 - Push modified flags
popf                ; 9D - Pop into EFLAGS

// Original: CLC (1 byte: F8)
// Transform to:
pushf               ; 9C
pop eax             ; 58
and eax, 0xFFFFFFFE ; 25 FE FF FF FF - Clear carry bit
push eax            ; 50
popf                ; 9D
```

**Verified:** Successfully transformed STC (F9) to 9-byte PUSHF/POPF sequence

**Flag Masks:**
- CF (Carry): bit 0 (0x01)
- ZF (Zero): bit 6 (0x40)
- SF (Sign): bit 7 (0x80)
- DF (Direction): bit 10 (0x400)
- OF (Overflow): bit 11 (0x800)

---

### Strategy 17: BSF/BSR Bit Scanning (Priority 80)

**File:** `src/bit_scanning_constant_strategies.c`
**File:** `src/bit_scanning_constant_strategies.h`

**Problem Statement:**
Power-of-2 immediate values frequently contain null bytes (0x100, 0x10000, 0x1000000) but can be constructed via bit position and shifting.

**Target Patterns:**
```asm
mov eax, 0x00010000    ; Bit 16 set (contains nulls)
mov ebx, 0x00000100    ; Bit 8 set (contains nulls)
mov ecx, 0x00001000    ; Bit 12 set (contains nulls)
```

**Transformation Strategy:**
```c
// Method 1: For small bit positions (0-7)
// Original: MOV EAX, 0x100
mov eax, 1             ; Load 1
shl eax, 8             ; Shift left 8 positions = 0x100

// Method 2: For larger bit positions (8-31)
// Original: MOV EAX, 0x10000
xor eax, eax           ; Zero register
mov al, 16             ; Bit position
mov ecx, 1             ; Start with 1
shl ecx, cl            ; Shift by bit position
mov eax, ecx           ; Move result
```

**Applicability:**
- Only works for power-of-2 values (single bit set)
- Bit position must not be a bad byte
- Common for bitmasks and flag values

---

### Strategy 22: LOOP Comprehensive Variants (Priority 79)

**File:** `src/loop_comprehensive_strategies.c`
**File:** `src/loop_comprehensive_strategies.h`

**Problem Statement:**
LOOP family instructions use 8-bit signed displacement which may contain bad bytes. These are common in shellcode iteration loops.

**Target Patterns:**
```asm
loop target      ; E2 XX - Decrement ECX, jump if not zero
loope target     ; E1 XX - Loop while equal (ZF=1, ECX!=0)
loopne target    ; E0 XX - Loop while not equal (ZF=0, ECX!=0)
```

**Transformation Strategy:**
```c
// Original: LOOP target (E2 XX)
// Transform to:
dec ecx          ; 49 - Decrement counter
jnz target       ; 75 XX - Jump if not zero

// Original: LOOPE target (E1 XX)
// Transform to:
dec ecx          ; 49
jz skip          ; 74 02 - Skip if ECX=0
je target        ; 74 XX - Jump if ZF=1
skip:

// Original: LOOPNE target (E0 XX)
// Transform to:
dec ecx          ; 49
jz skip          ; 74 02 - Skip if ECX=0
jne target       ; 75 XX - Jump if ZF=0
skip:
```

**Verified:** Successfully transformed LOOP -2 (E2 FE) to DEC ECX; JNZ -3 (49 75 FD)

**Size Impact:**
- LOOP: 2 bytes → 3 bytes
- LOOPE/LOOPNE: 2 bytes → 5 bytes

---

### Strategy 13: Atomic Operation Encoding Chains (Priority 78)

**File:** `src/atomic_operation_encoding_strategies.c` (already existed)
**File:** `src/atomic_operation_encoding_strategies.h`

**Problem Statement:**
LOCK-prefixed atomic operations may encode with bad bytes, particularly in multi-threaded exploitation scenarios. The LOCK prefix (F0h) combined with opcode bytes can form bad byte sequences.

**Target Patterns:**
```asm
lock xadd [mem], reg    ; F0 0F C1 XX - May contain bad chars
lock cmpxchg [mem], reg ; F0 0F B1 XX - May contain bad chars
lock inc [mem]          ; F0 FF 05 XX - May contain bad chars
```

**Transformation Strategy:**
```c
// LOCK XADD [mem], reg → Non-atomic equivalent
mov temp, [mem]        ; Load current value
add temp, reg          ; Add register value
mov [mem], temp        ; Store result
xchg reg, temp         ; Return old value in reg

// LOCK CMPXCHG [mem], reg → Non-atomic equivalent
cmp eax, [mem]         ; Compare EAX with memory
jne skip               ; Skip if not equal
mov [mem], reg         ; Store new value
skip:

// LOCK INC/DEC [mem] → Simply remove LOCK prefix
inc [mem]              ; Remove F0 prefix
```

**⚠️ WARNING:** Loses atomicity! Only use in single-threaded shellcode contexts.

**Status:** Previously implemented, verified registration in v3.5

---

## v3.6 Additional Strategies (2025-12-28)

### Strategy 18: BCD Arithmetic for Obfuscated Constant Generation (Priority 68)

**File:** `src/bcd_arithmetic_obfuscation_strategies.c`
**File:** `src/bcd_arithmetic_obfuscation_strategies.h`

**Problem Statement:**
MOV immediate instructions may contain bad bytes. Binary-Coded Decimal (BCD) arithmetic instructions provide an alternative method for constructing small constant values (0-99) through obfuscated arithmetic operations.

**Target Patterns:**
```asm
mov al, 42              ; Load immediate value (may have bad chars in encoding)
```

**Transformation Strategy:**
```c
// Original: MOV AL, 42
// Transform to:
mov al, 2               ; Ones digit
mov ah, 4               ; Tens digit
aad                     ; ASCII Adjust: AL = AH*10 + AL = 4*10 + 2 = 42
```

**BCD Instructions Used:**
- **AAM** (D4 0A): ASCII Adjust after Multiply - divides AL by 10
- **AAD** (D5 0A): ASCII Adjust before Division - multiplies AH by 10 and adds AL
- **DAA** (27): Decimal Adjust after Addition
- **DAS** (2F): Decimal Adjust after Subtraction

**Applicability:**
- Only practical for values 0-99
- x86 only (invalid in x64 long mode)
- Primarily for obfuscation rather than size optimization

---

### Strategy 23: ENTER/LEAVE Stack Frame Alternative Encoding (Priority 74)

**File:** `src/enter_leave_alternative_encoding_strategies.c`
**File:** `src/enter_leave_alternative_encoding_strategies.h`

**Problem Statement:**
ENTER and LEAVE instructions may encode with bad bytes in their immediate values. While rare in shellcode (<5% usage), they appear in compiler-generated payloads.

**Target Patterns:**
```asm
enter 0x0100, 0         ; Create stack frame (C8 00 01 00) - contains nulls
leave                   ; Destroy stack frame (C9)
```

**Transformation Strategy:**
```c
// Original: ENTER 0x100, 0
// Transform to:
push ebp                ; Save frame pointer (55)
mov ebp, esp            ; Set new frame pointer (89 E5)
sub esp, 0x100          ; Allocate stack space (81 EC XX XX XX XX)

// Original: LEAVE
// Transform to:
mov esp, ebp            ; Restore stack pointer (89 EC)
pop ebp                 ; Restore frame pointer (5D)
```

**Size Impact:**
- ENTER: 4 bytes → 9 bytes
- LEAVE: 1 byte → 3 bytes

**Benefits:**
- Manual prologue/epilogue is actually faster on modern CPUs
- Eliminates immediate values that may contain bad bytes

---

### Strategy 25: POPCNT/LZCNT/TZCNT Bit Counting (Priority 77)

**File:** `src/bit_counting_constant_strategies.c`
**File:** `src/bit_counting_constant_strategies.h`

**Problem Statement:**
Small constant values can be generated by counting bits in carefully chosen source values, providing an alternative to direct MOV immediates.

**Target Patterns:**
```asm
mov eax, 5              ; Small constant (may have bad chars)
mov eax, 16             ; Power-of-2 exponent
```

**Transformation Strategy:**
```c
// Method 1: POPCNT (count set bits)
// Original: MOV EAX, 5
mov ebx, 0x1F           ; 0x1F has 5 bits set (00011111)
popcnt eax, ebx         ; EAX = 5

// Method 2: TZCNT (count trailing zeros)
// Original: MOV EAX, 16
mov ebx, 0x10000        ; 2^16 = 65536
tzcnt eax, ebx          ; EAX = 16 (trailing zeros)
```

**CPU Requirements:**
- POPCNT: SSE4.2+ (2008+)
- LZCNT/TZCNT: BMI1+ (2013+)

**Applicability:**
- POPCNT: Values 0-32 (number of set bits)
- TZCNT: Power-of-2 exponents (0-31)
- Requires modern CPUs

---

### Strategy: SIMD XMM Register Immediate Loading (Priority 89)

**File:** `src/simd_xmm_register_strategies.c`
**File:** `src/simd_xmm_register_strategies.h`

**Problem Statement:**
Zero initialization via MOV EAX, 0 encodes with null bytes (B8 00 00 00 00). SIMD registers provide an alternative data path.

**Target Patterns:**
```asm
mov eax, 0              ; Zero initialization (contains nulls)
```

**Transformation Strategy:**
```c
// Original: MOV EAX, 0
// Transform to:
pxor xmm0, xmm0         ; Zero XMM0 (66 0F EF C0) - no nulls
movd eax, xmm0          ; Move XMM0[31:0] to EAX (66 0F 7E C0)
// Total: 8 bytes vs 5 bytes, but null-free
```

**SIMD Instructions Used:**
- **PXOR xmm, xmm**: Zero out 128-bit XMM register (4 bytes)
- **MOVD r32, xmm**: Move low 32 bits of XMM to GPR (4 bytes)

**CPU Requirements:**
- SSE2+ (available on all modern x86/x64 CPUs)

**Current Implementation:**
- Optimized for zero values (most common case)
- Can be extended for non-zero values via intermediate register transfers

---

### Strategy: JECXZ/JRCXZ Zero-Test Jump Transformation (Priority 85)

**File:** `src/jecxz_jrcxz_transformation_strategies.c`
**File:** `src/jecxz_jrcxz_transformation_strategies.h`

**Problem Statement:**
JECXZ (Jump if ECX Zero) and JRCXZ (Jump if RCX Zero) use 8-bit signed displacement which may contain bad bytes.

**Target Patterns:**
```asm
jecxz loop_end          ; E3 XX - Jump if ECX=0 (displacement XX may be bad)
jrcxz loop_end          ; E3 XX - Jump if RCX=0 (x64)
```

**Transformation Strategy:**
```c
// Original: JECXZ target (E3 XX)
// Transform to:
test ecx, ecx           ; Test ECX against itself (85 C9)
jz target               ; Jump if zero (74 XX)

// For x64:
test rcx, rcx           ; Test RCX (48 85 C9)
jz target               ; Jump if zero (74 XX)
```

**Size Impact:**
- x86: 2 bytes → 4 bytes
- x64: 2 bytes → 5 bytes

**Benefits:**
- TEST instruction sets ZF based on bitwise AND without modifying operands
- Fills gap in jump coverage for ECX/RCX zero-testing patterns
- Common in loop constructs

---

## Conclusion

The generic bad-byte elimination framework in BYVALVER v3.6 extends the tool's capabilities with 5 additional specialized strategies. The framework now includes:

- **153+ total strategies** covering diverse transformation patterns
- **20 newly documented strategies** from proposals (as of Dec 2025)
- **Verified implementations** with test cases and practical demonstrations

Recent additions (v3.5):
- **Network-aware**: BSWAP for endianness handling
- **Flag manipulation**: PUSHF/POPF for single-byte instruction replacement
- **Power-of-2 constants**: BSF/BSR bit scanning optimization
- **Loop transformations**: Comprehensive LOOP family handling
- **Atomic operations**: LOCK prefix removal with caveat warnings

Recent additions (v3.6 - 2025-12-28):
- **BCD arithmetic**: Obfuscated constant generation using AAM/AAD instructions
- **Stack frame operations**: ENTER/LEAVE alternative encoding
- **Modern CPU bit counting**: POPCNT/LZCNT/TZCNT for constant generation
- **SIMD zero initialization**: XMM register-based zeroing
- **Jump transformations**: JECXZ/JRCXZ zero-test jump handling

While **null-byte elimination** remains the primary, well-tested use case:
- **Generic bad-byte elimination** is fully functional
- **Strategies** continue to evolve for non-null character patterns
- **Testing** is recommended before production use
- **Community contributions** welcomed for additional patterns

The framework provides a solid foundation for advanced shellcode transformation and bad byte elimination scenarios.
