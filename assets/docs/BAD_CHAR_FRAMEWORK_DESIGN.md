# byvalver Generic Bad-Character Elimination Framework
## Comprehensive Design Document

**Version:** 3.0 (Proposed)
**Date:** 2025-12-16
**Status:** Design Phase

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Background & Motivation](#background--motivation)
3. [Requirements](#requirements)
4. [Architecture Overview](#architecture-overview)
5. [Detailed Design](#detailed-design)
6. [Implementation Plan](#implementation-plan)
7. [Testing Strategy](#testing-strategy)
8. [Performance Analysis](#performance-analysis)
9. [Migration & Backward Compatibility](#migration--backward-compatibility)
10. [Risks & Mitigation](#risks--mitigation)
11. [Future Enhancements](#future-enhancements)

---

## Executive Summary

This document outlines the design for transforming byvalver from a null-byte-specific shellcode elimination tool into a **generic bad-character elimination framework**. This enhancement will enable users to specify arbitrary sets of bytes to eliminate from shellcode, addressing scenarios beyond C string injection where characters like newlines (`0x0a`), carriage returns (`0x0d`), spaces (`0x20`), and others cause issues.

### Key Changes

- **Generic API:** Replace `is_null_free()` with `is_bad_char_free()` that accepts any set of bad characters
- **CLI Enhancement:** Add `--bad-chars "00,0a,0d"` option for user-specified bad bytes
- **Architecture Refactor:** Null-byte elimination becomes a special case (default: bad_chars=[0x00])
- **ML Integration:** Retrain neural network to understand varied bad character patterns
- **Verification Update:** Extend both C and Python verification tools

### Benefits

- **Flexibility:** Handle line-oriented protocols (HTTP, SMTP), alphanumeric restrictions, custom encoding constraints
- **Backward Compatible:** Default behavior unchanged (null-only when --bad-chars not specified)
- **Performance:** O(1) bitmap lookup maintains efficiency
- **Extensible:** Easy to add new bad-char sets for specific scenarios

---

## Background & Motivation

### Current State

byvalver currently eliminates only null bytes (`0x00`) from shellcode, which is sufficient for C string injection where null terminators would truncate the payload. However, many real-world exploitation scenarios require eliminating additional characters:

| Scenario | Bad Characters | Reason |
|----------|---------------|--------|
| **fgets() Line-Based Input** | `0x00, 0x0a` | fgets() includes `\n` in buffer; line processing may split payload |
| **HTTP/Network Protocols** | `0x00, 0x0a, 0x0d` | CRLF delimiters break multi-line payloads |
| **Text Log Injection** | `0x00, 0x0a, 0x0d, 0x09` | Tab/newline characters fragment log entries |
| **Alphanumeric Shellcode** | `0x00-0x2f, 0x3a-0x40, 0x5b-0x60, 0x7b-0xff` | Only printable ASCII allowed |
| **Space-Restricted Input** | `0x00, 0x20` | Space character treated as delimiter |

### Input Function Behaviors

From the user's research on input functions:

| Function | Newline Behavior | Use Case |
|----------|-----------------|----------|
| `gets()` | Discards `\n`, replaces with `\0` | No issue (deprecated anyway) |
| `fgets()` | **Includes `\n` in buffer** | **Problem:** Shellcode split at newline |
| `scanf("%s")` | Treats `\n` as delimiter | No issue (stops before newline) |
| `getline()` | **Includes `\n` in buffer** | **Problem:** Similar to fgets() |

### Motivation

Extending byvalver to handle generic bad characters addresses these scenarios comprehensively, making it useful for:
- Web application exploits (HTTP injection)
- Command injection with line-based parsing
- Format string vulnerabilities with restricted character sets
- Binary protocol exploits with embedded metadata
- Educational/CTF challenges with custom constraints

---

## Requirements

### Functional Requirements

**FR1:** Users shall specify arbitrary bad characters via CLI flag
- Format: `--bad-chars "00,0a,0d"` (comma-separated hex bytes)
- Range: Any byte value 0x00-0xFF
- Multiple bytes supported

**FR2:** Default behavior shall remain null-byte only (backward compatible)
- No `--bad-chars` flag → eliminate only 0x00
- `--bad-chars "00"` → identical to default

**FR3:** All 122+ transformation strategies shall support generic bad characters
- Strategies check against user-specified bad char set
- No hardcoded null-byte assumptions

**FR4:** Verification tools shall validate elimination of specified bad characters
- C verification: `verify_bad_char_elimination()`
- Python verification: `--bad-chars` argument

**FR5:** ML model shall adapt to different bad character configurations
- Feature extraction includes bad char patterns
- Model retrained with varied bad char sets

### Non-Functional Requirements

**NFR1:** Performance overhead shall be <5% vs null-only mode
- O(1) bitmap lookup for bad char checking
- Minimal memory overhead (256 bytes/process)

**NFR2:** 100% backward compatibility
- Existing usage patterns unchanged
- Old function names preserved as wrappers

**NFR3:** Robustness in error handling
- Validate hex input format
- Handle edge cases (empty, all bytes bad, duplicates)
- Clear error messages

**NFR4:** Maintainability
- Modular design for future extensions
- Clear separation of concerns
- Comprehensive documentation

---

## Architecture Overview

### Current Architecture (Null-Only)

```
┌─────────────┐
│   CLI       │ parse args
└──────┬──────┘
       │
       v
┌─────────────────────────────────────────┐
│  Core Processing (core.c)               │
│  ┌───────────────────────────────────┐  │
│  │ For each instruction:             │  │
│  │   1. Check: has_null_bytes(insn)  │  │
│  │   2. Select strategy              │  │
│  │   3. Generate replacement         │  │
│  │   4. Verify: no nulls introduced  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
       │
       v
┌─────────────────────────────────────────┐
│  Strategies (122+ files)                │
│  - can_handle(): has_null_bytes()       │
│  - generate(): create null-free code    │
│  - verify: is_null_free(val)            │
└─────────────────────────────────────────┘
       │
       v
┌─────────────────────────────────────────┐
│  Verification                           │
│  - C: verify_null_elimination()         │
│  - Python: analyze_shellcode_for_nulls()│
└─────────────────────────────────────────┘
```

### Proposed Architecture (Generic Bad-Char)

```
┌─────────────────────────────────┐
│   CLI (cli.c)                   │
│   parse --bad-chars "00,0a,0d"  │
└──────────┬──────────────────────┘
           │
           v
┌────────────────────────────────────────────┐
│  Bad Char Configuration                    │
│  ┌──────────────────────────────────────┐  │
│  │ bad_char_config_t:                   │  │
│  │   - uint8_t bad_chars[256] (bitmap)  │  │
│  │   - int bad_char_count               │  │
│  │   - uint8_t bad_char_list[256]       │  │
│  └──────────────────────────────────────┘  │
│  Global Context: g_bad_char_context       │
└────────────────────────────────────────────┘
           │
           v
┌──────────────────────────────────────────────┐
│  Generic Checking API (utils.c)             │
│  - is_bad_char_free_byte(byte)              │
│    → g_bad_char_context.config.bad_chars[byte] │
│  - is_bad_char_free(val) [O(1) per byte]   │
│  - has_bad_chars_insn(insn)                 │
└──────────────────────────────────────────────┘
           │
           v
┌──────────────────────────────────────────────┐
│  Core Processing (core.c)                   │
│  ┌────────────────────────────────────────┐  │
│  │ For each instruction:                  │  │
│  │   1. Check: has_bad_chars_insn(insn)   │  │
│  │   2. Select strategy                   │  │
│  │   3. Generate replacement              │  │
│  │   4. Verify: is_bad_char_free_buffer() │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
           │
           v
┌──────────────────────────────────────────────┐
│  Strategies (122+ files)                    │
│  - can_handle(): has_bad_chars_insn()       │
│  - generate(): create bad-char-free code    │
│  - verify: is_bad_char_free(val)            │
└──────────────────────────────────────────────┘
           │
           v
┌──────────────────────────────────────────────┐
│  ML Integration (ml_strategist.c)           │
│  - Extract bad char features                │
│  - Adapt strategy selection                 │
└──────────────────────────────────────────────┘
           │
           v
┌──────────────────────────────────────────────┐
│  Verification                                │
│  - C: verify_bad_char_elimination()          │
│  - Python: analyze_shellcode_for_bad_chars() │
└──────────────────────────────────────────────┘
```

### Key Architectural Changes

1. **Bad Char Configuration Layer:** New `bad_char_config_t` structure with bitmap for O(1) lookup
2. **Global Context:** `g_bad_char_context` avoids passing config through 100+ function calls
3. **Generic API:** `is_bad_char_free*()` replaces `is_null_free*()`
4. **Strategy Agnostic:** Strategies don't know what bytes are "bad", just check via API
5. **ML Feature Expansion:** Neural network learns patterns for different bad char sets

---

## Detailed Design

### 1. Data Structures

#### Bad Character Configuration

**File:** `src/cli.h`

```c
/**
 * Bad character configuration structure
 * Uses bitmap for O(1) lookup performance
 */
typedef struct {
    uint8_t bad_chars[256];      // Bitmap: bad_chars[byte] = 1 if bad, 0 if ok
    int bad_char_count;           // Number of distinct bad characters
    uint8_t bad_char_list[256];   // Ordered list of bad character values
} bad_char_config_t;
```

**Design Rationale:**
- **Bitmap (bad_chars[256]):** Enables O(1) lookup: `if (bad_chars[byte])` is single array access
- **Count (bad_char_count):** Quick check if any bad chars configured, useful for optimization
- **List (bad_char_list):** Facilitates iteration for display/logging without scanning entire bitmap

**Memory Footprint:** 256 + 4 + 256 = 516 bytes per configuration (negligible)

#### Global Context

**File:** `src/core.h`, `src/core.c`

```c
/**
 * Global bad character context
 * Thread-local in multi-threaded scenarios (future enhancement)
 */
typedef struct {
    bad_char_config_t config;     // Active configuration
    int initialized;               // 0 = uninitialized, 1 = ready
} bad_char_context_t;

extern bad_char_context_t g_bad_char_context;

/**
 * Initialize global bad character context
 * @param config: Configuration to copy (NULL = default to null-byte only)
 */
void init_bad_char_context(bad_char_config_t *config);

/**
 * Reset context to uninitialized state
 */
void reset_bad_char_context(void);

/**
 * Get pointer to current configuration (read-only)
 */
bad_char_config_t* get_bad_char_config(void);
```

**Design Rationale:**
- Global context avoids threading configuration through 200+ function signatures
- `initialized` flag allows fallback to default behavior (null-only) when uninitialized
- Future: Can be converted to thread-local storage (`__thread`) for parallelization

#### Configuration Extension

**File:** `src/cli.h` (lines 27-72)

```c
typedef struct {
    // ... existing fields ...

    // Bad character configuration (NEW)
    bad_char_config_t *bad_chars;  // Dynamically allocated configuration

    // ... rest of fields ...
} byvalver_config_t;
```

### 2. Core API Functions

#### Generic Checking Functions

**File:** `src/utils.h`, `src/utils.c` (replacing lines 1076-1083)

```c
/**
 * Check if a single byte is free of bad characters
 * @param byte: Byte to check
 * @return: 1 if ok, 0 if bad
 */
static inline int is_bad_char_free_byte(uint8_t byte) {
    // If context uninitialized, default to null-byte checking only
    if (!g_bad_char_context.initialized) {
        return byte != 0x00;
    }
    // O(1) bitmap lookup
    return g_bad_char_context.config.bad_chars[byte] == 0;
}

/**
 * Check if a 32-bit value is free of bad characters
 * @param val: 32-bit value to check
 * @return: 1 if all 4 bytes ok, 0 if any byte is bad
 */
static inline int is_bad_char_free(uint32_t val) {
    // Check each byte
    for (int i = 0; i < 4; i++) {
        uint8_t byte = (val >> (i * 8)) & 0xFF;
        if (!is_bad_char_free_byte(byte)) {
            return 0;  // Found a bad character
        }
    }
    return 1;  // All bytes ok
}

/**
 * Check if a buffer is free of bad characters
 * @param data: Buffer to check
 * @param size: Buffer size
 * @return: 1 if all bytes ok, 0 if any byte is bad
 */
int is_bad_char_free_buffer(const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (!is_bad_char_free_byte(data[i])) {
            return 0;
        }
    }
    return 1;
}

/**
 * Check if instruction encoding contains bad characters
 * Replaces has_null_bytes()
 * @param insn: Capstone instruction
 * @return: 1 if has bad chars, 0 if clean
 */
int has_bad_chars_insn(cs_insn *insn) {
    return !is_bad_char_free_buffer(insn->bytes, insn->size);
}
```

**Performance Optimization:**
- `static inline` for hot path (is_bad_char_free_byte, is_bad_char_free)
- Compiler will inline these into caller, eliminating function call overhead
- Bitmap lookup is single memory access, very cache-friendly

#### Backward Compatibility Wrappers

```c
/**
 * DEPRECATED: Use is_bad_char_free_byte() instead
 * Maintained for backward compatibility
 */
int is_null_free_byte(uint8_t byte) {
    return is_bad_char_free_byte(byte);
}

/**
 * DEPRECATED: Use is_bad_char_free() instead
 * Maintained for backward compatibility
 */
int is_null_free(uint32_t val) {
    return is_bad_char_free(val);
}
```

### 3. CLI Integration

#### Option Parsing

**File:** `src/cli.c`

**Add long option:**

```c
static struct option long_options[] = {
    // ... existing options ...
    {"bad-chars", required_argument, 0, 0},
    // ... rest ...
    {0, 0, 0, 0}
};
```

**Parsing logic:**

```c
case 0:  // Long options without short equivalent
    opt_name = long_options[option_index].name;

    // ... existing cases ...

    else if (strcmp(opt_name, "bad-chars") == 0) {
        config->bad_chars = parse_bad_chars_string(optarg);
        if (!config->bad_chars) {
            fprintf(stderr, "Error: Invalid --bad-chars format: %s\n", optarg);
            fprintf(stderr, "Expected: comma-separated hex bytes (e.g., \"00,0a,0d\")\n");
            return EXIT_INVALID_ARGUMENTS;
        }
    }
    break;
```

#### Parsing Function

```c
/**
 * Parse bad characters from comma-separated hex string
 * @param input: String like "00,0a,0d"
 * @return: Allocated bad_char_config_t or NULL on error
 */
bad_char_config_t* parse_bad_chars_string(const char *input) {
    if (!input || strlen(input) == 0) {
        return NULL;
    }

    bad_char_config_t *config = calloc(1, sizeof(bad_char_config_t));
    if (!config) {
        return NULL;
    }

    // Duplicate input for strtok
    char *input_copy = strdup(input);
    if (!input_copy) {
        free(config);
        return NULL;
    }

    // Parse comma-separated tokens
    char *token = strtok(input_copy, ",");
    while (token && config->bad_char_count < 256) {
        // Trim leading whitespace
        while (*token == ' ' || *token == '\t') {
            token++;
        }

        // Parse hex byte
        unsigned int byte_val;
        if (sscanf(token, "%02x", &byte_val) != 1 || byte_val > 0xFF) {
            // Invalid hex format
            free(input_copy);
            free(config);
            return NULL;
        }

        uint8_t byte = (uint8_t)byte_val;

        // Add to bitmap if not already present (avoid duplicates)
        if (config->bad_chars[byte] == 0) {
            config->bad_chars[byte] = 1;
            config->bad_char_list[config->bad_char_count++] = byte;
        }

        token = strtok(NULL, ",");
    }

    free(input_copy);

    // Default to null byte if no bytes specified
    if (config->bad_char_count == 0) {
        config->bad_chars[0x00] = 1;
        config->bad_char_list[0] = 0x00;
        config->bad_char_count = 1;
    }

    return config;
}
```

**Error Handling:**
- Invalid hex format: return NULL with clear error message
- Empty string: default to null-byte only
- Duplicates: silently deduplicate via bitmap
- Out of range (>0xFF): reject with error

#### Help Text

```c
void print_detailed_help(FILE *stream, const char *program_name) {
    // ... existing help ...

    fprintf(stream, "\n");
    fprintf(stream, "  Bad Character Options:\n");
    fprintf(stream, "    --bad-chars BYTES         Comma-separated hex bytes to eliminate\n");
    fprintf(stream, "                              (e.g., \"00,0a,0d\" for null, LF, CR)\n");
    fprintf(stream, "                              Default: \"00\" (null bytes only)\n");
    fprintf(stream, "\n");
    fprintf(stream, "  Examples:\n");
    fprintf(stream, "    # Eliminate null bytes only (default)\n");
    fprintf(stream, "    %s shellcode.bin output.bin\n", program_name);
    fprintf(stream, "\n");
    fprintf(stream, "    # Eliminate null, newline, and carriage return\n");
    fprintf(stream, "    %s --bad-chars \"00,0a,0d\" shellcode.bin output.bin\n", program_name);
    fprintf(stream, "\n");
    fprintf(stream, "    # Avoid space character (useful for command injection)\n");
    fprintf(stream, "    %s --bad-chars \"00,20\" shellcode.bin output.bin\n", program_name);

    // ... rest of help ...
}
```

### 4. Core Processing Updates

#### Context Initialization

**File:** `src/main.c`, `src/core.c`

**In main.c (process_single_file):**

```c
int process_single_file(const char *input_path, const char *output_path,
                       byvalver_config_t *config) {
    // Initialize bad character context from configuration
    init_bad_char_context(config->bad_chars);

    // ... rest of processing ...

    // Reset context after processing
    reset_bad_char_context();

    return status;
}
```

**In core.c (context management):**

```c
bad_char_context_t g_bad_char_context = {0};

void init_bad_char_context(bad_char_config_t *config) {
    if (config) {
        // Copy user configuration
        memcpy(&g_bad_char_context.config, config, sizeof(bad_char_config_t));
        g_bad_char_context.initialized = 1;
    } else {
        // Default configuration: null byte only
        memset(&g_bad_char_context, 0, sizeof(bad_char_context_t));
        g_bad_char_context.config.bad_chars[0x00] = 1;
        g_bad_char_context.config.bad_char_list[0] = 0x00;
        g_bad_char_context.config.bad_char_count = 1;
        g_bad_char_context.initialized = 1;
    }
}

void reset_bad_char_context(void) {
    memset(&g_bad_char_context, 0, sizeof(bad_char_context_t));
}

bad_char_config_t* get_bad_char_config(void) {
    return &g_bad_char_context.config;
}
```

#### Inline Check Updates

**File:** `src/core.c`

**Location 1: First pass check (lines 494-498):**

```c
// OLD:
int has_null = 0;
for (int j = 0; j < current->insn->size; j++) {
    if (current->insn->bytes[j] == 0x00) {
        has_null = 1;
        break;
    }
}

// NEW:
int has_bad_chars = has_bad_chars_insn(current->insn);
```

**Location 2: Generation phase check (lines 544-550):**

```c
// Same replacement as Location 1
int has_bad_chars = has_bad_chars_insn(current->insn);
```

**Location 3: Strategy output verification (lines 574-580):**

```c
// OLD:
int strategy_success = 1;
for (size_t i = before_gen; i < new_shellcode.size; i++) {
    if (new_shellcode.data[i] == 0x00) {
        fprintf(stderr, "ERROR: Strategy '%s' introduced null...\n", ...);
        strategy_success = 0;
        break;
    }
}

// NEW:
int strategy_success = is_bad_char_free_buffer(
    &new_shellcode.data[before_gen],
    new_shellcode.size - before_gen
);

if (!strategy_success) {
    fprintf(stderr, "ERROR: Strategy '%s' introduced bad character\n", ...);
}
```

**Location 4: Final verification (line 634):**

```c
// OLD:
for (size_t i = 0; i < new_shellcode.size; i++) {
    if (new_shellcode.data[i] == 0x00) {
        null_count++;
        fprintf(stderr, "WARNING: Null byte at offset %zu\n", i);
    }
}

// NEW:
for (size_t i = 0; i < new_shellcode.size; i++) {
    if (!is_bad_char_free_byte(new_shellcode.data[i])) {
        bad_char_count++;
        fprintf(stderr, "WARNING: Bad character 0x%02x at offset %zu\n",
                new_shellcode.data[i], i);
    }
}
```

#### Verification Function

**File:** `src/core.c` (lines 670-678)

```c
/**
 * Verify that processed buffer is free of bad characters
 * @param processed: Buffer to verify
 * @return: 1 if no bad chars, 0 if bad chars present
 */
int verify_bad_char_elimination(struct buffer *processed) {
    return is_bad_char_free_buffer(processed->data, processed->size);
}

/**
 * DEPRECATED: Use verify_bad_char_elimination() instead
 * Maintained for backward compatibility
 */
int verify_null_elimination(struct buffer *processed) {
    return verify_bad_char_elimination(processed);
}
```

### 5. Strategy Updates

#### Update Pattern

**Scope:** 122+ strategy files in `src/*strategies*.c`

**Search-Replace Operations:**

| Old Function | New Function | Count |
|--------------|-------------|--------|
| `has_null_bytes(insn)` | `has_bad_chars_insn(insn)` | ~150 calls |
| `is_null_free(val)` | `is_bad_char_free(val)` | 218 calls |
| `is_null_free_byte(byte)` | `is_bad_char_free_byte(byte)` | 9 calls |
| Manual loop checking `== 0x00` | `!is_bad_char_free_byte()` | ~50 instances |

**Example Transformation:**

**Before (src/mov_strategies.c:24):**

```c
int can_handle_mov_original(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    // Only handle if no null bytes
    if (has_null_bytes(insn)) {
        return 0;
    }

    return 1;
}
```

**After:**

```c
int can_handle_mov_original(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    // Only handle if no bad characters
    if (has_bad_chars_insn(insn)) {
        return 0;
    }

    return 1;
}
```

**Manual Loop Example (src/push_immediate_strategies.c:25):**

**Before:**

```c
uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;

for (int i = 0; i < 4; i++) {
    if (((imm >> (i * 8)) & 0xFF) == 0x00) {
        return 1; // Has null bytes
    }
}
```

**After:**

```c
uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;

if (!is_bad_char_free(imm)) {
    return 1; // Has bad characters
}
```

#### Automation Script

```bash
#!/bin/bash
# Script: update_strategies.sh
# Purpose: Semi-automated strategy file updates

STRATEGY_FILES=$(find src -name "*strategies.c")

echo "=== Phase 1: Automated Replacements ==="
for file in $STRATEGY_FILES; do
    echo "Processing: $file"

    # Backup original
    cp "$file" "$file.bak"

    # Replace function calls
    sed -i 's/has_null_bytes(/has_bad_chars_insn(/g' "$file"
    sed -i 's/is_null_free(/is_bad_char_free(/g' "$file"
    sed -i 's/is_null_free_byte(/is_bad_char_free_byte(/g' "$file"
done

echo ""
echo "=== Phase 2: Manual Review Required ==="
echo "The following patterns need manual inspection:"
grep -n "== 0x00" $STRATEGY_FILES
grep -n "!= 0x00" $STRATEGY_FILES

echo ""
echo "=== Phase 3: Compile Test ==="
make clean && make
if [ $? -eq 0 ]; then
    echo "SUCCESS: Compilation successful"
else
    echo "FAILURE: Compilation failed, review changes"
    exit 1
fi
```

### 6. Python Verification

**File:** `verify_denulled.py`

#### Generic Bad Character Analysis

```python
def analyze_shellcode_for_bad_chars(shellcode_data, bad_chars=None):
    """
    Analyze shellcode data to count bad characters.

    Args:
        shellcode_data (bytes): The shellcode data to analyze
        bad_chars (set): Set of bad byte values (default: {0x00})

    Returns:
        dict: Information about bad characters in the data
            - total_bytes: Total size
            - bad_char_count: Number of bad character occurrences
            - bad_char_percentage: Percentage of bad chars
            - bad_char_positions: Dict mapping byte value to list of positions
            - bad_char_sequences: List of (start, length, bytes) tuples
            - bad_chars_used: The bad character set used
    """
    if bad_chars is None:
        bad_chars = {0x00}  # Default to null bytes only

    bad_char_count = 0
    bad_char_positions = {byte_val: [] for byte_val in bad_chars}
    bad_char_sequences = []

    i = 0
    while i < len(shellcode_data):
        if shellcode_data[i] in bad_chars:
            # Start of bad char sequence
            seq_start = i
            seq_bytes = []

            while i < len(shellcode_data) and shellcode_data[i] in bad_chars:
                byte_val = shellcode_data[i]
                bad_char_count += 1
                bad_char_positions[byte_val].append(i)
                seq_bytes.append(byte_val)
                i += 1

            seq_length = i - seq_start
            bad_char_sequences.append((seq_start, seq_length, seq_bytes))
        else:
            i += 1

    total_bytes = len(shellcode_data)
    bad_char_percentage = (bad_char_count / total_bytes * 100) if total_bytes > 0 else 0.0

    return {
        'total_bytes': total_bytes,
        'bad_char_count': bad_char_count,
        'bad_char_percentage': bad_char_percentage,
        'bad_char_positions': bad_char_positions,
        'bad_char_sequences': bad_char_sequences,
        'bad_chars_used': bad_chars,
        'max_consecutive_bad_chars': max([seq[1] for seq in bad_char_sequences], default=0)
    }
```

#### CLI Arguments

```python
import argparse

parser = argparse.ArgumentParser(description='Verify bad character elimination in shellcode')
parser.add_argument('input_file', help='Input shellcode file')
parser.add_argument('--output-file', help='Output shellcode file (for comparison)')
parser.add_argument('--bad-chars', type=str, default='00',
                    help='Comma-separated hex bytes to check (default: 00)')
parser.add_argument('--verbose', '-v', action='store_true',
                    help='Verbose output')
args = parser.parse_args()

# Parse bad chars
bad_chars_str = args.bad_chars.split(',')
bad_chars = {int(bc.strip(), 16) for bc in bad_chars_str if bc.strip()}

# Analyze
with open(args.input_file, 'rb') as f:
    shellcode_data = f.read()

results = analyze_shellcode_for_bad_chars(shellcode_data, bad_chars)

# Display results
print(f"Total Bytes: {results['total_bytes']}")
print(f"Bad Character Count: {results['bad_char_count']}")
print(f"Bad Character Percentage: {results['bad_char_percentage']:.2f}%")

if results['bad_char_count'] > 0:
    print("\nBad Character Breakdown:")
    for byte_val in sorted(results['bad_chars_used']):
        positions = results['bad_char_positions'][byte_val]
        if positions:
            print(f"  0x{byte_val:02x}: {len(positions)} occurrences")
            if args.verbose:
                print(f"    Positions: {positions[:10]}{'...' if len(positions) > 10 else ''}")
```

#### Backward Compatibility Wrapper

```python
def analyze_shellcode_for_nulls(shellcode_data):
    """
    Legacy wrapper for backward compatibility.
    Analyzes only null bytes (0x00).
    """
    return analyze_shellcode_for_bad_chars(shellcode_data, bad_chars={0x00})
```

### 7. ML Integration

#### Feature Extraction

**File:** `src/ml_strategist.h`

```c
typedef struct {
    double features[MAX_INSTRUCTION_FEATURES];  // Expand to ~150 features
    int feature_count;

    // Instruction metadata
    int instruction_type;
    int operand_count;
    int operand_types[4];

    // Bad character features (NEW)
    int has_bad_chars;                    // Boolean: has any bad chars
    int bad_char_count;                   // Number of bad chars in instruction
    uint8_t bad_char_types[256];          // Which specific bad chars present
    double bad_char_density;              // bad_char_count / instruction_size
    double bad_char_positions[8];         // Normalized positions of bad chars

    // ... existing fields ...
} instruction_features_t;
```

**File:** `src/ml_strategist.c`

```c
int ml_extract_instruction_features(cs_insn* insn, instruction_features_t* features) {
    memset(features, 0, sizeof(instruction_features_t));

    // ... existing feature extraction ...

    // === NEW: Bad character features ===

    // 1. Detect presence of bad characters
    features->has_bad_chars = has_bad_chars_insn(insn);
    features->features[features->feature_count++] = (double)features->has_bad_chars;

    // 2. Count bad characters
    features->bad_char_count = 0;
    memset(features->bad_char_types, 0, 256);

    for (int i = 0; i < insn->size; i++) {
        if (!is_bad_char_free_byte(insn->bytes[i])) {
            uint8_t bad_byte = insn->bytes[i];

            // Mark this type of bad char as present
            if (features->bad_char_types[bad_byte] == 0) {
                features->bad_char_types[bad_byte] = 1;
                features->bad_char_count++;
            }
        }
    }

    features->features[features->feature_count++] = (double)features->bad_char_count;

    // 3. Bad character density (percentage of instruction that's bad)
    features->bad_char_density = (double)features->bad_char_count / (double)insn->size;
    features->features[features->feature_count++] = features->bad_char_density;

    // 4. Positional features (where in instruction are bad chars?)
    int pos_idx = 0;
    for (int i = 0; i < insn->size && pos_idx < 8; i++) {
        if (!is_bad_char_free_byte(insn->bytes[i])) {
            // Normalize position to [0, 1]
            features->bad_char_positions[pos_idx++] = (double)i / (double)insn->size;
        }
    }

    // Add positional features to feature vector
    for (int i = 0; i < 8; i++) {
        features->features[features->feature_count++] = features->bad_char_positions[i];
    }

    // 5. Bad character type histogram (most common bad chars)
    bad_char_config_t *config = get_bad_char_config();
    for (int i = 0; i < config->bad_char_count && i < 8; i++) {
        uint8_t bad_byte = config->bad_char_list[i];
        int count = 0;
        for (int j = 0; j < insn->size; j++) {
            if (insn->bytes[j] == bad_byte) {
                count++;
            }
        }
        // Normalize count
        features->features[features->feature_count++] = (double)count / (double)insn->size;
    }

    // ... rest of feature extraction ...

    return 1;  // Success
}
```

#### Model Retraining

**Training Data Collection:**

```bash
#!/bin/bash
# Script: collect_ml_training_data.sh

SAMPLES_DIR="samples"
OUTPUT_DIR="ml_training_data"
mkdir -p "$OUTPUT_DIR"

# Collect training data for various bad char configurations
echo "Collecting training data..."

# 1. Null only (baseline)
./byvalver --ml --metrics --metrics-export-csv="$OUTPUT_DIR/null_only.csv" \
    --bad-chars "00" "$SAMPLES_DIR"/*.bin

# 2. Network protocols (null + CRLF)
./byvalver --ml --metrics --metrics-export-csv="$OUTPUT_DIR/network.csv" \
    --bad-chars "00,0a,0d" "$SAMPLES_DIR"/*.bin

# 3. Space avoidance
./byvalver --ml --metrics --metrics-export-csv="$OUTPUT_DIR/space_avoid.csv" \
    --bad-chars "00,20" "$SAMPLES_DIR"/*.bin

# 4. Tab + space + CRLF
./byvalver --ml --metrics --metrics-export-csv="$OUTPUT_DIR/whitespace.csv" \
    --bad-chars "00,09,0a,0d,20" "$SAMPLES_DIR"/*.bin

# 5. Alphanumeric avoidance (partial)
./byvalver --ml --metrics --metrics-export-csv="$OUTPUT_DIR/alphanum.csv" \
    --bad-chars "30,31,32,33,34,35,36,37,38,39" "$SAMPLES_DIR"/*.bin

echo "Training data collection complete"
```

**Model Architecture:**

```
Input Layer: 150 features (up from 128)
  ├─ Instruction metadata (20 features)
  ├─ Bad character features (12 features, NEW)
  ├─ Operand features (40 features)
  ├─ Context features (30 features)
  └─ Historical features (48 features)

Hidden Layer 1: 256 neurons (ReLU)

Hidden Layer 2: 128 neurons (ReLU)

Hidden Layer 3: 64 neurons (ReLU)

Output Layer: 122+ neurons (softmax)
  └─ Probability distribution over strategies
```

**Retraining Process:**

```python
# pseudocode: retrain_ml_model.py

import pandas as pd
import numpy as np
from neural_network import NeuralNetwork

# 1. Load all training data
data_files = [
    'ml_training_data/null_only.csv',
    'ml_training_data/network.csv',
    'ml_training_data/space_avoid.csv',
    'ml_training_data/whitespace.csv',
    'ml_training_data/alphanum.csv'
]

X_train, y_train = [], []
for file in data_files:
    df = pd.read_csv(file)
    features = extract_features(df)  # Extract 150-dim feature vectors
    labels = extract_labels(df)       # Strategy success labels
    X_train.extend(features)
    y_train.extend(labels)

# 2. Split into train/validation (80/20)
X_train, X_val, y_train, y_val = train_test_split(X_train, y_train, test_size=0.2)

# 3. Initialize model
model = NeuralNetwork(
    input_dim=150,
    hidden_dims=[256, 128, 64],
    output_dim=122,
    learning_rate=0.001
)

# 4. Train with early stopping
model.train(
    X_train, y_train,
    X_val, y_val,
    epochs=100,
    batch_size=32,
    early_stopping_patience=10
)

# 5. Export trained model
model.export('models/byvalver_ml_model_v3.bin')
```

---

## Implementation Plan

### Phase 1: Infrastructure (Week 1, Days 1-4)

**Deliverables:**
- `bad_char_config_t` structure definition
- Generic checking functions implemented
- Global context management
- Unit tests for new functions

**Tasks:**
1. Add `bad_char_config_t` to `src/cli.h`
2. Add global context to `src/core.h`, `src/core.c`
3. Implement `is_bad_char_free_byte()` in `src/utils.c`
4. Implement `is_bad_char_free()` in `src/utils.c`
5. Implement `is_bad_char_free_buffer()` in `src/utils.c`
6. Implement `has_bad_chars_insn()` in `src/strategy_registry.c`
7. Implement context functions: `init_bad_char_context()`, `reset_bad_char_context()`
8. Write unit tests: `tests/test_bad_chars.c`
9. Compile and test infrastructure in isolation

**Success Criteria:**
- All unit tests pass
- Functions correctly detect bad chars in test data
- Default behavior (null-only) works

### Phase 2: CLI Integration (Week 1, Days 5-7)

**Deliverables:**
- `--bad-chars` CLI option functional
- Parsing and validation working
- Help text updated

**Tasks:**
1. Add `--bad-chars` to long_options in `src/cli.c`
2. Implement `parse_bad_chars_string()` function
3. Add parsing case in `parse_arguments()`
4. Update `config_create_default()` with default bad_chars
5. Implement input validation (hex format, range)
6. Update `print_detailed_help()` with documentation
7. Test CLI with various inputs (valid, invalid, edge cases)

**Success Criteria:**
- `./byvalver --bad-chars "00,0a,0d"` parses correctly
- Invalid input rejected with clear error messages
- Default behavior unchanged when flag omitted

### Phase 3: Core System (Week 2, Days 1-3)

**Deliverables:**
- Processing pipeline updated
- Verification functions converted
- Integration tests passing

**Tasks:**
1. Update `core.c:494-498` (first pass check)
2. Update `core.c:544-550` (generation check)
3. Update `core.c:574-580` (strategy verification)
4. Update `core.c:634` (final verification loop)
5. Update `verify_null_elimination()` → `verify_bad_char_elimination()`
6. Update `strategy_registry.c:403` (`has_null_bytes` → `has_bad_chars_insn`)
7. Add `init_bad_char_context()` call in `process_single_file()`
8. Write integration tests
9. Test end-to-end with sample shellcode

**Success Criteria:**
- Shellcode processed with custom bad chars
- Verification correctly detects remaining bad chars
- No regression in null-only mode

### Phase 4: Strategy Updates - Tier 1 (Week 2-3, Days 4-10)

**Deliverables:**
- High-priority strategy files updated
- Compilation successful
- Strategy-level tests passing

**Priority Files:**
1. `src/utils.c` - Contains helper functions used by strategies
2. `src/mov_strategies.c` - MOV instruction transformations
3. `src/arithmetic_strategies.c` - ADD/SUB/etc transformations
4. `src/push_immediate_strategies.c` - PUSH transformations
5. `src/immediate_split_strategies.c` - Immediate value splitting
6. `src/enhanced_mov_mem_strategies.c` - Memory MOV operations

**Tasks for Each File:**
1. Automated search-replace: `has_null_bytes` → `has_bad_chars_insn`
2. Automated search-replace: `is_null_free` → `is_bad_char_free`
3. Manual review of inline byte checks (`== 0x00`)
4. Compile and fix errors
5. Run strategy-specific tests
6. Verify no behavioral regression

**Success Criteria:**
- All Tier 1 files compile
- Strategy tests pass
- Sample shellcode processed correctly

### Phase 5: Strategy Updates - Tier 2 (Week 3, Days 1-7)

**Deliverables:**
- All 117+ remaining strategy files updated
- Full compilation successful
- Comprehensive testing

**Automation Script:**
```bash
./update_strategies.sh  # Semi-automated update script
```

**Tasks:**
1. Run automated replacements on all remaining files
2. Manual review of each file (spot-check critical sections)
3. Batch compile and fix errors
4. Run full test suite
5. Performance benchmarking

**Success Criteria:**
- All strategy files compile without errors
- No performance regression >5%
- All existing tests pass

### Phase 6: Verification Updates (Week 3-4, Days 1-3)

**Deliverables:**
- C verification updated
- Python verification updated
- Test suite for verification tools

**Tasks:**
1. Finalize `verify_bad_char_elimination()` in `src/core.c`
2. Update `verify_denulled.py` with `analyze_shellcode_for_bad_chars()`
3. Add `--bad-chars` argument to Python script
4. Write tests for verification functions
5. Test against known good/bad samples

**Success Criteria:**
- C verification detects all configured bad chars
- Python script produces accurate reports
- Both tools agree on results

### Phase 7: ML Integration (Week 4, Days 4-7)

**Deliverables:**
- Feature extraction expanded
- Training data collected
- Model retrained
- ML metrics updated

**Tasks:**
1. Update `instruction_features_t` in `src/ml_strategist.h`
2. Implement bad char feature extraction in `ml_extract_instruction_features()`
3. Run training data collection script with varied bad char sets
4. Retrain neural network with new features
5. Deploy updated model (`ml_model_v3.bin`)
6. Update ML metrics tracking
7. Validate model performance

**Success Criteria:**
- Model correctly adapts to different bad char sets
- Strategy selection accuracy maintained or improved
- No crashes or errors with new features

### Phase 8: Testing & Documentation (Week 5, Days 1-7)

**Deliverables:**
- Comprehensive test suite
- Performance benchmarks
- Updated documentation
- Migration guide

**Tasks:**
1. **Unit Tests:**
   - Bad char configuration parsing
   - Checking functions
   - Context management

2. **Integration Tests:**
   - End-to-end with various bad char sets
   - Batch processing compatibility
   - ML mode compatibility

3. **Regression Tests:**
   - Verify default behavior unchanged
   - Compare output with old version (null-only)

4. **Performance Tests:**
   - Benchmark: 1 bad char vs 5 bad chars vs 10 bad chars
   - Ensure <5% overhead

5. **Documentation:**
   - Update README.md with `--bad-chars` usage
   - Add use case examples (network protocols, alphanumeric, etc.)
   - Update man page
   - Create migration guide for users

6. **Code Review:**
   - Peer review of critical changes
   - Static analysis (cppcheck, valgrind)

**Success Criteria:**
- All tests pass (200+ test cases)
- Performance overhead <5%
- Documentation complete and accurate
- Code quality checks pass

---

## Testing Strategy

### Unit Tests

**Framework:** Custom C test framework or Unity

**Test File:** `tests/test_bad_chars.c`

**Test Cases:**

```c
void test_default_behavior() {
    // No initialization = null-only checking
    g_bad_char_context.initialized = 0;

    assert(is_bad_char_free_byte(0x00) == 0);  // 0x00 is bad
    assert(is_bad_char_free_byte(0x0a) == 1);  // 0x0a is ok
    assert(is_bad_char_free_byte(0xFF) == 1);  // 0xFF is ok
}

void test_custom_bad_chars() {
    // Initialize with {0x00, 0x0a, 0x0d}
    bad_char_config_t config = {0};
    config.bad_chars[0x00] = 1;
    config.bad_chars[0x0a] = 1;
    config.bad_chars[0x0d] = 1;
    config.bad_char_count = 3;
    init_bad_char_context(&config);

    assert(is_bad_char_free_byte(0x00) == 0);  // Bad
    assert(is_bad_char_free_byte(0x0a) == 0);  // Bad
    assert(is_bad_char_free_byte(0x0d) == 0);  // Bad
    assert(is_bad_char_free_byte(0x20) == 1);  // Ok
}

void test_is_bad_char_free_32bit() {
    bad_char_config_t config = {0};
    config.bad_chars[0x00] = 1;
    config.bad_chars[0x0a] = 1;
    init_bad_char_context(&config);

    assert(is_bad_char_free(0x12345678) == 1);  // Ok
    assert(is_bad_char_free(0x12340078) == 0);  // Has 0x00
    assert(is_bad_char_free(0x123400a) == 0);   // Has 0x0a
}

void test_cli_parsing() {
    bad_char_config_t *config;

    // Valid input
    config = parse_bad_chars_string("00,0a,0d");
    assert(config != NULL);
    assert(config->bad_char_count == 3);
    assert(config->bad_chars[0x00] == 1);
    assert(config->bad_chars[0x0a] == 1);
    assert(config->bad_chars[0x0d] == 1);
    free(config);

    // Invalid input
    config = parse_bad_chars_string("00,ZZ,0d");
    assert(config == NULL);  // Should fail

    // Empty input
    config = parse_bad_chars_string("");
    assert(config == NULL);
}

void test_edge_cases() {
    bad_char_config_t *config;

    // Duplicate bytes
    config = parse_bad_chars_string("00,00,00");
    assert(config->bad_char_count == 1);  // Deduplicated
    free(config);

    // Out of range
    config = parse_bad_chars_string("00,100");
    assert(config == NULL);  // Should fail
}
```

### Integration Tests

**Test Script:** `tests/run_integration_tests.sh`

```bash
#!/bin/bash
set -e

TEST_DIR="tests/integration"
SAMPLES="samples"

echo "=== Integration Test Suite ==="

# Test 1: Default null-only mode
echo "[TEST 1] Default null elimination"
./byvalver "$SAMPLES/calc.bin" "$TEST_DIR/output1.bin"
python3 verify_denulled.py "$TEST_DIR/output1.bin" --bad-chars "00"
assert_exit_code 0

# Test 2: Custom bad chars (network protocols)
echo "[TEST 2] Eliminate 0x00, 0x0a, 0x0d"
./byvalver --bad-chars "00,0a,0d" "$SAMPLES/calc.bin" "$TEST_DIR/output2.bin"
python3 verify_denulled.py "$TEST_DIR/output2.bin" --bad-chars "00,0a,0d"
assert_exit_code 0

# Test 3: Space avoidance
echo "[TEST 3] Eliminate 0x00, 0x20"
./byvalver --bad-chars "00,20" "$SAMPLES/calc.bin" "$TEST_DIR/output3.bin"
python3 verify_denulled.py "$TEST_DIR/output3.bin" --bad-chars "00,20"
assert_exit_code 0

# Test 4: Batch processing compatibility
echo "[TEST 4] Batch processing with bad chars"
./byvalver -r --bad-chars "00,0a" "$SAMPLES" "$TEST_DIR/batch_output"
assert_exit_code 0

# Test 5: ML mode compatibility
echo "[TEST 5] ML mode with bad chars"
./byvalver --ml --bad-chars "00,0d" "$SAMPLES/calc.bin" "$TEST_DIR/output_ml.bin"
assert_exit_code 0

# Test 6: Verify backward compatibility
echo "[TEST 6] Backward compatibility check"
./byvalver "$SAMPLES/calc.bin" "$TEST_DIR/old_style.bin"
./byvalver --bad-chars "00" "$SAMPLES/calc.bin" "$TEST_DIR/new_style.bin"
diff "$TEST_DIR/old_style.bin" "$TEST_DIR/new_style.bin"
assert_exit_code 0  # Files should be identical

echo "=== All Integration Tests Passed ==="
```

### Regression Tests

**Objective:** Ensure no breaking changes for existing users

**Test Cases:**

1. **No-Flag Test:**
   ```bash
   # Old usage (no --bad-chars) should work exactly as before
   ./byvalver input.bin output.bin
   # Verify only null bytes eliminated
   ```

2. **Output Comparison:**
   ```bash
   # v2.x (old version)
   ./byvalver_v2 input.bin old_output.bin

   # v3.x (new version, null-only)
   ./byvalver_v3 --bad-chars "00" input.bin new_output.bin

   # Outputs should be binary identical
   diff old_output.bin new_output.bin
   ```

3. **Performance Regression:**
   ```bash
   # Benchmark: v2.x vs v3.x (null-only mode)
   time ./byvalver_v2 samples/*.bin
   time ./byvalver_v3 --bad-chars "00" samples/*.bin
   # Difference should be <5%
   ```

### Performance Tests

**Benchmark Script:** `tests/benchmark_bad_chars.sh`

```bash
#!/bin/bash

SAMPLES="samples/*.bin"
ITERATIONS=10

echo "=== Performance Benchmarking ==="

# Baseline: null-only (new implementation)
echo "[Benchmark 1] Null-only (new)"
time_start=$(date +%s%N)
for i in $(seq 1 $ITERATIONS); do
    ./byvalver --bad-chars "00" $SAMPLES > /dev/null
done
time_end=$(date +%s%N)
time_null=$((($time_end - $time_start) / 1000000))  # Convert to ms
echo "Time: ${time_null}ms"

# Test: 3 bad chars
echo "[Benchmark 2] 3 bad chars (00,0a,0d)"
time_start=$(date +%s%N)
for i in $(seq 1 $ITERATIONS); do
    ./byvalver --bad-chars "00,0a,0d" $SAMPLES > /dev/null
done
time_end=$(date +%s%N)
time_3chars=$((($time_end - $time_start) / 1000000))
echo "Time: ${time_3chars}ms"
overhead=$((($time_3chars - $time_null) * 100 / $time_null))
echo "Overhead: ${overhead}%"

# Test: 5 bad chars
echo "[Benchmark 3] 5 bad chars (00,0a,0d,20,09)"
time_start=$(date +%s%N)
for i in $(seq 1 $ITERATIONS); do
    ./byvalver --bad-chars "00,0a,0d,20,09" $SAMPLES > /dev/null
done
time_end=$(date +%s%N)
time_5chars=$((($time_end - $time_start) / 1000000))
echo "Time: ${time_5chars}ms"
overhead=$((($time_5chars - $time_null) * 100 / $time_null))
echo "Overhead: ${overhead}%"

# Test: 10 bad chars
echo "[Benchmark 4] 10 bad chars"
time_start=$(date +%s%N)
for i in $(seq 1 $ITERATIONS); do
    ./byvalver --bad-chars "00,01,02,03,04,05,06,07,08,09" $SAMPLES > /dev/null
done
time_end=$(date +%s%N)
time_10chars=$((($time_end - $time_start) / 1000000))
echo "Time: ${time_10chars}ms"
overhead=$((($time_10chars - $time_null) * 100 / $time_null))
echo "Overhead: ${overhead}%"

echo "=== Benchmark Complete ==="
```

**Expected Results:**
- Null-only: Baseline (100%)
- 3 bad chars: 101-103% (1-3% overhead)
- 5 bad chars: 102-104% (2-4% overhead)
- 10 bad chars: 103-105% (3-5% overhead)

---

## Performance Analysis

### Theoretical Analysis

**Checking Function Complexity:**

```c
// Old: is_null_free_byte()
int is_null_free_byte(uint8_t byte) {
    return byte != 0x00;  // 1 comparison
}

// New: is_bad_char_free_byte()
int is_bad_char_free_byte(uint8_t byte) {
    return g_bad_char_context.config.bad_chars[byte] == 0;  // 1 array access + 1 comparison
}
```

**Operations:**
- Old: 1 comparison
- New: 1 array access + 1 comparison

**Cost:**
- Array access: ~1-2 CPU cycles (L1 cache hit)
- Comparison: ~1 CPU cycle
- **Total overhead: ~1-2 cycles per byte check**

**Frequency:**
- Typical shellcode: 100-500 bytes
- Checks per byte: ~3-5 (instruction scan, operand checks, verification)
- Total extra cycles: 300-1000 cycles = **0.0003-0.001ms** @ 1GHz

**Conclusion:** Overhead is negligible (<0.1% in practice due to caching).

### Empirical Measurements

**Profiling Plan:**

```bash
# Profile with Valgrind/Cachegrind
valgrind --tool=cachegrind ./byvalver --bad-chars "00" input.bin output.bin
valgrind --tool=cachegrind ./byvalver --bad-chars "00,0a,0d,20,09" input.bin output.bin

# Compare cache miss rates, instruction counts
cg_annotate cachegrind.out.*
```

**Expected Findings:**
- **L1 cache miss rate:** <1% increase (bitmap fits in L1)
- **Instruction count:** +0.5% (extra array access)
- **Total runtime:** +2-3% worst case

### Optimization Opportunities

**1. Inline Functions:**
```c
static inline int is_bad_char_free_byte(uint8_t byte) {
    // Compiler inlines this, eliminating function call overhead
}
```

**2. Likely/Unlikely Hints:**
```c
static inline int is_bad_char_free_byte(uint8_t byte) {
    if (__builtin_expect(!g_bad_char_context.initialized, 0)) {
        return byte != 0x00;  // Cold path
    }
    return g_bad_char_context.config.bad_chars[byte] == 0;  // Hot path
}
```

**3. SIMD Acceleration (Future):**
```c
// Check 16 bytes at once with SSE
#ifdef __SSE2__
int is_bad_char_free_buffer_simd(const uint8_t *data, size_t size) {
    // Use SIMD instructions for parallel checking
    // Potential 4-8x speedup for large buffers
}
#endif
```

---

## Migration & Backward Compatibility

### Compatibility Guarantees

**1. Command-Line Compatibility:**
```bash
# Old usage (v2.x): Still works in v3.x
./byvalver input.bin output.bin

# Behavior: Identical to v2.x (eliminates only null bytes)
```

**2. API Compatibility:**
```c
// Old functions remain available as wrappers
int is_null_free(uint32_t val);         // Still callable
int is_null_free_byte(uint8_t byte);    // Still callable
```

**3. Output Compatibility:**
```bash
# Same input + null-only mode = identical output
./byvalver --bad-chars "00" input.bin output_v3.bin

# output_v3.bin is byte-for-byte identical to v2.x output
```

### Migration Paths

**For End Users:**

```markdown
## Migrating to byvalver v3.x

### No Changes Required
If you only eliminate null bytes, **no changes are needed**:
```bash
# Your existing commands work as-is
./byvalver shellcode.bin clean.bin
```

### New Features Available
To eliminate additional bad characters:
```bash
# Eliminate null + newline (for fgets scenarios)
./byvalver --bad-chars "00,0a" shellcode.bin clean.bin

# Eliminate null + CRLF (for network protocols)
./byvalver --bad-chars "00,0a,0d" shellcode.bin clean.bin
```

### Python Verification
Update your verification scripts:
```bash
# Old: checks only null bytes
python3 verify_denulled.py output.bin

# New: checks custom bad chars
python3 verify_denulled.py output.bin --bad-chars "00,0a,0d"
```
```

**For Developers Integrating byvalver:**

```markdown
## API Migration Guide

### Function Renames
If you call byvalver functions directly, update your code:

| Old Function | New Function | Notes |
|--------------|--------------|-------|
| `is_null_free(val)` | `is_bad_char_free(val)` | Old function still works (wrapper) |
| `is_null_free_byte(byte)` | `is_bad_char_free_byte(byte)` | Old function still works (wrapper) |
| `has_null_bytes(insn)` | `has_bad_chars_insn(insn)` | Must update if using internal API |
| `verify_null_elimination(buf)` | `verify_bad_char_elimination(buf)` | Old function still works (wrapper) |

### Initialization Required
If using as a library, initialize bad char context:
```c
#include "core.h"

int main() {
    // Initialize with custom bad chars
    bad_char_config_t config = {0};
    config.bad_chars[0x00] = 1;  // Null
    config.bad_chars[0x0a] = 1;  // LF
    config.bad_char_count = 2;

    init_bad_char_context(&config);

    // Process shellcode...

    reset_bad_char_context();
    return 0;
}
```
```

### Deprecation Timeline

**Version 3.0 (Current):**
- New functions introduced: `is_bad_char_free*()`, `has_bad_chars_insn()`
- Old functions maintained as wrappers: `is_null_free*()`, `has_null_bytes()`
- No warnings, full backward compatibility

**Version 4.0 (Future, 12 months):**
- Old functions marked deprecated with compiler warnings
- Documentation updated to recommend new functions
- All examples use new API

**Version 5.0 (Future, 24 months):**
- Old functions removed (breaking change)
- Major version bump signals breaking change
- Migration guide provided

### Rollback Plan

**If Critical Issues Arise:**

1. **Compile-Time Rollback:**
   ```c
   // Add to Makefile: -DUSE_LEGACY_NULL_CHECKING
   #ifdef USE_LEGACY_NULL_CHECKING
   #define is_bad_char_free(val) is_null_free(val)
   #define has_bad_chars_insn(insn) has_null_bytes(insn)
   #endif
   ```

2. **Runtime Rollback:**
   ```bash
   # Disable --bad-chars option, always use null-only
   if [ "$USE_LEGACY_MODE" = "1" ]; then
       unset BAD_CHARS_ARG
   fi
   ```

3. **Binary Rollback:**
   ```bash
   # Keep v2.x binary available as fallback
   ln -s /usr/bin/byvalver_v2 /usr/bin/byvalver_legacy
   ```

---

## Risks & Mitigation

### High Risk: Strategy File Updates

**Risk:** 122+ strategy files need updating; high chance of missed cases or errors.

**Impact:** Incomplete bad char elimination, crashes, incorrect transformations.

**Likelihood:** High (large-scale refactoring)

**Mitigation:**
1. **Semi-Automated Process:**
   - Use `sed`/`awk` for bulk replacements
   - Manual review of critical sections
   - Git commit after each batch for rollback capability

2. **Incremental Testing:**
   - Compile and test after each file or small batch
   - Run regression tests frequently
   - Use static analysis tools (cppcheck)

3. **Comprehensive Test Suite:**
   - Unit tests for each strategy
   - Integration tests with diverse shellcode samples
   - Verification against known-good outputs

4. **Code Review:**
   - Peer review of all changes
   - Focus on inline null checks (most error-prone)

### Medium Risk: Performance Regression

**Risk:** Additional overhead from bitmap lookups degrades performance >5%.

**Impact:** Users experience slower processing times.

**Likelihood:** Low-Medium (well-designed algorithm, but large-scale impact)

**Mitigation:**
1. **Optimization:**
   - Use `static inline` for hot-path functions
   - Bitmap fits in L1 cache (64 bytes)
   - Compiler optimizations enabled (`-O3 -march=native`)

2. **Profiling:**
   - Profile with Valgrind/Cachegrind before/after
   - Identify and optimize hotspots
   - Benchmark with realistic workloads

3. **Fallback:**
   - If >5% regression detected, add compile-time fast path:
     ```c
     #ifdef FAST_NULL_ONLY_MODE
     // Use optimized null-only checks
     #endif
     ```

4. **Continuous Monitoring:**
   - Add performance regression tests to CI/CD
   - Alert on >3% slowdown

### Medium Risk: ML Model Degradation

**Risk:** Retraining with bad char features reduces model accuracy.

**Impact:** Suboptimal strategy selection, lower success rate.

**Likelihood:** Medium (ML training can be unpredictable)

**Mitigation:**
1. **Baseline Comparison:**
   - Measure current model accuracy before retraining
   - Accept new model only if accuracy ≥ baseline

2. **A/B Testing:**
   - Deploy new model to subset of users
   - Monitor success rates vs. old model
   - Rollback if significant degradation

3. **Feature Engineering:**
   - Carefully design bad char features (normalized, informative)
   - Avoid feature explosion (keep to 150 dims)

4. **Graceful Fallback:**
   - If ML model fails to load, fall back to deterministic strategy selection
   - Log warnings but continue processing

### Low Risk: Backward Compatibility Break

**Risk:** Default behavior changes unintentionally, breaking existing users.

**Impact:** Users' workflows fail or produce unexpected results.

**Likelihood:** Low (design explicitly maintains compatibility)

**Mitigation:**
1. **Extensive Regression Testing:**
   - 100+ test cases comparing v2.x vs v3.x (null-only)
   - Binary output comparison

2. **Clear Documentation:**
   - Migration guide emphasizes "no changes needed"
   - Examples show default behavior unchanged

3. **Version Announcement:**
   - Release notes clearly state backward compatibility guarantee
   - Changelog highlights new features as opt-in

4. **Canary Deployment:**
   - Release beta version for early adopters
   - Gather feedback before general release

### Low Risk: Edge Case Bugs

**Risk:** Unusual inputs (empty bad chars, all bytes bad, etc.) cause crashes.

**Impact:** Tool unusable for specific inputs.

**Likelihood:** Low (handled in design)

**Mitigation:**
1. **Input Validation:**
   - Reject empty bad char sets (default to null)
   - Reject "all bytes bad" (error message)
   - Validate hex input format

2. **Edge Case Testing:**
   - Test with extreme inputs (1 byte, 255 bytes bad)
   - Fuzz testing with random inputs
   - Boundary value analysis

3. **Defensive Programming:**
   - Null checks before dereferencing pointers
   - Bounds checking on array accesses
   - Graceful error handling with user-friendly messages

---

## Future Enhancements

### 1. Alphanumeric Shellcode Mode

**Feature:** Preset for alphanumeric-only shellcode.

```bash
./byvalver --alphanumeric-only input.bin output.bin
# Equivalent to: --bad-chars "00-2f,3a-40,5b-60,7b-ff"
```

**Benefits:**
- Simplifies common use case
- Pre-optimized strategies for alphanumeric constraints

### 2. Unicode/UTF-8 Support

**Feature:** Handle multi-byte bad character sequences.

```bash
./byvalver --bad-chars-utf8 "00,c2a0"  # Null + non-breaking space
```

**Challenges:**
- Multi-byte character detection
- Cross-boundary checking

### 3. Context-Aware Bad Chars

**Feature:** Different bad chars for different code sections.

```bash
./byvalver --bad-chars-map "0-100:00,0a;101-200:00,20"
# Bytes 0-100: avoid null + LF
# Bytes 101-200: avoid null + space
```

**Benefits:**
- Handle complex encoding scenarios
- Optimize for specific shellcode sections

### 4. Machine Learning Auto-Detection

**Feature:** ML model suggests bad chars based on target environment.

```bash
./byvalver --target-env "http-get-request" input.bin output.bin
# Auto-configures: --bad-chars "00,0a,0d,20"
```

**ML Model:**
- Train on common exploitation scenarios
- Suggest optimal bad char sets

### 5. Performance: SIMD Acceleration

**Feature:** Use SSE/AVX for parallel bad char checking.

```c
#ifdef __AVX2__
// Check 32 bytes in parallel with AVX2
__m256i bad_mask = _mm256_loadu_si256((__m256i*)&config->bad_chars[0]);
// ... SIMD comparison logic ...
#endif
```

**Speedup:** 4-8x for large buffers.

### 6. Cloud-Based Strategy Optimization

**Feature:** Submit anonymized metrics to cloud service for global model improvement.

```bash
./byvalver --cloud-optimize --bad-chars "00,0a,0d" input.bin output.bin
# Uploads: instruction patterns, strategy success rates (anonymized)
# Downloads: Optimized model from global dataset
```

**Privacy:** Opt-in, no shellcode content uploaded.

---

## Conclusion

This design document outlines a comprehensive plan to transform byvalver into a generic bad-character elimination framework. The approach prioritizes:

1. **Backward Compatibility:** Existing users experience zero breaking changes
2. **Performance:** <5% overhead through O(1) bitmap lookups and inlining
3. **Extensibility:** Clean architecture enables future enhancements
4. **Robustness:** Extensive testing and error handling

**Key Achievements:**
- Solves real-world problems beyond C string injection (HTTP, fgets, alphanumeric, etc.)
- Maintains byvalver's core strengths (122+ strategies, ML optimization, high success rate)
- Provides smooth migration path with deprecation timeline
- Establishes foundation for future features (SIMD, cloud optimization, etc.)

**Implementation Timeline:** 4-5 weeks

**Estimated Impact:**
- **Users:** Expanded use cases, improved flexibility
- **Codebase:** Cleaner abstraction, easier to extend
- **Performance:** Negligible overhead (2-3% worst case)
- **Success Rate:** Maintained or improved with ML retraining

---

## References

### Related Documents
- `README.md` - Current byvalver documentation
- `docs/DENULL_STRATS.md` - Denullification strategies
- `docs/OBFUSCATION_STRATS.md` - Obfuscation strategies

### Academic References
- **Input Function Behaviors:** C99 Standard (ISO/IEC 9899:1999), Section 7.21 (Input/Output)
- **Shellcode Encoding:** Skape, "Understanding Windows Shellcode" (2003)
- **Bad Character Restrictions:** OWASP Testing Guide, "Testing for Code Injection"

### Implementation Resources
- Capstone Disassembly Engine: https://www.capstone-engine.org/
- NASM Assembler: https://www.nasm.us/
- Neural Network Training: scikit-learn, TensorFlow documentation

---

**Document Version:** 1.0
**Last Updated:** 2025-12-16
**Maintainer:** byvalver Development Team
