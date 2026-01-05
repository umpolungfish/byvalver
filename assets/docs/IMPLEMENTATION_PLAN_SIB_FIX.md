# Implementation Plan: Profile-Aware SIB Byte Generation

## Overview
This document provides a step-by-step implementation plan to fix the SIB byte 0x20 (SPACE) issue that causes 79.7% failure rate in http-whitespace profile.

## Phase 1: Core Infrastructure (Week 1, Days 1-2)

### Step 1.1: Add Profile-Aware SIB Byte Utility Functions

**File**: `src/profile_aware_sib.c` (NEW)
**File**: `src/profile_aware_sib.h` (NEW)

```c
// profile_aware_sib.h
#ifndef PROFILE_AWARE_SIB_H
#define PROFILE_AWARE_SIB_H

#include <stdint.h>
#include <stddef.h>
#include "utils.h"

/**
 * @brief Strategy for encoding memory access without bad bytes
 */
typedef enum {
    SIB_ENCODING_STANDARD,      // Use standard SIB 0x20 if safe
    SIB_ENCODING_DISP8,         // Use [reg + disp8] with compensation
    SIB_ENCODING_ALTERNATIVE,   // Use alternative SIB bytes
    SIB_ENCODING_PUSHPOP        // Use PUSH/POP based approach
} sib_encoding_strategy_t;

/**
 * @brief Result of SIB encoding selection
 */
typedef struct {
    sib_encoding_strategy_t strategy;
    uint8_t sib_byte;           // SIB byte to use (if applicable)
    uint8_t modrm_byte;         // ModR/M byte to use
    int8_t disp8;               // Displacement value (if using DISP8)
    bool needs_compensation;    // Whether address needs compensation
    int8_t compensation;        // Compensation value to apply
} sib_encoding_result_t;

/**
 * @brief Select best SIB encoding for [EAX] based on bad byte profile
 * @param dst_reg Destination register (for ModR/M encoding)
 * @return Encoding result with strategy and bytes to use
 */
sib_encoding_result_t select_sib_encoding_for_eax(x86_reg dst_reg);

/**
 * @brief Select best SIB encoding for [base_reg] based on bad byte profile
 * @param base_reg Base register for addressing
 * @param dst_reg Destination register (for ModR/M encoding)
 * @return Encoding result with strategy and bytes to use
 */
sib_encoding_result_t select_sib_encoding_for_reg(x86_reg base_reg, x86_reg dst_reg);

/**
 * @brief Generate MOV dst_reg, [base_reg] using profile-safe encoding
 * @param b Output buffer
 * @param dst_reg Destination register
 * @param base_reg Base register for memory operand
 * @return 0 on success, -1 on failure
 */
int generate_safe_mov_reg_mem(struct buffer *b, x86_reg dst_reg, x86_reg base_reg);

/**
 * @brief Generate MOV [base_reg], src_reg using profile-safe encoding
 * @param b Output buffer
 * @param base_reg Base register for memory operand
 * @param src_reg Source register
 * @return 0 on success, -1 on failure
 */
int generate_safe_mov_mem_reg(struct buffer *b, x86_reg base_reg, x86_reg src_reg);

/**
 * @brief Generate LEA dst_reg, [base_reg] using profile-safe encoding
 * @param b Output buffer
 * @param dst_reg Destination register
 * @param base_reg Base register for memory operand
 * @return 0 on success, -1 on failure
 */
int generate_safe_lea_reg_mem(struct buffer *b, x86_reg dst_reg, x86_reg base_reg);

#endif // PROFILE_AWARE_SIB_H
```

```c
// profile_aware_sib.c
#include "profile_aware_sib.h"
#include "utils.h"
#include <stdio.h>

/**
 * @brief Check if a specific SIB byte is safe to use
 */
static bool is_sib_byte_safe(uint8_t sib_byte) {
    return is_bad_byte_free_buffer(&sib_byte, 1);
}

/**
 * @brief Check if a specific displacement value is safe
 */
static bool is_disp8_safe(int8_t disp) {
    uint8_t byte = (uint8_t)disp;
    return is_bad_byte_free_buffer(&byte, 1);
}

/**
 * @brief Select best SIB encoding for [EAX] based on bad byte profile
 */
sib_encoding_result_t select_sib_encoding_for_eax(x86_reg dst_reg) {
    sib_encoding_result_t result = {0};
    uint8_t dst_idx = get_reg_index(dst_reg);

    // Strategy 1: Standard SIB byte 0x20 (if safe)
    // SIB 0x20 = scale:00(1), index:100(ESP/none), base:000(EAX)
    if (is_sib_byte_safe(0x20)) {
        result.strategy = SIB_ENCODING_STANDARD;
        result.modrm_byte = 0x04 | (dst_idx << 3);  // mod:00, reg:dst, r/m:100(SIB)
        result.sib_byte = 0x20;
        result.needs_compensation = false;
        return result;
    }

    // Strategy 2: Try alternative SIB bytes
    // SIB 0x00 = scale:00, index:000(EAX), base:000(EAX) = [EAX + EAX*1]
    // This means [EAX*2] which is wrong, but we could compensate
    // Actually, let's try other bases with ESP as index (no index)

    // Try SIB with different bases (all encode [base_reg] with no index)
    uint8_t alternative_sibs[] = {
        0x21,  // base:001(ECX)
        0x22,  // base:010(EDX)
        0x23,  // base:011(EBX)
        0x24,  // base:100(ESP) - special case
        0x25,  // base:101(EBP)
        0x26,  // base:110(ESI)
        0x27   // base:111(EDI)
    };

    // These don't work for [EAX], they encode different registers
    // So alternative SIBs won't help us here

    // Strategy 3: Use [EAX + disp8] with 8-bit displacement
    // Try common safe displacement values
    int8_t safe_displacements[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08,
                                   0x0B, 0x0C, 0x0E, 0x0F, 0x10, 0x11, 0x7F,
                                   -1, -2, -3, -4, -5, -7, -8};

    for (size_t i = 0; i < sizeof(safe_displacements)/sizeof(safe_displacements[0]); i++) {
        if (is_disp8_safe(safe_displacements[i])) {
            result.strategy = SIB_ENCODING_DISP8;
            result.modrm_byte = 0x40 | dst_idx;  // mod:01(disp8), reg:dst, r/m:000(EAX)
            result.disp8 = safe_displacements[i];
            result.needs_compensation = true;
            result.compensation = -safe_displacements[i];  // Compensate for displacement
            return result;
        }
    }

    // Strategy 4: Fallback to PUSH/POP approach
    result.strategy = SIB_ENCODING_PUSHPOP;
    result.needs_compensation = false;
    return result;
}

/**
 * @brief Select best SIB encoding for arbitrary base register
 */
sib_encoding_result_t select_sib_encoding_for_reg(x86_reg base_reg, x86_reg dst_reg) {
    sib_encoding_result_t result = {0};
    uint8_t base_idx = get_reg_index(base_reg);
    uint8_t dst_idx = get_reg_index(dst_reg);

    // Special case: if base is EAX, use specialized function
    if (base_reg == X86_REG_EAX) {
        return select_sib_encoding_for_eax(dst_reg);
    }

    // For other registers, first try direct ModR/M encoding (no SIB needed)
    uint8_t modrm = 0x00 | (dst_idx << 3) | base_idx;  // mod:00, reg:dst, r/m:base

    if (is_bad_byte_free_buffer(&modrm, 1)) {
        result.strategy = SIB_ENCODING_STANDARD;
        result.modrm_byte = modrm;
        result.needs_compensation = false;
        return result;
    }

    // If direct encoding has bad byte, try [base + disp8]
    int8_t safe_displacements[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08,
                                   0x0B, 0x0C, 0x0E, 0x0F, 0x10, 0x11, 0x7F};

    for (size_t i = 0; i < sizeof(safe_displacements)/sizeof(safe_displacements[0]); i++) {
        if (is_disp8_safe(safe_displacements[i])) {
            modrm = 0x40 | (dst_idx << 3) | base_idx;  // mod:01(disp8)
            if (is_bad_byte_free_buffer(&modrm, 1)) {
                result.strategy = SIB_ENCODING_DISP8;
                result.modrm_byte = modrm;
                result.disp8 = safe_displacements[i];
                result.needs_compensation = true;
                result.compensation = -safe_displacements[i];
                return result;
            }
        }
    }

    // Fallback
    result.strategy = SIB_ENCODING_PUSHPOP;
    return result;
}

/**
 * @brief Generate MOV dst_reg, [base_reg] using profile-safe encoding
 */
int generate_safe_mov_reg_mem(struct buffer *b, x86_reg dst_reg, x86_reg base_reg) {
    sib_encoding_result_t enc = select_sib_encoding_for_reg(base_reg, dst_reg);

    switch (enc.strategy) {
        case SIB_ENCODING_STANDARD: {
            // Standard encoding: MOV dst, [base]
            uint8_t code[3];
            code[0] = 0x8B;  // MOV r32, r/m32
            code[1] = enc.modrm_byte;

            if ((enc.modrm_byte & 0x07) == 0x04) {
                // SIB byte follows
                code[2] = enc.sib_byte;
                buffer_append(b, code, 3);
            } else {
                buffer_append(b, code, 2);
            }
            return 0;
        }

        case SIB_ENCODING_DISP8: {
            // With displacement: first adjust base register
            if (enc.needs_compensation) {
                // SUB base_reg, disp8 or ADD base_reg, -disp8
                if (enc.compensation > 0) {
                    // ADD base_reg, compensation
                    uint8_t add_code[] = {0x83, 0xC0 | get_reg_index(base_reg), (uint8_t)enc.compensation};
                    buffer_append(b, add_code, 3);
                } else {
                    // SUB base_reg, -compensation
                    uint8_t sub_code[] = {0x83, 0xE8 | get_reg_index(base_reg), (uint8_t)(-enc.compensation)};
                    buffer_append(b, sub_code, 3);
                }
            }

            // MOV dst, [base + disp8]
            uint8_t mov_code[] = {0x8B, enc.modrm_byte, (uint8_t)enc.disp8};
            buffer_append(b, mov_code, 3);

            // Restore base register
            if (enc.needs_compensation) {
                if (enc.compensation > 0) {
                    // SUB base_reg, compensation (undo the ADD)
                    uint8_t sub_code[] = {0x83, 0xE8 | get_reg_index(base_reg), (uint8_t)enc.compensation};
                    buffer_append(b, sub_code, 3);
                } else {
                    // ADD base_reg, -compensation (undo the SUB)
                    uint8_t add_code[] = {0x83, 0xC0 | get_reg_index(base_reg), (uint8_t)(-enc.compensation)};
                    buffer_append(b, add_code, 3);
                }
            }
            return 0;
        }

        case SIB_ENCODING_PUSHPOP: {
            // Fallback: use PUSH [base] / POP dst approach
            // PUSH [base_reg]
            uint8_t push_modrm = 0x30 | get_reg_index(base_reg);  // /6 for PUSH
            uint8_t push_code[] = {0xFF, push_modrm};
            buffer_append(b, push_code, 2);

            // POP dst_reg
            uint8_t pop_code[] = {0x58 | get_reg_index(dst_reg)};
            buffer_append(b, pop_code, 1);
            return 0;
        }

        default:
            return -1;
    }
}

/**
 * @brief Generate MOV [base_reg], src_reg using profile-safe encoding
 */
int generate_safe_mov_mem_reg(struct buffer *b, x86_reg base_reg, x86_reg src_reg) {
    sib_encoding_result_t enc = select_sib_encoding_for_reg(base_reg, src_reg);

    switch (enc.strategy) {
        case SIB_ENCODING_STANDARD: {
            uint8_t code[3];
            code[0] = 0x89;  // MOV r/m32, r32
            code[1] = enc.modrm_byte;

            if ((enc.modrm_byte & 0x07) == 0x04) {
                code[2] = enc.sib_byte;
                buffer_append(b, code, 3);
            } else {
                buffer_append(b, code, 2);
            }
            return 0;
        }

        case SIB_ENCODING_DISP8: {
            if (enc.needs_compensation) {
                if (enc.compensation > 0) {
                    uint8_t add_code[] = {0x83, 0xC0 | get_reg_index(base_reg), (uint8_t)enc.compensation};
                    buffer_append(b, add_code, 3);
                } else {
                    uint8_t sub_code[] = {0x83, 0xE8 | get_reg_index(base_reg), (uint8_t)(-enc.compensation)};
                    buffer_append(b, sub_code, 3);
                }
            }

            uint8_t mov_code[] = {0x89, enc.modrm_byte, (uint8_t)enc.disp8};
            buffer_append(b, mov_code, 3);

            if (enc.needs_compensation) {
                if (enc.compensation > 0) {
                    uint8_t sub_code[] = {0x83, 0xE8 | get_reg_index(base_reg), (uint8_t)enc.compensation};
                    buffer_append(b, sub_code, 3);
                } else {
                    uint8_t add_code[] = {0x83, 0xC0 | get_reg_index(base_reg), (uint8_t)(-enc.compensation)};
                    buffer_append(b, add_code, 3);
                }
            }
            return 0;
        }

        case SIB_ENCODING_PUSHPOP: {
            // PUSH src_reg
            uint8_t push_code[] = {0x50 | get_reg_index(src_reg)};
            buffer_append(b, push_code, 1);

            // POP [base_reg]
            uint8_t pop_modrm = 0x00 | get_reg_index(base_reg);
            uint8_t pop_code[] = {0x8F, pop_modrm};
            buffer_append(b, pop_code, 2);
            return 0;
        }

        default:
            return -1;
    }
}

/**
 * @brief Generate LEA dst_reg, [base_reg] using profile-safe encoding
 */
int generate_safe_lea_reg_mem(struct buffer *b, x86_reg dst_reg, x86_reg base_reg) {
    sib_encoding_result_t enc = select_sib_encoding_for_reg(base_reg, dst_reg);

    switch (enc.strategy) {
        case SIB_ENCODING_STANDARD: {
            uint8_t code[3];
            code[0] = 0x8D;  // LEA r32, m
            code[1] = enc.modrm_byte;

            if ((enc.modrm_byte & 0x07) == 0x04) {
                code[2] = enc.sib_byte;
                buffer_append(b, code, 3);
            } else {
                buffer_append(b, code, 2);
            }
            return 0;
        }

        case SIB_ENCODING_DISP8: {
            // LEA dst, [base + disp8], then subtract disp8 from result
            uint8_t lea_code[] = {0x8D, enc.modrm_byte, (uint8_t)enc.disp8};
            buffer_append(b, lea_code, 3);

            // Compensate: SUB dst, disp8 or ADD dst, -disp8
            if (enc.disp8 > 0) {
                uint8_t sub_code[] = {0x83, 0xE8 | get_reg_index(dst_reg), (uint8_t)enc.disp8};
                buffer_append(b, sub_code, 3);
            } else {
                uint8_t add_code[] = {0x83, 0xC0 | get_reg_index(dst_reg), (uint8_t)(-enc.disp8)};
                buffer_append(b, add_code, 3);
            }
            return 0;
        }

        case SIB_ENCODING_PUSHPOP: {
            // LEA is just MOV for [reg] case
            // MOV dst, base
            uint8_t mov_code[] = {0x89, 0xC0 | (get_reg_index(base_reg) << 3) | get_reg_index(dst_reg)};
            buffer_append(b, mov_code, 2);
            return 0;
        }

        default:
            return -1;
    }
}
```

### Step 1.2: Update Makefile to Include New Files

**File**: `Makefile`

Add to SOURCES:
```makefile
SOURCES += src/profile_aware_sib.c
```

## Phase 2: Fix Top 3 Failing Strategies (Week 1, Days 3-5)

### Step 2.1: Fix `mov_mem_disp_enhanced` Strategy

**File**: `src/remaining_null_elimination_strategies.c`

**Current Problem (lines 173-193)**:
```c
void generate_mov_mem_disp_enhanced(struct buffer *b, cs_insn *insn) {
    // ...
    // MOV dst_reg, [EAX] using SIB addressing
    uint8_t mov_inst[] = {0x8B, 0x04, 0x20};  // ← HARDCODED 0x20!
    mov_inst[1] = 0x04 | (get_reg_index(dst_reg) << 3);
    buffer_append(b, mov_inst, 3);
    // ...
}
```

**Fixed Version**:
```c
#include "profile_aware_sib.h"  // Add to top of file

void generate_mov_mem_disp_enhanced(struct buffer *b, cs_insn *insn) {
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    uint32_t disp = (uint32_t)insn->detail->x86.operands[1].mem.disp;

    // PUSH EAX to save
    uint8_t push_eax[] = {0x50};
    buffer_append(b, push_eax, 1);

    // MOV EAX, disp (null-safe construction)
    generate_mov_eax_imm(b, disp);

    // MOV dst_reg, [EAX] using PROFILE-SAFE encoding
    // FIXED: Use profile-aware SIB generation instead of hardcoded 0x20
    if (generate_safe_mov_reg_mem(b, dst_reg, X86_REG_EAX) != 0) {
        fprintf(stderr, "[ERROR] Failed to generate safe MOV for mov_mem_disp_enhanced\n");
        // Fallback: use PUSH/POP approach
        uint8_t push_mem[] = {0xFF, 0x30};  // PUSH [EAX]
        buffer_append(b, push_mem, 2);
        uint8_t pop_dst[] = {0x58 | get_reg_index(dst_reg)};  // POP dst_reg
        buffer_append(b, pop_dst, 1);
    }

    // POP EAX to restore
    uint8_t pop_eax[] = {0x58};
    buffer_append(b, pop_eax, 1);
}
```

**Update size estimation**:
```c
size_t get_size_mov_mem_disp_enhanced(__attribute__((unused)) cs_insn *insn) {
    // PUSH EAX (1) + MOV EAX, imm32 (7 max) + safe MOV with compensation (9 max) + POP EAX (1)
    return 18; // Increased from 15 to account for compensation
}
```

### Step 2.2: Fix `indirect_call_mem` Strategy

**File**: `src/indirect_call_strategies.c`

**Current Problem (lines 65-83)**:
```c
void generate_indirect_call_mem(struct buffer *b, cs_insn *insn) {
    // ...
    // Step 2: Dereference - Load the value at [EAX] into EAX
    uint8_t mov_eax_deref[] = {0x8B, 0x04, 0x20};  // ← HARDCODED 0x20!
    buffer_append(b, mov_eax_deref, 3);
    // ...
}
```

**Fixed Version**:
```c
#include "profile_aware_sib.h"  // Add to top of file

void generate_indirect_call_mem(struct buffer *b, cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;

    // Step 1: Load the address into EAX (null-free construction)
    generate_mov_eax_imm(b, addr);

    // Step 2: Dereference - Load the value at [EAX] into EAX
    // FIXED: Use profile-aware SIB generation
    if (generate_safe_mov_reg_mem(b, X86_REG_EAX, X86_REG_EAX) != 0) {
        fprintf(stderr, "[ERROR] Failed to generate safe MOV [EAX], EAX for indirect_call_mem\n");
        // Fallback: PUSH [EAX] / POP EAX
        uint8_t push_mem[] = {0xFF, 0x30};  // PUSH [EAX]
        buffer_append(b, push_mem, 2);
        uint8_t pop_eax[] = {0x58};  // POP EAX
        buffer_append(b, pop_eax, 1);
    }

    // Step 3: Call the function pointer now in EAX
    uint8_t call_eax[] = {0xFF, 0xD0};
    buffer_append(b, call_eax, 2);
}
```

**Update size estimation**:
```c
size_t get_size_indirect_call_mem(cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;
    // MOV EAX, addr (var) + safe MOV [EAX] (9 max) + CALL EAX (2)
    return get_mov_eax_imm_size(addr) + 9 + 2;
}
```

### Step 2.3: Fix `indirect_jmp_mem` Strategy

**File**: `src/indirect_call_strategies.c`

**Current Problem (lines 152-170)**:
```c
void generate_indirect_jmp_mem(struct buffer *b, cs_insn *insn) {
    // ...
    uint8_t mov_eax_deref[] = {0x8B, 0x04, 0x20};  // ← HARDCODED 0x20!
    buffer_append(b, mov_eax_deref, 3);
    // ...
}
```

**Fixed Version**:
```c
void generate_indirect_jmp_mem(struct buffer *b, cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;

    // Step 1: Load the address into EAX (null-free construction)
    generate_mov_eax_imm(b, addr);

    // Step 2: Dereference - Load the value at [EAX] into EAX
    // FIXED: Use profile-aware SIB generation
    if (generate_safe_mov_reg_mem(b, X86_REG_EAX, X86_REG_EAX) != 0) {
        fprintf(stderr, "[ERROR] Failed to generate safe MOV [EAX], EAX for indirect_jmp_mem\n");
        // Fallback
        uint8_t push_mem[] = {0xFF, 0x30};  // PUSH [EAX]
        buffer_append(b, push_mem, 2);
        uint8_t pop_eax[] = {0x58};  // POP EAX
        buffer_append(b, pop_eax, 1);
    }

    // Step 3: Jump to the address now in EAX
    uint8_t jmp_eax[] = {0xFF, 0xE0};
    buffer_append(b, jmp_eax, 2);
}
```

**Update size estimation**:
```c
size_t get_size_indirect_jmp_mem(cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;
    // MOV EAX, addr (var) + safe MOV [EAX] (9 max) + JMP EAX (2)
    return get_mov_eax_imm_size(addr) + 9 + 2;
}
```

## Phase 3: Mass Update Remaining Files (Week 2)

### Step 3.1: Create Search and Replace Script

**File**: `scripts/fix_hardcoded_sib.sh` (NEW)

```bash
#!/bin/bash
# Script to identify and report all hardcoded SIB 0x20 usage

echo "=== Scanning for hardcoded SIB byte 0x20 ==="
echo ""

# Find all instances
grep -rn "0x20}" src/*.c | grep -E "(0x04, 0x20|0x20})" > /tmp/sib_instances.txt

echo "Found $(wc -l < /tmp/sib_instances.txt) instances of potential hardcoded SIB 0x20"
echo ""
echo "Files affected:"
cut -d: -f1 /tmp/sib_instances.txt | sort -u

echo ""
echo "=== Detailed instances ==="
cat /tmp/sib_instances.txt

echo ""
echo "=== Recommendations ==="
echo "Each instance should be reviewed and replaced with:"
echo "  generate_safe_mov_reg_mem() for MOV operations"
echo "  generate_safe_mov_mem_reg() for MOV to memory"
echo "  generate_safe_lea_reg_mem() for LEA operations"
```

### Step 3.2: Systematic File Updates

For each file identified:

1. **Add include**: `#include "profile_aware_sib.h"`
2. **Replace patterns**:
   - `{0x8B, 0x04, 0x20}` (MOV reg, [base]) → `generate_safe_mov_reg_mem()`
   - `{0x89, 0x04, 0x20}` (MOV [base], reg) → `generate_safe_mov_mem_reg()`
   - `{0x8D, 0x04, 0x20}` (LEA reg, [base]) → `generate_safe_lea_reg_mem()`
3. **Update size estimates** to account for compensation bytes
4. **Test each file** individually

**Priority order** (based on usage frequency):
1. ✅ `src/remaining_null_elimination_strategies.c` (Week 1)
2. ✅ `src/indirect_call_strategies.c` (Week 1)
3. `src/lea_strategies.c` (Week 2, Day 1)
4. `src/advanced_transformations.c` (Week 2, Day 1)
5. `src/core.c` (Week 2, Day 2) ⚠️ CRITICAL - core file
6. `src/sib_strategies.c` (Week 2, Day 2)
7. `src/enhanced_mov_mem_strategies.c` (Week 2, Day 3)
8. ... remaining 20+ files (Week 2, Days 3-5)

## Phase 4: Verification and Validation (Week 3)

### Step 4.1: Create Verification Tool

**File**: `tools/verify_no_hardcoded_sib.py` (NEW)

```python
#!/usr/bin/env python3
"""
Verify that no strategy files contain hardcoded SIB byte 0x20
without proper profile checks
"""

import re
import sys
from pathlib import Path

def check_file(filepath):
    """Check a single file for hardcoded SIB issues"""
    issues = []

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        lines = content.split('\n')

    # Pattern 1: Direct array initialization with 0x20
    # {0x8B, 0x04, 0x20} or similar
    pattern1 = re.compile(r'\{[^}]*0x04,\s*0x20[^}]*\}')

    # Pattern 2: Assignment to array index
    # code[2] = 0x20;
    pattern2 = re.compile(r'\[\s*2\s*\]\s*=\s*0x20\s*;')

    for i, line in enumerate(lines, 1):
        # Check for hardcoded SIB patterns
        if pattern1.search(line):
            # Check if there's a safety check nearby
            context_start = max(0, i-5)
            context_end = min(len(lines), i+5)
            context = '\n'.join(lines[context_start:context_end])

            if 'profile_aware_sib' not in context and 'generate_safe_' not in context:
                issues.append({
                    'line': i,
                    'content': line.strip(),
                    'type': 'Hardcoded SIB array initialization'
                })

        if pattern2.search(line):
            issues.append({
                'line': i,
                'content': line.strip(),
                'type': 'Hardcoded SIB assignment'
            })

    return issues

def main():
    src_dir = Path('src')
    all_issues = {}

    for c_file in src_dir.glob('*.c'):
        issues = check_file(c_file)
        if issues:
            all_issues[str(c_file)] = issues

    if not all_issues:
        print("✓ No hardcoded SIB byte 0x20 issues found!")
        return 0

    print("✗ Found hardcoded SIB byte 0x20 in the following files:\n")

    for filepath, issues in all_issues.items():
        print(f"{filepath}:")
        for issue in issues:
            print(f"  Line {issue['line']}: {issue['type']}")
            print(f"    {issue['content']}")
        print()

    print(f"Total files with issues: {len(all_issues)}")
    print(f"Total issues: {sum(len(issues) for issues in all_issues.values())}")

    return 1

if __name__ == '__main__':
    sys.exit(main())
```

### Step 4.2: Integration Tests

**File**: `tests/test_http_whitespace_profile.sh` (NEW)

```bash
#!/bin/bash
# Test http-whitespace profile specifically

set -e

echo "=== HTTP-Whitespace Profile Test Suite ==="

# Test 1: Verify profile-aware SIB utility
echo "Test 1: Profile-aware SIB utility..."
./bin/byvalver --test-sib-generation --profile http-whitespace

# Test 2: Process simple shellcode samples
echo "Test 2: Simple shellcode samples..."
for sample in tests/samples/simple_*.bin; do
    if [ -f "$sample" ]; then
        echo "  Processing $sample..."
        ./bin/byvalver --profile http-whitespace "$sample" /tmp/test_output.bin

        # Verify output has no bad bytes
        if hexdump -C /tmp/test_output.bin | grep -E " 00 | 09 | 0a | 0d | 20 "; then
            echo "  ✗ FAIL: Output contains bad bytes!"
            exit 1
        fi
        echo "  ✓ PASS"
    fi
done

# Test 3: Batch process test corpus
echo "Test 3: Batch processing..."
./bin/byvalver --profile http-whitespace tests/corpus/ /tmp/batch_output/ --stats

# Test 4: Verify no hardcoded SIB bytes
echo "Test 4: Static analysis..."
python3 tools/verify_no_hardcoded_sib.py

echo ""
echo "=== All tests passed! ==="
```

## Phase 5: Performance Optimization (Week 4)

### Step 5.1: Caching SIB Encoding Decisions

```c
// Add to profile_aware_sib.c
static sib_encoding_result_t cached_eax_encoding = {0};
static bool cache_valid = false;

sib_encoding_result_t select_sib_encoding_for_eax(x86_reg dst_reg) {
    // Use cache if valid for this destination register
    if (cache_valid && cached_eax_encoding.modrm_byte == (0x04 | (get_reg_index(dst_reg) << 3))) {
        return cached_eax_encoding;
    }

    // ... existing code ...

    // Cache result
    cached_eax_encoding = result;
    cache_valid = true;

    return result;
}

void invalidate_sib_cache(void) {
    cache_valid = false;
}
```

### Step 5.2: Add Metrics Tracking

```c
// Track which encoding strategies are used most
typedef struct {
    uint32_t standard_count;
    uint32_t disp8_count;
    uint32_t pushpop_count;
} sib_encoding_stats_t;

extern sib_encoding_stats_t g_sib_stats;

void print_sib_encoding_stats(void) {
    printf("SIB Encoding Statistics:\n");
    printf("  Standard (SIB 0x20):     %u\n", g_sib_stats.standard_count);
    printf("  Displacement-based:      %u\n", g_sib_stats.disp8_count);
    printf("  Push/Pop fallback:       %u\n", g_sib_stats.pushpop_count);
}
```

## Testing Strategy

### Unit Tests
1. Test `select_sib_encoding_for_eax()` with different profiles
2. Test `generate_safe_mov_reg_mem()` output validation
3. Test compensation logic correctness

### Integration Tests
1. Process test corpus with http-whitespace profile
2. Compare before/after success rates
3. Verify semantic equivalence of transformations

### Regression Tests
1. Ensure null-only profile still works
2. Verify no performance degradation
3. Check memory safety (no buffer overflows)

## Success Criteria

✅ **Phase 1 Complete**: Core utility functions implemented and tested
✅ **Phase 2 Complete**: Top 3 failing strategies fixed, success rate >50%
✅ **Phase 3 Complete**: All hardcoded SIB bytes replaced, success rate >85%
✅ **Phase 4 Complete**: No regressions, automated tests passing
✅ **Phase 5 Complete**: Performance optimized, metrics tracked

## Rollback Plan

If issues arise:
1. Each phase is in separate commits for easy revert
2. Feature flag `ENABLE_PROFILE_AWARE_SIB` to disable new code
3. Preserve original functions as `*_legacy()` variants during transition

## Documentation Updates

1. Update `README.md` with new profile-aware features
2. Document `profile_aware_sib.h` API
3. Add examples to `docs/STRATEGY_DEVELOPMENT.md`
4. Update `CHANGELOG.md` with breaking changes
