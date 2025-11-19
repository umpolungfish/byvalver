# BYVALVER PHASE 1 STRATEGIES: IMPLEMENTATION GUIDE

This document provides detailed implementation guidance for the 5 priority strategies that will achieve 100% success rate on the current test suite.

---

## PRIORITY 1: CONDITIONAL JUMP NULL-OFFSET ELIMINATION

**File**: `/home/mrnob0dy666/byvalver_PUBLIC/src/conditional_jump_offset_strategies.c`
**Priority**: 150
**Impact**: Fixes 8 null bytes in 2 files

### Problem Statement

After instruction size changes, conditional jump offsets are recalculated and patched. If the new rel32 offset contains null bytes, there's no fallback transformation.

**Example**:
```
Original:     JNE 0x50b
After patch:  JNE 0x50b  (rel32 = 0x02AC)
Encoding:     0f 85 ac 02 00 00
                          ^^ ^^ null bytes!
```

### Transformation Approach

Transform to opposite conditional jump + unconditional jump:

```assembly
Original:
  JNE target    ; 0f 85 ac 02 00 00 (6 bytes, has nulls)

Transformed:
  JE skip       ; 74 05 (2 bytes, short jump)
  JMP target    ; e9 xx xx xx xx (5 bytes, null-free)
skip:
```

### Implementation

```c
// src/conditional_jump_offset_strategies.c

#include "strategy.h"
#include "utils.h"
#include <stdio.h>

// Map conditional jump opcodes to their opposites
static uint8_t get_opposite_short_jcc_opcode(x86_insn jcc_id) {
    switch(jcc_id) {
        case X86_INS_JO:  return 0x71; // JO → JNO
        case X86_INS_JNO: return 0x70; // JNO → JO
        case X86_INS_JB:  return 0x73; // JB → JAE
        case X86_INS_JAE: return 0x72; // JAE → JB
        case X86_INS_JE:  return 0x75; // JE → JNE
        case X86_INS_JNE: return 0x74; // JNE → JE
        case X86_INS_JBE: return 0x77; // JBE → JA
        case X86_INS_JA:  return 0x76; // JA → JBE
        case X86_INS_JS:  return 0x79; // JS → JNS
        case X86_INS_JNS: return 0x78; // JNS → JS
        case X86_INS_JP:  return 0x7B; // JP → JNP
        case X86_INS_JNP: return 0x7A; // JNP → JP
        case X86_INS_JL:  return 0x7D; // JL → JGE
        case X86_INS_JGE: return 0x7C; // JGE → JL
        case X86_INS_JLE: return 0x7F; // JLE → JG
        case X86_INS_JG:  return 0x7E; // JG → JLE
        default: return 0x74; // Default to JNE
    }
}

// Check if conditional jump offset contains nulls
static int offset_has_null_bytes(int32_t offset) {
    uint32_t val = (uint32_t)offset;
    return ((val & 0xFF) == 0) ||
           ((val & 0xFF00) == 0) ||
           ((val & 0xFF0000) == 0) ||
           ((val & 0xFF000000) == 0);
}

int can_handle_conditional_jump_null_offset(cs_insn *insn) {
    // Check if conditional jump
    if (insn->id < X86_INS_JAE || insn->id > X86_INS_JS) {
        return 0;
    }

    // Check if operand is immediate (rel32)
    if (insn->detail->x86.op_count != 1 ||
        insn->detail->x86.operands[0].type != X86_OP_IMM) {
        return 0;
    }

    // Check if this is a long form (0F 8x) that could have null offset
    // Note: This will be checked AFTER offset patching in core.c
    if (has_null_bytes(insn)) {
        return 1;
    }

    return 0;
}

size_t get_size_conditional_jump_null_offset(cs_insn *insn) {
    // Opposite short jump (2 bytes) + unconditional JMP (5 bytes minimum)
    // If target is far and JMP also needs transformation, could be larger

    int64_t target = insn->detail->x86.operands[0].imm;

    // Calculate if unconditional JMP will need null-free transformation
    // For now, estimate conservatively
    size_t jmp_size = 5; // Standard JMP rel32

    // If JMP target would also have nulls, need MOV+JMP sequence
    // This is a conservative estimate
    int32_t rel32 = (int32_t)(target - (insn->address + 7)); // 2 + 5 bytes
    if (offset_has_null_bytes(rel32)) {
        jmp_size = 20; // Worst case: null-free JMP construction
    }

    return 2 + jmp_size; // Short JCC + JMP
}

void generate_conditional_jump_null_offset(struct buffer *b, cs_insn *insn) {
    // Get target address
    int64_t target = insn->detail->x86.operands[0].imm;

    // Calculate JMP rel32 offset
    // Current buffer position + 2 (opposite JCC) + 5 (JMP) = position after our code
    size_t current_offset = b->size;
    size_t jmp_start = current_offset + 2;
    int32_t jmp_offset = (int32_t)(target - (jmp_start + 5));

    // Generate opposite condition short jump
    uint8_t opposite_opcode = get_opposite_short_jcc_opcode(insn->id);

    // Calculate skip distance (skip over the JMP instruction)
    uint8_t skip_distance;

    if (offset_has_null_bytes(jmp_offset)) {
        // JMP will need null-free construction, size varies
        // Use null-free JMP generation
        skip_distance = 0x05 + estimate_null_free_jmp_size(jmp_offset);
    } else {
        // Standard JMP rel32
        skip_distance = 0x05;
    }

    // Write opposite short jump
    buffer_write_byte(b, opposite_opcode);
    buffer_write_byte(b, skip_distance);

    // Generate unconditional JMP
    if (offset_has_null_bytes(jmp_offset)) {
        // Use null-free JMP construction (MOV reg, target; JMP reg)
        generate_jmp_null_free(b, target);
    } else {
        // Standard JMP rel32
        buffer_write_byte(b, 0xE9);
        buffer_write_dword(b, jmp_offset);
    }
}

// Helper: Generate null-free JMP to target
static void generate_jmp_null_free(struct buffer *b, uint64_t target) {
    // Use EAX as temp register for JMP
    // MOV EAX, target (null-free construction)
    generate_mov_eax_imm(b, (uint32_t)target);

    // JMP EAX
    uint8_t jmp_eax[] = {0xFF, 0xE0};
    buffer_append(b, jmp_eax, 2);
}

strategy_t conditional_jump_null_offset_strategy = {
    .name = "conditional_jump_null_offset",
    .can_handle = can_handle_conditional_jump_null_offset,
    .get_size = get_size_conditional_jump_null_offset,
    .generate = generate_conditional_jump_null_offset,
    .priority = 150 // Very high - must run after offset patching
};

void register_conditional_jump_offset_strategies() {
    register_strategy(&conditional_jump_null_offset_strategy);
}
```

### Integration into Makefile

Add to `/home/mrnob0dy666/byvalver_PUBLIC/Makefile`:

```makefile
MAIN_SRCS = ... existing sources ... \
            src/conditional_jump_offset_strategies.c
```

### Integration into Strategy Registry

Edit `/home/mrnob0dy666/byvalver_PUBLIC/src/strategy_registry.c`:

```c
// Forward declaration
void register_conditional_jump_offset_strategies();

// In init_strategies()
void init_strategies() {
    // ... existing registrations ...
    register_conditional_jump_offset_strategies();
}
```

### Test Case

Create `/home/mrnob0dy666/byvalver_PUBLIC/.tests/test_conditional_jump_null_offset.py`:

```python
#!/usr/bin/env python3

# Generate shellcode with conditional jump that will have null offset after processing

shellcode = b""
shellcode += b"\x31\xc0"        # XOR EAX, EAX
shellcode += b"\x85\xc0"        # TEST EAX, EAX
shellcode += b"\x0f\x85\xac\x02\x00\x00"  # JNE +0x2ac (contains nulls)
shellcode += b"\xcc" * 0x2ac    # Padding to reach target
shellcode += b"\xcc"            # INT3 (target)

with open('.test_bins/conditional_jump_null_offset.bin', 'wb') as f:
    f.write(shellcode)

print("Generated test case: conditional_jump_null_offset.bin")
print(f"Size: {len(shellcode)} bytes")
print(f"Null bytes: {shellcode.count(b'\\x00')}")
```

---

## PRIORITY 2: ADD/SUB IMMEDIATE ENCODING OPTIMIZATION

**File**: `/home/mrnob0dy666/byvalver_PUBLIC/src/arithmetic_encoding_opt_strategies.c`
**Priority**: 60
**Impact**: Fixes 9+ null bytes in cheapsuit.bin

### Problem Statement

ADD/SUB with small immediate values encoded as imm32 when imm8 would suffice, introducing null bytes.

**Example**:
```
Original:  ADD EAX, 0x88
Encoding:  81 c0 88 00 00 00  (6 bytes, imm32 form)
                    ^^ ^^ ^^ null bytes!

Should be: 83 c0 88            (3 bytes, sign-extended imm8)
```

### Transformation Approach

Detect imm32 encoding where imm8 would work, re-encode as imm8.

### Implementation

```c
// src/arithmetic_encoding_opt_strategies.c

#include "strategy.h"
#include "utils.h"
#include <stdio.h>

// Check if value fits in signed 8-bit (-128 to 127)
static int fits_in_imm8(int64_t imm) {
    return (imm >= -128 && imm <= 127);
}

// Check if instruction uses imm32 encoding (opcode 81)
static int uses_imm32_encoding(cs_insn *insn) {
    return (insn->size >= 5 && insn->bytes[0] == 0x81);
}

int can_handle_add_sub_imm32_to_imm8(cs_insn *insn) {
    // Only handle ADD and SUB
    if (insn->id != X86_INS_ADD && insn->id != X86_INS_SUB) {
        return 0;
    }

    // Must have 2 operands: reg, imm
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    // First operand must be register
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }

    // Second operand must be immediate
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    int64_t imm = insn->detail->x86.operands[1].imm;

    // Check if immediate fits in imm8 AND instruction uses imm32 encoding
    if (fits_in_imm8(imm) && uses_imm32_encoding(insn)) {
        // Check if imm32 encoding introduces null bytes
        uint32_t imm32 = (uint32_t)imm;
        if (((imm32 & 0xFF) == 0) ||
            ((imm32 & 0xFF00) == 0) ||
            ((imm32 & 0xFF0000) == 0) ||
            ((imm32 & 0xFF000000) == 0)) {
            return 1;
        }
    }

    return 0;
}

size_t get_size_add_sub_imm32_to_imm8(cs_insn *insn) {
    // imm8 form: opcode (83) + ModR/M + imm8 = 3 bytes
    (void)insn; // Unused
    return 3;
}

void generate_add_sub_imm32_to_imm8(struct buffer *b, cs_insn *insn) {
    x86_reg dest_reg = insn->detail->x86.operands[0].reg;
    int64_t imm = insn->detail->x86.operands[1].imm;
    uint8_t imm8 = (uint8_t)(imm & 0xFF);

    // Opcode for imm8 form
    uint8_t opcode = 0x83;
    buffer_write_byte(b, opcode);

    // ModR/M byte: mod=11 (register), reg field depends on instruction
    uint8_t reg_field;
    if (insn->id == X86_INS_ADD) {
        reg_field = 0; // ADD uses /0
    } else if (insn->id == X86_INS_SUB) {
        reg_field = 5; // SUB uses /5
    } else {
        reg_field = 0; // Default
    }

    uint8_t modrm = 0xC0 | (reg_field << 3) | (dest_reg - X86_REG_EAX);
    buffer_write_byte(b, modrm);

    // Immediate (sign-extended 8-bit)
    buffer_write_byte(b, imm8);
}

strategy_t add_sub_imm32_to_imm8_strategy = {
    .name = "add_sub_imm32_to_imm8",
    .can_handle = can_handle_add_sub_imm32_to_imm8,
    .get_size = get_size_add_sub_imm32_to_imm8,
    .generate = generate_add_sub_imm32_to_imm8,
    .priority = 60 // After general arithmetic strategies
};

void register_arithmetic_encoding_opt_strategies() {
    register_strategy(&add_sub_imm32_to_imm8_strategy);
}
```

### Test Case

```python
#!/usr/bin/env python3

shellcode = b""
shellcode += b"\x31\xc0"                      # XOR EAX, EAX
shellcode += b"\x81\xc0\x88\x00\x00\x00"      # ADD EAX, 0x88 (imm32, has nulls)
shellcode += b"\x81\xc0\x90\x00\x00\x00"      # ADD EAX, 0x90 (imm32, has nulls)
shellcode += b"\xc3"                          # RET

with open('.test_bins/add_imm32_encoding.bin', 'wb') as f:
    f.write(shellcode)
```

---

## PRIORITY 3: CMP MEMORY DISPLACEMENT STRATEGY

**File**: `/home/mrnob0dy666/byvalver_PUBLIC/src/cmp_memory_disp_strategies.c`
**Priority**: 55
**Impact**: Fixes 3 null bytes in cutyourmeat-static.bin

### Problem Statement

CMP with memory operand using disp32 encoding where disp8 would suffice, or where displacement contains nulls.

**Example**:
```
Original:  CMP BYTE PTR [EBX+0x18], AL
Encoding:  38 83 18 00 00 00  (6 bytes, disp32)
                 ^^ ^^ ^^ null bytes!

Should be: 38 43 18            (3 bytes, disp8)
```

### Transformation Approach

Option 1: Re-encode with disp8 if possible
Option 2: Use LEA to construct address, then CMP [reg]

### Implementation

```c
// src/cmp_memory_disp_strategies.c

#include "strategy.h"
#include "utils.h"
#include <stdio.h>

// Check if displacement fits in signed 8-bit
static int fits_in_disp8(int64_t disp) {
    return (disp >= -128 && disp <= 127);
}

// Check if current encoding uses disp32 (ModR/M byte indicates it)
static int uses_disp32_encoding(cs_insn *insn) {
    // Check if ModR/M byte indicates disp32
    // This requires examining instruction bytes
    if (insn->size >= 6) {
        uint8_t modrm = insn->bytes[1];
        uint8_t mod = (modrm >> 6) & 0x03;
        uint8_t rm = modrm & 0x07;

        // mod=10 with rm!=100 indicates [reg+disp32]
        if (mod == 0x02 && rm != 0x04) {
            return 1;
        }
    }
    return 0;
}

int can_handle_cmp_mem_disp_null(cs_insn *insn) {
    if (insn->id != X86_INS_CMP) {
        return 0;
    }

    // Check for memory operand
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        if (insn->detail->x86.operands[i].type == X86_OP_MEM) {
            int64_t disp = insn->detail->x86.operands[i].mem.disp;

            // Check if disp32 encoding is used when disp8 would work
            if (fits_in_disp8(disp) && uses_disp32_encoding(insn)) {
                // Check for null bytes in displacement encoding
                uint32_t disp32 = (uint32_t)disp;
                if (((disp32 & 0xFF) == 0) ||
                    ((disp32 & 0xFF00) == 0) ||
                    ((disp32 & 0xFF0000) == 0) ||
                    ((disp32 & 0xFF000000) == 0)) {
                    return 1;
                }
            }
        }
    }

    return 0;
}

size_t get_size_cmp_mem_disp_null(cs_insn *insn) {
    // disp8 form: opcode + ModR/M + disp8 = 3 bytes (for byte operands)
    // For larger operands, might be 3-4 bytes
    (void)insn;
    return 3;
}

void generate_cmp_mem_disp_null(struct buffer *b, cs_insn *insn) {
    // Extract operands
    x86_op_mem *mem_op = NULL;
    x86_reg cmp_reg = X86_REG_INVALID;
    uint8_t opcode = 0x39; // Default to dword CMP

    // Find memory operand and register operand
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        if (insn->detail->x86.operands[i].type == X86_OP_MEM) {
            mem_op = &insn->detail->x86.operands[i].mem;
        } else if (insn->detail->x86.operands[i].type == X86_OP_REG) {
            cmp_reg = insn->detail->x86.operands[i].reg;
        }
    }

    if (!mem_op || cmp_reg == X86_REG_INVALID) {
        return; // Error
    }

    // Determine opcode based on operand size
    if (insn->detail->x86.operands[0].size == 1) {
        opcode = 0x38; // CMP byte ptr
    }

    x86_reg base_reg = mem_op->base;
    int8_t disp8 = (int8_t)(mem_op->disp & 0xFF);

    // Re-encode with disp8
    buffer_write_byte(b, opcode);

    // ModR/M byte: mod=01 (disp8), reg=cmp_reg_index, r/m=base_reg_index
    uint8_t reg_index = get_reg_index(cmp_reg);
    uint8_t base_index = get_reg_index(base_reg);

    uint8_t modrm = 0x40 | (reg_index << 3) | base_index;
    buffer_write_byte(b, modrm);

    // disp8
    buffer_write_byte(b, (uint8_t)disp8);
}

strategy_t cmp_mem_disp_null_strategy = {
    .name = "cmp_mem_disp_null",
    .can_handle = can_handle_cmp_mem_disp_null,
    .get_size = get_size_cmp_mem_disp_null,
    .generate = generate_cmp_mem_disp_null,
    .priority = 55
};

void register_cmp_memory_disp_strategies() {
    register_strategy(&cmp_mem_disp_null_strategy);
}
```

---

## PRIORITY 4 & 5: BT AND TEST STRATEGIES

**Files**:
- `/home/mrnob0dy666/byvalver_PUBLIC/src/bit_test_strategies.c`
- `/home/mrnob0dy666/byvalver_PUBLIC/src/test_memory_strategies.c`

### BT Strategy (Priority 4)

```c
int can_handle_bt_null_imm(cs_insn *insn) {
    if (insn->id != X86_INS_BT) return 0;

    if (insn->detail->x86.op_count == 2 &&
        insn->detail->x86.operands[1].type == X86_OP_IMM) {
        int64_t bit_index = insn->detail->x86.operands[1].imm;

        // Check if immediate is 0 or contains null bytes
        if (bit_index == 0 || has_null_bytes_in_imm(bit_index)) {
            return 1;
        }
    }
    return 0;
}

void generate_bt_null_imm(struct buffer *b, cs_insn *insn) {
    x86_reg target_reg = insn->detail->x86.operands[0].reg;
    int64_t bit_index = insn->detail->x86.operands[1].imm;

    if (bit_index == 0) {
        // PUSH target_reg
        buffer_write_byte(b, 0x50 + (target_reg - X86_REG_EAX));

        // SHR target_reg, 1 (shifts bit 0 into CF)
        buffer_write_byte(b, 0xD1);
        buffer_write_byte(b, 0xE8 + (target_reg - X86_REG_EAX));

        // POP target_reg
        buffer_write_byte(b, 0x58 + (target_reg - X86_REG_EAX));
    }
}
```

### TEST Strategy (Priority 5)

```c
void generate_test_mem_null_modrm(struct buffer *b, cs_insn *insn) {
    x86_reg base = insn->detail->x86.operands[0].mem.base;
    x86_reg test_reg = insn->detail->x86.operands[1].reg;
    uint8_t size = insn->detail->x86.operands[0].size;

    // TEST [base], test_reg using SIB encoding to avoid null ModR/M
    uint8_t opcode = (size == 1) ? 0x84 : 0x85;
    uint8_t modrm = 0x04 | (get_reg_index(test_reg) << 3);
    uint8_t sib = 0x20 | (base - X86_REG_EAX);

    buffer_write_byte(b, opcode);
    buffer_write_byte(b, modrm);
    buffer_write_byte(b, sib);
}
```

---

## COMPILATION AND TESTING

### Build Process

```bash
# Add new files to Makefile
make clean
make

# Verify compilation
./bin/byvalver --help
```

### Test Each Strategy

```bash
# Generate test cases
python3 .tests/test_conditional_jump_null_offset.py
python3 .tests/test_add_imm32_encoding.py
python3 .tests/test_cmp_mem_disp_null.py

# Process with byvalver
./bin/byvalver .test_bins/conditional_jump_null_offset.bin

# Verify nulls removed
python3 verify_nulls.py --detailed .test_bins/conditional_jump_null_offset_processed.bin

# Verify functionality preserved
python3 verify_functionality.py .test_bins/conditional_jump_null_offset.bin .test_bins/conditional_jump_null_offset_processed.bin
```

### Test on Failing Files

```bash
# Process all failing files
for file in EHS.bin ouroboros_core.bin cutyourmeat-static.bin cheapsuit.bin; do
    ./bin/byvalver .binzzz/$file .binzzz/processed/$file
    python3 verify_nulls.py --detailed .binzzz/processed/$file
done
```

---

## SUCCESS CRITERIA

Phase 1 complete when:

1. All 10 .binzzz files process with 0 null bytes
2. verify_functionality.py reports no semantic differences
3. Code expansion ratio remains reasonable (<5x average)
4. No regressions in previously clean files

---

For full analysis, see `/home/mrnob0dy666/byvalver_PUBLIC/comprehensive_assessment.md`
