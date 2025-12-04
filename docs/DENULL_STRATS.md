# BYVALVER Denullification Strategies (DENULL_STRATS.md)

## Overview

BYVALVER implements a comprehensive suite of denullification strategies to eliminate null bytes from shellcode while preserving functional equivalence. These strategies form the core of the second pass in the biphasic processing architecture, following obfuscation in Pass 1 if enabled.

## Strategy Registry System

The denullification strategies are organized using a strategy pattern with the following interface:

```c
typedef struct {
    const char* name;                           // Strategy name for identification
    int (*can_handle)(cs_insn *insn);          // Function to check if strategy can handle instruction
    size_t (*get_size)(cs_insn *insn);         // Function to calculate new size
    void (*generate)(struct buffer *b, cs_insn *insn);  // Function to generate new code
    int priority;                              // Priority for strategy selection (higher = more preferred)
} strategy_t;
```

Strategies are registered in priority order, with higher priority strategies taking precedence when multiple strategies can handle the same instruction.

## Denullification Strategy Catalog

### MOV Instruction Strategies

#### 1. MOV Original Strategy
- **Name:** `mov_original`
- **Priority:** 10
- **Description:** Pass-through strategy that maintains original MOV instructions when they don't contain null bytes.
- **Condition:** Applies to MOV instructions that don't already contain null bytes.
- **Transformation:** No transformation; original instruction is preserved as-is.
- **Generated code:** Original MOV instruction bytes.

#### 2. MOV NEG Strategy
- **Name:** `mov_neg`
- **Priority:** 13
- **Description:** Eliminates null bytes by using negation operations to achieve the same result.
- **Condition:** Applies to MOV reg, imm instructions where the immediate contains null bytes but can be expressed as a negation.
- **Transformation:** MOV reg, value → NEG temp_reg; MOV reg, temp_reg (where value = -(-value)).
- **Generated code:** Sequence of NEG and MOV instructions to avoid null bytes.

#### 3. MOV NOT Strategy
- **Name:** `mov_not`
- **Priority:** 12
- **Description:** Eliminates null bytes by using bitwise NOT operations to achieve the same result.
- **Condition:** Applies to MOV reg, imm instructions where the immediate contains null bytes but can be expressed as a NOT operation.
- **Transformation:** MOV reg, value → NOT reg; NOT reg (where the double NOT cancels out).
- **Generated code:** NOT instruction sequence to avoid null bytes.

#### 4. MOV XOR Strategy
- **Name:** `mov_xor`
- **Priority:** 6
- **Description:** Uses XOR operations to reconstruct values without containing null bytes.
- **Condition:** Applies to MOV reg, imm instructions where the immediate contains null bytes.
- **Transformation:** MOV reg, value → XOR reg, key; XOR reg, key (where value XOR key XOR key = value).
- **Generated code:** XOR instruction sequences to achieve the target value without null bytes.

#### 5. MOV Shift Strategy
- **Name:** `mov_shift`
- **Priority:** 7
- **Description:** Uses bit shifting operations to reconstruct values without containing null bytes.
- **Condition:** Applies to MOV reg, imm instructions where the immediate contains null bytes but can be constructed via shifting.
- **Transformation:** MOV reg, value → sequence of shift operations to build the target value.
- **Generated code:** Shift instruction sequences to avoid null bytes.

#### 6. MOV ADD/SUB Strategy
- **Name:** `mov_addsub`
- **Priority:** 11
- **Description:** Decomposes values into addition/subtraction components to avoid null bytes.
- **Condition:** Applies to MOV reg, imm instructions where the immediate contains null bytes but can be expressed as a sum/difference.
- **Transformation:** MOV reg, value → MOV reg, val1; ADD/SUB reg, val2 (where val1 + val2 = value).
- **Generated code:** ADD/SUB instruction sequences to achieve the target value without null bytes.

### Arithmetic Instruction Strategies

#### 7. Arithmetic Original Strategy
- **Name:** `arithmetic_original`
- **Priority:** 10
- **Description:** Pass-through strategy for arithmetic instructions without null bytes.
- **Condition:** Applies to arithmetic operations (ADD, SUB, AND, OR, XOR, CMP) that don't contain null bytes.
- **Transformation:** No transformation; original instruction is preserved.
- **Generated code:** Original arithmetic instruction.

#### 8. Arithmetic NEG Strategy
- **Name:** `arithmetic_neg`
- **Priority:** 9
- **Description:** Uses negation to eliminate null bytes in immediate operands.
- **Condition:** Applies to arithmetic operations where the immediate contains null bytes but can be negated.
- **Transformation:** Operation reg, value → Operation reg, -(-value).
- **Generated code:** Arithmetic instruction with negated immediate value.

#### 9. Arithmetic XOR Strategy
- **Name:** `arithmetic_xor`
- **Priority:** 7
- **Description:** Uses XOR encoding to eliminate null bytes in immediate operands.
- **Condition:** Applies to arithmetic operations where the immediate contains null bytes.
- **Transformation:** Operation reg, value → sequence using XOR to achieve equivalent result.
- **Generated code:** XOR-based arithmetic operation sequence.

#### 10. Arithmetic ADD/SUB Strategy
- **Name:** `arithmetic_addsub`
- **Priority:** 7
- **Description:** Decomposes immediate values using addition/subtraction to avoid null bytes.
- **Condition:** Applies to arithmetic operations where the immediate contains null bytes.
- **Transformation:** Operation reg, value → multiple operations that sum to the target value.
- **Generated code:** ADD/SUB operation sequence to achieve equivalent result.

### Jump and Control Flow Strategies

#### 11. CALL Immediate Strategy
- **Name:** `call_imm`
- **Priority:** 8
- **Description:** Handles CALL instructions with null bytes in immediate addresses.
- **Condition:** Applies to CALL instructions where the immediate address contains null bytes.
- **Transformation:** CALL address → MOV EAX, address; CALL EAX.
- **Generated code:** MOV instruction to load address followed by register-based CALL.

#### 12. CALL Memory Displacement 32 Strategy
- **Name:** `call_mem_disp32`
- **Priority:** 8
- **Description:** Handles indirect CALL instructions with null bytes in memory displacement.
- **Condition:** Applies to CALL [disp32] instructions where displacement contains null bytes.
- **Transformation:** CALL [address] → MOV EAX, address; CALL EAX.
- **Generated code:** MOV to register followed by register-based CALL.

#### 13. JMP Memory Displacement 32 Strategy
- **Name:** `jmp_mem_disp32`
- **Priority:** 8
- **Description:** Handles indirect JMP instructions with null bytes in memory displacement.
- **Condition:** Applies to JMP [disp32] instructions where displacement contains null bytes.
- **Transformation:** JMP [address] → MOV EAX, address; JMP EAX.
- **Generated code:** MOV to register followed by register-based JMP.

#### 14. Generic Memory Null Displacement Strategy
- **Name:** `generic_mem_null_disp`
- **Priority:** 3
- **Description:** Catch-all strategy for memory operations with null displacement bytes.
- **Condition:** Applies to any instruction with memory operands that have displacement values containing null bytes.
- **Transformation:** Uses SIB (Scale-Index-Base) addressing to avoid null bytes in ModR/M encoding.
- **Generated code:** SIB-based addressing modes to access memory without null bytes.

#### 15. Conditional Jump Null Offset Elimination Strategy
- **Name:** `Conditional Jump Null Offset Elimination`
- **Priority:** 150
- **Description:** Critical strategy for eliminating null bytes in conditional jump offsets.
- **Condition:** Applies when conditional jumps have rel32 offsets containing null bytes after instruction size changes.
- **Transformation:** Jcc target → J!cc skip; JMP target; skip: (where J!cc is the opposite condition).
- **Generated code:** Opposite short conditional jump + unconditional long jump to preserve semantics.

### Advanced Transformation Strategies

#### 16. ModR/M Null-Bypass Strategy
- **Name:** `ModR/M Byte Null-Bypass Transformations`
- **Priority:** High (part of advanced transformations)
- **Description:** Handles instructions where the ModR/M byte contains null bytes due to register encoding.
- **Condition:** Applies to INC/DEC and similar instructions where ModR/M byte contains nulls.
- **Transformation:** INC reg → MOV temp_reg, reg; INC temp_reg; MOV reg, temp_reg.
- **Generated code:** Register preservation sequence to avoid ModR/M null bytes.

#### 17. Arithmetic Substitution Strategy
- **Name:** `Arithmetic Substitution`
- **Priority:** High (part of advanced transformations)
- **Description:** Uses register-preserving arithmetic operations to avoid null bytes.
- **Condition:** Applies to INC/DEC operations where direct encoding would contain nulls.
- **Transformation:** DEC reg → MOV temp_reg, reg; ADD temp_reg, -1; MOV reg, temp_reg.
- **Generated code:** MOV-ARITH-MOV sequence for register-preserving operations.

#### 18. Flag Preserving TEST Strategy
- **Name:** `Conditional Flag Preservation Techniques`
- **Priority:** High (part of advanced transformations)
- **Description:** Uses alternative flag-preserving operations that don't contain null bytes.
- **Condition:** Applies to TEST reg, reg operations that might contain null bytes.
- **Transformation:** TEST reg, reg → OR reg, reg (preserves ZF, SF, PF flags).
- **Generated code:** OR reg, reg instruction that preserves flags like TEST.

#### 19. SIB Addressing Strategy
- **Name:** `Displacement-Offset Null-Bypass with SIB`
- **Priority:** High (part of advanced transformations)
- **Description:** Uses SIB (Scale-Index-Base) addressing to avoid null bytes in memory operations.
- **Condition:** Applies to MOV operations with memory operands containing null displacement values.
- **Transformation:** MOV [disp32], reg → MOV EAX, disp32; MOV [EAX], reg (with SIB encoding).
- **Generated code:** MOV with SIB addressing to access memory without null bytes.

#### 20. XOR Null-Free Strategy
- **Name:** `Bitwise Operations with Null-Free Immediate Values`
- **Priority:** High (part of advanced transformations)
- **Description:** Handles XOR operations with immediate values containing null bytes.
- **Condition:** Applies to XOR reg, imm operations where immediate contains null bytes.
- **Transformation:** XOR reg, value → MOV EAX, value; XOR reg, EAX (using temporary register).
- **Generated code:** MOV to register followed by register-based XOR.

#### 21. PUSH Optimized Strategy
- **Name:** `Push/Pop Sequence Optimization`
- **Priority:** High (part of advanced transformations)
- **Description:** Optimized PUSH operations to avoid null bytes in immediate operands.
- **Condition:** Applies to PUSH operations with immediate values containing null bytes.
- **Transformation:** PUSH imm32 → MOV EAX, imm32 (null-free); PUSH EAX.
- **Generated code:** MOV-then-PUSH sequence with null-free immediate.

### Memory and Displacement Strategies

#### 22. Memory Displacement Null Strategy
- **Name:** (Part of memory displacement strategies)
- **Priority:** 82-85
- **Description:** Handles memory operands with displacement values containing null bytes.
- **Condition:** Applies to instructions with memory operands where displacement contains nulls.
- **Transformation:** Uses SIB addressing or register-based addressing to avoid nulls.
- **Generated code:** Alternative addressing modes without null bytes.

#### 23. Small Immediate Strategy
- **Name:** `small_immediate_strategy`
- **Priority:** 75
- **Description:** Optimizes small immediate values to avoid null bytes.
- **Condition:** Applies to operations with immediate values that can be optimized.
- **Transformation:** Uses sign-extended encoding when possible to avoid nulls.
- **Generated code:** Optimized immediate encoding.

#### 24. Large Immediate Strategy
- **Name:** `large_immediate_strategy`
- **Priority:** 85
- **Description:** Handles large immediate values that may contain null bytes.
- **Condition:** Applies to operations with 32-bit immediate values containing nulls.
- **Transformation:** Alternative encoding or register-based approaches.
- **Generated code:** Alternative immediate encodings.

### Specialized Strategies

#### 25. LEA Strategy
- **Name:** (Register LEA strategies)
- **Priority:** Varies
- **Description:** Handles LEA (Load Effective Address) instructions with null bytes.
- **Condition:** Applies to LEA operations with memory operands containing nulls.
- **Transformation:** Uses alternative addressing or register operations.
- **Generated code:** LEA with null-free addressing modes.

#### 26. CMP Memory Displacement Strategy
- **Name:** `cmp_memory_disp_null_strategy`
- **Priority:** 55
- **Description:** Handles CMP operations with memory operands containing null displacement values.
- **Condition:** Applies to CMP instructions with memory operands containing nulls.
- **Transformation:** Uses SIB addressing or register-based comparison.
- **Generated code:** Alternative CMP encoding without null bytes.

#### 27. SIB Strategy
- **Name:** `sib_strategies`
- **Priority:** 65
- **Description:** Uses SIB addressing to eliminate null bytes in ModR/M encoding.
- **Condition:** Applies to SIB addressing patterns that contain null bytes.
- **Transformation:** Alternative SIB encoding that avoids null bytes.
- **Generated code:** SIB-encoded instructions without null bytes.

#### 28. RIP-Relative Strategy
- **Name:** `rip_relative_strategy`
- **Priority:** 80
- **Description:** Handles RIP-relative addressing in x64 that may contain null bytes.
- **Condition:** Applies to RIP-relative addressing modes with null displacement.
- **Transformation:** Alternative addressing approaches for x64.
- **Generated code:** RIP-relative addressing without null bytes.

#### 29. Multi-byte NOP Strategy
- **Name:** `multibyte_nop_strategy`
- **Priority:** 90
- **Description:** Handles multi-byte NOP sequences that may contain null bytes.
- **Condition:** Applies to NOP instructions with null byte content.
- **Transformation:** Alternative NOP encoding that maintains padding.
- **Generated code:** Null-free NOP sequences.

#### 30. Relative Jump Strategy
- **Name:** `relative_jump_strategy`
- **Priority:** 85
- **Description:** Handles relative CALL/JMP displacement that may contain null bytes.
- **Condition:** Applies to relative jumps with displacement values containing nulls.
- **Transformation:** Alternative jump encoding or register-based jumps.
- **Generated code:** Relative jumps without null bytes.

#### 31. Immediate Split Strategy
- **Name:** `immediate_split_strategy`
- **Priority:** 77
- **Description:** Splits immediate values to avoid null bytes.
- **Condition:** Applies to operations with immediate values containing nulls.
- **Transformation:** Decomposes immediate into parts that don't contain nulls.
- **Generated code:** Multiple operations to reconstruct the value.

#### 32. Socket Address Strategy
- **Name:** `socket_address_strategies`
- **Priority:** 77-80
- **Description:** Handles socket address structures containing null bytes.
- **Condition:** Applies to socket operations with address values containing nulls.
- **Transformation:** Alternative methods to construct socket addresses.
- **Generated code:** Socket address construction without null bytes.

#### 33. Unicode String Strategy
- **Name:** `unicode_string_strategies`
- **Priority:** 74-78
- **Description:** Handles UTF-16 (Unicode) string operations containing null bytes.
- **Condition:** Applies to operations involving Unicode strings with nulls.
- **Transformation:** Alternative string construction methods.
- **Generated code:** Unicode string operations without null bytes.

#### 34. Register Chaining Strategy
- **Name:** `register_chaining_strategies`
- **Priority:** 60-65
- **Description:** Uses register chains to avoid null bytes in complex operations.
- **Condition:** Applies to operations where chaining registers avoids nulls.
- **Transformation:** Sequence of register operations to achieve the result.
- **Generated code:** Register chaining sequences without null bytes.

#### 35. Linux Socketcall Strategy
- **Name:** `linux_socketcall_strategies`
- **Priority:** 72-75
- **Description:** Handles Linux socketcall operations with null bytes.
- **Condition:** Applies to Linux-specific socketcall instructions with nulls.
- **Transformation:** Alternative socketcall patterns without nulls.
- **Generated code:** Linux socketcall operations without null bytes.

#### 36. Linux String Push Strategy
- **Name:** `linux_string_push_strategies`
- **Priority:** 68-70
- **Description:** Handles Linux string construction via PUSH operations with nulls.
- **Condition:** Applies to Linux string operations that would introduce nulls.
- **Transformation:** Alternative string construction methods.
- **Generated code:** String construction without null bytes.

#### 37. Syscall Number Strategy
- **Name:** `syscall_number_strategies`
- **Priority:** 77-78
- **Description:** Handles Linux syscall number encoding with null bytes.
- **Condition:** Applies to syscall operations with number values containing nulls.
- **Transformation:** Alternative syscall number encoding.
- **Generated code:** Syscall operations without null bytes.

### Arithmetic Decomposition Strategies

#### 38. Arithmetic Decomposition Strategy
- **Name:** `mov_arith_decomp_strategy`
- **Priority:** 70
- **Description:** Decomposes MOV operations into arithmetic sequences to avoid nulls.
- **Condition:** Applies to MOV operations where immediate contains nulls but arithmetic decomposition is possible.
- **Transformation:** MOV reg, value → sequence of arithmetic operations to build value.
- **Generated code:** Arithmetic sequence to achieve target value.

### Byte Construction Strategy

#### 39. Byte Construction Strategy
- **Name:** `byte_construct_strategy`
- **Priority:** Variable
- **Description:** Constructs values byte-by-byte to avoid null bytes.
- **Condition:** Applies to operations where byte-level construction avoids nulls.
- **Transformation:** Series of byte operations to build the value.
- **Generated code:** Byte-level construction sequence.

### Context and Preservation Strategies

#### 40. Context Preservation Strategy
- **Name:** (Context preservation strategies)
- **Priority:** Variable
- **Description:** Preserves processor context during transformations.
- **Condition:** Applies to transformations that must maintain context.
- **Transformation:** Uses PUSH/POP or other context preservation.
- **Generated code:** Context preservation sequences.

#### 41. Sequence Preservation Strategy
- **Name:** (Sequence preservation strategies)
- **Priority:** Variable
- **Description:** Preserves execution sequence during transformations.
- **Condition:** Applies to transformations that must maintain order.
- **Transformation:** Maintains execution flow while avoiding nulls.
- **Generated code:** Sequenced operations without null bytes.

### Advanced Transformation Strategies (Cont.)

#### 42. Byte Granularity Strategy
- **Name:** `Byte-Granularity Null Elimination`
- **Priority:** High (part of advanced transformations)
- **Description:** Handles byte-level operations that might introduce null bytes.
- **Condition:** Applies to low-byte register operations (AL, BL, CL, DL) that might have encoding issues.
- **Transformation:** Uses full register operations to avoid low-byte addressing nulls.
- **Generated code:** Full register operations instead of byte-specific ones.

#### 43. Conditional Jump Target Strategy
- **Name:** `Conditional Jump Target Preservation`
- **Priority:** High (part of advanced transformations)
- **Description:** Handles conditional jumps to addresses containing null bytes.
- **Condition:** Applies to conditional jumps (JE, JNE, JG, etc.) where the target address contains null bytes.
- **Transformation:** Complex sequence involving register-based indirect jumps while preserving condition flags.
- **Generated code:** Conditional jump sequence with indirect target access.

### Other Specialized Strategies

#### 44. RET Strategy
- **Name:** `ret_strategies`
- **Priority:** 78
- **Description:** Handles RET instructions with immediate operands containing null bytes.
- **Condition:** Applies to RET imm16 instructions where immediate contains nulls.
- **Transformation:** Alternative return methods that avoid null bytes.
- **Generated code:** Return sequences without null bytes.

#### 45. RETF Strategy
- **Name:** `retf_strategies`
- **Priority:** 85
- **Description:** Handles far return instructions with null bytes.
- **Condition:** Applies to RETF instructions containing null bytes.
- **Transformation:** Alternative far return patterns.
- **Generated code:** Far return without null bytes.

#### 46. CMP Strategy
- **Name:** `cmp_strategies`
- **Priority:** 85-88
- **Description:** Handles CMP instructions with null bytes.
- **Condition:** Applies to CMP operations containing null bytes.
- **Transformation:** Alternative comparison methods.
- **Generated code:** Comparison operations without null bytes.

#### 47. Shift Strategy
- **Name:** `shift_based_strategy`
- **Priority:** Variable
- **Description:** Uses bit shifting to avoid null bytes.
- **Condition:** Applies to operations where shifting can avoid nulls.
- **Transformation:** Shift-based arithmetic alternatives.
- **Generated code:** Shift operations without null bytes.

#### 48. XCHG Strategy
- **Name:** `xchg_strategies`
- **Priority:** 60
- **Description:** Handles XCHG operations with potential null bytes.
- **Condition:** Applies to XCHG instructions containing null bytes.
- **Transformation:** Alternative register exchange methods.
- **Generated code:** Register exchange without null bytes.

#### 49. BT Strategy
- **Name:** `bt_strategies`
- **Priority:** 80
- **Description:** Handles BT (Bit Test) operations with null bytes.
- **Condition:** Applies to BT instructions containing null bytes.
- **Transformation:** Alternative bit testing methods.
- **Generated code:** Bit testing without null bytes.

#### 50. Loop Strategy
- **Name:** `loop_strategies`
- **Priority:** 75-80
- **Description:** Handles loop instructions with null bytes.
- **Condition:** Applies to LOOP family instructions containing null bytes.
- **Transformation:** Alternative loop patterns.
- **Generated code:** Loop operations without null bytes.

#### 51. ADC Strategy
- **Name:** `adc_strategies`
- **Priority:** 69-70
- **Description:** Handles ADC (Add with Carry) operations with null bytes.
- **Condition:** Applies to ADC instructions containing null bytes.
- **Transformation:** Alternative add-with-carry methods.
- **Generated code:** ADC operations without null bytes.

#### 52. SBB Strategy
- **Name:** `sbb_strategies`
- **Priority:** 69-70
- **Description:** Handles SBB (Subtract with Borrow) operations with null bytes.
- **Condition:** Applies to SBB instructions containing null bytes.
- **Transformation:** Alternative subtract-with-borrow methods.
- **Generated code:** SBB operations without null bytes.

#### 53. SETcc Strategy
- **Name:** `setcc_strategies`
- **Priority:** 70-75
- **Description:** Handles SETcc (Set on Condition) operations with null bytes.
- **Condition:** Applies to SETcc family instructions containing null bytes.
- **Transformation:** Alternative conditional set methods.
- **Generated code:** Conditional set operations without null bytes.

#### 54. IMUL Strategy
- **Name:** `imul_strategies`
- **Priority:** 71-72
- **Description:** Handles IMUL (Signed Multiply) operations with null bytes.
- **Condition:** Applies to IMUL instructions containing null bytes.
- **Transformation:** Alternative signed multiplication methods.
- **Generated code:** Multiplication operations without null bytes.

#### 55. FPU Strategy
- **Name:** `fpu_strategies`
- **Priority:** 60
- **Description:** Handles x87 FPU (Floating Point Unit) operations with null bytes.
- **Condition:** Applies to FPU instructions containing null bytes.
- **Transformation:** Alternative FPU operations.
- **Generated code:** FPU operations without null bytes.

#### 56. SLDT Strategy
- **Name:** `sldt_strategies`
- **Priority:** 60
- **Description:** Handles SLDT (Store Local Descriptor Table) operations with null bytes.
- **Condition:** Applies to SLDT instructions containing null bytes.
- **Transformation:** Alternative descriptor table operations.
- **Generated code:** Descriptor table operations without null bytes.

#### 57. SLDT Replacement Strategy
- **Name:** `sldt_replacement_strategy`
- **Priority:** 95
- **Description:** High-priority strategy for SLDT replacement when null bytes are present.
- **Condition:** Applies to SLDT instructions containing null bytes.
- **Transformation:** Alternative register operations that achieve the same effect.
- **Generated code:** Equivalent operations without using SLDT.

#### 58. ARPL Strategy
- **Name:** `arpl_strategies`
- **Priority:** 75
- **Description:** Handles ARPL (Adjust RPL) operations with null bytes.
- **Condition:** Applies to ARPL instructions containing null bytes.
- **Transformation:** Alternative RPL adjustment methods.
- **Generated code:** RPL adjustment without null bytes.

#### 59. BOUND Strategy
- **Name:** `bound_strategies`
- **Priority:** 70
- **Description:** Handles BOUND operations with null bytes.
- **Condition:** Applies to BOUND instructions containing null bytes.
- **Transformation:** Alternative bounds checking methods.
- **Generated code:** Bounds checking without null bytes.

#### 60. ROR/ROL Strategy
- **Name:** `ror_rol_strategies`
- **Priority:** 70
- **Description:** Handles rotation operations with null bytes.
- **Condition:** Applies to ROR/ROL instructions containing null bytes.
- **Transformation:** Alternative rotation patterns.
- **Generated code:** Rotation operations without null bytes.

#### 61. SALC Strategy
- **Name:** `salc_zero_al_strategy`
- **Priority:** 91
- **Description:** Uses SALC (Set AL on Carry) to efficiently zero AL register.
- **Condition:** Applies when setting AL register with null-free instruction.
- **Transformation:** SALC instruction for AL zeroing.
- **Generated code:** SALC instruction for efficient AL zeroing.

#### 62. XCHG Preservation Strategy
- **Name:** `push_imm_preservation_strategy`
- **Priority:** 86
- **Description:** Optimizes PUSH immediate operations using XCHG preservation.
- **Condition:** Applies to PUSH operations that can use register preservation.
- **Transformation:** PUSH alternative using register exchanges.
- **Generated code:** PUSH operations optimized for null elimination.

#### 63. REP STOSB Strategy
- **Name:** `rep_stosb_count_setup_strategy`
- **Priority:** 92
- **Description:** Uses REP STOSB for efficient memory initialization without null bytes.
- **Condition:** Applies to memory initialization sequences with null bytes.
- **Transformation:** REP STOSB for null-free memory operations.
- **Generated code:** REP STOSB memory initialization.

#### 64. Stack String Strategy
- **Name:** `enhanced_stack_string_strategy`
- **Priority:** 85
- **Description:** Constructs strings on the stack without introducing null bytes.
- **Condition:** Applies to string construction operations that would contain nulls.
- **Transformation:** Stack-based string construction methods.
- **Generated code:** Stack string operations without null bytes.

#### 65. Syscall Strategy
- **Name:** `syscall_number_mov_strategy`
- **Priority:** 95
- **Description:** Handles Windows syscall direct invocation without null bytes.
- **Condition:** Applies to Windows syscall operations with null bytes.
- **Transformation:** Alternative syscall patterns.
- **Generated code:** Syscall operations without null bytes.

## Strategy Priority System

The strategy selection system uses a priority-based approach:

- **Highest Priority (150):** Critical transformations like conditional jump null offset elimination
- **High Priority (90-150):** Essential transformations like SLDT replacement, REP STOSB, SALC
- **Medium Priority (70-89):** Common transformations like memory operations, arithmetic
- **Low Priority (60-69):** Specialized transformations
- **Fallback Priority (<60):** General-purpose transformations used as last resort

## Implementation Notes

1. **Functional Equivalence:** All strategies must preserve the original functionality of the shellcode.

2. **Null-Free Guarantee:** Each strategy must ensure that its output contains no null bytes.

3. **Size Considerations:** Strategies may increase the size of instructions, which can affect relative jumps.

4. **Context Awareness:** Some strategies must consider the surrounding context to avoid breaking program flow.

5. **Register Availability:** Strategies must be mindful of register availability and context preservation.

## Performance Characteristics

- **Strategy Selection Time:** O(n) where n is the number of applicable strategies
- **Transformation Complexity:** Varies by strategy, typically O(1) to O(k) where k is constant
- **Output Size:** Most strategies increase code size, requiring offset recalculation
- **Memory Usage:** Proportional to input shellcode size

## Testing Considerations

Each strategy should be tested with:
- Various immediate values containing different null byte patterns
- Different register combinations
- Different addressing modes
- Edge cases like extreme values, zero values
- Functional equivalence verification
- Null byte elimination verification

## New Strategies in Version 2.1

### MOV Register Self-Reference Strategy

#### 66. MOV Register Memory Self Reference Strategy
- **Name:** `transform_mov_reg_mem_self`
- **Priority:** 100
- **Description:** Handles the common `mov reg32, [reg32]` pattern that produces null bytes in the ModR/M byte, such as `mov eax, [eax]` (opcode `8B 00`).
- **Condition:** Applies when the MOV instruction has a 32-bit register as destination and the same register as a memory operand with zero displacement (e.g., `[eax]`).
- **Transformation:** Uses a temporary register with displacement arithmetic to avoid the null-byte ModR/M encoding:
  ```
  push temp_reg      ; Save temporary register
  lea temp_reg, [src_reg - 1]  ; Load effective address with non-null displacement
  mov dest_reg, [temp_reg + 1] ; Dereference the correct address
  pop temp_reg       ; Restore temporary register
  ```
- **Generated code:** Null-byte-free sequence that preserves all registers (except flags) and achieves the same result as the original `mov reg, [reg]` instruction.

### ADD Memory Register8 Strategy

#### 67. ADD Memory Register8 Strategy
- **Name:** `transform_add_mem_reg8`
- **Priority:** 100
- **Description:** Handles the `add [mem], reg8` pattern that creates null bytes, such as `add [eax], al` (opcode `00 00`). This instruction encodes null bytes in both the opcode and ModR/M byte.
- **Condition:** Applies when an ADD instruction has a memory operand as the destination and an 8-bit register as the source, where the original encoding contains null bytes.
- **Transformation:** Replaces the null-byte instruction with a sequence using null-byte-free instructions:
  ```
  push temp_reg                 ; Save temporary register
  movzx temp_reg, byte ptr [mem] ; Load the byte from memory into temp register
  add temp_reg, src_reg8        ; Perform the addition
  mov byte ptr [mem], temp_reg  ; Store the result back into memory
  pop temp_reg                  ; Restore temporary register
  ```
- **Generated code:** Null-byte-free sequence that performs the same memory addition operation as the original instruction.

### Disassembly Validation Enhancement

- **Description:** Added robust validation to detect invalid shellcode input. If Capstone disassembler returns zero instructions, BYVALVER now provides a clear error message instead of proceeding with invalid data.

## Strategy Priority System Updates

With the addition of the new strategies in v2.1:
- **Critical Priority (100+):** The new MOV and ADD strategies have high priority (100) to ensure they are applied before general fallback strategies
- **Strategy Selection:** The new strategies are specifically designed to handle common null-byte patterns that were previously unhandled

## Implementation Notes for New Strategies

1. **Register Preservation:** Both new strategies preserve all registers except flags, maintaining functional equivalence.

2. **Null-Free Output:** Both strategies guarantee null-byte-free output sequences.

3. **Size Impact:** The new strategies may increase the size of the shellcode due to multi-instruction sequences, which is properly handled by the offset recalculation system.

4. **Specific Targeting:** These strategies specifically target common x86 patterns that frequently produce null bytes in shellcode.