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
- **Description:** Pass-through strategy for arithmetic operations without null bytes.
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

#### 38. Register Remap Nulls Strategy (DISABLED)

#### 39. Generic Memory Null Displacement Enhanced Strategy
- **Name:** `generic_mem_null_disp_enhanced`
- **Priority:** 65
- **Description:** Enhanced strategy for handling generic memory operations with null displacement values, using register-based addressing to avoid null bytes in displacement encoding.
- **Condition:** Applies to any instruction with memory operands where displacement contains null bytes.
- **Transformation:** MOV [disp32], reg → PUSH temp_reg; MOV temp_reg, disp32 (null-free construction); MOV [temp_reg], reg; POP temp_reg.
- **Generated code:** Register-based addressing sequence to access memory without null displacement bytes.

#### 40. LEA Displacement Nulls Strategy
- **Name:** `lea_displacement_nulls`
- **Priority:** 82
- **Description:** Handles LEA instructions with displacement values containing null bytes by using register arithmetic to calculate addresses.
- **Condition:** Applies to LEA operations where base+index*scale+disp addressing contains null bytes in displacement.
- **Transformation:** LEA reg, [base + disp] → MOV reg, base; ADD reg, disp (constructed with null-free approach).
- **Generated code:** Register arithmetic sequence to calculate effective address without null displacement.

#### 41. SIB Addressing Null Elimination Strategy
- **Name:** `SIB Addressing Null Elimination`
- **Priority:** 65
- **Description:** Handles SIB (Scale-Index-Base) addressing modes that create null bytes in SIB byte encoding.
- **Condition:** Applies to memory operations with SIB addressing where index*scale+base addressing contains null bytes.
- **Transformation:** [base + index*scale + disp] → PUSH temp_reg; calculate address in temp_reg; MOV/MEMOP [temp_reg]; POP temp_reg.
- **Generated code:** Register-based addressing to avoid problematic SIB byte encoding.

#### 42. Conditional Jump Displacement Strategy
- **Name:** `conditional_jump_displacement`
- **Priority:** 85
- **Description:** Handles conditional jumps with null-byte displacement by using conditional set and return-based jumps.
- **Condition:** Applies to conditional jumps (JE, JNE, JZ, JNZ, etc.) where displacement contains null bytes.
- **Transformation:** JZ target → PUSH target_addr; SETZ CL; CMP CL, 0; JZ skip; RET; skip: (or similar pattern).
- **Generated code:** Conditional operation sequence to avoid null-byte displacement in jump instructions.

#### 43. MOV Memory Immediate Strategy
- **Name:** `mov_mem_imm`
- **Priority:** 8
- **Description:** Handles MOV reg, [disp32] operations where the displacement address contains null bytes.
- **Condition:** Applies to MOV operations where destination is register and source is memory address with null displacement.
- **Transformation:** MOV reg, [disp32] → PUSH temp_reg; MOV temp_reg, disp32 (null-free construction); MOV reg, [temp_reg]; POP temp_reg.
- **Generated code:** Register-based memory access to avoid null displacement addressing.

#### 44. Register Remap Nulls Strategy (DISABLED)
- **Name:** `register_remap_nulls`
- **Priority:** 75
- **Description:** [DISABLED] Was intended to handle register usage that creates null bytes in encoding.
- **Condition:** Applied to instructions where register usage could create null-byte patterns.
- **Status:** DISABLED due to bug where it would append original instruction with nulls instead of properly transforming.
- **Issue:** The strategy introduced null bytes instead of eliminating them.

#### 39. MOV Register Remap Strategy (DISABLED)
- **Name:** `mov_register_remap`
- **Priority:** 78
- **Description:** [DISABLED] Was intended for MOV register remapping to avoid addressing nulls.
- **Condition:** Applied to MOV instructions where source/destination registers might be problematic.
- **Status:** DISABLED due to bug where it would append original instruction with nulls instead of proper transformation.
- **Issue:** The strategy introduced null bytes instead of eliminating them.

#### 40. Contextual Register Swap Strategy (DISABLED)
- **Name:** `contextual_register_swap`
- **Priority:** 72
- **Description:** [DISABLED] Was intended for context-aware register swapping to avoid nulls.
- **Condition:** Applied to instructions where register usage could create null-byte patterns.
- **Status:** DISABLED due to bug where it would introduce null bytes instead of eliminating them.
- **Issue:** The strategy introduced null bytes instead of eliminating them.

#### 41. Hash-Based Resolution Strategy (DISABLED)
- **Name:** `hash_based_resolution`
- **Priority:** 89
- **Description:** [DISABLED] Was intended for hash-based API resolution patterns with null-byte handling.
- **Condition:** Applied to CMP operations with function name comparisons containing null bytes.
- **Status:** DISABLED due to incomplete/buggy implementation that introduced null bytes.
- **Issue:** The strategy introduced null bytes instead of eliminating them.

#### 42. Enhanced PEB Traversal Strategy (DISABLED)
- **Name:** `enhanced_peb_traversal`
- **Priority:** 88
- **Description:** [DISABLED] Was intended for PEB traversal instructions with null-byte displacement handling.
- **Condition:** Applied to MOV operations with PEB offset displacements containing nulls.
- **Status:** DISABLED due to incomplete implementation that introduced null bytes.
- **Issue:** The strategy introduced null bytes instead of eliminating them.

#### 43. PEB Conditional Jump Strategy (DISABLED)
- **Name:** `peb_conditional_jump`
- **Priority:** 87
- **Description:** [DISABLED] Was intended for conditional jumps in PEB traversal loops with null displacement.
- **Condition:** Applied to conditional jump instructions in API resolution loops.
- **Status:** DISABLED due to incomplete implementation that introduced null bytes.
- **Issue:** The strategy introduced null bytes instead of eliminating them.

### Enhanced Strategies for Null-Byte Elimination

#### 44. Enhanced MOV Memory Strategy
- **Name:** `enhanced_mov_mem_strategies`
- **Priority:** Medium
- **Description:** Enhanced MOV memory operations with alternative addressing modes to avoid null bytes.
- **Condition:** Applies to MOV operations with memory operands that may contain null bytes in displacement or encoding.
- **Transformation:** Uses alternative addressing techniques to avoid null bytes in ModR/M and SIB bytes.
- **Generated code:** MOV instructions with null-free addressing modes.

#### 39. Enhanced Register Chaining Strategy
- **Name:** `enhanced_register_chaining_strategies`
- **Priority:** Medium
- **Description:** Enhanced register chaining operations to avoid null bytes in complex operations.
- **Condition:** Applies when register chaining can avoid null bytes in instruction encoding.
- **Transformation:** Sequence of register operations with null-avoiding patterns.
- **Generated code:** Register chaining sequences optimized for null-byte elimination.

#### 40. Enhanced Arithmetic Strategy
- **Name:** `enhanced_arithmetic_strategies`
- **Priority:** High
- **Description:** Enhanced arithmetic operations using multiple techniques to eliminate null bytes.
- **Condition:** Applies to arithmetic operations where immediate values contain null bytes.
- **Transformation:** Uses XOR encoding, negation, or other arithmetic techniques to avoid nulls.
- **Generated code:** Arithmetic operations with null-free immediate encoding.

#### 41. Enhanced Immediate Strategy
- **Name:** `enhanced_immediate_strategies`
- **Priority:** High
- **Description:** Enhanced immediate value encoding techniques to avoid null bytes.
- **Condition:** Applies to operations with immediate values containing null bytes.
- **Transformation:** Uses multiple encoding methods to construct immediate values without nulls.
- **Generated code:** Immediate operations with null-free encoding.

#### 42. Improved MOV Strategy
- **Name:** `improved_mov_strategies`
- **Priority:** High
- **Description:** Improved MOV operations with better null-byte avoidance techniques.
- **Condition:** Applies to MOV operations with immediate values containing null bytes.
- **Transformation:** Advanced MOV transformation techniques.
- **Generated code:** MOV instructions with null-free immediate encoding.

#### 43. Improved Arithmetic Strategy
- **Name:** `improved_arithmetic_strategies`
- **Priority:** High
- **Description:** Improved arithmetic operations with better null-byte avoidance techniques.
- **Condition:** Applies to arithmetic operations with immediate values containing null bytes.
- **Transformation:** Advanced arithmetic decomposition techniques.
- **Generated code:** Arithmetic operations with null-free encoding.

### Remaining Null Elimination Strategies

#### 44. Remaining Null Elimination Strategy
- **Name:** `remaining_null_elimination_strategies`
- **Priority:** 160 (highest)
- **Description:** Final cleanup strategy for remaining null bytes after all other strategies have been applied.
- **Condition:** Applied to any remaining instructions that still contain null bytes.
- **Transformation:** Comprehensive techniques to ensure final null-byte elimination.
- **Generated code:** Various techniques depending on instruction type.

### Windows-Specific Strategies

#### 45. CALL/POP Immediate Loading Strategy
- **Name:** `call_pop_immediate_strategy`
- **Priority:** 85
- **Description:** Uses CALL/POP technique to load immediate values without encoding nulls in instructions.
- **Condition:** Applies to MOV reg, imm32 patterns where immediate contains null bytes.
- **Transformation:** MOV reg, imm32 → CALL next; PUSH imm32; POP reg; next:
- **Generated code:** CALL/POP sequence to load immediate values.

#### 46. PEB API Hashing Strategy
- **Name:** `peb_api_hashing_strategy`
- **Priority:** 95
- **Description:** Uses PEB traversal to find kernel32.dll and hash-based API resolution for stealthy function calls.
- **Condition:** Applies to direct API calls with addresses that contain null bytes.
- **Transformation:** Direct API call → PEB traversal → hash-based API resolution → call via register.
- **Generated code:** PEB traversal and API hashing code for stealthy API calls.

#### 47. SALC + Conditional Flag Strategy
- **Name:** `salc_conditional_flag_strategy`
- **Priority:** 91
- **Description:** Uses SALC (Set AL on Carry) instruction for efficient AL register zeroing without MOV AL, 0x00.
- **Condition:** Applies to MOV AL, 0x00 patterns and other zero-setting operations.
- **Transformation:** MOV AL, 0x00 → CLC; SALC (if AL needs to be 0 when carry is clear).
- **Generated code:** SALC-based register manipulation without null bytes.

#### 48. LEA Arithmetic Substitution Strategy
- **Name:** `lea_arithmetic_substitution_strategy`
- **Priority:** 80
- **Description:** Uses LEA instruction to perform arithmetic operations without immediate null bytes.
- **Condition:** Applies to arithmetic operations where immediate values contain null bytes.
- **Transformation:** ADD reg, value → LEA reg, [reg + value] (when value is suitable for LEA).
- **Generated code:** LEA instructions for arithmetic operations with null-free encoding.

#### 49. Shift Value Construction Strategy
- **Name:** `shift_value_construction_strategy`
- **Priority:** 78
- **Description:** Uses bit shift operations combined with arithmetic to build values containing null bytes.
- **Condition:** Applies to MOV reg, imm patterns where immediate contains null bytes but can be constructed via shifts.
- **Transformation:** MOV reg, value → sequence of SHL/SHR/ADD operations to build value.
- **Generated code:** Shift and arithmetic sequences to construct target values.

#### 50. Stack String Construction Strategy
- **Name:** `stack_string_construction_strategy`
- **Priority:** 85
- **Description:** Constructs strings using multiple PUSH operations to avoid null-laden string literals.
- **Condition:** Applies to string construction operations containing null bytes.
- **Transformation:** MOV string → sequence of PUSH operations for each part of string.
- **Generated code:** Stack-based string construction without null bytes.

#### 51. Register Swapping Immediate Strategy
- **Name:** `register_swapping_immediate_strategy`
- **Priority:** 70
- **Description:** Uses XCHG and register swapping techniques for immediate value loading.
- **Condition:** Applies to MOV operations with immediate values containing null bytes.
- **Transformation:** MOV reg, imm → use register swapping with null-free construction.
- **Generated code:** XCHG-based immediate value loading.

#### 52. SCASB/CMPSB Strategy
- **Name:** `scasb_cmpsb_strategy`
- **Priority:** 75
- **Description:** Uses SCASB/CMPSB conditional operations as alternatives to other patterns.
- **Condition:** Applies to conditional operations and comparisons.
- **Transformation:** Alternative string comparison/scan operations.
- **Generated code:** SCASB/CMPSB-based conditional operations.

#### 53. Short Conditional Jump Strategy
- **Name:** `short_conditional_jump_strategy`
- **Priority:** 85
- **Description:** Uses short conditional jumps with 8-bit displacement to avoid null-byte offsets.
- **Condition:** Applies to conditional jumps where 32-bit displacement contains null bytes.
- **Transformation:** Jcc far_target → J!cc skip; JMP far_target; skip: (or use short jump if target is near).
- **Generated code:** Short conditional jumps or alternative jump patterns.

#### 54. LEA Complex Addressing Strategy
- **Name:** `lea_complex_addressing_strategy`
- **Priority:** 80
- **Description:** Uses LEA with complex addressing for value construction strategy.
- **Condition:** Applies when LEA can be used to construct values with null-containing displacements.
- **Transformation:** Alternative LEA addressing modes to avoid null bytes.
- **Generated code:** LEA with complex addressing modes.

#### 55. INC/DEC Chain Strategy
- **Name:** `inc_dec_chain_strategy`
- **Priority:** 75
- **Description:** Uses INC/DEC chain strategies for register operations.
- **Condition:** Applies to INC/DEC operations that might contain null bytes in encoding.
- **Transformation:** INC/DEC reg → MOV temp_reg, reg; INC/DEC temp_reg; MOV reg, temp_reg.
- **Generated code:** INC/DEC with register preservation to avoid null bytes.

#### 56. LEA Arithmetic Calculation Strategy
- **Name:** `lea_arithmetic_calculation_strategy`
- **Priority:** 78
- **Description:** Uses LEA arithmetic calculation strategy for complex value construction.
- **Condition:** Applies when LEA can be used to perform arithmetic calculations.
- **Transformation:** Arithmetic operations → LEA-based calculations.
- **Generated code:** LEA-based arithmetic operations.

#### 57. PUSH-POP Immediate Strategy
- **Name:** `push_pop_immediate_strategy`
- **Priority:** 77
- **Description:** PUSH-POP immediate loading strategy for immediate value handling.
- **Condition:** Applies to immediate value loading operations containing null bytes.
- **Transformation:** MOV reg, imm → PUSH imm (null-free construction); POP reg.
- **Generated code:** PUSH-POP sequences for immediate value loading.

#### 58. Bitwise Flag Manipulation Strategy
- **Name:** `bitwise_flag_manipulation_strategy`
- **Priority:** 72
- **Description:** Bitwise flag manipulation strategy for flag handling.
- **Condition:** Applies to flag manipulation operations containing null bytes.
- **Transformation:** Alternative bitwise operations for flag manipulation.
- **Generated code:** Bitwise operations without null bytes.

#### 59. SALC Zero Flag Strategy
- **Name:** `salc_zero_flag_strategy`
- **Priority:** 75
- **Description:** SALC zero flag strategy for AL register manipulation.
- **Condition:** Applies to AL register zeroing and flag manipulation.
- **Transformation:** MOV AL, 0 → SALC based on carry flag state.
- **Generated code:** SALC-based AL manipulation.

#### 60. XCHG Immediate Construction Strategy
- **Name:** `xchg_immediate_construction_strategy`
- **Priority:** 70
- **Description:** XCHG immediate construction strategy for value loading.
- **Condition:** Applies to immediate value loading operations.
- **Transformation:** Value loading using XCHG instructions.
- **Generated code:** XCHG-based value loading.

### New Gap-Fill Strategies (Added to Address Specific Gaps)

#### 61. Enhanced PEB API Resolution Strategy
- **Name:** `enhanced_peb_traversal_strategy`
- **Priority:** 88
- **Description:** Enhanced PEB-based API resolution strategies that handle sophisticated Windows API resolution patterns with null-byte displacements in PEB traversal.
- **Condition:** Applies to MOV operations in PEB traversal patterns (e.g., `mov eax, [ebx + 0x3c]`) where displacement contains null bytes.
- **Transformation:** MOV reg, [base + disp_with_nulls] → MOV reg, base; ADD reg, disp (constructed without nulls); MOV reg, [reg].
- **Generated code:** PEB traversal code without null-byte displacements.

#### 62. Hash-Based API Resolution Strategy
- **Name:** `hash_based_resolution_strategy`
- **Priority:** 89
- **Description:** Handles hash-based API resolution patterns that contain null bytes in function name comparisons.
- **Condition:** Applies to CMP operations comparing function names (e.g., `cmp [eax], 0x50746547` for "GetProc") where immediate contains null bytes.
- **Transformation:** CMP [mem], imm_with_nulls → MOV temp_reg, imm (constructed without nulls); CMP [mem], temp_reg.
- **Generated code:** Hash-based API resolution without null-byte immediates.

#### 63. PEB Conditional Jump Strategy
- **Name:** `peb_conditional_jump_strategy`
- **Priority:** 87
- **Description:** Handles conditional jumps in PEB API resolution loops that have null bytes in displacement or encoding.
- **Condition:** Applies to conditional jumps (jz, jnz, je, jne, etc.) in PEB traversal loops that contain null bytes.
- **Transformation:** Jcc target_with_nulls → alternative jump pattern using short jumps or conditional logic.
- **Generated code:** PEB traversal conditional jumps without null-byte displacements.

#### 64. Conditional Jump Displacement Strategy
- **Name:** `conditional_jump_displacement_strategy`
- **Priority:** 88
- **Description:** Handles conditional jumps that contain null bytes in displacement fields, common in API resolution loops.
- **Condition:** Applies to conditional jumps (jz, jnz, je, jne, etc.) where instruction encoding or displacement contains null bytes.
- **Transformation:** Jcc near_label_with_nulls → inverse condition with short jump over long jump.
- **Generated code:** Conditional jump alternatives without null-byte displacements.

#### 65. Short Conditional Jump with Nulls Strategy
- **Name:** `short_conditional_jump_with_nulls_strategy`
- **Priority:** 85
- **Description:** Handles short conditional jumps that contain null bytes in their encoding.
- **Condition:** Applies to short conditional jumps where the instruction encoding contains null bytes.
- **Transformation:** Jcc rel8_with_nulls → Convert to alternative conditional pattern.
- **Generated code:** Short conditional jump alternatives without null bytes.

#### 66. Register Remap Nulls Strategy
- **Name:** `register_remap_nulls_strategy`
- **Priority:** 75
- **Description:** Handles register remapping to avoid null-byte patterns by selecting alternative registers.
- **Condition:** Applies to instructions that use registers in ways that create null bytes in encoding, especially EBP/R13 addressing without displacement.
- **Transformation:** Use alternative registers and transfer values when needed to avoid problematic encodings.
- **Generated code:** Register remapped code that avoids null bytes.

#### 67. MOV Register Remap Strategy
- **Name:** `mov_register_remap_strategy`
- **Priority:** 78
- **Description:** Specific MOV register remapping to avoid null-byte patterns in addressing modes.
- **Condition:** Applies to MOV instructions with memory operands that would create null bytes in addressing.
- **Transformation:** MOV operations using alternative registers to avoid null-byte addressing.
- **Generated code:** MOV instructions with null-byte-free addressing.

#### 68. Contextual Register Swap Strategy
- **Name:** `contextual_register_swap_strategy`
- **Priority:** 72
- **Description:** Contextual register swapping that considers the whole instruction context to avoid nulls.
- **Condition:** Applies when register swapping could reduce null bytes based on instruction context.
- **Transformation:** Alternative register usage to avoid null-byte patterns.
- **Generated code:** Contextually optimized register usage.

#### 69. LEA Displacement Nulls Strategy
- **Name:** `lea_displacement_nulls_strategy`
- **Priority:** 82
- **Description:** Handles LEA instructions with null-byte displacements in addressing modes.
- **Condition:** Applies to LEA reg, [base + disp32] where disp32 contains null bytes.
- **Transformation:** LEA reg, [base + disp_with_nulls] → MOV reg, base; ADD reg, disp (constructed without nulls).
- **Generated code:** LEA alternatives without displacement null bytes.

#### 70. LEA Problematic Encoding Strategy
- **Name:** `lea_problematic_encoding_strategy`
- **Priority:** 81
- **Description:** Handles LEA instructions with problematic addressing that creates null encoding bytes.
- **Condition:** Applies to LEA operations with EBP/R13 base registers and zero displacement that require null displacement bytes.
- **Transformation:** LEA dst, [EBP] (requires 00 displacement) → MOV dst_reg, base_reg.
- **Generated code:** LEA alternatives with null-byte-free encoding.

## Critical Bug Fixes (v2.8) - Achieving 100% Success Rate

### Bug Fix #1: PUSH 0 Null-Byte Introduction

**Location:** `src/xchg_preservation_strategies.c` (lines 78-79, 101-103)

**Problem Description:**
The PUSH Immediate Null-Byte Elimination strategy (priority 86) had a critical bug where it would encode `PUSH 0` using the imm8 encoding (`6A 00`), which contains a null byte in the immediate field. This directly violated the strategy's purpose of eliminating null bytes.

**Root Cause:**
The strategy optimized small immediate values (-128 to 127) to use the compact PUSH imm8 encoding (2 bytes) instead of PUSH imm32 (5 bytes). However, it failed to exclude the value 0 from this optimization:

```c
// BUGGY CODE (before fix):
if (imm >= -128 && imm <= 127) {
    // PUSH imm8: 6A XX
    buffer_write_byte(b, 0x6A);
    buffer_write_byte(b, (uint8_t)(imm & 0xFF));  // When imm=0, this writes 0x00!
    return;
}
```

**The Fix:**
Added explicit exclusion of `imm == 0` from the imm8 optimization path, forcing it to use the null-free MOV+PUSH construction:

```c
// FIXED CODE:
// IMPORTANT: Exclude 0 because PUSH 0 encodes as 6A 00 which contains a null byte!
if (imm >= -128 && imm <= 127 && imm != 0) {
    // PUSH imm8: 6A XX (safe for all values except 0)
    buffer_write_byte(b, 0x6A);
    buffer_write_byte(b, (uint8_t)(imm & 0xFF));
    return;
}

// For imm=0, fall through to Strategy B:
// MOV EAX, 0xFFFFFFFF; NOT EAX; PUSH EAX (completely null-free)
```

**Impact:**
- Affected 2 of 3 failing files: `skeeterspit.bin`, `wingaypi.bin`
- Both files contained `PUSH 0` instructions that were being incorrectly encoded
- Fix ensures `PUSH 0` is transformed to null-free sequence: `MOV EAX, 0xFFFFFFFF; NOT EAX; PUSH EAX`

**Test Results:**
```bash
# Before fix:
ERROR: Strategy 'PUSH Immediate Null-Byte Elimination' introduced null at offset 1

# After fix:
✓ skeeterspit.bin: SUCCESS (null-free)
✓ wingaypi.bin: SUCCESS (null-free)
```

### Bug Fix #2: SIB Strategy Handling Unsupported Instructions

**Location:** `src/sib_strategies.c` (lines 46-49)

**Problem Description:**
The SIB Addressing Null Elimination strategy had a critical mismatch between its `can_handle()` and `generate()` functions. The `can_handle_sib_null()` function claimed to handle ANY instruction with SIB addressing patterns, but the `generate_sib_null()` switch statement only implemented transformations for specific instruction types (MOV, PUSH, LEA, CMP, ADD, SUB, AND, OR, XOR). Unsupported instructions like ARPL would pass the `can_handle()` check, then fall through to the default case in `generate()` which just copied the original instruction bytes—nulls and all.

**Root Cause:**
The strategy selection system trusted `can_handle()` to be accurate, but the function only checked for SIB addressing patterns without verifying the instruction was actually supported:

```c
// BUGGY CODE (before fix):
static int can_handle_sib_null(cs_insn *insn) {
    // ... checks for SIB addressing patterns ...
    // Returns 1 for ANY instruction with SIB addressing, including ARPL!
    return 1;
}

static void generate_sib_null(struct buffer *b, cs_insn *insn) {
    switch (insn->id) {
        case X86_INS_MOV:   /* ... */ break;
        case X86_INS_PUSH:  /* ... */ break;
        case X86_INS_LEA:   /* ... */ break;
        // ... other supported instructions ...
        default:
            // BUG: Unsupported instructions fall through here and get copied with nulls!
            buffer_append(b, insn->bytes, insn->size);
            break;
    }
}
```

**The Fix:**
Added an instruction type filter at the beginning of `can_handle_sib_null()` to only accept instructions that are actually implemented in the `generate()` switch statement:

```c
// FIXED CODE:
static int can_handle_sib_null(cs_insn *insn) {
    if (!insn || !insn->detail) {
        return 0;
    }

    // CRITICAL: Only handle instructions we actually support in the switch statement
    // Otherwise we'll fall through to default case which just copies the original with nulls!
    if (insn->id != X86_INS_MOV && insn->id != X86_INS_PUSH && insn->id != X86_INS_LEA &&
        insn->id != X86_INS_CMP && insn->id != X86_INS_ADD && insn->id != X86_INS_SUB &&
        insn->id != X86_INS_AND && insn->id != X86_INS_OR && insn->id != X86_INS_XOR) {
        return 0;  // Don't handle instructions not in our switch statement
    }

    // ... rest of SIB addressing pattern checks ...
}
```

**Impact:**
- Affected 1 of 3 failing files: `SSIWML.bin`
- File contained ARPL instruction with SIB addressing: `arpl word ptr gs:[eax + eax - 0x18], si`
- Strategy would claim to handle it, then copy original bytes with null at offset 21
- Fix ensures unsupported instructions are rejected by `can_handle()`, allowing other strategies to handle them

**Specific Failing Instruction:**
```asm
arpl word ptr gs:[eax + eax - 0x18], si
; Encoding: 65 63 74 00 E8
;                    ^^ null byte at offset 21
```

**Test Results:**
```bash
# Before fix:
ERROR: Strategy 'SIB Addressing Null Elimination' introduced null at offset 21

# After fix:
✓ SSIWML.bin: SUCCESS (null-free)
```

### Combined Impact: 100% Success Rate Achievement

**Before Fixes:**
- Success Rate: 16/19 (84.2%)
- Failing Files: SSIWML.bin, skeeterspit.bin, wingaypi.bin
- Issues: PUSH 0 encoding bug (2 files), SIB ARPL handling bug (1 file)

**After Fixes:**
- Success Rate: **19/19 (100%)**
- Failing Files: **0**
- All null-byte patterns successfully eliminated

**Batch Test Results:**
```
===== BATCH PROCESSING SUMMARY =====
Total files:       19
Processed:         19
Failed:            0
Skipped:           0
Total input size:  11333142 bytes
Total output size: 70773 bytes
Size ratio:        0.01x
====================================
```

### Technical Lessons Learned

1. **Strategy Selection Must Be Accurate**: The `can_handle()` function must accurately reflect what `generate()` can actually handle. Any mismatch leads to silent failures where strategies claim to fix null bytes but actually introduce or preserve them.

2. **Edge Cases in Optimizations**: When optimizing for common cases (like imm8 encoding for small values), always consider edge cases where the optimization itself might introduce the problem you're trying to solve (like 0 in PUSH imm8).

3. **Switch Statement Coverage**: When using switch statements with default cases, ensure the entry conditions (like `can_handle()`) filter out anything that would hit the default case unintentionally.

4. **Priority Matters**: The PUSH 0 bug was in the higher priority strategy (86), which was selected before the working lower priority strategy (75). This demonstrates why testing must cover the actual code paths being executed, not just whether working code exists.

5. **Comprehensive Testing**: These bugs only manifested in 3 specific files out of 19. Without comprehensive batch testing across diverse shellcode samples, these edge cases might have gone unnoticed.
