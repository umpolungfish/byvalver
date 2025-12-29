# BYVALVER Obfuscation Strategies (OBFUSCATION_STRATS.md)

## Overview

BYVALVER implements a comprehensive suite of obfuscation strategies that are applied during the first pass of biphasic processing. These strategies are designed to increase the complexity and analytical difficulty of shellcode before bad-character elimination is applied (v3.0: generic bad-character elimination, v2.x: null-byte elimination only). The obfuscation layer adds significant anti-analysis features that make reverse engineering more difficult.

**Note (v3.0):** Obfuscation strategies work in conjunction with the generic bad-character elimination framework. The obfuscated output from Pass 1 is then processed through Pass 2 (bad-character elimination) using the configured bad character set.
   
  ## Strategy Interface

  All obfuscation strategies implement the same interface:
- `can_handle` - Returns true if the strategy can process a given instruction
- `get_size` - Returns the size of the obfuscated output
- `generate` - Creates the obfuscated transformation

## Strategy Registry

The obfuscation strategies are registered in `src/obfuscation_strategy_registry.c` and are applied before denullification
   
## Detailed Strategy Descriptions

### Basic Obfuscation Strategies

#### 1. MOV Register Exchange Obfuscation

- **Name:** `mov_register_exchange_obfuscation`
- **Priority:** 75
- **Description:** Replaces simple MOV operations with equivalent register exchange patterns that increase complexity.
- **Condition:** Applies to MOV instructions between registers.
- **Transformation:** Uses XCHG or push/pop patterns to achieve the same result.
- **Generated code:** Register exchange patterns that preserve functionality.

#### 2. MOV Immediate Obfuscation

- **Name:** `mov_immediate_obfuscation`
- **Priority:** 70
- **Description:** Obfuscates MOV operations with immediate values using multiple arithmetic operations.
- **Condition:** Applies to MOV instructions with immediate values.
- **Transformation:** Uses ADD/SUB, XOR, or LEA operations to achieve the same result.
- **Generated code:** Arithmetic sequences that produce the same final value.

#### 3. Arithmetic Substitution Obfuscation

- **Name:** `arithmetic_substitution_obfuscation`
- **Priority:** 72
- **Description:** Replaces arithmetic instructions with functionally equivalent but more complex alternatives.
- **Condition:** Applies to ADD, SUB, AND, OR, XOR operations.
- **Transformation:** Uses equivalent operations with additional operands or steps.
- **Generated code:** More complex arithmetic sequences that achieve the same result.
### Memory Operation Obfuscation Strategies

#### 4. Memory Access Obfuscation

- **Name:** `memory_access_pattern_obfuscation`
- **Priority:** 68
- **Description:** Obfuscates memory read/write operations using pointer arithmetic and register indirection.
- **Condition:** Applies to MOV operations involving memory addresses.
- **Transformation:** Uses LEA for address calculation and more complex addressing modes.
- **Generated code:** Memory operations with additional indirection layers.

#### 5. Stack Operation Obfuscation

- **Name:** `stack_operation_obfuscation`
- **Priority:** 70
- **Description:** Obfuscates PUSH/POP operations by using alternative stack manipulation techniques.
- **Condition:** Applies to PUSH/POP instructions.
- **Transformation:** Uses MOV operations with ESP-relative addressing and manual stack management.
- **Generated code:** Manual stack operations instead of direct PUSH/POP.
### Control Flow Obfuscation Strategies

#### 6. Conditional Jump Obfuscation

- **Name:** `conditional_jump_obfuscation`
- **Priority:** 80
- **Description:** Obfuscates conditional jumps by using conditional moves or SETcc instructions instead of branching.
- **Condition:** Applies to conditional jump instructions (JE, JNE, JL, JG, etc.).
- **Transformation:** Uses SETcc followed by conditional operations or pointer selection.
- **Generated code:** Conditional logic without explicit jumps.

#### 7. Unconditional Jump Obfuscation

- **Name:** `unconditional_jump_obfuscation`
- **Priority:** 75
- **Description:** Replaces direct jumps with more complex jump mechanisms.
- **Condition:** Applies to JMP instructions.
- **Transformation:** Uses register indirect jumps or computed goto patterns.
- **Generated code:** Indirect jump mechanisms that achieve the same control flow.

#### 8. Call Obfuscation

- **Name:** `call_instruction_obfuscation`
- **Priority:** 78
- **Description:** Obfuscates CALL instructions by using more complex call mechanisms.
- **Condition:** Applies to CALL instructions.
- **Transformation:** Uses PUSH + JMP patterns or register indirect calls.
- **Generated code:** Call-like behavior without direct CALL instruction.
### Advanced Obfuscation Strategies

#### 9. Control Flow Flattening

- **Name:** `control_flow_flattening_obfuscation`
- **Priority:** 85
- **Description:** Flattens control flow by using a dispatcher pattern that makes the execution flow linear.
- **Condition:** Applies to complex control flow constructs.
- **Transformation:** Replaces structured flow with a state machine and dispatcher.
- **Generated code:** Linear execution with state-based dispatching.

#### 10. Instruction Substitution

- **Name:** `instruction_substitution_obfuscation`
- **Priority:** 75
- **Description:** Replaces instructions with functionally equivalent but more complex alternatives.
- **Condition:** Applies to various instruction types.
- **Transformation:** Uses different instructions that achieve the same effect.
- **Generated code:** Equivalent operations with different instruction encodings.

#### 11. Dead Code Insertion

- **Name:** `dead_code_insertion_obfuscation`
- **Priority:** 60
- **Description:** Inserts computation that has no effect on the final result but increases complexity.
- **Condition:** Applies generally to increase complexity.
- **Transformation:** Inserts operations that don't affect program state.
- **Generated code:** Additional code that has no functional impact.

#### 12. Register Reassignment

- **Name:** `register_reassignment_obfuscation`
- **Priority:** 80
- **Description:** Changes register usage patterns to make data flow analysis more difficult.
- **Condition:** Applies to register-based operations.
- **Transformation:** Uses different registers with appropriate data movement.
- **Generated code:** Same logic with different register assignments.
### Arithmetic Obfuscation Strategies

#### 13. Multiplication by One Substitution

- **Name:** `multiplication_by_one_obfuscation`
- **Priority:** 65
- **Description:** Replaces operations with equivalent multiplication by one patterns.
- **Condition:** Applies to arithmetic operations that can be expressed differently.
- **Transformation:** Uses IMUL or other operations to achieve the same result.
- **Generated code:** Arithmetic operations with multiplication patterns.

#### 14. NOP Sled Insertion

- **Name:** `nop_sled_insertion_obfuscation`
- **Priority:** 55
- **Description:** Inserts variable-length NOP sleds between instructions to obscure code structure.
- **Condition:** General insertion points between instructions.
- **Transformation:** Adds padding with equivalent operations.
- **Generated code:** Same execution with additional padding instructions.

#### 15. Equivalent Operation Substitution

- **Name:** `equivalent_operation_substitution_obfuscation`
- **Priority:** 70
- **Description:** Substitutes operations with functionally equivalent but different instructions.
- **Condition:** Applies to various operations that have alternatives.
- **Transformation:** Replaces with equivalent but more complex operations.
- **Generated code:** Different instructions with the same result.
### Jump Target Obfuscation Strategies

#### 16. Jump Target Decoy

- **Name:** `jump_target_decoy_obfuscation`
- **Priority:** 72
- **Description:** Creates fake jump targets to confuse analysis tools.
- **Condition:** Applies near jump or call instructions.
- **Transformation:** Inserts decoy code paths that appear to be valid targets.
- **Generated code:** Additional code paths that appear to be valid destinations.

#### 17. Relative Offset Obfuscation

- **Name:** `relative_offset_obfuscation`
- **Priority:** 68
- **Description:** Obfuscates relative offsets by adjusting jump targets with additional calculations.
- **Condition:** Applies to relative jump and call instructions.
- **Transformation:** Uses additional arithmetic to calculate final target.
- **Generated code:** Jumps with additional offset calculation.
### Advanced Control Flow Obfuscation

#### 18. Switch-Based Obfuscation

- **Name:** `switch_based_obfuscation`
- **Priority:** 82
- **Description:** Replaces conditional logic with switch-case patterns that are harder to follow.
- **Condition:** Applies to conditionally executed code.
- **Transformation:** Uses computed jumps based on state values.
- **Generated code:** Switch-like control flow structures.

#### 19. Boolean Expression Obfuscation

- **Name:** `boolean_expression_obfuscation`
- **Priority:** 76
- **Description:** Obfuscates boolean expressions by using more complex logical combinations.
- **Condition:** Applies to conditional operations.
- **Transformation:** Uses De Morgan's laws and equivalent boolean expressions.
- **Generated code:** Equivalent boolean logic with additional complexity.

#### 20. Variable Encoding

- **Name:** `variable_encoding_obfuscation`
- **Priority:** 78
- **Description:** Encodes variable values using reversible transformations.
- **Condition:** Applies to variables that can be safely encoded.
- **Transformation:** Uses XOR, ADD, or other reversible operations.
- **Generated code:** Operations that decode values at use time.
### Obfuscation-Specific Anti-Analysis Techniques

#### 21. Timing Variation Obfuscation

- **Name:** `timing_variation_obfuscation`
- **Priority:** 62
- **Description:** Adds timing variations to make execution analysis more difficult.
- **Condition:** Applies to code sections where timing matters.
- **Transformation:** Inserts variable-length delays or operations.
- **Generated code:** Execution with variable timing characteristics.

#### 22. Register State Obfuscation

- **Name:** `register_state_obfuscation`
- **Priority:** 73
- **Description:** Obfuscates register states by performing equivalent operations.
- **Condition:** Applies to register operations.
- **Transformation:** Uses equivalent but more complex register manipulations.
- **Generated code:** Same register state with more complex operations.

#### 23. Stack Frame Manipulation

- **Name:** `stack_frame_manipulation_obfuscation`
- **Priority:** 74
- **Description:** Manipulates stack frames to hide calling conventions.
- **Condition:** Applies to function prologues and epilogues.
- **Transformation:** Uses custom stack management instead of standard patterns.
- **Generated code:** Non-standard stack frame handling.

#### 24. API Resolution Obfuscation

- **Name:** `api_resolution_obfuscation`
- **Priority:** 80
- **Description:** Obfuscates Windows API resolution techniques.
- **Condition:** Applies to API hash lookup and resolution code.
- **Transformation:** Uses more complex hash functions or resolution methods.
- **Generated code:** API resolution with additional obfuscation layers.
### Data Encoding Obfuscation Strategies

#### 25. String Encoding Obfuscation

- **Name:** `string_encoding_obfuscation`
- **Priority:** 75
- **Description:** Obfuscates string literals using various encoding techniques.
- **Condition:** Applied to string data in the code.
- **Transformation:** Encodes strings with reversible transformations.
- **Generated code:** Encoded strings with decoding operations at runtime.

#### 26. Constant Obfuscation

- **Name:** `constant_obfuscation`
- **Priority:** 65
- **Description:** Obfuscates constant values with equivalent expressions.
- **Condition:** Applies to immediate values and constants.
- **Transformation:** Uses expression evaluation to recreate constants.
- **Generated code:** Constants generated through calculations.
### Anti-Debugging Obfuscation

#### 27. Debugger Detection Obfuscation

- **Name:** `debugger_detection_obfuscation`
- **Priority:** 85
- **Description:** Adds obfuscated anti-debugging checks throughout the code.
- **Condition:** Applied widely throughout the codebase.
- **Transformation:** Inserts anti-debug techniques with obfuscated detection.
- **Generated code:** Code with embedded anti-analysis protections.

#### 28. VM Detection Obfuscation

- **Name:** `vm_detection_obfuscation`
- **Priority:** 82
- **Description:** Obfuscates virtual machine detection code.
- **Condition:** Applied to VM detection routines.
- **Transformation:** Uses obfuscated methods to detect virtualized environments.
- **Generated code:** VM detection with additional concealment.

## NEW: v3.0 Advanced Obfuscation Strategies

### 29. Mutated Junk Insertion Obfuscation (Priority 93)

- **Name:** `mutated_junk_insertion_obfuscation`
- **Priority:** 93
- **Status:** IMPLEMENTED
- **Description:** Inserts semantically meaningless but syntactically valid instruction sequences using opaque predicates and conditional jumps. Creates complex control flow with dead code paths.
- **Condition:** Applies to ~15% of non-control-flow instructions
- **Transformation:**
  - Pattern 1: XOR reg, reg; JZ +N (always taken)
  - Pattern 2: TEST EAX, EAX; JNZ +N after XOR (never taken)
  - Pattern 3: CMP reg, reg; JE +N (always taken)
- **Generated code:** Opaque predicates followed by junk payloads (INT3, dead operations, garbage bytes)
- **File:** `src/mutated_junk_insertion_obfuscation.c`

### 30. Semantic Equivalence Substitution (Priority 88-84)

- **Name:** `semantic_equivalence_substitution`
- **Priority:** 88 (XOR→SUB), 87 (INC→ADD), 86 (DEC→SUB), 85 (MOV 0→XOR), 84 (INC→LEA)
- **Status:** IMPLEMENTED (5 sub-strategies)
- **Description:** Replaces common instructions with functionally equivalent but less common sequences for signature breaking.
- **Condition:** Applies to XOR reg,reg / INC / DEC / MOV reg,0 / INC (32-bit)
- **Transformation:**
  - `XOR EAX, EAX` → `SUB EAX, EAX`
  - `INC EAX` → `ADD EAX, 1`
  - `DEC EAX` → `SUB EAX, 1`
  - `MOV EAX, 0` → `XOR EAX, EAX`
  - `INC EAX` → `LEA EAX, [EAX+1]`
- **Generated code:** Semantically equivalent instructions with different bytecode
- **File:** `src/semantic_equivalence_substitution.c`

### 31. FPU Stack Obfuscation (Priority 86)

- **Name:** `fpu_stack_obfuscation`
- **Priority:** 86
- **Status:** IMPLEMENTED
- **Description:** Leverages FPU (x87) instructions for obfuscation. Inserts dead FPU operations that analyzers often ignore.
- **Condition:** Applies to ~10% of non-control-flow, non-FPU instructions
- **Transformation:**
  - Pattern 1: FNOP (FPU NOP)
  - Pattern 2: FLD1; FSTP ST(0) (push/pop 1.0)
  - Pattern 3: FLDZ; FSTP ST(0) (push/pop 0.0)
  - Pattern 4: FLDPI; FSTP ST(0) (push/pop PI)
- **Generated code:** 6 bytes of FPU junk before original instruction
- **File:** `src/fpu_stack_obfuscation.c`

### 32. Register Shuffle Obfuscation (Priority 82)

- **Name:** `register_shuffle_obfuscation`
- **Priority:** 82
- **Status:** IMPLEMENTED
- **Description:** Inserts self-canceling XCHG operations to confuse data flow analysis without changing program state.
- **Condition:** Applies to ~12% of non-control-flow, non-stack instructions
- **Transformation:**
  - `XCHG reg1, reg2; XCHG reg1, reg2` (double XCHG = NOP)
  - Register pairs: ECX/EDX, EBX/ESI, ESI/EDI
- **Generated code:** 2-4 bytes of self-canceling register exchanges
- **File:** `src/register_shuffle_obfuscation.c`

### 33. Syscall Instruction Substitution (Priority 79-78)

- **Name:** `syscall_instruction_substitution`
- **Priority:** 79 (INT 0x80), 78 (SYSCALL)
- **Status:** IMPLEMENTED (2 sub-strategies)
- **Description:** Replaces standard syscall mechanisms with alternative invocation methods for IDS/hook evasion.
- **Condition:** Applies to INT 0x80 and SYSCALL instructions
- **Transformation:**
  - `INT 0x80` → `CALL +2; INT 0x80; RET` (8 bytes)
  - `SYSCALL` → `CALL +1; SYSCALL; RET` (8 bytes)
- **Generated code:** Syscalls wrapped in CALL/RET trampolines
- **File:** `src/syscall_instruction_substitution.c`

### 34. Mixed Arithmetic Base Obfuscation (Priority 73)

- **Name:** `mixed_arithmetic_base_obfuscation`
- **Priority:** 73
- **Status:** IMPLEMENTED
- **Description:** Expresses immediate values using complex arithmetic expressions for constant hiding.
- **Condition:** Applies to MOV reg, imm (32-bit regs, imm ≤ 0xFFFF)
- **Transformation:**
  - `MOV EAX, 0` → `XOR EAX, EAX`
  - `MOV EAX, 11` → `XOR EAX, EAX; MOV AL, 8; ADD AL, 3`
  - Power of 2: `MOV EAX, 16` → `MOV EAX, 1; SHL EAX, 4`
  - Others: Decompose using shifts, additions
- **Generated code:** Multi-step arithmetic sequences producing the same value
- **File:** `src/mixed_arithmetic_base_obfuscation.c`

### 35. Runtime Self-Modification Obfuscation (Priority 99) - STUB

- **Name:** `runtime_selfmod_obfuscation`
- **Priority:** 99
- **Status:** STUBBED (future implementation)
- **Description:** Implements runtime self-modifying code where instructions are encoded with marker bytes and decoded at runtime.
- **Future Implementation:**
  - Marker byte selection and encoding scheme
  - Runtime decoder loop generation
  - Self-modifying code support
  - End marker detection
- **File:** `src/runtime_selfmod_obfuscation.c` (stub)

### 36. Incremental Decoder Obfuscation (Priority 97) - STUB

- **Name:** `incremental_decoder_obfuscation`
- **Priority:** 97
- **Status:** STUBBED (future implementation)
- **Description:** Transforms instructions using incremental arithmetic decoding (XOR/ROT13/SUB chains).
- **Future Implementation:**
  - Full shellcode block encoding
  - Decoder stub with loop and counter
  - Multiple encoding key support
  - Integration with offset calculation
- **File:** `src/incremental_decoder_obfuscation.c` (stub)

### 37. Overlapping Instruction Obfuscation (Priority 84) - STUB

- **Name:** `overlapping_instruction_obfuscation`
- **Priority:** 84
- **Status:** STUBBED (future implementation)
- **Description:** Creates instruction sequences where bytes decode differently based on entry point.
- **Future Implementation:**
  - Multi-interpretation byte sequence construction
  - Careful offset management for jump targets
  - Disassembler confusion analysis
- **File:** `src/overlapping_instruction_obfuscation.c` (stub)

### 38. Control Flow Dispatcher Obfuscation (Priority 77) - STUB

- **Name:** `control_flow_dispatcher_obfuscation`
- **Priority:** 77
- **Status:** STUBBED (future implementation)
- **Description:** Implements state-machine dispatcher for CFG flattening.
- **Future Implementation:**
  - Basic block identification and extraction
  - CFG construction
  - Dispatcher loop generation
  - State variable management
  - Block reordering
- **File:** `src/control_flow_dispatcher_obfuscation.c` (stub)

### 39. Unicode Negation Encoding Obfuscation (Priority 81)

- **Name:** `unicode_negation_encoding_obfuscation`
- **Priority:** 81
- **Status:** IMPLEMENTED
- **Description:** Constructs UTF-16/Unicode string values by using NEG instruction on carefully crafted negative immediates, rather than directly PUSH-ing Unicode values containing null bytes.
- **Condition:** Applies to PUSH imm32 where immediate is a Unicode value (contains null bytes)
- **Transformation:**
  - `PUSH 0x00730072` (contains nulls) → `MOV EDX, 0xFF8CFF8E; NEG EDX; PUSH EDX`
  - Mathematical relationship: `NEG(0xFF8CFF8E) = 0x00730072`
- **Benefits:**
  - Completely eliminates null bytes from Unicode string construction
  - Defeats string scanning techniques
  - Only 3 bytes overhead per value (MOV+NEG)
  - Works for ANY Unicode value with null bytes
- **File:** `src/unicode_negation_encoding_obfuscation.c`

### 40. PEB Module Name Length-Based Fingerprinting Obfuscation (Priority 84)

- **Name:** `peb_namelength_fingerprint_obfuscation`
- **Priority:** 84
- **Status:** IMPLEMENTED
- **Description:** Adds length-based checking patterns to CMP instructions used in PEB traversal, simulating the technique of identifying DLLs by name length rather than full string comparison.
- **Condition:** Applies to approximately 8% of CMP instructions
- **Transformation:** Inserts redundant TEST CX, CX before CMP to simulate length fingerprinting pattern
- **Benefits:**
  - More compact than full string comparison
  - Faster execution
  - Stealthier - avoids recognizable API name strings
  - Evades typical "hash API names" patterns that AV looks for
- **File:** `src/peb_namelength_fingerprint_obfuscation.c`

### 41. LOOPNZ-Based Compact Search Patterns Obfuscation (Priority 76)

- **Name:** `loopnz_compact_search_obfuscation`
- **Priority:** 76
- **Status:** IMPLEMENTED
- **Description:** Uses LOOPNZ instruction patterns to create ultra-compact search loops for egg hunters and memory scanners. LOOPNZ atomically performs: ECX--; if (ECX != 0 && ZF == 0) jump.
- **Condition:** Applies to approximately 15% of DEC ECX instructions (common in loops)
- **Transformation:** Adds TEST ECX, ECX before DEC to simulate LOOPNZ usage pattern
- **Benefits:**
  - 40% size reduction potential (6 bytes → 4 bytes) in actual LOOPNZ usage
  - Fewer instructions = harder to pattern match
  - Non-standard loop pattern breaks typical detection heuristics
  - Improves instruction cache utilization
- **File:** `src/loopnz_compact_search_obfuscation.c`

### 42. 16-bit Partial Hash Comparison Obfuscation (Priority 83)

- **Name:** `partial_16bit_hash_obfuscation`
- **Priority:** 83
- **Status:** IMPLEMENTED
- **Description:** Simulates the pattern of using only lower 16 bits (DX register) for API hash comparison instead of full 32-bit hashes, adding variation to hash-based API resolution patterns.
- **Condition:** Applies to approximately 10% of XOR/ROR instructions involving DL, DX, or EDX registers
- **Transformation:** Adds NOP after hash-related instructions for pattern variation
- **Benefits:**
  - 16-bit hashes = half the storage space (2 bytes vs 4 bytes)
  - More compact comparison operations
  - Varies signature patterns - not all hash-based lookups use 32-bit
  - Sufficient uniqueness for small API sets (65,536 possible values)
- **File:** `src/partial_16bit_hash_obfuscation.c`

### 43. CALL/POP PIC Delta Retrieval Obfuscation (Priority 95)

- **Name:** `call_pop_pic_delta_obfuscation`
- **Priority:** 95
- **Status:** IMPLEMENTED
- **Description:** Uses CALL instruction's return address mechanism to dynamically retrieve current EIP without hardcoded addresses. Creates fully position-independent shellcode patterns.
- **Condition:** Applies to approximately 5% of MOV/LEA instructions with absolute addressing
- **Transformation:**
  - Inserts CALL/POP pattern: `CALL $+5; POP EDX; LEA EDX, [EDX-5]`
  - Adds PIC (Position-Independent Code) capability to absolute references
- **Benefits:**
  - True position independence - executes from any memory location
  - No hardcoded offsets
  - ASLR bypass capability
  - Only 5-6 bytes overhead for GetPC functionality
  - Allows data co-location with automatic addressing
  - Makes memory dump analysis harder (no absolute addresses)
- **File:** `src/call_pop_pic_delta_obfuscation.c`

### Obfuscation Strategy Priority System

The obfuscation strategy selection system uses a priority-based approach:
- **Highest Priority (99-90):** Runtime encoding/decoding and advanced anti-analysis
- **High Priority (88-80):** Instruction transformation and equivalence substitution
- **Medium Priority (79-70):** Syscall substitution, control flow, register manipulation
- **Low Priority (73-55):** Constant hiding, padding, simple substitutions

### Implementation Notes

1. **Functional Equivalence:** All obfuscation strategies must preserve the original functionality of the shellcode.
2. **Complexity Addition:** Unlike denullification, obfuscation specifically increases complexity and code size.
3. **Analysis Resistance:** The primary goal is to make static and dynamic analysis more difficult.
4. **Performance Impact:** Obfuscation may impact execution performance but preserves functionality.
5. **Composability:** Obfuscation strategies should work well with subsequent denullification strategies.

### Performance Characteristics

- **Obfuscation Pass Time:** Proportional to input shellcode size, typically O(n)
- **Output Size:** Almost always increases code size by 20-100% depending on strategies used
- **Complexity:** Significantly increases static analysis difficulty
- **Runtime Overhead:** May introduce moderate performance overhead

### Testing Considerations

Each obfuscation strategy should be tested with:
- Verification of functional equivalence after obfuscation
- Analysis of increased complexity metrics
- Performance impact assessment
- Compatibility with denullification strategies
- Resistance to deobfuscation tools