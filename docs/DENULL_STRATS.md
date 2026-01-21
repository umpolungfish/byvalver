# DENULLIFICATION STRATEGIES

This document provides comprehensive documentation for all denullification strategies implemented in `byvalver`.

## Overview

`byvalver` uses a modular strategy pattern with over 170+ ranked transformation strategies. Strategies are prioritized by effectiveness and applied in order to eliminate bad bytes while maintaining functional equivalence.

## Strategy Categories

### 1. MOV Strategies
Immediate value loading and register operations.

### 2. Arithmetic Strategies
Mathematical operations and constant construction.

### 3. Memory/Displacement Strategies
Memory access patterns and addressing modes.

### 4. Control Flow Strategies
Jumps, calls, and conditional operations.

### 5. Advanced Techniques
Complex transformations for edge cases.

## New in v4.1: Modern x64 and Obfuscation Strategies

### SETcc Flag Accumulation Chains (Priority 85-86)
**File:** `src/setcc_flag_accumulation_strategies.c`

Replaces conditional jumps with linear SETcc operations that accumulate flag results without jumps.

#### Techniques:
- **SETcc to Register**: `CMP EAX, EBX; SETZ CL; MOVZX ECX, CL`
- **Arithmetic from Flags**: Uses SETcc results in arithmetic operations

**Target:** Conditional jump patterns with bad offset bytes
**Benefit:** Eliminates jump offsets, provides linear code flow

### Polymorphic Immediate Value Construction (Priority 86-90)
**File:** `src/polymorphic_immediate_construction_strategies.c`

Generates multiple equivalent encodings for immediate values to avoid bad bytes.

#### Techniques:
- **XOR Encoding Chain**: `MOV EAX, key1; XOR EAX, key2`
- **ADD/SUB Decomposition**: Split into multiple operations
- **Shift and OR**: Byte-by-byte construction
- **Stack Construction**: PUSH/POP sequences
- **LEA Calculation**: Arithmetic via LEA

**Target:** MOV instructions with bad immediate values
**Benefit:** 5+ encoding variants per immediate value

### Register Dependency Chain Optimization (Priority 91)
**File:** `src/register_dependency_chain_optimization_strategies.c`

Analyzes multi-instruction patterns with register dependencies for optimization.

#### Techniques:
- **Accumulation Folding**: Combine arithmetic sequences
- **Register Copy Elimination**: Remove redundant MOV operations
- **Instruction Reordering**: Change operand order for better encoding

**Target:** Sequential instructions with register dependencies
**Benefit:** Size reduction and bad-char avoidance across instruction boundaries

### RIP-Relative Addressing Optimization (Priority 85-87)
**File:** `src/rip_relative_optimization_strategies.c`

Advanced RIP-relative transformations for x64 position-independent code.

#### Techniques:
- **Offset Decomposition**: `LEA RAX, [RIP]; ADD RAX, offset`
- **Double-RIP Calculation**: Split complex displacements
- **RIP-Relative via Stack**: CALL/POP method for fallback

**Target:** RIP-relative instructions with bad offset bytes
**Benefit:** Maintains PIC properties while avoiding bad bytes

### Negative Displacement Memory Addressing (Priority 82-84)
**File:** `src/negative_displacement_addressing_strategies.c`

Transforms positive displacements with bad bytes using negative offsets and base register adjustments.

#### Techniques:
- **Negative Offset Conversion**: Adjust base register temporarily
- **Alternative Base Register**: Use LEA + indirect access
- **Complement Offset**: Mathematical complement calculations

**Target:** Memory accesses with bad displacement bytes
**Benefit:** Alternative displacement encodings

### Multi-Byte NOP Interlacing (Priority 79-82)
**File:** `src/multibyte_nop_interlacing_strategies.c`

Replaces standard NOP instructions with complex sequences for obfuscation.

#### Techniques:
- **Arithmetic NOPs**: LEA, XCHG, PUSH/POP sequences
- **Register Rotation NOPs**: Multi-register preservation
- **Conditional NOPs**: Appear conditional but always execute
- **FPU NOPs**: Floating-point no-operation instructions

**Target:** NOP instructions of various sizes
**Benefit:** Harder to detect padding, multiple encoding variants

### Bit Manipulation Constant Construction (Priority 80-83)
**File:** `src/bit_manipulation_constant_construction_strategies.c`

Uses modern x64 bit manipulation instructions for constant construction.

#### Techniques:
- **BSWAP**: Byte reordering for endianness conversion
- **BSF/BSR**: Bit scanning for power-of-2 values
- **POPCNT**: Population count for small constants
- **PEXT/PDEP**: Advanced bit extraction/insertion (BMI2)

**Target:** Constants that can be constructed via bit operations
**Benefit:** Modern instruction usage, alternative encodings

## New in v4.2: Enhanced x64 Strategy Support

### x86/x64 Strategy Compatibility Layer
**File:** `src/strategy_registry.c`

Enables 128+ existing x86 strategies to work transparently on x64 shellcode.

#### Implementation:
- **Compatibility Function**: `is_strategy_arch_compatible()` allows x86 strategies on x64
- **Incompatible Instruction Filter**: Automatically excludes x86-only instructions (SALC, ARPL, BOUND, BCD)
- **Zero Code Changes**: Existing strategies work without modification

**Target:** x64 shellcode that was previously failing with 0% success rate
**Benefit:** Immediate access to 128+ proven transformation strategies

### MOVABS 64-bit Immediate Strategies (Priority 90)
**File:** `src/movabs_strategies.c`

Handles 64-bit immediate values in x64 MOV instructions with null byte elimination.

#### Techniques:
- **XOR Key Encoding**: `MOV RAX, encoded; XOR RAX, key` with null-free values
- **ADD/SUB Construction**: Split into arithmetic operations
- **Byte-by-Byte Building**: SHL + OR sequences for complex values
- **32-bit Sign Extension**: Use 32-bit MOV when upper bits are sign-extended

**Target:** `movabs rax, imm64` instructions with null bytes
**Benefit:** Handles 64-bit immediates that 32-bit strategies cannot

### SBB Immediate Zero Strategies (Priority 86)
**File:** `src/sbb_imm_zero_strategies.c`

Transforms SBB (Subtract with Borrow) instructions that use immediate 0, which encodes with null bytes.

#### Techniques:
- **XOR Temp + SBB**: Load 0 into temp register via XOR, use register operand
- **Flag Preservation**: Maintains CF (Carry Flag) semantics
- **Size Variants**: Handles AL, AX, EAX, and RAX operand sizes

**Target:** `SBB AL, 0`, `SBB AX, 0`, `SBB EAX, 0` patterns
**Benefit:** Common idiom in carry-based arithmetic (multi-precision math)

### TEST Large Immediate Strategies (Priority 85)
**File:** `src/test_large_imm_strategies.c`

Transforms TEST instructions with immediate values containing null bytes.

#### Techniques:
- **Register Operand Conversion**: Load immediate to temp register, TEST with register
- **XOR Key Construction**: Build immediate via XOR with null-free key
- **Arithmetic Building**: Construct value through ADD operations

**Target:** `TEST EAX, imm32`, `TEST RAX, imm32` with null-containing immediates
**Benefit:** TEST instructions are common in flag-setting code (40%+ of shellcode)

### SSE Memory Operation Strategies (Priority 88)
**File:** `src/sse_memory_strategies.c`

Handles SSE/SSE2 memory operations where displacement or ModR/M encoding contains null bytes.

#### Techniques:
- **Address Calculation**: Use LEA to compute address in temp register
- **Indirect Access**: Replace `[base+disp]` with `[temp_reg]` form
- **Prefix Handling**: Proper handling of 0x66, 0xF2, 0xF3 prefixes

**Supported Instructions:**
- MOVUPS / MOVAPS (unaligned/aligned packed single)
- MOVDQU / MOVDQA (unaligned/aligned packed double quad)
- MOVSD / MOVSS (scalar double/single)

**Target:** SSE memory operations with null bytes in encoding
**Benefit:** SSE is ubiquitous in modern x64 shellcode (stack operations, data movement)

### LEA x64 Displacement Strategies (Priority 87)
**File:** `src/lea_x64_displacement_strategies.c`

Advanced LEA transformation for x64 with large displacement values.

#### Techniques:
- **Displacement Decomposition**: Split large displacements into arithmetic
- **Base Register Adjustment**: Temporarily adjust base, use smaller displacement
- **Two-Step LEA**: Multiple LEA instructions for complex calculations
- **REX Prefix Handling**: Proper R8-R15 register encoding

**Target:** `LEA RBP, [RSP+0x80]`, `LEA R12, [RBX+large_disp]` patterns
**Benefit:** Stack frame setup is critical in x64 ABI compliance

### Extended Register Support
**File:** `src/utils.c`, `src/core.c`

Utility functions for handling x64 extended registers (R8-R15).

#### New Functions:
- `is_64bit_register(x86_reg)`: Check if register requires REX.W
- `is_extended_register(x86_reg)`: Check if register requires REX.B/R/X
- `build_rex_prefix(w, r, x, b)`: Construct REX prefix byte
- `get_reg_index()` extended: Now handles R8-R15 properly

**Benefit:** Foundation for correct x64 instruction encoding in all strategies

## Legacy Strategy Categories

### MOV Strategies

#### Basic MOV Transformations
- **Original**: Pass-through for valid instructions
- **XOR Decomposition**: `MOV EAX, val` → `XOR EAX, EAX; XOR EAX, val`
- **NEG/NOT Operations**: Two's complement and bitwise NOT transformations
- **Shift-Based**: Using SHL/SHR for value construction

#### Advanced MOV Techniques
- **Arithmetic Decomposition**: Break values into ADD/SUB sequences
- **Stack-Based Loading**: PUSH immediate + POP register
- **LEA-Based Construction**: Use LEA for complex value calculation

### Arithmetic Strategies

#### Basic Operations
- **ADD/SUB**: Original operations with decomposition alternatives
- **XOR/IMUL**: Bitwise and multiplication operations
- **NEG**: Two's complement transformations

#### Advanced Arithmetic
- **Constant Folding**: Pre-compute complex expressions
- **Polynomial Construction**: Build values through mathematical operations
- **Modular Arithmetic**: Use modulo operations for value constraints

### Memory and Displacement Strategies

#### Displacement Handling
- **Zero Displacement**: Convert non-zero to zero displacement via base adjustment
- **SIB Addressing**: Scale-Index-Base transformations
- **RIP-Relative**: Position-independent code optimizations

#### Memory Access Patterns
- **Indirect Addressing**: Pointer-based memory access
- **Segment Registers**: FS/GS segment usage for Windows structures
- **Stack Frame Access**: EBP/ESP based local variable access

### Control Flow Strategies

#### Jump Transformations
- **Conditional Jumps**: Jcc → SETcc + TEST + JMP sequences
- **Unconditional Jumps**: CALL + RET, PUSH + RET patterns
- **Indirect Jumps**: Register-based jump tables

#### Call Transformations
- **Direct Calls**: CALL → PUSH + JMP sequences
- **Indirect Calls**: Function pointer obfuscation
- **API Resolution**: Hash-based Windows API lookup

### Advanced Techniques

#### Windows-Specific Strategies
- **PEB Traversal**: Process Environment Block navigation
- **API Hashing**: Runtime function resolution
- **SALC Instructions**: Undefined opcode for flag manipulation

#### Stack-Based Strategies
- **String Construction**: Build strings on stack
- **Structure Building**: Complex data structure creation
- **Frame Manipulation**: Custom stack frame handling

#### Modern x64 Features
- **SIMD Operations**: XMM register usage for data movement
- **Bit Manipulation**: BMI1/BMI2 instruction usage
- **Advanced Addressing**: Complex SIB and displacement patterns

## Strategy Priority System

Strategies are ranked by priority (higher = applied first):

- **90+**: Critical transformations (syscall handling, immediate construction)
- **80-89**: High-value optimizations (memory, control flow)
- **70-79**: Medium-priority techniques (arithmetic, basic patterns)
- **60-69**: Low-priority fallbacks (generic transformations)
- **<60**: Specialized or experimental techniques

## ML Integration

The ML strategist learns from strategy success/failure to optimize selection:

- **Feature Extraction**: 84-dimensional instruction context vectors
- **Neural Network**: 3-layer feedforward (336→512→200) with softmax output
- **Training**: Success/failure feedback from transformation attempts
- **Fallback**: Deterministic priority ordering when ML unavailable

## Testing and Validation

All strategies are validated for:
- **Functional Equivalence**: Output produces identical results
- **Size Efficiency**: Reasonable code expansion ratios
- **Bad-Byte Elimination**: Complete removal of specified bytes
- **Performance**: Minimal runtime overhead

## Adding New Strategies

To add a new strategy:

1. Create `src/new_strategy.c` and `src/new_strategy.h`
2. Implement the strategy interface functions
3. Register in `src/strategy_registry.c`
4. Add documentation to this file
5. Test with the validation suite

## Performance Metrics

Real-world performance data:
- **Success Rate**: 100% on null-byte elimination test corpus
- **Strategy Coverage**: 170+ active strategies
- **ML Confidence**: Adaptive learning from feedback
- **Size Overhead**: Typically 1.1-1.5x expansion ratio

## Future Enhancements

Planned strategy additions:
- ARM/ARM64 strategy expansion
- Advanced control flow flattening
- Self-modifying code techniques
- AI-assisted strategy generation