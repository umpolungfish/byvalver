# Denull Strategies To Be Implemented

This document outlines the denull strategies that need to be implemented in BYVALVER to further enhance its null-byte elimination capabilities.

## Strategy 1: PUSH Immediate with SIB Addressing
- **Description**: Transform PUSH operations with immediate values containing nulls by first loading the value into a register using null-free instructions, then PUSHing the register. For complex immediates, use SIB addressing to construct the value.
- **Target Instructions**: X86_INS_PUSH with immediate operands containing null bytes
- **Implementation Approach**: MOV reg, imm (null-free) + PUSH reg or use SIB addressing techniques
- **Priority**: Medium-High

## Strategy 2: LEA with Complex Displacement
- **Description**: Use the LEA (Load Effective Address) instruction with complex displacement values to construct immediate values containing nulls without directly encoding them in instruction immediates.
- **Target Instructions**: MOV reg, imm32 where imm32 contains null bytes
- **Implementation Approach**: Calculate a null-free address expression that resolves to the target value
- **Priority**: High

## Strategy 3: XCHG-based Immediate Loading
- **Description**: Use XCHG (Exchange) instructions with temporary registers to load immediate values containing nulls without directly using immediate operands with nulls.
- **Target Instructions**: MOV reg, imm where imm contains null bytes
- **Implementation Approach**: Load value via XCHG operations with pre-loaded or calculated values
- **Priority**: Medium

## Strategy 4: String Instruction with Null Construction
- **Description**: Use STOSB, STOSD, or similar string instructions with loops to construct immediate values containing nulls in memory rather than through direct immediate encoding.
- **Target Instructions**: MOV reg, imm where imm contains null bytes
- **Implementation Approach**: Use ECX counter and string instructions to build the target value byte by byte
- **Priority**: Medium-Low

## Strategy 5: Conditional Flag Manipulation
- **Description**: Transform conditional jumps with null bytes in displacement to use alternate flag manipulation techniques, such as preserving the flag state through different instruction sequences.
- **Target Instructions**: Conditional jumps (JE, JNE, JZ, JNZ, etc.) with displacements containing null bytes
- **Implementation Approach**: Use a register to mirror flag state, then perform conditional jump based on register value
- **Priority**: High

## Strategy 6: PEB Traversal & API Hashing
- **Description**: Dynamically resolve API addresses by traversing the Process Environment Block (PEB) and hashing function names, avoiding hardcoded strings and nulls in API names and their addresses.
- **Target Instructions**: Any API call with string names or addresses that might contain nulls.
- **Implementation Approach**: Implement PEB parsing logic and a hashing algorithm to find API addresses at runtime.
- **Priority**: High

## Strategy 7: Stack-based String/Constant Construction
- **Description**: Construct strings (e.g., "ws2_32") and complex constants directly on the stack using multiple `PUSH` operations with non-null bytes, avoiding direct string literals or immediate values with nulls.
- **Target Instructions**: String literals or immediate constants containing nulls.
- **Implementation Approach**: Break down strings/constants into non-null byte chunks and push them onto the stack.
- **Priority**: Medium-High

## Strategy 8: Arithmetic/Bitwise Constant Generation
- **Description**: Generate constants (e.g., `0x10`, `0x300`) through register manipulation, increment/decrement, or bitwise operations instead of direct immediate values that might contain nulls.
- **Target Instructions**: Instructions using immediate values that contain nulls.
- **Implementation Approach**: Use sequences like `MOV CH, 0x3` and `SUB ESP, ECX` or `INC reg` to achieve desired constant values.
- **Priority**: Medium

## Strategy 9: SALC + REP STOSB for Null-filled Buffers
- **Description**: Utilize `SALC` to set `AL` to zero and then `REP STOSB` to efficiently fill memory regions with null bytes without embedding them in instructions, useful for initializing structures or buffers.
- **Target Instructions**: Operations requiring null-filled memory regions.
- **Implementation Approach**: Implement a sequence of `SALC` followed by `REP STOSB` with appropriate `ECX` setup.
- **Priority**: Low-Medium

## Strategy 10: XOR reg, reg for Zeroing Registers
- **Description**: Consistently use the `XOR` instruction with the same register to zero it out, which is a a classic null-byte-free alternative to `MOV reg, 0`.
- **Target Instructions**: Any instruction that zeroes a register using a null byte (e.g., `MOV reg, 0`).
- **Implementation Approach**: Replace `MOV reg, 0` with `XOR reg, reg`.
- **Priority**: High

## Strategy 6: Zero-Byte Immediate to XOR Substitution
- **Description**: Transform immediate operations with zero values that create null bytes by using XOR operations that achieve the same result without null bytes in the instruction encoding.
- **Target Instructions**: MOV reg, 0, PUSH 0, and other operations with immediate zero values
- **Implementation Approach**: Replace with XOR reg, reg for MOV reg, 0 or use INC/DEC pairs for PUSH 0
- **Priority**: High

## Strategy 7: Immediate Value Arithmetic Reconstruction
- **Description**: Transform immediate values containing null bytes (e.g., 0x00123456) by using arithmetic operations to reconstruct the value from null-free components.
- **Target Instructions**: MOV reg, imm32 where high byte of imm32 is zero
- **Implementation Approach**: Use ADD, SUB, LEA, or other arithmetic to reconstruct the value from smaller null-free components
- **Priority**: High

## Strategy 8: CALL/POP for Immediate Loading
- **Description**: Use the CALL/POP technique to load immediate values that contain null bytes by pushing the value onto the stack and retrieving it without directly encoding the nulls.
- **Target Instructions**: MOV reg, imm32 where imm32 contains null bytes
- **Implementation Approach**: CALL next_instruction; dd immediate_value; next_instruction: POP reg
- **Priority**: Medium-High

## Strategy 9: SIB Addressing for Displacement Nulls
- **Description**: When displacement fields in memory operations contain null bytes, use SIB (Scale-Index-Base) addressing to avoid encoding the null displacement directly.
- **Target Instructions**: MOV reg, [base + disp32] where disp32 contains null bytes
- **Implementation Approach**: Convert to [base + index*scale + adjusted_disp] to eliminate null bytes in displacement
- **Priority**: Medium-High

## Strategy 10: Flag-Based Conditional Jumps
- **Description**: Transform conditional jumps with null bytes in displacement by using flag manipulation and unconditional jumps to equivalent locations, bypassing the null displacement issue.
- **Target Instructions**: Conditional jumps (JNE, JZ, JNZ, etc.) with displacements containing null bytes
- **Implementation Approach**: Use flag-preserving operations to set up an inverse condition with a short jump
- **Priority**: Medium

## Strategy 11: Stack-Based Immediate Reconstruction
- **Description**: Push null-free byte components onto the stack and use MOV operations to reconstruct values containing null bytes in registers.
- **Target Instructions**: MOV reg, imm32 where imm32 contains null bytes
- **Implementation Approach**: Push individual bytes or smaller null-free components and rebuild the full value using stack operations
- **Priority**: High

## Strategy 12: Byte-by-Byte Memory Construction
- **Description**: Construct immediate values containing null bytes by pushing null-free components and using byte-level operations to build the desired value in memory or registers.
- **Target Instructions**: MOV reg, imm32 where imm32 contains null bytes
- **Implementation Approach**: Use multiple PUSH operations with null-free values followed by byte-level MOV operations to reconstruct the full value
- **Priority**: High

## Strategy 13: Shift-Based Value Construction
- **Description**: Use bit shift operations (SHL, SHR) combined with arithmetic operations to construct immediate values that contain null bytes.
- **Target Instructions**: MOV reg, imm32 where imm32 contains null bytes
- **Implementation Approach**: Shift and arithmetic operations to build the value from null-free components
- **Priority**: Medium-High

## Strategy 14: XOR-Encoding with Runtime Decoding
- **Description**: Encode immediate values containing null bytes using XOR operation with a key, and include a small decoder stub to restore the original value at runtime.
- **Target Instructions**: MOV reg, imm32 where imm32 contains null bytes
- **Implementation Approach**: Transform the immediate to an XOR-encoded form with null-free components and include small decoder stub
- **Priority**: Medium

## Strategy 15: Register Swapping with Immediate Loading
- **Description**: Use register exchange operations to load immediate values containing null bytes by first loading null-free partial values and then exchanging them.
- **Target Instructions**: MOV reg, imm32 where imm32 contains null bytes
- **Implementation Approach**: Load partial values using null-free immediates, then use XCHG or MOV to reposition the bytes in the correct order
- **Priority**: Medium