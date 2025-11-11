# BYVALVER Strategy Diagrams

This directory contains diagrams for all the advanced strategies implemented in BYVALVER for null-byte shellcode elimination.

## List of Strategy Diagrams

1. [Arithmetic Equivalent Replacement](arithmetic_equivalent_replacement.md)
   - Uses arithmetic combinations to avoid null bytes in immediate operands
   - Example: `mov bx,1666; sub bx,1634` to achieve 0x0020 without nulls

2. [Shift-Based Construction](shift_based_construction.md)
   - Uses shift operations (SHL/SHR) to construct values that would otherwise contain null bytes
   - Example: `MOV EAX, 0x00001FF0; SHL EAX, 12` instead of direct MOV

3. [GET PC (Get Program Counter) Technique](get_pc_technique.md)
   - Uses CALL/POP to retrieve the current program counter for position-independent code
   - Embeds immediate values as data after CALL instructions

4. [Decoder Stub Implementation](decoder_stub_implementation.md)
   - Encodes shellcode and includes a decoder stub to restore functionality at runtime
   - Uses XOR, ADD/SUB or other operations to avoid null bytes in the initial payload

5. [Null-Free Immediate Value Construction with NEG Operations](neg_operations.md)
   - Uses NEG (negation) operations to construct immediate values containing null bytes
   - Example: Load negated value then apply NEG to restore original

6. [Null-Free Immediate Value Construction with NOT Operations](not_operations.md)
   - Uses NOT operations to construct immediate values containing null bytes
   - Based on the property that NOT(NOT(x)) = x

7. [XOR-Based Arithmetic Operation Strategy](xor_arithmetic_strategy.md)
   - Encodes immediate values for arithmetic operations using XOR to avoid null bytes
   - Temporarily stores encoded value in register, decodes it, then performs operation

8. [Generic Memory Operand Handling Strategy](memory_operand_handling.md)
   - Handles instructions with memory operands containing null bytes in displacement
   - Transforms to use register-based addressing instead of direct displacement

9. [ADD/SUB Encoding for Polymorphic Shellcode](add_sub_encoding.md)
   - Uses ADD/SUB operations to encode immediate values for polymorphism
   - Provides multiple equivalent approaches for same null-byte elimination goal

10. [Byte-by-Byte Construction Fallback](byte_by_byte_construction.md)
    - Constructs any 32-bit value byte by byte when other strategies fail
    - Uses shifts, OR operations, and register manipulation to avoid null bytes