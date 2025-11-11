# Generic Memory Operand Handling Strategy

## Concept

This strategy handles any instruction with memory operands containing null bytes in displacement by transforming them to use register-based addressing instead of direct displacement.

## Diagram

```
Original: JMP [0x00112233] (displacement contains null bytes)

Register-based approach:
  MOV EAX, 0x00112233    ; Load displacement into register (null-free construction)
  JMP [EAX]              ; Use register-based addressing

Alternative for other operations:
  MOV EAX, 0x00112233    ; Load displacement into register (null-free construction)
  MOV EBX, [EAX]         ; Access memory using register-based addressing
```

## Process Flow

```
Input: Instruction with memory operand [disp32] where disp32 contains null bytes
  ↓
Detect memory operand with null-byte displacement
  ↓
Generate MOV instruction to load displacement into register
  ↓
Transform original instruction to use register-based addressing
  ↓
Use null-free construction methods for the MOV immediate value
  ↓
Output: Equivalent functionality without null bytes in displacement
```

## Visual Representation

```
Before:
  [Instruction] [displacement with nulls]
  JMP           [0x00112233]

After:
  MOV EAX, [null-free construction of 0x00112233]  ; Could use NEG, NOT, XOR, etc.
  JMP [EAX]                                       ; Register-based addressing
```

## Example Implementations

For JMP with null-byte displacement:
```
MOV EAX, 0x00112233    ; Load displacement (using null-free construction)
JMP [EAX]              ; Jump to address in register
```

For CALL with null-byte displacement:
```
MOV EAX, 0x40000000    ; Load displacement (using null-free construction)
CALL [EAX]             ; Call address in register
```

For MOV with null-byte displacement:
```
MOV EAX, 0x00112233    ; Load displacement (using null-free construction)
MOV EBX, [EAX]         ; Move from address in register
```

## Multiple Instruction Support

The strategy handles various instructions:
- JMP [disp32] → MOV reg, disp32 + JMP [reg]
- CALL [disp32] → MOV reg, disp32 + CALL [reg] 
- MOV reg, [disp32] → MOV reg2, disp32 + MOV reg, [reg2]
- PUSH [disp32] → MOV reg, disp32 + PUSH [reg]
- etc.