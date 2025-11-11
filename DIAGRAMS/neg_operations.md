# Null-Free Immediate Value Construction with NEG Operations

## Concept

This strategy uses NEG (negation) operations to construct immediate values that contain null bytes by loading the negated value and then applying NEG to achieve the target.

## Diagram

```
Original: MOV EAX, 0x00730071 (contains null bytes)

NEG approach:
  MOV EAX, 0xFF8CFF8F    ; Load negated value (-0x00730071, no nulls)
  NEG EAX                ; Negate again to get original value
  ; Result: EAX = 0x00730071

Mathematical basis:
  neg(neg(x)) = x
```

## Process Flow

```
Input: Immediate value with null bytes
  ↓
Calculate negated value (-imm)
  ↓
Check if negated value is null-free
  ↓
If null-free: generate MOV + NEG sequence
  ↓
If not null-free: try alternative strategy
  ↓
Output: Equivalent functionality without null bytes in instructions
```

## Visual Representation

```
  Original Value: 0x00730071
         ↓
    Negate: -0x00730071 = 0xFF8CFF8F
         ↓
    Store in register if null-free
         ↓
    Apply NEG to get original value
         ↓
    Result: 0x00730071 in register
```

## Example Implementation

For EAX register:
```
MOV EAX, 0xFF8CFF8F    ; Load negated value (null-free)
NEG EAX                ; Get original value
```

For non-EAX registers:
```
PUSH EAX               ; Save EAX
MOV EAX, 0xFF8CFF8F    ; Load negated value in EAX (null-free)
MOV EBX, EAX           ; Move to target register
NEG EBX                ; Negate to get original value
POP EAX                ; Restore EAX
```

## For Arithmetic Operations

For ADD, SUB, AND, OR, XOR, CMP operations:
```
PUSH ECX               ; Save temporary register
MOV ECX, 0xFF8CFF8F    ; Load negated immediate (null-free)
NEG ECX                ; Get original immediate value
ADD EAX, ECX           ; Perform operation with original value
POP ECX                ; Restore temporary register
```