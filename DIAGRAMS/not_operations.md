# Null-Free Immediate Value Construction with NOT Operations

## Concept

This strategy uses NOT operations to construct immediate values that contain null bytes by loading the bitwise NOT of the value and then applying NOT to achieve the target.

## Diagram

```
Original: MOV EAX, 0x11220033 (contains null bytes)

NOT approach:
  MOV EAX, 0xEEDDFFCC    ; Load bitwise NOT of value (~0x11220033, no nulls)
  NOT EAX                ; Apply NOT again to get original value
  ; Result: EAX = 0x11220033

Mathematical basis:
  NOT(NOT(x)) = x
```

## Process Flow

```
Input: Immediate value with null bytes
  ↓
Calculate bitwise NOT of value (~imm)
  ↓
Check if NOT-ed value is null-free
  ↓
If null-free: generate MOV + NOT sequence
  ↓
If not null-free: try alternative strategy
  ↓
Output: Equivalent functionality without null bytes in instructions
```

## Visual Representation

```
  Original Value: 0x11220033
         ↓
    Bitwise NOT: ~0x11220033 = 0xEEDDFFCC
         ↓
    Store in register if null-free
         ↓
    Apply NOT to get original value
         ↓
    Result: 0x11220033 in register
```

## Example Implementation

```
MOV EAX, 0xEEDDFFCC    ; Load NOT-ed value (null-free)
NOT EAX                ; Get original value
```

## For XOR Operations

For XOR reg, imm where imm contains nulls:
```
PUSH EBX               ; Save temporary register
MOV EBX, 0xEEDDFFCC    ; Load NOT-ed immediate (null-free)
NOT EBX                ; Get original immediate value
XOR EAX, EBX           ; Perform XOR with original value
POP EBX                ; Restore temporary register
```