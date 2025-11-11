# Shift-Based Immediate Value Construction

## Concept

This strategy uses shift operations (SHL/SHR) when direct immediate values contain null bytes.

## Diagram

```
Original: MOV EAX, 0x001FF000 (contains null bytes)

Alternative approach using shifts:
  MOV EAX, 0x00001FF0    ; base value without nulls
  SHL EAX, 12            ; shift left by 12 bits
  ; Result: EAX = 0x001FF000

Example from linux_x86/37390.asm:
  PUSH 0x1FF9090         ; encoded value
  SHR ECX, 0x10          ; shift right by 16 bits
  ; Result: ECX = 0x000001FF
```

## Process Flow

```
Input: Immediate value with null bytes
  ↓
Check if value can be formed via shifting a null-free value
  ↓
Find base value and shift amount without null bytes
  ↓
Generate MOV + shift instruction sequence
  ↓
Output: Equivalent functionality without null bytes
```

## Visual Representation

```
  [0x00001FF0] → [SHL 12] → [0x001FF000]
     Base        Shift        Target
   (no nulls)   Amount       Value
```