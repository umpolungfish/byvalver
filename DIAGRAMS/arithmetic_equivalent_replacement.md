# Arithmetic Equivalent Replacement Strategy

## Concept

This strategy finds arithmetic combinations that produce target values without null bytes in immediate operands.

## Diagram

```
Original: MOV EAX, 0x0020 (contains null bytes)

Find alternatives: target = first_val ± second_val

Example:
  target = 0x0020 (32 decimal)
  first_val = 1666 (0x682)
  second_val = 1634 (0x662)
  1666 - 1634 = 32 (0x0020)

Transformation:
  MOV BX, 1666     ; first_val (no nulls)
  SUB BX, 1634     ; second_val (no nulls)  
  MOV EAX, EBX     ; move result to target reg

Alternative approach:
  MOV EAX, 0x00001FF0    ; load base value without nulls
  SHL EAX, 12            ; shift to get target value
```

## Process Flow

```
Input: Immediate value with null bytes
  ↓
Find arithmetic combinations (±) without null bytes
  ↓
Calculate target = first_val ± second_val
  ↓
Generate MOV + arithmetic instruction sequence
  ↓
Output: Equivalent functionality without null bytes
```