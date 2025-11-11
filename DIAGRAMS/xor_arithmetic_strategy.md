# XOR-Based Arithmetic Operation Strategy

## Concept

This strategy encodes immediate values for arithmetic operations using XOR to avoid null bytes, temporarily storing the encoded value in a register, decoding it, and then performing the desired operation.

## Diagram

```
Original: ADD EAX, 0x00730071 (contains null bytes)

XOR approach:
  PUSH EBX                    ; Save temporary register
  MOV EBX, 0x00730072        ; Load (imm XOR key), where key=0x00000003
  XOR EBX, 0x00000003        ; Decode to get original immediate 0x00730071
  ADD EAX, EBX               ; Perform operation with decoded value
  POP EBX                    ; Restore temporary register
```

## Process Flow

```
Input: Arithmetic operation with immediate value containing null bytes
  ↓
Find appropriate XOR key to make (imm XOR key) null-free
  ↓
Generate: MOV temp_reg, (imm XOR key)
  ↓
Generate: XOR temp_reg, key
  ↓
Generate: arithmetic_op target_reg, temp_reg
  ↓
Restore temporary register
  ↓
Output: Equivalent functionality without null bytes in instructions
```

## Visual Representation

```
  Original: [OP reg, imm] where imm has nulls
         ↓
    Find key where (imm XOR key) has no nulls
         ↓
    [MOV temp_reg, (imm XOR key)] ← null-free
         ↓
    [XOR temp_reg, key] ← restores original imm
         ↓
    [OP reg, temp_reg] ← performs original operation
         ↓
    Result: Same functionality, no null bytes in instructions
```

## Example Implementation

For ADD, SUB, AND, OR, XOR, CMP operations:
```
PUSH temp_reg            ; Save temporary register
MOV temp_reg, (imm32 XOR key)  ; Load encoded immediate (null-free)
XOR temp_reg, key        ; Decode to get original immediate
OP reg, temp_reg         ; Perform original operation
POP temp_reg             ; Restore temporary register
```

## Key Selection Process

```
Input: imm32 with null bytes
  ↓
Try different keys until (imm32 XOR key) is null-free
  ↓
Key options: 0x01, 0x02, 0x03, ..., 0xFF, 0x0100, etc.
  ↓
Select first key that makes (imm32 XOR key) null-free
  ↓
If no suitable key found, try alternative strategy
```