# ADD/SUB Encoding for Polymorphic Shellcode

## Concept

This strategy uses ADD/SUB operations to encode immediate values, providing polymorphism by offering multiple equivalent approaches to achieve null-byte elimination.

## Diagram

```
Original: MOV EAX, 0x00730071 (contains null bytes)

ADD/SUB approach #1 (Additive):
  MOV EAX, 0x00720070    ; Base value (null-free)
  ADD EAX, 0x00010001    ; Addend (null-free)
  ; Result: EAX = 0x00730071

ADD/SUB approach #2 (Subtractive):
  MOV EAX, 0x00740072    ; Base value (null-free)
  SUB EAX, 0x00010001    ; Subtrahend (null-free)
  ; Result: EAX = 0x00730071
```

## Process Flow

```
Input: Immediate value with null bytes
  ↓
Try various addend/subtrahend combinations
  ↓
Check if both base value and operation value are null-free
  ↓
If found: generate MOV + ADD/SUB sequence
  ↓
If not found: try alternative strategy (XOR, NEG, NOT, etc.)
  ↓
Output: Equivalent functionality with polymorphic encoding
```

## Visual Representation

```
Multiple encoding options for same value:

Option 1: [MOV + ADD]
  0x00720070 + 0x00010001 = 0x00730071

Option 2: [MOV + SUB] 
  0x00740072 - 0x00010001 = 0x00730071

Option 3: [XOR encoding]
  (0x00730072 XOR 0x00000003) = 0x00730071

Option 4: [NEG encoding]
  NEG(0xFF8CFF8F) = 0x00730071

Strategy selection: Choose most efficient/polymorphic option
```

## Example Implementations

For MOV instruction with null-byte immediate:
```
; Instead of: MOV EAX, 0x00120045
MOV EAX, 0x00110044    ; Base value (null-free)
ADD EAX, 0x00010001    ; Addend (null-free)
; EAX now contains 0x00120045
```

For arithmetic operations:
```
; Instead of: ADD EBX, 0x00730071
PUSH EAX               ; Save temporary register
MOV EAX, 0x00720070    ; Base value (null-free)
ADD EAX, 0x00010001    ; Addend (null-free)
ADD EBX, EAX           ; Perform original operation
POP EAX                ; Restore temporary register
```

## Polymorphic Benefits

```
Same logical operation → Multiple physical implementations

Target: MOV EAX, 0x00730071

Variation 1: MOV EAX, 0x00720070; ADD EAX, 0x00010001
Variation 2: MOV EAX, 0x00740072; SUB EAX, 0x00010001
Variation 3: MOV EAX, 0xFF8CFF8F; NEG EAX
Variation 4: MOV EAX, 0x00730072; XOR EAX, 0x00000003
```

This polymorphism makes detection harder by varying the instruction sequence while maintaining functionality.