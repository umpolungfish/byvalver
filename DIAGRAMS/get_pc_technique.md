# GET PC (Get Program Counter) Technique

## Concept

This strategy uses CALL/POP to retrieve the current program counter, enabling null-free loading of immediate values by embedding them as data after CALL instructions.

## Diagram

```
Original: MOV EAX, 0x00730071 (contains null bytes)

GET PC approach:
  CALL next_instruction    ; Push return address onto stack
  embedded_data: DD 0x00730071  ; Data embedded after CALL (may contain nulls)
  next_instruction:
  POP EBX                 ; Get current address (points to embedded_data)
  MOV EAX, [EBX]          ; Load the immediate value from memory
  ADD EBX, 4              ; Move to next data if needed
```

## Process Flow

```
Input: MOV reg, immediate_value with null bytes
  ↓
Replace with CALL to next instruction
  ↓
Embed immediate value as data after CALL
  ↓
Use POP to retrieve address of embedded data
  ↓
Use memory access to load the value
  ↓
Output: Position-independent code without null bytes in instructions
```

## Visual Representation

```
Stack before:
  [ ... ]
  [ return addr ]

→ CALL next_instruction
  ↓
Stack during:
  [ ... ]
  [ return addr ] ← ESP points here

→ POP EBX
  ↓
EBX = return addr (points to embedded data)

→ MOV EAX, [EBX]
  ↓
EAX = value from embedded data
```

## Benefits

- Creates position-independent code
- Avoids null bytes in instruction stream
- Embedded data can contain nulls without causing string termination