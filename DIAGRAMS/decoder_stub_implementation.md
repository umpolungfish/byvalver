# Decoder Stub Implementation

## Concept

This strategy uses self-decoding techniques where shellcode is encoded (e.g., XOR, ADD/SUB) and then decoded at runtime, avoiding null bytes in the initial payload.

## Diagram

```
Original shellcode: [A0 00 B0 00 C0 00] (contains null bytes)

Encoded shellcode:  [A1 01 B1 01 C1 01] (no null bytes, XOR'd with key 0x01)
Decoder stub:       [decode instructions]
                    ↓
Runtime execution:
  ↓
Decoder stub iterates through encoded payload
  ↓
Each byte is decoded (XOR'd back with key)
  ↓
Final payload in memory: [A0 00 B0 00 C0 00] (original functionality)
```

## Process Flow

```
Input: Shellcode with null bytes
  ↓
Encode entire payload using XOR/ADD/SUB with chosen key
  ↓
Generate decoder stub that iterates and decodes
  ↓
Combine: [Decoder Stub] + [Encoded Payload]
  ↓
Output: Null-free shellcode that decodes to original functionality at runtime
```

## Visual Representation

```
Before execution:
  [Decoder Stub] [Encoded Payload]
  [48 FF C6 01] [A1 01 B1 01 C1 01]

At runtime:
  ↓ (decoder executes)
  [Decoded Payload in memory]
  [A0 00 B0 00 C0 00] (original functionality restored)
```

## Example Implementation

```
; Decoder stub example (XOR-based)
  CALL get_payload          ; Get address of encoded payload
  POP ESI                   ; ESI points to payload
  MOV ECX, PAYLOAD_SIZE     ; ECX = size of payload
  MOV EAX, 0x90             ; EAX = XOR key

decode_loop:
  XOR [ESI], AL             ; Decode current byte
  INC ESI                   ; Move to next byte
  LOOP decode_loop          ; Repeat until done

  ; Jump to decoded payload
  JMP decoded_start

get_payload:
  CALL next_location        ; Trick to get EIP
next_location:
  ; Encoded payload follows...
```