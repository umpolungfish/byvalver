; Test file for Partial Register Optimization Strategy
; This contains MOV r8, imm8 instructions that will have null bytes in encoding

BITS 32

; Test 1: MOV with zero immediate (will encode with 0x00 byte)
mov al, 0x00      ; B0 00 - has null byte
mov bl, 0x00      ; B3 00 - has null byte
mov cl, 0x00      ; B1 00 - has null byte
mov dl, 0x00      ; B2 00 - has null byte

; Test 2: MOV with non-zero immediate (should still be handled efficiently)
mov al, 0x42      ; B0 42 - no null, but strategy should handle
mov bl, 0xFF      ; B3 FF - no null
mov cl, 0x01      ; B1 01 - no null
mov dl, 0x7F      ; B2 7F - no null

; Test 3: MOV to high byte registers with zero
mov ah, 0x00      ; B4 00 - has null byte
mov bh, 0x00      ; B7 00 - has null byte
mov ch, 0x00      ; B5 00 - has null byte
mov dh, 0x00      ; B6 00 - has null byte

; Test 4: MOV to high byte registers with non-zero
mov ah, 0x55      ; B4 55 - no null
mov bh, 0xAA      ; B7 AA - no null
mov ch, 0x12      ; B5 12 - no null
mov dh, 0x34      ; B6 34 - no null

; Test 5: Mixed with other instructions (should not be affected)
xor eax, eax      ; 31 C0 - no null
inc ecx           ; 41 - no null
push ebx          ; 53 - no null
pop edi           ; 5F - no null

; Test 6: More MOV r8, imm8 with nulls
mov al, 0x00      ; B0 00
mov bl, 0x00      ; B3 00
mov cl, 0x00      ; B1 00
mov dl, 0x00      ; B2 00

; End marker
ret               ; C3
