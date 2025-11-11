; Assembly test file to create shellcode with NEG strategy applicable immediate values
; This file will be assembled and tested

section .text
    ; MOV EAX, 0x800000 (has no null bytes but we'll use one that does)
    ; Use MOV EAX, 0x00800000 (this has a null byte which when negated becomes 0xFF800000 - no nulls)
    ; Actually we want MOV EAX, 0x0090FF8E which would become 0xFF6F0072 when negated
    
    ; For testing purpose, we can't just write assembly like this directly to binary
    ; Let's create the raw bytes manually for a MOV EAX, 0x0090FF8E instruction
    ; 0xB8 0x8E 0xFF 0x90 0x00 = MOV EAX, 0x0090FF8E
    ; This contains a null byte at the end that should trigger our NEG strategy
    ; If our NEG strategy works, it should use MOV EAX, 0xFF6F0072 followed by NEG EAX
    ; Since 0x0090FF8E negated is 0xFF6F0072
    ; Wait, that's not how negation works.
    ; -0x0090FF8E = 0xFF6F0072? Let me check: 
    ; 0x0090FF8E = 9503630
    ; -9503630 = -9503630
    ; In 2's complement: 0xFFFFFFFF - 0x0090FF8E + 1 = 0xFF6F0071 + 1 = 0xFF6F0072
    ; Yes that's correct!

    ; We'll create the raw bytes manually to test
    db 0xB8, 0x8E, 0xFF, 0x90, 0x00   ; MOV EAX, 0x0090FF8E
    db 0xBB, 0x8E, 0xFF, 0x8C, 0x00   ; MOV EBX, 0x008CFF8E
    db 0xB9, 0x8E, 0x00, 0x9E, 0x00   ; MOV ECX, 0x009E008E - this has a zero in the middle