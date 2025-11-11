section .text
    global _start

_start:
    ; MOV EAX, 0x00120045 - this contains null bytes at positions 1 and 3 in little endian
    ; Byte representation: 45 00 12 00 (little endian) - has nulls
    ; NEG equivalent: 0 - 0x00120045 = 0xFFEDFFBB, which in little endian is BB FF ED FF (no nulls)
    mov eax, 0x00120045