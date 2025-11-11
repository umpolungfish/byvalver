section .text
    global _start

_start:
    ; MOV EAX, 0x00730072 - this contains null bytes at positions 1 and 3 (little endian: 72 00 73 00)
    ; The negation would be: 0 - 0x00730072 = 0xFF8CFF8E = 8E FF 8C FF little endian (no nulls!)
    ; So byvalver should potentially use: MOV EAX, 0xFF8CFF8E; NEG EAX
    ; which achieves the same effect as MOV EAX, 0x00730072 but without null bytes
    mov eax, 0x00730072