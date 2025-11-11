bits 32
section .text
    global _start

_start:
    ; MOV EAX, 0x00730072 - this contains null bytes
    mov eax, 0x00730072