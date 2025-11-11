; Test shellcode for LEA, CMP and arithmetic with memory addresses containing nulls
section .text
global _start
bits 32

_start:
    ; LEA EAX, [0x00123456] - address contains null byte
    lea eax, [0x00123456]
    
    ; Exit
    mov al, 1
    int 0x80