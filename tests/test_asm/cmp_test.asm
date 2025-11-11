; Test CMP [address], register where address contains nulls
section .text
global _start
bits 32

_start:
    ; CMP [0x00123456], EAX - address contains null byte
    cmp dword [0x00123456], eax
    
    ; Exit
    mov al, 1
    int 0x80