; 32-bit test file with MOV EAX, 0x00112233 (contains null byte)
section .text
global _start
bits 32

_start:
    ; MOV EAX, 0x00112233 - This should contain null bytes (32-bit version)
    mov eax, 0x00112233
    
    ; Exit
    mov al, 1
    int 0x80