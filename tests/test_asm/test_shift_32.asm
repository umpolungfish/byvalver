; Test shellcode with 32-bit immediate values that contain null bytes
; This file is for testing the shift-based strategy

bits 32
section .text
    global _start

_start:
    ; MOV EAX, 0x00112233  ; This contains null byte - should trigger shift strategy
    mov eax, 0x00112233
    
    ; MOV EBX, 0x00200000  ; This contains multiple null bytes - good for arithmetic or shift strategy
    mov ebx, 0x00200000
    
    ; MOV ECX, 0x00001000  ; This has null bytes
    mov ecx, 0x00001000
    
    ; MOV EDX, 0x12345678  ; This is null-free, should not trigger our strategy
    mov edx, 0x12345678
    
    ; Exit syscall
    mov eax, 1          ; sys_exit
    int 0x80