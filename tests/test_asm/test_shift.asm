; Test shellcode with immediate values that contain null bytes
; This file is for testing the shift-based strategy

section .text
    global _start

_start:
    ; MOV EAX, 0x00112233  ; This contains null byte - should trigger shift strategy
    mov eax, 0x00112233
    
    ; MOV EBX, 0x00200000  ; This contains multiple null bytes - good for arithmetic or shift strategy
    mov ebx, 0x00200000
    
    ; MOV ECX, 0x1000      ; This has a null word
    mov ecx, 0x1000
    
    ; MOV EDX, 0x12345678  ; This is null-free, should not trigger our strategy
    mov edx, 0x12345678
    
    ; Exit syscall
    mov eax, 1          ; sys_exit
    int 0x80