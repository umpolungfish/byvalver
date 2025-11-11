; Test shift-based strategy with specific patterns
; This should contain values that our shift strategy can optimize

bits 32
section .text
    global _start

_start:
    ; MOV EAX, 0x00001000 - multiple null bytes (should be good for shift strategy)
    mov eax, 0x00001000

    ; MOV EBX, 0x00200000 - multiple null bytes
    mov ebx, 0x00200000

    ; MOV ECX, 0x10000000 - multiple null bytes
    mov ecx, 0x10000000
    
    ; Exit syscall
    mov eax, 1
    mov ebx, 0
    int 0x80