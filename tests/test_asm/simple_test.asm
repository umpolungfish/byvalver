; Simple test assembly with clear null byte patterns
section .text
    global _start

_start:
    mov eax, 0x00112233      ; This has null bytes (0x00112233)  
    mov ebx, 0x44005566      ; This has null bytes (0x44005566)
    mov ecx, 0               ; This should zero ECX
    mov edx, 0               ; This should zero EDX