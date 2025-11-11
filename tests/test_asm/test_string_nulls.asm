section .text
    global _start

_start:
    ; Example that will have null bytes in immediate values that represent strings
    mov eax, 0x00676574   ; "get" with null byte at the start
    mov ebx, 0x6c6c6500   ; "ell" with null byte at the end  
    mov ecx, 0x00737562   ; "sub" with null byte at the start
    mov edx, 0x6e6f6300   ; "con" with null byte at the end