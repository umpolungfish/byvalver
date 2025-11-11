BITS 32

_start:
    ; Simple shellcode to exit with code 0x12345678
    mov eax, 0x12345678
    mov ebx, 0x00000001 ; exit syscall number
    int 0x80
