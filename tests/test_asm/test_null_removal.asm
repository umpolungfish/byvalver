; Simple test shellcode with null bytes to verify the fixes work
bits 32
section .text
    global _start

_start:
    mov eax, 0x00000001      ; This has null bytes - B8 01 00 00 00
    mov ebx, 0x41414141      ; This doesn't have null bytes
    mov ecx, 0x00000000      ; This has null bytes (all zeros) - B9 00 00 00 00
    add eax, 0x00000005      ; This has null bytes in immediate - 83 C0 05 (no null!)
    sub esp, 0x00000100      ; This has null bytes - 81 EC 00 01 00 00
    call next_instruction    ; Call instruction to test - E8 00 00 00 00
next_instruction:
    nop
    int 0x80                 ; Exit syscall