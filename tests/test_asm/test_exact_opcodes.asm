; Test assembly with specific problematic opcodes - more explicit
bits 32
section .text
    global _start

_start:
    mov eax, 0x00000001      ; B8 01 00 00 00 (has nulls)
    mov ebx, 0x41414141      ; BB 41 41 41 41 (no nulls)
    mov ecx, 0x00000000      ; B9 00 00 00 00 (has nulls)
    sub esp, 0x00000100      ; 83 EC 00 or 81 EC 00 01 00 00 (has nulls)
    ; To create a CALL with nulls in displacement, we need to use a far address
    ; So we'll create an exact byte sequence for the problematic instruction:
    db 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00  ; SUB ESP, 0x100 (81 EC 00 01 00 00)
    db 0xE8, 0x00, 0x00, 0x00, 0x00        ; CALL 0x5 with null displacement (E8 00 00 00 00)
    nop
    int 0x80                 ; Exit syscall