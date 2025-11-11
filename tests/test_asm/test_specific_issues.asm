; Test assembly with specific problematic opcodes
bits 32
section .text
    global _start

_start:
    mov eax, 0x00000001      ; MOV EAX, 1 -> B8 01 00 00 00 (has nulls)
    mov ebx, 0x41414141      ; MOV EBX, 0x41414141 -> BB 41 41 41 41 (no nulls)
    mov ecx, 0x00000000      ; MOV ECX, 0 -> B9 00 00 00 00 (all nulls!)
    ; The instruction from the bug report: sub esp, 0x100
    sub esp, 0x00000100      ; SUB ESP, 0x100 -> 81 EC 00 01 00 00 (has nulls)
    ; The call instruction from the bug report
    call 0x00000005          ; CALL 0x5 -> E8 00 00 00 00 (all nulls in displacement!)
    nop
    int 0x80                 ; Exit syscall