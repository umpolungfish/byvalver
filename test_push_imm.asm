; Test file for PUSH immediate with null bytes
; This file contains PUSH instructions with immediate values that have null bytes

BITS 32

_start:
    ; PUSH 0x100 - has null bytes: 68 00 01 00 00
    push 0x100

    ; PUSH 0x104 - has null bytes: 68 04 01 00 00
    push 0x104

    ; PUSH 0x1000 - has null bytes: 68 00 10 00 00
    push 0x1000

    ; PUSH 0x6 - null-free: 6A 06 (sign-extended)
    push byte 0x6

    ; PUSH 0x10 - null-free: 6A 10
    push byte 0x10

    ; Exit syscall
    xor eax, eax
    inc eax
    int 0x80
