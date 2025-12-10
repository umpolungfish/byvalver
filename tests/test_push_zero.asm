; Test PUSH 0 specifically
BITS 32

_start:
    push 0      ; This is 6A 00 - has null byte
    push 0x80   ; This is 68 80 00 00 00 - has null bytes
    ret
