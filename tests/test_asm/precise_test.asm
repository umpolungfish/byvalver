; Simple assembly code that should generate specific MOV instructions with null bytes
section .text
global _start

_start:
    mov eax, 0x00730071  ; B8 71 00 73 00 - has null bytes
    mov ebx, 0x00FF0000  ; BB 00 00 FF 00 - has null bytes
    add eax, 0x00AABBCC  ; 83 C0 ?? - but 81 C0 CC BB AA 00 - has null bytes
    nop
    ret