bits 32

_start:
    mov eax, 0x00730071  ; Should generate: B8 71 00 73 00 
    mov ebx, 0x00FF0000  ; Should generate: BB 00 00 FF 00
    add eax, 0x00AABBCC  ; Should generate: 81 C0 CC BB AA 00
    nop
    ret