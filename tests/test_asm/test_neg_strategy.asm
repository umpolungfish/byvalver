section .text
    global _start

_start:
    ; MOV EAX, 0x00ABCDEF - this contains a null byte at position 0
    ; The negation will be: 0 - 0x00ABCDEF = 0xFF543211 (which has no nulls)
    ; So BYVALVER should use: MOV EAX, 0xFF543211; NEG EAX
    mov eax, 0x00ABCDEF