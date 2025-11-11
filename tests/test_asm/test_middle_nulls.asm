section .text
    global _start

_start:
    ; MOV EAX, 0x12005678 - this contains a null byte in the middle
    mov eax, 0x12005678    ; First instruction with null byte in the middle
    ; MOV EBX, 0x12345678  ; Another instruction without nulls
    mov ebx, 0x12345678
    ; MOV ECX, 0x12340078  ; Another instruction with null byte in the middle
    mov ecx, 0x12340078