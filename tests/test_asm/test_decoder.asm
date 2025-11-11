; Test assembly with instructions containing immediate values with null bytes
section .text
global _start

_start:
    ; MOV EAX, 0x00112233  ; Contains null byte - should be replaced
    mov eax, 0x00112233
    ; MOV EBX, 0x44005566  ; Contains null byte - should be replaced
    mov ebx, 0x44005566
    ; MOV ECX, 0x789000AB  ; Contains null byte - should be replaced
    mov ecx, 0x789000AB
    ; ADD EDX, 0x00AABBCC  ; Contains null byte - should be replaced
    add edx, 0x00AABBCC
    ; PUSH 0x00FFEE00  ; Contains null bytes - should be replaced
    push 0x00FFEE00