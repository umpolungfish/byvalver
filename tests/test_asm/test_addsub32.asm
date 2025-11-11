; Test shellcode with 32-bit immediate values containing null bytes
section .text
    global _start

_start:
    ; MOV EAX, 0x00112233 (contains nulls)
    mov eax, 0x00112233
    
    ; MOV EBX, 0x00445566 (contains nulls)
    mov ebx, 0x00445566
    
    ; ADD ECX, 0x00778899 (contains nulls)
    add ecx, 0x00778899
    
    ; SUB EDX, 0x00AABBCC (contains nulls)
    sub edx, 0x00AABBCC