; Test shellcode with immediate values containing null bytes
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
    
    ; MOV EDI, 0x00123456 (contains nulls)
    mov edi, 0x00123456
    
    ; XOR ESI, 0x00FEDCBA (contains nulls)
    xor esi, 0x00FEDCBA