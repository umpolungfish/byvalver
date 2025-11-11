; Test shellcode with null bytes
section .text
global _start

_start:
    ; MOV EAX, 0x12340056 (contains nulls)
    mov eax, 0x12340056
    
    ; MOV EBX, 0x00789abc (contains nulls) 
    mov ebx, 0x00789abc
    
    ; ADD EAX, 0x00112233 (contains nulls)
    add eax, 0x00112233
    
    ; PUSH 0x12340056 (contains nulls)
    push dword 0x12340056
    
    ; CMP [0x12340056], eax (address contains nulls)
    cmp dword [0x12340056], eax
    
    ; MOV EAX, [0x12340078] (address contains nulls)
    mov eax, [0x12340078]
    
    ; MOV [0x12340099], EBX (address contains nulls)
    mov [0x12340099], ebx
    
    ; LEA ECX, [0x123400AB] (address contains nulls)
    lea ecx, [0x123400AB]
    
    ; Exit
    mov al, 1
    int 0x80