; Test shellcode with null bytes - MOV EAX, 0x00000001 (contains nulls)
BITS 32

section .text
_start:
    mov eax, 0x00000001      ; This will have null bytes
    mov ebx, 0x00000002      ; This will also have null bytes
    add eax, ebx             ; This will be OK
    mov ecx, 0x00100000      ; This contains null bytes
    mov edx, 0x00008000      ; This contains null bytes
    cmp eax, 0x00000000      ; This contains null bytes
    je skip                  ; This jump is OK
    mov ebx, 0x00000071      ; This contains null bytes
    xor ecx, ecx             ; This is OK
    mov cl, 0x00             ; This contains a null byte
    push 0x0000000F          ; This contains null bytes
    pop eax                  ; This is OK
    mov eax, 0x00730071      ; This contains null bytes - from the exploit-db example
    mov eax, 0x001FF000      ; This contains null bytes - shift-based example
    xor edx, edx             ; This is OK
    mov [0x00400000], eax    ; This contains null bytes in address
    mov eax, [0x00500000]    ; This contains null bytes in address
    jmp short skip           ; This is OK
skip:
    ret                      ; This is OK