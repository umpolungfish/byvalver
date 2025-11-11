; More complex test shellcode with null bytes including jumps and calls
BITS 32

section .text
_start:
    mov eax, 0x00730071      ; Contains null bytes - NEG example
    mov ebx, 0x00200404      ; Contains null bytes - arithmetic example
    sub ebx, 0x404           ; This is OK
    push 0x00000000          ; Contains null bytes - will be converted to XOR
    call target              ; Call to target function  
    jmp end                  ; Jump to end
target:
    mov ecx, 0x00100000      ; Contains null bytes
    ret                      ; Return
end:
    cmp eax, 0x00000000      ; Compare with null - contains null bytes
    je skip                  ; Conditional jump
    mov [0x00400000], eax    ; Memory store with null address
    mov eax, [0x00500000]    ; Memory load with null address
    push 0x0000ABCD          ; Contains null bytes
    pop ebx                  ; Pop is OK
    and eax, 0x00000000      ; AND with null - contains null bytes
    or eax, 0x00000001       ; OR with null bytes
    xor eax, 0x00000002      ; XOR with null bytes
    add eax, 0x00000003      ; ADD with null bytes
    sub eax, 0x00000004      ; SUB with null bytes
skip:
    ; More instructions that might have nulls
    mov edx, 0x0000F000      ; Contains null bytes
    mov esi, 0x0000F001      ; Contains null bytes
    mov edi, 0x0000F002      ; Contains null bytes
    jmp short end2           ; Short jump
end2:
    ret                      ; Return