BITS 32

; Test shellcode with multiple types of conditional jumps
_start:
    mov eax, 0x1
    mov ebx, 0x1
    cmp eax, ebx
    
    je skip_nop      ; Jump if equal
    jne continue1       ; Jump if not equal - this should skip the next instruction
    nop                 ; This gets skipped by jne
skip_nop:
continue1:
    jl skip1            ; Jump if less - won't happen since eax=ebx
    nop
skip1:
    jg skip2            ; Jump if greater - won't happen since eax=ebx  
    nop
skip2:
    ; Do final operations
    mov eax, 1
    int 0x80