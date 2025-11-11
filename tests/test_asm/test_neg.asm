section .text
    ; This assembly contains MOV instructions with immediate values that have null bytes
    ; MOV EAX, 0x00730071 (this value has null bytes)
    ; 0x00730071 = 7544945 decimal
    ; The negated value would be -7544945 = 0xFF8CFF8F (no nulls in this case)
    
    mov eax, 0x00730071  ; This has null bytes that should be processed with NEG strategy
    mov ebx, 0x00FF0000  ; Another value with null bytes
    mov ecx, 0x000000FF  ; Another value with null bytes
    nop
    add edx, 0x00AABBCC  ; ADD with null bytes in immediate
    sub eax, 0x00730071  ; SUB with null bytes in immediate
    and ebx, 0x0000FF00  ; AND with null bytes in immediate
    cmp ecx, 0x00000000  ; Compare with zero
    ret