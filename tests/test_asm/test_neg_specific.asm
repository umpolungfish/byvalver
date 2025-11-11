bits 32

_start:
    ; MOV EAX, 0x00FFFFFF (has 1 null byte, negated is 0x00000001 - still has nulls, so should not use NEG)
    ; Actually, let's try 0x000000FF which negates to 0xFFFFFF01
    ; 0xFFFFFF01 has no null bytes, so NEG should be used
    mov eax, 0x000000FF  ; This should trigger the NEG strategy
    mov ebx, 0x000000FF  ; Same value for another register
    add ecx, 0x000000FF  ; Same value for arithmetic
    nop
    ret