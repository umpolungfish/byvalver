; Test for specific known problem: MOV with 32-bit immediate containing nulls
BITS 32

section .text
_start:
    ; MOV EAX with immediate values that contain nulls
    mov eax, 0x00000001      ; This has 3 null bytes
    mov ebx, 0x00100000      ; This has 2 null bytes
    mov ecx, 0x00730071      ; This has 2 null bytes - from exploit-db technique
    mov edx, 0x0000F000      ; This has 2 null bytes
    
    ; Operations with immediate values that contain nulls
    add eax, 0x00000005      ; This has null bytes
    sub ebx, 0x00000010      ; This has null bytes
    and ecx, 0x0000FFFF      ; This has null bytes
    or  edx, 0x00000001      ; This has null bytes
    xor eax, 0x000000F0      ; This has null bytes
    
    ; Memory operations with addresses containing nulls
    mov [0x00400000], eax    ; This address has null bytes
    mov eax, [0x00500000]    ; This address has null bytes
    
    ; PUSH with immediate containing nulls
    push 0x00001234          ; This has null bytes
    
    ; Direct call with immediate containing nulls (should be rare in real code)
    ; call 0x00400000        ; This would have null bytes
    
    ret