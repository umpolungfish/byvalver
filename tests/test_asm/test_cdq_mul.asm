; Test assembly file that will be converted to shellcode for testing CDQ/MUL strategies
; This contains patterns that could benefit from efficient register zeroing

section .text
    global _start

_start:
    ; Set up some null-byte containing instructions that would be replaced
    mov eax, 0x00112233      ; This has null bytes and will be converted 
    mov ebx, 0x00445566      ; This has null bytes and will be converted
    mov ecx, 0              ; This is a zeroing operation: MOV ECX, 0 -> XOR ECX, ECX
    mov edx, 0              ; This is a zeroing operation: MOV EDX, 0 -> Using CDQ if EAX is zero
    mov edi, 0x00778899      ; More null bytes to convert
    xor eax, eax             ; Explicitly zero EAX
    cdq                      ; This should zero EDX (EAX is zero)
    mul ebx                  ; This should zero EAX and EDX if one of them was zero