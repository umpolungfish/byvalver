; Test assembly file to test register zeroing strategies
; We'll have patterns that could benefit from CDQ/MUL optimizations

section .text
    global _start

_start:
    ; Some operations that create null bytes
    mov eax, 0x00110000      ; This will trigger null-byte processing
    mov ebx, 0x00220000      ; This will trigger null-byte processing
    mov ecx, 0x00330000      ; This will trigger null-byte processing
    
    ; Now we have some zeroing operations that could be optimized
    mov eax, 0               ; Zero EAX - currently becomes XOR EAX, EAX
    mov edx, 0               ; Zero EDX - could use CDQ if EAX is known to be 0
    mov ebx, 0               ; Zero EBX - becomes XOR EBX, EBX
    mov ecx, 0               ; Zero ECX - becomes XOR ECX, ECX
    
    ; If we had multiple registers to zero at once, we could use MUL strategies
    ; e.g., if EAX is 0, then MUL EBX would make both EAX and EDX 0