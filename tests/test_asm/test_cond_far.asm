BITS 32

; Test with a conditional jump that will have a longer displacement to potentially cause null bytes after transformation
; The target will be far away to force a longer displacement

_start:
    ; Set up values to compare
    mov eax, 0x1
    mov ebx, 0x1
    cmp eax, ebx
    
    ; This jump will have to jump over many instructions to reach the target
    je far_target
    
    ; Insert many instructions that will expand significantly to push the target far away
    mov ecx, 0x00110022  ; This will expand to multiple instructions without nulls
    mov edx, 0x00330044  ; This will also expand
    add edi, 0x00550066  ; This will also expand
    push 0x00770088      ; This will expand too
    mov esi, 0x00990011  ; Another expanding instruction
    
    ; Add more to make the jump even further
    nop
    nop
    nop
    nop
    nop
    
far_target:
    ; Final instructions
    mov eax, 1
    int 0x80