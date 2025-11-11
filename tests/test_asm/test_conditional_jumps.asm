BITS 32

; Test shellcode with conditional jumps that might have null bytes in displacements
; This will test our new conditional jump handling

_start:
    ; Set up some values for testing
    mov eax, 0x1
    mov ebx, 0x1
    
    ; Compare values to set flags
    cmp eax, ebx
    
    ; Test various conditional jumps that might have null displacements after processing
    je near_target    ; Jump if equal - displacement might contain nulls
    nop
    nop
    nop
    
    ; Pad with more instructions to make target further away
    nop
    nop
    nop
    nop
    
near_target:
    ; Do something at the target
    mov ecx, 0x5
    int 0x80