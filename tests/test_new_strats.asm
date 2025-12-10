; Simple test shellcode with potential null byte issues
bits 32

section .text
global _start

_start:
    ; Test 1: MOV with null-containing immediate
    mov eax, 0x00123456      ; This has a null in the first byte
    
    ; Test 2: CMP with zero (could have null issues)
    cmp eax, 0               ; Compare with zero
    
    ; Test 3: ADD with null immediate
    add ebx, 0x00001000      ; Addition with null containing immediate
    
    ; Test 4: Conditional jump (might have null displacement after transformation)
    jne somewhere             ; Jump if not equal
    
    ; Some padding to reach the jump target
    times 300 db 0x90         ; NOPs to make sure jump target is far enough
    
somewhere:
    ; Exit syscall 
    mov eax, 1       ; sys_exit
    mov ebx, 0       ; exit status
    int 0x80