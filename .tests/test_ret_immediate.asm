; Test shellcode for RET immediate null-byte elimination
; This file tests the RET immediate strategy with various immediate values

BITS 32

section .text
global _start

_start:
    ; Function call with stack cleanup patterns
    ; These patterns are common in Windows API calling conventions

    ; Test 1: RET 4 (clean up 1 DWORD argument)
    ; Encoding: C2 04 00 (has null byte)
    push ebx
    mov ebx, esp
    ret 4

    ; Test 2: RET 8 (clean up 2 DWORD arguments)
    ; Encoding: C2 08 00 (has null byte)
    push ebx
    push ecx
    mov ebx, esp
    ret 8

    ; Test 3: RET 12 (clean up 3 DWORD arguments - common for 3-arg API)
    ; Encoding: C2 0C 00 (has null byte)
    push ebx
    push ecx
    push edx
    mov ebx, esp
    ret 12

    ; Test 4: RET 16 (clean up 4 DWORD arguments)
    ; Encoding: C2 10 00 (has null byte)
    push ebx
    push ecx
    push edx
    push esi
    mov ebx, esp
    ret 16

    ; Test 5: RET 20 (clean up 5 DWORD arguments)
    ; Encoding: C2 14 00 (has null byte)
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov ebx, esp
    ret 20

    ; Test 6: Plain RET (no immediate - should not be transformed)
    ; Encoding: C3 (no null bytes)
    ret
