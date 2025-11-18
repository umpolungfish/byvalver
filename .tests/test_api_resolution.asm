; Minimal Windows API resolution pattern test
; Tests the critical MOVZX with SIB addressing pattern
; Assemble with: nasm -f bin test_api_resolution.asm -o test_api_resolution.bin

BITS 32

; Simulate Windows PE export table ordinal lookup
; This is the CORE pattern observed in 70%+ of Windows shellcode

section .text

global _start
_start:
    ; Setup: Simulate getting export table pointers
    xor ebx, ebx
    mov ebx, 0x77E50000        ; Simulated kernel32.dll base (null-free)
    mov eax, [ebx + 0x3C]      ; PE header offset
    add eax, ebx               ; EAX = PE header

    ; Get export directory
    mov ecx, [eax + 0x78]      ; Export directory RVA
    add ecx, ebx               ; ECX = Export directory

    ; Get ordinal table pointer
    mov ecx, [ecx + 0x24]      ; Ordinals table offset
    add ecx, ebx               ; ECX = Ordinals table address

    ; ========== CRITICAL PATTERN ==========
    ; Read 16-bit ordinal value using SIB addressing
    ; This is THE pattern that appears in 70%+ of samples
    xor edx, edx
    mov edx, 0x12              ; Function index (arbitrary)
    MOVZX EDX, WORD [ECX + 2*EDX]   ; <-- THIS IS THE PATTERN!
    ; =====================================

    ; Another variant with different registers
    mov ebx, ecx
    xor ecx, ecx
    mov ecx, 0x05
    MOVZX EDX, WORD [EBX + 2*ECX]   ; Variant pattern

    ; Variant with displacement
    mov ebp, ebx
    MOVZX EDX, WORD [EBP + 2*ECX - 2]   ; With displacement

    ; Sign-extend variant
    MOVSX EAX, WORD [EBX + 2*ECX]

    ; Byte variant
    MOVZX EAX, BYTE [EBX + ECX]

    ; Destination same as base (tricky case)
    MOVZX EDX, WORD [EDX + 2*ECX]

    ; Exit (simplified)
    ret
