; ROR13 Hash Algorithm Test - Windows API Resolution Pattern
; This pattern appears in ~90% of Windows shellcode samples
; Assemble with: nasm -f bin test_ror13_hash.asm -o test_ror13_hash.bin

BITS 32

section .text

global _start
_start:
    ; ========== ROR13 Hash Algorithm ==========
    ; Used to hash function names for API resolution
    ; Pattern observed in exploit-db samples: 13504, 13514, 13516, 40560, etc.

    ; Setup: Point ESI to function name string
    lea esi, [function_name]
    xor edi, edi            ; Clear hash accumulator

hash_loop:
    lodsb                   ; Load next character from [ESI] into AL
    test al, al             ; Check for null terminator
    jz hash_done            ; Jump if end of string

    ; === CRITICAL PATTERN ===
    ; ROR EDI, 0x0D - Rotate hash accumulator right by 13 bits
    ; This is THE pattern that appears in 90%+ of samples
    ror edi, 0x0D           ; <-- THIS IS WHAT WE'RE TESTING!
    ; ========================

    add edi, eax            ; Add character to hash
    jmp hash_loop           ; Continue loop

hash_done:
    ; EDI now contains the ROR13 hash of the function name
    ; Compare with target hash...
    cmp edi, 0x876F8B31     ; Example: GetProcAddress hash
    je found_match

    ; Not found, continue...
    jmp end_test

found_match:
    ; Match found!
    xor eax, eax
    inc eax                 ; Return 1
    jmp end_test

; Test other rotation patterns that might have nulls
test_other_rotations:
    ; ROL with immediate
    rol eax, 0x05           ; ROL5 hash variant
    rol ebx, 0x0D           ; ROL13 variant

    ; ROR with different registers
    ror ecx, 0x0D           ; ROR13 with ECX
    ror edx, 0x07           ; ROR7 variant
    ror ebp, 0x0D           ; ROR13 with EBP

    ; Edge case: rotation by 0 (might create null in encoding)
    ; This should be handled by the strategy
    db 0xC1, 0xCF, 0x00     ; ROR EDI, 0 (manually encoded)

    ; Edge case: rotation by 1 (special encoding)
    ror esi, 1
    rol edi, 1

    ; RCR/RCL (Rotate through Carry)
    rcr eax, 0x0D
    rcl ebx, 0x05

end_test:
    ret

; Data section
function_name:
    db 'GetProcAddress', 0

; Test string for hashing
test_string:
    db 'LoadLibraryA', 0
