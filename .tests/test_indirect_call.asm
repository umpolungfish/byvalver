; Indirect CALL/JMP strategy test
; Tests the critical pattern: CALL/JMP DWORD PTR [addr]
; This is the primary Windows API resolution pattern
; Assemble with: nasm -f bin test_indirect_call.asm -o test_indirect_call.bin

BITS 32

section .text

global _start
_start:
    ; Setup: Simulate Import Address Table (IAT) structure
    ; Windows executables use this pattern extensively for API calls

    ; ========== CRITICAL PATTERN 1: CALL [disp32] ==========
    ; Pattern: FF 15 [32-bit address]
    ; This is how Windows calls imported functions via IAT

    ; Simulate IAT addresses with null bytes (typical in real binaries)
    CALL [0x00401000]              ; IAT entry for GetProcAddress (contains nulls!)
    ; =======================================================

    ; ========== CRITICAL PATTERN 2: JMP [disp32] ==========
    ; Pattern: FF 25 [32-bit address]
    ; Used for indirect jumps through function pointers

    JMP [0x00402000]               ; Jump through IAT (contains nulls!)
    ; =======================================================

    ; More realistic examples with different null-containing addresses
    CALL [0x10001000]              ; Different null pattern
    CALL [0x00000400]              ; Multiple nulls
    JMP [0x77001100]               ; JMP variant with nulls

    ; Edge case: address with trailing nulls
    CALL [0x12340000]

    ; Edge case: address with middle nulls
    CALL [0x00FF0000]

    ; Edge case: minimal address (many nulls)
    JMP [0x00000100]

    ; This pattern is also used for calling through vtables
    ; Simulating virtual function call pattern
    mov eax, 0x00401000            ; Object pointer (null bytes)
    CALL [eax]                     ; Virtual function call (different pattern - register base)

    ; Return
    ret

; Simulated IAT data section (would contain actual function pointers)
section .data
    iat_getprocaddress: dd 0x77D51234
    iat_loadlibrary: dd 0x77D52345
