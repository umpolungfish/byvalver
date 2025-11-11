BITS 32

; Test shellcode with CALL instruction that has null bytes in immediate
; This will test our new JMP/CALL/POP strategy

_start:
    ; Example: call 0x00110045 - This address has null bytes (0x00 and 0x00)
    call 0x00110045

    ; Add some more instructions to make the test comprehensive
    mov eax, 0x00401123    ; This has null bytes too
    add ebx, 0x00000456    ; This has null bytes too
    push 0x00780012        ; This has null bytes too