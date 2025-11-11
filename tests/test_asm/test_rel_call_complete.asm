BITS 32

; Create a more complete test with actual target instructions
_start:
    call target_func    ; This will have a displacement that may contain nulls

    ; Some padding to push the target function further
    nop
    nop
    nop

target_func:
    ; Actual function to be targeted
    mov eax, 0x1
    int 0x80