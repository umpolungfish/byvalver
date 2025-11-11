BITS 32

; This test shellcode contains ADD/SUB/AND/OR/XOR/CMP instructions with null bytes in immediate values
; This should trigger our new XOR-based arithmetic strategy

mov eax, 0x11223344
add eax, 0x00110011    ; This has null bytes in the immediate
sub eax, 0x00220022    ; This has null bytes in the immediate
and eax, 0x00330033    ; This has null bytes in the immediate
or  eax, 0x00440044    ; This has null bytes in the immediate
xor eax, 0x00550055    ; This has null bytes in the immediate
cmp eax, 0x00660066    ; This has null bytes in the immediate

; More operations with null bytes
mov ebx, 0x99887766
add ebx, 0x00770077    ; This has null bytes in the immediate