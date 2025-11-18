; Test cases where MOVZX with SIB addressing produces NULL bytes
; Assemble with: nasm -f bin test_movzx_null_sib.asm -o test_movzx_null_sib.bin

BITS 32

section .text

global _start
_start:
    ; Test Case 1: SIB byte = 0x00
    ; MOVZX EAX, WORD [EAX + EAX*1]
    ; Encoding: 0F B7 04 00
    ; SIB byte: scale=00 (1), index=EAX (000), base=EAX (000) = 0x00
    db 0x0F, 0xB7, 0x04, 0x00

    ; Test Case 2: Another SIB = 0x00 pattern
    ; MOVZX ECX, WORD [EAX + EAX*1]
    ; Encoding: 0F B7 0C 00
    db 0x0F, 0xB7, 0x0C, 0x00

    ; Test Case 3: MOVSX variant with null SIB
    ; MOVSX EDX, WORD [EAX + EAX*1]
    ; Encoding: 0F BF 14 00
    db 0x0F, 0xBF, 0x14, 0x00

    ; Test Case 4: ModR/M = 0x00 (without SIB)
    ; MOVZX EAX, BYTE [EAX]
    ; Encoding: 0F B6 00
    db 0x0F, 0xB6, 0x00

    ; Test Case 5: MOVZX EAX, WORD [EAX]
    ; Encoding: 0F B7 00
    db 0x0F, 0xB7, 0x00

    ; Test Case 6: Displacement with null
    ; MOVZX EAX, WORD [EBP + 0]
    ; Encoding: 0F B7 45 00
    db 0x0F, 0xB7, 0x45, 0x00

    ; Test Case 7: Complex case - null in displacement with SIB
    ; MOVZX EDX, WORD [EBP + EAX*2]
    ; EBP as base requires disp8, if disp=0 it's null
    ; Encoding: 0F B7 54 45 00
    db 0x0F, 0xB7, 0x54, 0x45, 0x00

    ; Test Case 8: Scale=1, with EAX+EAX (SIB=00)
    ; MOVZX EBX, BYTE [EAX + EAX]
    ; Encoding: 0F B6 1C 00
    db 0x0F, 0xB6, 0x1C, 0x00

    ret
