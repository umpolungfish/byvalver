bits 32

; Test shellcode with problematic patterns that cause null bytes
; add byte ptr [eax], al - creates null byte in ModR/M
; dec eax
; mov edx, edi
; call dword ptr [0x10ca] - displacement contains nulls
; inc ecx
; call dword ptr [0x108f] - displacement contains nulls
; mov edx, 0 - immediate contains nulls
; mov eax, 0x3000 - immediate contains nulls

; This creates the instruction: add byte ptr [eax], al (0x00 0x00)
db 0x00, 0x00

; This creates dec eax
db 0x48

; This creates mov edx, edi  
db 0x89, 0xf2

; This creates call dword ptr [0x10ca] (contains null bytes in disp32)
db 0xff, 0x15, 0xca, 0x10, 0x00, 0x00

; This creates inc ecx
db 0x41

; This creates call dword ptr [0x108f] (contains null bytes in disp32)
db 0xff, 0x15, 0x8f, 0x10, 0x00, 0x00

; This creates mov edx, 0 (contains null bytes in imm32)
db 0xbA, 0x00, 0x00, 0x00, 0x00

; This creates mov eax, 0x3000 (contains null bytes in imm32)
db 0xb8, 0x00, 0x30, 0x00, 0x00