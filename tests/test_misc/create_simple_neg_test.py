#!/usr/bin/env python3
# Create a simple test case that should definitely trigger the NEG strategy
# MOV EDX, 0x00730071 - this should work with NEG strategy
# The negated value should be 0xFF8CFF8F

# Machine code for MOV EDX, 0x00730071:
# BAh 71h 00h 73h 00h  (BA = MOV EDX, imm32)

shellcode = bytearray()
shellcode.extend([0xBA, 0x71, 0x00, 0x73, 0x00])  # MOV EDX, 0x00730071

with open("simple_neg_test.bin", "wb") as f:
    f.write(shellcode)