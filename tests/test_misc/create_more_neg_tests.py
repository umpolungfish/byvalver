#!/usr/bin/env python3
import struct

# Test to create shellcode with immediate values that should trigger NEG strategy
# We need to make sure the negated value has NO null bytes but the original has null bytes

shellcode = bytearray()

# MOV EAX, 0x00100001  (0xB8 0x01 0x00 0x10 0x00)
# Contains null bytes at positions 1 and 4
# Negated: -0x00100001 = 0xFFFFFFFF - 0x00100001 + 1 = 0xFFEFFFFF (no null bytes!)
shellcode.extend([0xB8, 0x01, 0x00, 0x10, 0x00])

with open("test_neg_simple.bin", "wb") as f:
    f.write(shellcode)

# Another test: MOV EAX, 0x00FF00FF 
# Negated: -0x00FF00FF = 0xFF00FF01 (no nulls!)
shellcode2 = bytearray()
shellcode2.extend([0xB8, 0xFF, 0x00, 0xFF, 0x00])  # MOV EAX, 0x00FF00FF

with open("test_neg_32.bin", "wb") as f:
    f.write(shellcode2)