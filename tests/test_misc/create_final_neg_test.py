#!/usr/bin/env python3
# Create a test case where NEG strategy should work
# Target: 0x00112234 (has nulls) -> negated: 0xFEEDDDCC (no nulls)

shellcode = bytearray()
shellcode.extend([0xB8, 0x34, 0x22, 0x11, 0x00])  # MOV EAX, 0x00112234 (has nulls at position 4)

with open("test_neg_final.bin", "wb") as f:
    f.write(shellcode)