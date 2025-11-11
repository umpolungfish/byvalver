#!/usr/bin/env python3
# Create a test case where NEG strategy should be beneficial
# MOV EAX, 0x80000001 - this has no null bytes, so it won't trigger our strategies
# We need MOV EAX, imm32 where imm32 has null bytes but -imm32 does not

# Let's try MOV EAX, 0x010000FF
# The negated value is -0x010000FF = 0xFEFFFFFF 
# 0xFEFFFFFF = 0xFE 0xFF 0xFF 0xFF - no null bytes! Perfect for NEG strategy.

shellcode = bytearray()
shellcode.extend([0xB8, 0xFF, 0x00, 0x00, 0x01])  # MOV EAX, 0x010000FF (has nulls at positions 1 and 2)

with open("test_neg_definite.bin", "wb") as f:
    f.write(shellcode)