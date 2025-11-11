#!/usr/bin/env python3
import struct

# Create raw shellcode with MOV instructions containing immediate values with null bytes
# These should trigger the NEG strategy if the negated value has no null bytes

shellcode = bytearray()

# MOV EAX, 0x0090FF8E  (0xB8 0x8E 0xFF 0x90 0x00)
# This immediate contains a null byte at the end
# The negated value would be -0x0090FF8E = 0xFF6F0072
# 0xFF6F0072 = 4285397106 decimal, which has a null byte in position 2!
# Let me find better examples...

# Instead use MOV EAX, 0x00800000 (0xB8 0x00 0x00 0x80 0x00)
# The negated value would be -0x00800000 = 0xFF800000 (this has a null byte too!)
# 2's complement of 0x00800000 = 0xFFFFFFFF - 0x00800000 + 1 = 0xFF7FFFFF + 1 = 0xFF800000

# Let's try MOV EAX, 0x00100001 (0xB8 0x01 0x00 0x10 0x00)
# The negated value would be -0x00100001 = 0xFFEFFFFF (this has no null bytes!)
# 2's complement of 0x00100001 = 0xFFFFFFFF - 0x00100001 + 1 = 0xFEFFFFFE + 1 = 0xFEFFFFF

# Actually let me do the math correctly:
# To get -x, we calculate ~x + 1 where ~x is bitwise complement
# For 0x00100001:  complement is 0xFFEFFFFE, add 1 gives 0xFFEFFFFF
# 0xFFEFFFFF has no null bytes! This is perfect for NEG strategy

shellcode.extend([0xB8, 0x01, 0x00, 0x10, 0x00])  # MOV EAX, 0x00100001

# Another example: MOV EBX, 0x00110023
# -0x00110023 = 0xFFEEFFDD (let's check: 0xFFFFFFFF - 0x00110023 = 0xFFEEFFDC, +1 = 0xFFEEFFDD)
# 0xFFEEFFDD has no null bytes, perfect for NEG strategy
shellcode.extend([0xBB, 0x23, 0x00, 0x11, 0x00])  # MOV EBX, 0x00110023

with open("test_neg_strategy.bin", "wb") as f:
    f.write(shellcode)