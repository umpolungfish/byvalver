#!/usr/bin/env python3

# Create a simple test to verify BYVALVER functionality
import struct

# Create shellcode that has a relative call with null bytes in displacement
# This simulates what we want to fix
shellcode = bytearray()

# A relative call to a location that would have nulls in displacement
# For our test, let's create a simple scenario where we know there are null bytes
# We'll create: call + some_offset where offset has nulls

# This is a manual construction of the test case
# e8 XX XX XX XX - CALL rel32 instruction
# We'll make the displacement have null bytes like 0x00110040 (little endian: 40 00 11 00)

shellcode.extend(b'\xe8\x40\x00\x11\x00')  # call with displacement that has nulls
shellcode.extend(b'\x90' * 10)              # 10 NOPs as target

with open('test_rel_call.bin', 'wb') as f:
    f.write(shellcode)

print(f"Created test shellcode with relative call and null bytes. Size: {len(shellcode)}")
print("Original shellcode hex:", shellcode.hex())