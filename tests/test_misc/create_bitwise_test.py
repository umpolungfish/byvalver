
import struct

# This shellcode will be MOV EAX, 0x11223344
# The immediate value has no null bytes, but we will modify the C code to force the use of bitwise operations
shellcode = b'\xb8\x00\x33\x00\x11'

with open("bitwise_test.bin", "wb") as f:
    f.write(shellcode)
