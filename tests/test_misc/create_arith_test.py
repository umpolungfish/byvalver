import struct

# Create a shellcode with immediate values containing null bytes that would benefit from arithmetic strategies
shellcode = bytearray()

# MOV EAX, 0x00200000  (has null bytes)
shellcode.extend(b'\xb8\x00\x00\x20\x00')

# MOV EBX, 0x00100000  (has null bytes) 
shellcode.extend(b'\xbb\x00\x00\x10\x00')

# ADD ECX, 0x00300000  (has null bytes)
shellcode.extend(b'\x83\xc1\x00')  # This is actually ADD ECX, 0 which is not what we want
shellcode.extend(b'\x81\xc1\x00\x00\x30\x00')  # ADD ECX, 0x00300000

with open("test_arith_shellcode.bin", "wb") as f:
    f.write(shellcode)