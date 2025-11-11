#!/usr/bin/env python3

# Create shellcode that will definitely cause displacement changes
# This shellcode will have MOV operations with null bytes that will expand,
# thereby changing the distance for conditional jumps

shellcode = bytearray()

# Some initial instructions
shellcode.extend(b'\x48')  # DEC EAX
shellcode.extend(b'\x49')  # DEC ECX
shellcode.extend(b'\x31\xc0')  # XOR EAX, EAX
shellcode.extend(b'\x31\xdb')  # XOR EBX, EBX

# Here's the critical part: a conditional jump to a target after many expanding instructions
# 74 10 = JE +16 (jump if equal, 16 bytes ahead)
shellcode.extend(b'\x74\x10')  # JE to target after expanding instruction

# Now we'll put an instruction that will expand significantly
shellcode.extend(b'\xb8\x45\x00\x11\x00')  # MOV EAX, 0x00110045 - this will expand to many instructions

# The target for the JE jump should be here, but it will be moved due to expansion
shellcode.extend(b'\xb8\x01\x00\x00\x00')  # MOV EAX, 1
shellcode.extend(b'\xcd\x80')              # INT 0x80

with open('test_cond_expansion.bin', 'wb') as f:
    f.write(shellcode)

print(f"Created shellcode with conditional jump that will be affected by expansion. Size: {len(shellcode)}")
print("Original has: JE +0x10 -> MOV EAX, 0x00110045 (expands significantly) -> target")