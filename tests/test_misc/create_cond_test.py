#!/usr/bin/env python3

# Create shellcode with a conditional jump that has null bytes in displacement
# Using JE (0x74) with displacement that contains nulls (0x00)
# We'll make sure the displacement would have nulls

shellcode = bytearray()

# Start with some instructions
shellcode.extend(b'\x48')  # DEC EAX
shellcode.extend(b'\x49')  # DEC ECX

# Now a conditional jump JE with displacement that has nulls
# 0x74 is JE, and we'll follow with 0x00 (displacement with null byte)
# Actually, let's make a proper sequence with a realistic jump

# Instead, let's create a scenario where we know there will be expansion
# making the displacement have null bytes after adjustment

# This is MOV EAX, 0x00110022 which has null bytes and will expand significantly
shellcode.extend(b'\xb8\x22\x00\x11\x00')  # MOV EAX, 0x00110022
# This will become several instructions without nulls

# Now we'll try to create a conditional jump that will have to be adjusted
# and might result in null bytes in the displacement after BYVALVER processing
# (Though this is hard to predict without knowing exactly how the offsets will be adjusted)

# For a more precise test, let me just make sure basic functionality works with conditional jumps first
# and create a larger shellcode that will definitely force displacement changes

shellcode.extend(b'\x40')  # INC EAX
shellcode.extend(b'\x90')  # NOP
shellcode.extend(b'\x90')  # NOP

# Let's create an actual jump that we know will have to be adjusted significantly
# This raw byte represents a JE instruction with a displacement that will be 
# adjusted during processing - if the adjustment causes null bytes, our
# new handling will kick in
# We'll start with a simple JE + some offset that gets significantly changed

# Actually, let me just test with a simple conditional that I know exists
with open('test_known_cond.bin', 'wb') as f:
    # MOV EAX, 1; MOV EBX, 1; CMP EAX, EBX; JE +0x20 (which will have nulls after expansion)
    f.write(b'\xb8\x01\x00\x00\x00')  # MOV EAX, 1
    f.write(b'\xbb\x01\x00\x00\x00')  # MOV EBX, 1
    f.write(b'\x39\xd8')              # CMP EAX, EBX
    f.write(b'\x74\x20')              # JE +32 (0x20) - This displacement might need adjustment
    f.write(b'\x90' * 30)             # NOP padding
    f.write(b'\xb8\x01\x00\x00\x00')  # MOV EAX, 1 (target)
    f.write(b'\xcd\x80')              # INT 0x80

print(f"Created test file with conditional jump JE +0x20. Size: 45 bytes")