#!/usr/bin/env python3
"""Create a binary shellcode file with patterns that could benefit from CDQ/MUL strategies"""

# Create test shellcode with null bytes that will be processed
# In raw x86 bytecode: mov eax, 0x00112233 (b8 33 22 11 00)
#                        mov ebx, 0x44005566 (bb 66 55 00 44)  
#                        mov ecx, 0 (b9 00 00 00 00)
#                        mov edx, 0 (ba 00 00 00 00)

shellcode = (
    b"\xb8\x33\x22\x11\x00"  # mov eax, 0x00112233
    b"\xbb\x66\x55\x00\x44"  # mov ebx, 0x44005566  
    b"\xb9\x00\x00\x00\x00"  # mov ecx, 0
    b"\xba\x00\x00\x00\x00"  # mov edx, 0
)

with open("direct_test.bin", "wb") as f:
    f.write(shellcode)
    
print(f"Created direct_test.bin with {len(shellcode)} bytes")
print("Shellcode contains null bytes that should be removed by BYVALVER")