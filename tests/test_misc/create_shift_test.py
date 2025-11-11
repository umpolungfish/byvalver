#!/usr/bin/env python3
"""
Test script to create shellcode that matches the example from exploit-db:
The example used `push 0x1ff9090; shr $0x10, %ecx` to load 0x1ff into ecx.
"""
import struct

def create_test_shellcode():
    """Create test shellcode with immediate values that can be constructed using shifts"""
    
    shellcode = bytearray()
    
    # This is what we want to achieve: MOV EAX, 0x000001FF (contains nulls)
    # But we'll use shift operations to construct it from a non-null value
    # The original example used: push 0x1ff9090; shr $0x10, %ecx to get 0x1ff in ecx
    # But we need to adapt this to our MOV instruction
    
    # Let's try: MOV EAX, 0x01FF0000 - this has nulls in position 1 and 2
    # We could construct this as 0x01FF << 16
    shellcode.extend(b'\xB8\x00\x00\xFF\x01')  # MOV EAX, 0x01FF0000 (has null bytes)
    
    # Another example: MOV ECX, 0xFF000000 - has nulls, could be 0xFF << 24
    shellcode.extend(b'\xB9\x00\x00\x00\xFF')  # MOV ECX, 0xFF000000 (has null bytes)
    
    # Example 3: MOV EBX, 0x0001FF00 - has nulls, could be 0x1FF0000 >> 8
    shellcode.extend(b'\xBB\x00\xFF\x01\x00')  # MOV EBX, 0x0001FF00 (has null bytes)
    
    # Example 4: MOV EDX, 0x00001FF0 - has nulls, could be 0x1FF0000 >> 12
    shellcode.extend(b'\xBA\xF0\x1F\x00\x00')  # MOV EDX, 0x00001FF0 (has null bytes)
    
    # Add some operations to make it more realistic
    shellcode.extend(b'\x40')  # INC EAX
    shellcode.extend(b'\x41')  # INC ECX
    shellcode.extend(b'\x42')  # INC EDX
    shellcode.extend(b'\x43')  # INC EBX
    
    return shellcode

def main():
    shellcode = create_test_shellcode()
    
    print(f"Created test shellcode with {len(shellcode)} bytes")
    print("Shellcode bytes:", " ".join([f"\\x{byte:02x}" for byte in shellcode]))
    print("Hex dump format: ", " ".join([f"{byte:02x}" for byte in shellcode]))
    
    # Write to file
    with open("shift_test.bin", "wb") as f:
        f.write(shellcode)
    
    print("Shellcode written to shift_test.bin")
    
    # Count null bytes in the test shellcode
    null_count = shellcode.count(0)
    print(f"Number of null bytes in test shellcode: {null_count}")

if __name__ == "__main__":
    main()