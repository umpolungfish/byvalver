#!/usr/bin/env python3
"""
Create shellcode that specifically targets the shift example from exploit-db:
The example used `push 0x1ff9090; shr $0x10, %ecx` to load 0x1ff into ecx.
"""
import struct

def create_shift_example_shellcode():
    """Create shellcode similar to the exploit-db example: MOV ECX, 0x1FF (but with nulls that need processing)"""
    
    shellcode = bytearray()
    
    # Create a MOV ECX, 0x001FF900 (from the example but with appropriate byte order)
    # In little endian: 0x001FF900 becomes bytes [0x00, 0xF9, 0x1F, 0x00] 
    # But we want: MOV ECX, 0x001FF900  which is B9 00 F9 1F 00
    shellcode.extend(b'\xB9\x00\xF9\x1F\x00')  # MOV ECX, 0x001FF900 (has null bytes)
    
    # Now we want to shift this right by 0x10 to get 0x000001FF in ECX
    # This should be detected by our new strategy
    # Actually, our strategy should work when we want to create 0x000001FF directly
    
    # Let's also add: MOV EDX, 0x000001FF (which should trigger the shift strategy)
    shellcode.extend(b'\xBA\xFF\x01\x00\x00')  # MOV EDX, 0x000001FF (has null bytes)
    
    # Add INC instructions to make it more complex
    shellcode.extend(b'\x40')  # INC EAX
    shellcode.extend(b'\x41')  # INC ECX
    shellcode.extend(b'\x42')  # INC EDX
    
    return shellcode

def main():
    shellcode = create_shift_example_shellcode()
    
    print(f"Created shift example shellcode with {len(shellcode)} bytes")
    print("Shellcode bytes:", " ".join([f"\\x{byte:02x}" for byte in shellcode]))
    print("Hex dump format: ", " ".join([f"{byte:02x}" for byte in shellcode]))
    
    # Write to file
    with open("shift_example_test.bin", "wb") as f:
        f.write(shellcode)
    
    print("Shellcode written to shift_example_test.bin")
    
    # Count null bytes in the test shellcode
    null_count = shellcode.count(0)
    print(f"Number of null bytes in test shellcode: {null_count}")

if __name__ == "__main__":
    main()