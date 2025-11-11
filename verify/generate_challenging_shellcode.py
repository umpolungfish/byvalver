#!/usr/bin/env python3
"""
Generate a challenging shellcode containing numerous null bytes across different instruction types
to test BYVALVER's performance.
"""
import struct
import sys

def generate_challenging_shellcode():
    """
    Generate complex shellcode with many null bytes across different instruction types
    """
    shellcode = bytearray()
    
    # Multiple MOV instructions with immediate values containing null bytes
    shellcode.extend(b'\xb8\x00\x00\x00\x01')  # MOV EAX, 0x01000000 (has 3 nulls)
    shellcode.extend(b'\xbb\x00\x10\x00\x00')  # MOV EBX, 0x00001000 (has 2 nulls)  
    shellcode.extend(b'\xbc\x00\x00\x20\x00')  # MOV ESP, 0x00200000 (has 2 nulls)
    shellcode.extend(b'\xbd\x00\x30\x00\x00')  # MOV EBP, 0x00003000 (has 2 nulls)
    shellcode.extend(b'\xbe\x00\x00\x40\x00')  # MOV ESI, 0x00400000 (has 2 nulls)
    
    # PUSH instructions with immediate values containing null bytes
    shellcode.extend(b'\x68\x00\x50\x00\x00')  # PUSH 0x00005000 (has 2 nulls)
    shellcode.extend(b'\x68\x00\x00\x60\x00')  # PUSH 0x00600000 (has 2 nulls)
    shellcode.extend(b'\x68\x70\x00\x00\x00')  # PUSH 0x00000070 (has 2 nulls) 
    shellcode.extend(b'\x68\x00\x80\x00\x90')  # PUSH 0x90008000 (has 1 null)
    
    # ADD/SUB operations with immediate values containing null bytes
    shellcode.extend(b'\x83\xc0\x20')          # ADD EAX, 0x20 (8-bit immediate, no null)
    shellcode.extend(b'\x81\xc3\x00\x01\x00\x00')  # ADD EBX, 0x00000100 (has nulls)
    shellcode.extend(b'\x81\xec\x00\x02\x00\x00')  # SUB ESP, 0x00000200 (has nulls)
    
    # String-related operations with embedded nulls
    shellcode.extend(b'\x68\x00\x00\x63\x61')  # PUSH 0x61630000 ("ca" with nulls)
    shellcode.extend(b'\x68\x6c\x00\x00\x63')  # PUSH 0x6300006c ("c" + nulls + "l")
    
    # CALL/JMP with immediate addresses containing null bytes
    shellcode.extend(b'\xe8\x00\x00\x00\x00')  # CALL 0x00000000 (relative, has nulls)
    
    # XOR/AND/OR operations with immediate values containing null bytes
    shellcode.extend(b'\x83\xf0\x30')          # XOR EAX, 0x30 (8-bit immediate, no null)
    shellcode.extend(b'\x81\xf3\x00\x00\x04\x00')  # XOR EBX, 0x00040000 (has nulls)
    shellcode.extend(b'\x81\xe4\x00\x08\x00\x00')  # AND ESP, 0x00000800 (has nulls)
    
    # More complex patterns
    shellcode.extend(b'\x68\xab\xcd\x00\xef')  # PUSH 0xef00cdab (has 1 null)
    shellcode.extend(b'\x68\x12\x00\x34\x00')  # PUSH 0x00340012 (has 2 nulls)
    shellcode.extend(b'\x68\x00\x56\x00\x78')  # PUSH 0x78005600 (has 2 nulls)
    
    # Some operations to balance the stack
    shellcode.extend(b'\x58')  # POP EAX
    shellcode.extend(b'\x58')  # POP EAX
    shellcode.extend(b'\x58')  # POP EAX
    shellcode.extend(b'\x58')  # POP EAX
    shellcode.extend(b'\x58')  # POP EAX
    shellcode.extend(b'\x58')  # POP EAX
    
    return shellcode

def main():
    shellcode = generate_challenging_shellcode()
    
    # Write to file
    with open("challenging_shellcode.bin", "wb") as f:
        f.write(shellcode)
    
    print(f"Generated {len(shellcode)} byte challenging test shellcode")
    print(f"Shellcode written to challenging_shellcode.bin")
    print(f"Shellcode bytes: {shellcode.hex()}")
    
    # Count null bytes
    null_count = 0
    for i, byte in enumerate(shellcode):
        if byte == 0:
            null_count += 1
            
    print(f"\nTotal null bytes in original shellcode: {null_count}")
    print(f"Percentage null bytes: {null_count/len(shellcode)*100:.1f}%")
    
    # Show positions of null bytes
    null_positions = []
    for i, byte in enumerate(shellcode):
        if byte == 0:
            null_positions.append(i)
    print(f"Null byte positions: {null_positions[:20]}{'...' if len(null_positions) > 20 else ''}")

if __name__ == "__main__":
    main()