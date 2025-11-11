#!/usr/bin/env python3
"""
Generate a shellcode with simple cases BYVALVER can reliably handle
to demonstrate its effectiveness.
"""
import struct

def generate_simple_effective_shellcode():
    """
    Generate shellcode with simple null-byte cases BYVALVER handles well
    """
    shellcode = bytearray()
    
    # Simple MOV operations with null bytes - these should convert well with NEG/XOR strategies
    shellcode.extend(b'\x68\x00\x01\x02\x03')  # PUSH 0x03020100 (has null in first byte)
    shellcode.extend(b'\x68\xab\x00\xcd\xef')  # PUSH 0xefcd00ab (has null in second byte) 
    shellcode.extend(b'\x68\x12\x34\x00\x78')  # PUSH 0x78003412 (has null in third byte)
    shellcode.extend(b'\x68\x10\x20\x30\x00')  # PUSH 0x00302010 (has null in fourth byte)
    
    # String-like PUSH with embedded nulls
    shellcode.extend(b'\x68\x00\x65\x6c\x62')  # PUSH "ble" with null at start (for "ble" part of "enable", etc.)
    shellcode.extend(b'\x68\x6f\x00\x63\x61')  # PUSH "cao" with null in second position
    
    # MOV with simple null-byte patterns
    shellcode.extend(b'\xb8\x00\x44\x33\x22')  # MOV EAX, 0x22334400 (null at end)
    
    # More PUSH operations
    shellcode.extend(b'\x68\xde\xad\x00\xbe')  # PUSH 0xbe00adde (classic 0xDEADBEEF-like)
    shellcode.extend(b'\x68\xca\x00\xfe\xba')  # PUSH 0xbafeca00 (null in middle)
    
    # Balance stack - we had 9 PUSH operations
    for _ in range(9):
        shellcode.extend(b'\x58')  # POP EAX
    
    return shellcode

def main():
    shellcode = generate_simple_effective_shellcode()
    
    # Write to file
    with open("simple_effective.bin", "wb") as f:
        f.write(shellcode)
    
    print(f"Generated {len(shellcode)} byte simple effective test shellcode")
    print(f"Shellcode written to simple_effective.bin")
    
    # Count null bytes
    null_count = 0
    for i, byte in enumerate(shellcode):
        if byte == 0:
            null_count += 1
            
    print(f"Total null bytes in original shellcode: {null_count}")
    print(f"Percentage null bytes: {null_count/len(shellcode)*100:.1f}%")

if __name__ == "__main__":
    main()