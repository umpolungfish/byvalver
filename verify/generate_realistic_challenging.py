#!/usr/bin/env python3
"""
Generate another challenging but more realistic shellcode containing null bytes
to test BYVALVER's performance on common patterns.
"""
import struct

def generate_realistic_challenging_shellcode():
    """
    Generate realistic shellcode with common patterns that have null bytes
    """
    shellcode = bytearray()
    
    # Common patterns that would appear in real shellcode:
    
    # 1. String operations (NULL-terminated strings)
    shellcode.extend(b'\x68\x00\x00\x00\x00')  # PUSH 0x00000000 (often used as NULL)
    shellcode.extend(b'\x68\x00\x65\x00\x63')  # PUSH "ce" with nulls (for "calc" or "exec")
    shellcode.extend(b'\x68\x6c\x00\x00\x61')  # PUSH "a" + nulls + "l" (for "api" or "call")  
    
    # 2. Port numbers and addresses
    shellcode.extend(b'\x68\x00\x10\x00\x00')  # PUSH 0x00001000 (common memory size)
    shellcode.extend(b'\x68\x00\x00\x20\x00')  # PUSH 0x00200000 (another memory value)
    
    # 3. Registry/Path related constants
    shellcode.extend(b'\x68\x73\x00\x00\x5c')  # PUSH "\s" with nulls (for paths like "\system")
    shellcode.extend(b'\x68\x00\x69\x74\x65')  # PUSH "eti" with a null (for "write", "delete", etc.)
    
    # 4. API function addresses (in direct form - though unusual)
    shellcode.extend(b'\xb8\x00\x00\x80\x7c')  # MOV EAX, kernel32 base address (has null)
    shellcode.extend(b'\xbb\x00\x00\x40\x00')  # MOV EBX, 0x00400000 (has nulls)
    
    # 5. Function parameters and flags
    shellcode.extend(b'\x68\x00\x02\x00\x00')  # PUSH 0x00000200 (flag or parameter)
    shellcode.extend(b'\x68\x00\x00\x04\x00')  # PUSH 0x00040000 (flag or parameter)
    
    # 6. Address offsets
    shellcode.extend(b'\x81\xc4\x00\x08\x00\x00')  # ADD ESP, 0x00000800 (has nulls)
    shellcode.extend(b'\x81\xec\x00\x00\x10\x00')  # SUB ESP, 0x00100000 (has nulls)
    
    # 7. More string data
    shellcode.extend(b'\x68\x00\x41\x00\x64')  # PUSH "dA" with null (for "Add", "Admin", etc.)
    
    # Balance stack
    for _ in range(13):  # We did 13 PUSH ops
        shellcode.extend(b'\x58')  # POP EAX
    
    return shellcode

def main():
    shellcode = generate_realistic_challenging_shellcode()
    
    # Write to file
    with open("realistic_challenging.bin", "wb") as f:
        f.write(shellcode)
    
    print(f"Generated {len(shellcode)} byte realistic challenging test shellcode")
    print(f"Shellcode written to realistic_challenging.bin")
    
    # Count null bytes
    null_count = 0
    for i, byte in enumerate(shellcode):
        if byte == 0:
            null_count += 1
            
    print(f"Total null bytes in original shellcode: {null_count}")
    print(f"Percentage null bytes: {null_count/len(shellcode)*100:.1f}%")

if __name__ == "__main__":
    main()