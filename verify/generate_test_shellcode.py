#!/usr/bin/env python3
import struct
import sys

def generate_shellcode(size):
    """
    Generate a shellcode of specified size with various instructions that may contain null bytes
    """
    shellcode = bytearray()
    
    # Add a few instructions that are likely to have null bytes
    # This will create a pattern of instructions that BYVALVER would need to process
    
    # Pattern: MOV instructions with immediate values that contain nulls
    instructions = [
        b'\xb8\x33\x22\x11\x00',  # mov eax, 0x00112233 (has null)
        b'\xb9\x44\x33\x22\x00',  # mov ecx, 0x00223344 (has null)
        b'\xba\x55\x44\x33\x00',  # mov edx, 0x00334455 (has null)
        b'\xbb\x66\x55\x44\x00',  # mov ebx, 0x00445566 (has null)
        b'\xbc\x77\x66\x55\x00',  # mov esp, 0x00556677 (has null)
        b'\xbd\x88\x77\x66\x00',  # mov ebp, 0x00667788 (has null)
        b'\xbe\x99\x88\x77\x00',  # mov esi, 0x00778899 (has null)
        b'\xbf\xaa\x99\x88\x00',  # mov edi, 0x008899aa (has null)
    ]
    
    # Add basic instructions that don't have nulls for padding
    safe_instructions = [
        b'\x90',  # nop
        b'\x40',  # inc eax
        b'\x41',  # inc ecx
        b'\x42',  # inc edx
        b'\x43',  # inc ebx
        b'\x90',  # nop
        b'\x31\xc0',  # xor eax, eax
        b'\x31\xc9',  # xor ecx, ecx
        b'\x31\xd2',  # xor edx, edx
        b'\x31\xdb',  # xor ebx, ebx
    ]
    
    # Calculate how many full instruction patterns we can fit
    pattern_size = sum(len(inst) for inst in instructions)
    safe_pattern_size = sum(len(inst) for inst in safe_instructions)
    
    while len(shellcode) < size:
        # Add some null-containing instructions
        for inst in instructions:
            if len(shellcode) + len(inst) <= size:
                shellcode.extend(inst)
            else:
                break
        
        # Add some safe instructions to reach the target size
        for inst in safe_instructions:
            if len(shellcode) + len(inst) <= size:
                shellcode.extend(inst)
            else:
                break
    
    # If we haven't reached the target size, pad with NOPs
    while len(shellcode) < size:
        shellcode.append(0x90)  # NOP
    
    # Truncate to exact size if needed
    return shellcode[:size]

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <output_file> <size_in_bytes>")
        sys.exit(1)
    
    output_file = sys.argv[1]
    size = int(sys.argv[2])
    
    shellcode = generate_shellcode(size)
    
    with open(output_file, 'wb') as f:
        f.write(shellcode)
    
    print(f"Generated {len(shellcode)} byte shellcode in {output_file}")

if __name__ == "__main__":
    main()