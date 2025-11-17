#!/usr/bin/env python3
"""
Test script for GET PC (CALL/POP) strategy

Creates shellcode samples with null-byte containing immediate values
that should be handled by the GET PC strategy.
"""

import struct
import sys
import os

def create_getpc_test_shellcode():
    """
    Create test shellcode with MOV instructions containing null bytes
    in the immediate operand - perfect for testing GET PC strategy.
    """
    shellcode = bytearray()

    # Test Case 1: MOV EAX, 0x00112233 (contains null byte in MSB)
    # B8 33 22 11 00 (5 bytes)
    shellcode.extend(b'\xB8\x33\x22\x11\x00')

    # Test Case 2: MOV EBX, 0x44005566 (contains null byte in middle)
    # BB 66 55 00 44 (5 bytes)
    shellcode.extend(b'\xBB\x66\x55\x00\x44')

    # Test Case 3: MOV ECX, 0x00000001 (mostly nulls)
    # B9 01 00 00 00 (5 bytes)
    shellcode.extend(b'\xB9\x01\x00\x00\x00')

    # Test Case 4: MOV EDX, 0x12003400 (null byte in middle)
    # BA 00 34 00 12 (5 bytes)
    shellcode.extend(b'\xBA\x00\x34\x00\x12')

    # Test Case 5: MOV ESI, 0xDEADBEEF (no null bytes - should not trigger GET PC)
    # BE EF BE AD DE (5 bytes)
    shellcode.extend(b'\xBE\xEF\xBE\xAD\xDE')

    # Test Case 6: MOV EDI, 0x00FACADE (contains null byte)
    # BF DE CA FA 00 (5 bytes)
    shellcode.extend(b'\xBF\xDE\xCA\xFA\x00')

    # Test Case 7: MOV EBP, 0xFF00FF00 (two null bytes)
    # BD 00 FF 00 FF (5 bytes)
    shellcode.extend(b'\xBD\x00\xFF\x00\xFF')

    # Test Case 8: Some instructions between MOVs to test context
    # NOP (1 byte)
    shellcode.extend(b'\x90')

    # Test Case 9: MOV EAX, 0x13370000 (two trailing nulls)
    # B8 00 00 37 13 (5 bytes - note little endian)
    shellcode.extend(b'\xB8\x00\x00\x37\x13')

    return bytes(shellcode)

def analyze_shellcode(shellcode):
    """Analyze the shellcode and print information about it."""
    print(f"Generated test shellcode: {len(shellcode)} bytes")
    print("\nHexdump:")
    for i in range(0, len(shellcode), 16):
        hex_str = ' '.join(f'{b:02x}' for b in shellcode[i:i+16])
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in shellcode[i:i+16])
        print(f"{i:04x}:  {hex_str:<48}  {ascii_str}")

    # Count null bytes
    null_count = shellcode.count(0x00)
    print(f"\nNull bytes found: {null_count}")

    # Identify positions of null bytes
    null_positions = [i for i, b in enumerate(shellcode) if b == 0x00]
    if null_positions:
        print(f"Null byte positions: {null_positions}")

def main():
    # Create output directory if it doesn't exist
    os.makedirs('.test_bins', exist_ok=True)

    # Generate test shellcode
    print("=" * 70)
    print("GET PC Strategy Test Shellcode Generator")
    print("=" * 70)
    print()

    shellcode = create_getpc_test_shellcode()

    # Analyze the shellcode
    analyze_shellcode(shellcode)

    # Write to file
    output_file = '.test_bins/getpc_test.bin'
    with open(output_file, 'wb') as f:
        f.write(shellcode)

    print(f"\nTest shellcode written to: {output_file}")
    print("\nTo test:")
    print(f"  ./bin/byvalver {output_file} .test_bins/getpc_test_processed.bin")
    print(f"  hexdump -C .test_bins/getpc_test_processed.bin")

    return 0

if __name__ == '__main__':
    sys.exit(main())
