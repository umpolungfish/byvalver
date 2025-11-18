#!/usr/bin/env python3
"""
Test script for MOVZX/MOVSX null-byte elimination strategy

Creates shellcode samples with MOVZX/MOVSX instructions that produce null bytes
due to ModR/M encoding or displacement values - critical for Windows API resolution.
"""

import struct
import sys
import os

def create_movzx_test_shellcode():
    """
    Create test shellcode with MOVZX/MOVSX instructions containing null bytes.

    Common patterns in Windows shellcode for PE export table ordinal reading.
    """
    shellcode = bytearray()

    # Test Case 1: movzx eax, byte [eax]
    # Encoding: 0F B6 00 (contains null byte in ModR/M)
    # ModR/M: 00 = mod=00 (no displacement), reg=000 (EAX), r/m=000 (EAX)
    print("Test 1: movzx eax, byte [eax] -> 0F B6 00")
    shellcode.extend(b'\x0F\xB6\x00')

    # Test Case 2: movzx eax, byte [ebp]
    # Encoding: 0F B6 45 00 (contains null byte in displacement)
    # ModR/M: 45 = mod=01 (disp8), reg=000 (EAX), r/m=101 (EBP)
    # Displacement: 00 (null byte)
    print("Test 2: movzx eax, byte [ebp] -> 0F B6 45 00")
    shellcode.extend(b'\x0F\xB6\x45\x00')

    # Test Case 3: movzx ecx, byte [ecx]
    # Encoding: 0F B6 09 (no null - control test)
    # ModR/M: 09 = mod=00, reg=001 (ECX), r/m=001 (ECX)
    print("Test 3: movzx ecx, byte [ecx] -> 0F B6 09 (null-free control)")
    shellcode.extend(b'\x0F\xB6\x09')

    # Test Case 4: movzx edx, byte [edx]
    # Encoding: 0F B6 12 (no null - another control)
    print("Test 4: movzx edx, byte [edx] -> 0F B6 12 (null-free control)")
    shellcode.extend(b'\x0F\xB6\x12')

    # Test Case 5: movzx ebx, byte [ebx]
    # Encoding: 0F B6 1B (no null)
    print("Test 5: movzx ebx, byte [ebx] -> 0F B6 1B (null-free control)")
    shellcode.extend(b'\x0F\xB6\x1B')

    # Test Case 6: movzx eax, word [eax]
    # Encoding: 0F B7 00 (contains null - word version)
    # This is used for reading 16-bit ordinals from export tables
    print("Test 6: movzx eax, word [eax] -> 0F B7 00 (16-bit ordinal read)")
    shellcode.extend(b'\x0F\xB7\x00')

    # Test Case 7: movsx eax, byte [eax]
    # Encoding: 0F BE 00 (contains null - sign-extend variant)
    print("Test 7: movsx eax, byte [eax] -> 0F BE 00 (sign-extend)")
    shellcode.extend(b'\x0F\xBE\x00')

    # Test Case 8: movsx eax, word [eax]
    # Encoding: 0F BF 00 (contains null - word sign-extend)
    print("Test 8: movsx eax, word [eax] -> 0F BF 00 (word sign-extend)")
    shellcode.extend(b'\x0F\xBF\x00')

    # Test Case 9: Some realistic context - simulating ordinal lookup
    # mov eax, [some_address] ; get export table address
    # movzx ecx, word [eax]   ; read 16-bit ordinal (THIS WILL HAVE NULL!)
    # The second instruction is the critical one
    print("\nTest 9: Realistic API resolution pattern")
    # For simplicity, just test the MOVZX part
    shellcode.extend(b'\x0F\xB7\x08')  # movzx ecx, word [eax] (null-free)

    # Test Case 10: movzx with EBP base and zero displacement (common pattern)
    # movzx edx, byte [ebp+0]
    # Encoding: 0F B6 55 00 (contains null in displacement)
    print("Test 10: movzx edx, byte [ebp+0] -> 0F B6 55 00")
    shellcode.extend(b'\x0F\xB6\x55\x00')

    return bytes(shellcode)

def analyze_shellcode(shellcode):
    """Analyze the shellcode and print information about it."""
    print("\n" + "=" * 70)
    print(f"Generated test shellcode: {len(shellcode)} bytes")
    print("=" * 70)
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
        print("\nInstructions with null bytes:")
        # Group by instruction boundaries (every 3-4 bytes)
        for pos in null_positions:
            # Find the start of the instruction (look back for 0x0F prefix)
            start = max(0, pos - 3)
            end = min(len(shellcode), pos + 2)
            instr_bytes = shellcode[start:end]
            hex_str = ' '.join(f'{b:02x}' for b in instr_bytes)
            print(f"  Offset {pos}: ...{hex_str}...")

def main():
    # Create output directory if it doesn't exist
    os.makedirs('.test_bins', exist_ok=True)

    # Generate test shellcode
    print("=" * 70)
    print("MOVZX/MOVSX Strategy Test Shellcode Generator")
    print("=" * 70)
    print("\nCreating test cases for null-producing MOVZX/MOVSX instructions:")
    print("-" * 70)
    print()

    shellcode = create_movzx_test_shellcode()

    # Analyze the shellcode
    analyze_shellcode(shellcode)

    # Write to file
    output_file = '.test_bins/movzx_test.bin'
    with open(output_file, 'wb') as f:
        f.write(shellcode)

    print(f"\n{'=' * 70}")
    print(f"Test shellcode written to: {output_file}")
    print("=" * 70)
    print("\nTo test the MOVZX/MOVSX strategy:")
    print(f"  1. Build byvalver:")
    print(f"     make clean && make")
    print(f"  2. Process the test shellcode:")
    print(f"     ./bin/byvalver {output_file}")
    print(f"  3. Verify null bytes removed:")
    print(f"     python3 verify_nulls.py .test_bins/movzx_test_processed.bin")
    print(f"  4. Examine the output:")
    print(f"     hexdump -C .test_bins/movzx_test_processed.bin")
    print()
    print("Expected behavior:")
    print("  - Original shellcode has ~5 null bytes (in MOVZX/MOVSX encodings)")
    print("  - Processed shellcode should have 0 null bytes")
    print("  - Size should increase ~2-3x (temp register substitution)")
    print("=" * 70)

    return 0

if __name__ == '__main__':
    sys.exit(main())
