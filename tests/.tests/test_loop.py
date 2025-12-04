#!/usr/bin/env python3
"""
Test script for LOOP family instruction strategies

Creates shellcode samples with LOOP/JECXZ/LOOPE/LOOPNE instructions
containing null bytes in the displacement field.
"""

import struct
import sys
import os

def create_loop_test_shellcode():
    """
    Create test shellcode with LOOP family instructions containing null bytes
    in the displacement operand.
    """
    shellcode = bytearray()

    # Test Case 1: LOOP with null displacement (E2 00)
    # This represents LOOP to next instruction (loop to offset +2)
    # Common pattern in edge cases
    shellcode.extend(b'\xE2\x00')

    # Test Case 2: JECXZ with null displacement (E3 00)
    # Jump if ECX=0 to next instruction
    shellcode.extend(b'\xE3\x00')

    # Test Case 3: LOOPE with null displacement (E1 00)
    # Loop while ZF=1 to next instruction
    shellcode.extend(b'\xE1\x00')

    # Test Case 4: LOOPNE with null displacement (E0 00)
    # Loop while ZF=0 to next instruction
    shellcode.extend(b'\xE0\x00')

    # Test Case 5: Typical LOOP pattern for ROR13 hash calculation
    # This simulates a common Windows shellcode pattern:
    # MOV ECX, 0x03 (set loop counter to 3)
    shellcode.extend(b'\xB9\x03\x00\x00\x00')
    # LOOP back 5 bytes - but this has a null: E2 FB (-5 in signed byte)
    # Let's use LOOP with displacement that contains null
    # Actually, let's make a LOOP 0x00 to test null displacement
    shellcode.extend(b'\xE2\x00')

    # Test Case 6: JECXZ forward jump with null
    # This tests forward jump scenario
    shellcode.extend(b'\xE3\x00')
    # NOP to jump over
    shellcode.extend(b'\x90')

    # Test Case 7: Mix with other instructions
    # Set ECX for loop
    shellcode.extend(b'\xB9\x05\x00\x00\x00')  # MOV ECX, 5
    # LOOP with null displacement
    shellcode.extend(b'\xE2\x00')

    # Test Case 8: LOOPE in string comparison scenario
    # Simulate a string comparison loop
    shellcode.extend(b'\xB9\x0A\x00\x00\x00')  # MOV ECX, 10
    # LODSB (load byte from DS:ESI)
    shellcode.extend(b'\xAC')
    # CMP AL, 0x41 (compare with 'A')
    shellcode.extend(b'\x3C\x41')
    # LOOPE with null (loop while equal)
    shellcode.extend(b'\xE1\x00')

    # Test Case 9: LOOPNE in hash calculation
    # Used for iterating until non-zero or count expires
    shellcode.extend(b'\xB9\xFF\x00\x00\x00')  # MOV ECX, 255
    # Some operation
    shellcode.extend(b'\x90')  # NOP placeholder
    # LOOPNE with null
    shellcode.extend(b'\xE0\x00')

    # Test Case 10: Normal LOOP without null (should not be transformed)
    # LOOP -10 (E2 F6) - no null byte
    shellcode.extend(b'\xE2\xF6')

    # Test Case 11: JECXZ with non-null displacement (should not be transformed)
    # JECXZ +5 (E3 05) - no null byte
    shellcode.extend(b'\xE3\x05')

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

    # Identify LOOP family instructions with nulls
    print("\nLOOP family instructions with null displacement:")
    loop_opcodes = {
        0xE0: "LOOPNE",
        0xE1: "LOOPE",
        0xE2: "LOOP",
        0xE3: "JECXZ"
    }

    for i in range(len(shellcode) - 1):
        if shellcode[i] in loop_opcodes:
            disp = shellcode[i + 1]
            has_null = "NULL!" if disp == 0x00 else ""
            print(f"  Offset {i:04x}: {loop_opcodes[shellcode[i]]} {disp:02x} {has_null}")

def main():
    # Create output directory if it doesn't exist
    os.makedirs('.test_bins', exist_ok=True)

    # Generate test shellcode
    print("=" * 70)
    print("LOOP Family Strategy Test Shellcode Generator")
    print("=" * 70)
    print()

    shellcode = create_loop_test_shellcode()

    # Analyze the shellcode
    analyze_shellcode(shellcode)

    # Write to file
    output_file = '.test_bins/loop_test.bin'
    with open(output_file, 'wb') as f:
        f.write(shellcode)

    print(f"\nTest shellcode written to: {output_file}")
    print("\nTo test:")
    print(f"  ./bin/byvalver {output_file} .test_bins/loop_test_processed.bin")
    print(f"  python3 verify_nulls.py .test_bins/loop_test_processed.bin")
    print(f"  hexdump -C .test_bins/loop_test_processed.bin")
    print("\nExpected transformations:")
    print("  LOOP 00   (E2 00) -> DEC ECX + JNZ (49 75 XX) [3 bytes]")
    print("  JECXZ 00  (E3 00) -> TEST ECX,ECX + JZ (85 C9 74 XX) [4 bytes]")
    print("  LOOPE 00  (E1 00) -> DEC ECX + JNZ +2 + JZ (49 75 02 74 XX) [5 bytes]")
    print("  LOOPNE 00 (E0 00) -> DEC ECX + JZ +2 + JNZ (49 74 02 75 XX) [5 bytes]")

    return 0

if __name__ == '__main__':
    sys.exit(main())
