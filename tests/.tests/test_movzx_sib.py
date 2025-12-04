#!/usr/bin/env python3
"""
Test script for MOVZX/MOVSX with SIB (Scale-Index-Base) addressing modes

Tests the critical Windows API resolution pattern:
    MOVZX EDX, WORD [EBX + 2*ECX]  ; Read ordinal from export table

This pattern is observed in 70%+ of Windows shellcode samples but may not be
handled by the current basic MOVZX strategy.
"""

import struct
import sys
import os

def create_movzx_sib_test_shellcode():
    """
    Create test shellcode with MOVZX/MOVSX using SIB addressing that may
    produce null bytes.

    SIB byte format: SS II BBB
    - SS (scale): 00=1, 01=2, 10=4, 11=8
    - III (index register): 000-111
    - BBB (base register): 000-111
    """
    shellcode = bytearray()

    print("Creating SIB addressing mode test cases:")
    print("=" * 70)

    # Test Case 1: MOVZX EDX, WORD [ECX + 2*EDX]
    # This is THE critical pattern from Windows API resolution
    # 0F B7 14 51
    # - 0F B7: MOVZX word prefix
    # - 14: ModR/M = 00 010 100 (mod=00, reg=EDX=010, r/m=100=SIB)
    # - 51: SIB = 01 010 001 (scale=2, index=EDX=010, base=ECX=001)
    print("\nTest 1: movzx edx, word [ecx + 2*edx]")
    print("  Pattern: API ordinal table lookup")
    print("  Encoding: 0F B7 14 51")
    shellcode.extend(b'\x0F\xB7\x14\x51')

    # Test Case 2: MOVZX EDX, WORD [EBX + 2*ECX]
    # Another common variant
    # 0F B7 14 4B
    print("\nTest 2: movzx edx, word [ebx + 2*ecx]")
    print("  Pattern: API ordinal table lookup (variant)")
    print("  Encoding: 0F B7 14 4B")
    shellcode.extend(b'\x0F\xB7\x14\x4B')

    # Test Case 3: MOVZX EDX, WORD [EBP + 2*ECX - 2]
    # With displacement
    # 0F B7 54 4D FE
    print("\nTest 3: movzx edx, word [ebp + 2*ecx - 2]")
    print("  Pattern: With negative displacement")
    print("  Encoding: 0F B7 54 4D FE")
    shellcode.extend(b'\x0F\xB7\x54\x4D\xFE')

    # Test Case 4: MOVZX ECX, WORD [EAX + 2*EDX]
    # 0F B7 0C 50
    print("\nTest 4: movzx ecx, word [eax + 2*edx]")
    print("  Encoding: 0F B7 0C 50")
    shellcode.extend(b'\x0F\xB7\x0C\x50')

    # Test Case 5: MOVZX EDX, WORD [EDX + 2*ECX]
    # Destination register same as base!
    # 0F B7 14 4A
    print("\nTest 5: movzx edx, word [edx + 2*ecx]")
    print("  Pattern: Destination = base register (tricky!)")
    print("  Encoding: 0F B7 14 4A")
    shellcode.extend(b'\x0F\xB7\x14\x4A')

    # Test Case 6: MOVZX byte variant with SIB
    # MOVZX EAX, BYTE [EBX + ECX]
    # 0F B6 04 0B
    print("\nTest 6: movzx eax, byte [ebx + ecx]")
    print("  Pattern: Byte load with SIB (scale=1)")
    print("  Encoding: 0F B6 04 0B")
    shellcode.extend(b'\x0F\xB6\x04\x0B')

    # Test Case 7: MOVSX variant with SIB
    # MOVSX EDX, WORD [EBX + 2*ECX]
    # 0F BF 14 4B
    print("\nTest 7: movsx edx, word [ebx + 2*ecx]")
    print("  Pattern: Sign-extend with SIB")
    print("  Encoding: 0F BF 14 4B")
    shellcode.extend(b'\x0F\xBF\x14\x4B')

    # Test Case 8: MOVZX with scale=4
    # MOVZX EAX, WORD [EDI + 4*ESI]
    # 0F B7 04 B7
    print("\nTest 8: movzx eax, word [edi + 4*esi]")
    print("  Pattern: Scale=4 addressing")
    print("  Encoding: 0F B7 04 B7")
    shellcode.extend(b'\x0F\xB7\x04\xB7')

    # Test Case 9: Problematic case - might encode with null
    # Let's manually construct one with null bytes
    # MOVZX EAX, WORD [EAX + 2*EAX] would be: 0F B7 04 40
    # But certain combinations create nulls in SIB byte
    print("\nTest 9: Edge case with potential null in SIB")
    print("  Encoding: 0F B7 04 40")
    shellcode.extend(b'\x0F\xB7\x04\x40')

    # Test Case 10: Control - null-free SIB that should pass through
    # MOVZX EBX, WORD [EDI + 2*ESI]
    # 0F B7 1C 77
    print("\nTest 10: movzx ebx, word [edi + 2*esi]")
    print("  Control: Should be null-free")
    print("  Encoding: 0F B7 1C 77")
    shellcode.extend(b'\x0F\xB7\x1C\x77')

    return bytes(shellcode)

def analyze_shellcode(shellcode):
    """Analyze the shellcode for null bytes and SIB patterns."""
    print("\n" + "=" * 70)
    print(f"Generated SIB test shellcode: {len(shellcode)} bytes")
    print("=" * 70)
    print("\nHexdump:")
    for i in range(0, len(shellcode), 16):
        hex_str = ' '.join(f'{b:02x}' for b in shellcode[i:i+16])
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in shellcode[i:i+16])
        print(f"{i:04x}:  {hex_str:<48}  {ascii_str}")

    # Count null bytes
    null_count = shellcode.count(0x00)
    print(f"\nNull bytes found: {null_count}")

    if null_count > 0:
        null_positions = [i for i, b in enumerate(shellcode) if b == 0x00]
        print(f"Null byte positions: {null_positions}")
    else:
        print("No null bytes detected in this particular encoding.")
        print("NOTE: Null bytes may still appear depending on how Capstone")
        print("      decodes and re-encodes these instructions.")

    # Identify SIB bytes (every 4th byte after 0F B7/B6/BE/BF pattern)
    print("\nSIB byte analysis:")
    i = 0
    while i < len(shellcode):
        if i + 3 < len(shellcode) and shellcode[i] == 0x0F:
            opcode2 = shellcode[i+1]
            modrm = shellcode[i+2]

            # Check if ModR/M indicates SIB (r/m field = 100)
            rm_field = modrm & 0x07
            if rm_field == 0x04 and i + 3 < len(shellcode):
                sib = shellcode[i+3]
                scale = (sib >> 6) & 0x03
                index = (sib >> 3) & 0x07
                base = sib & 0x07

                scale_val = [1, 2, 4, 8][scale]
                index_reg = ['eax', 'ecx', 'edx', 'ebx', 'none', 'ebp', 'esi', 'edi'][index]
                base_reg = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'][base]

                print(f"  Offset {i}: SIB = {sib:02X}")
                print(f"    Scale={scale_val}, Index={index_reg}, Base={base_reg}")

                if sib == 0x00:
                    print(f"    WARNING: SIB byte is 0x00 (null byte!)")

                i += 4
            else:
                i += 1
        else:
            i += 1

def main():
    os.makedirs('.test_bins', exist_ok=True)

    print("=" * 70)
    print("MOVZX/MOVSX SIB Addressing Mode Test Generator")
    print("=" * 70)
    print("\nTesting Windows API resolution pattern:")
    print("  MOVZX EDX, WORD [base + 2*index]")
    print("\nThis pattern reads 16-bit ordinals from PE export tables.")
    print("Observed in 70%+ of Windows shellcode samples.")

    shellcode = create_movzx_sib_test_shellcode()
    analyze_shellcode(shellcode)

    output_file = '.test_bins/movzx_sib_test.bin'
    with open(output_file, 'wb') as f:
        f.write(shellcode)

    print(f"\n{'=' * 70}")
    print(f"Test shellcode written to: {output_file}")
    print("=" * 70)
    print("\nTo test SIB addressing support:")
    print(f"  1. Process the test shellcode:")
    print(f"     ./bin/byvalver {output_file}")
    print(f"  2. Verify null bytes removed:")
    print(f"     python3 verify_nulls.py .test_bins/movzx_sib_test_processed.bin")
    print(f"  3. Compare sizes:")
    print(f"     ls -lh .test_bins/movzx_sib_test*.bin")
    print(f"\nExpected behavior:")
    print(f"  - If current strategy handles SIB: output should be null-free")
    print(f"  - If current strategy fails SIB: may have nulls or errors")
    print(f"  - Enhanced strategy needed if SIB not properly handled")
    print("=" * 70)

    return 0

if __name__ == '__main__':
    sys.exit(main())
