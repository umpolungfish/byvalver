#!/usr/bin/env python3
"""
Test script for Indirect CALL/JMP strategy

Tests the critical pattern: CALL/JMP DWORD PTR [disp32]
This is the primary Windows API resolution pattern appearing 50+ times
in real-world shellcode samples.
"""

import subprocess
import sys
import os

def assemble_test():
    """Assemble the test assembly file to binary"""
    print("[*] Assembling test_indirect_call.asm...")

    asm_file = ".tests/test_indirect_call.asm"
    bin_file = ".test_bins/indirect_call_test.bin"

    # Create output directory if it doesn't exist
    os.makedirs(".test_bins", exist_ok=True)

    # Assemble with NASM
    result = subprocess.run(
        ["nasm", "-f", "bin", asm_file, "-o", bin_file],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"[!] Assembly failed: {result.stderr}")
        return None

    print(f"[+] Successfully assembled to {bin_file}")
    return bin_file

def check_null_bytes(filename):
    """Check if file contains null bytes and report statistics"""
    with open(filename, 'rb') as f:
        data = f.read()

    null_count = data.count(b'\x00')
    total_bytes = len(data)
    null_percentage = (null_count / total_bytes * 100) if total_bytes > 0 else 0

    print(f"[*] File: {filename}")
    print(f"    Total bytes: {total_bytes}")
    print(f"    Null bytes: {null_count} ({null_percentage:.2f}%)")

    return null_count > 0

def verify_pattern(filename):
    """Verify the file contains the expected CALL/JMP patterns"""
    with open(filename, 'rb') as f:
        data = f.read()

    # Look for the patterns:
    # FF 15 = CALL DWORD PTR [disp32]
    # FF 25 = JMP DWORD PTR [disp32]

    call_pattern_count = 0
    jmp_pattern_count = 0

    for i in range(len(data) - 1):
        if data[i:i+2] == b'\xFF\x15':
            call_pattern_count += 1
        elif data[i:i+2] == b'\xFF\x25':
            jmp_pattern_count += 1

    print(f"[*] Pattern verification:")
    print(f"    CALL DWORD PTR [mem] patterns: {call_pattern_count}")
    print(f"    JMP DWORD PTR [mem] patterns: {jmp_pattern_count}")

    return call_pattern_count > 0 or jmp_pattern_count > 0

def main():
    """Main test function"""
    print("=" * 60)
    print("Indirect CALL/JMP Strategy Test")
    print("=" * 60)
    print()

    # Step 1: Assemble the test
    bin_file = assemble_test()
    if not bin_file:
        print("[!] Test failed: Could not assemble test file")
        return 1

    print()

    # Step 2: Check for null bytes
    print("[*] Checking for null bytes in original...")
    has_nulls = check_null_bytes(bin_file)

    if not has_nulls:
        print("[!] Warning: Test shellcode contains no null bytes!")

    print()

    # Step 3: Verify pattern exists
    print("[*] Verifying indirect CALL/JMP patterns...")
    has_pattern = verify_pattern(bin_file)

    if not has_pattern:
        print("[!] Warning: Expected CALL/JMP patterns not found!")

    print()
    print("[+] Test preparation complete!")
    print(f"[*] Test file: {bin_file}")
    print()
    print("To process with byvalver:")
    print(f"  ./bin/byvalver {bin_file}")
    print()
    print("To verify null-byte elimination:")
    print(f"  python3 verify_nulls.py {bin_file.replace('.bin', '_processed.bin')}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
