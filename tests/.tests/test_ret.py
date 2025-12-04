#!/usr/bin/env python3
"""
Test script for RET immediate null-byte elimination strategy

This script:
1. Assembles test_ret_immediate.asm to generate shellcode with RET imm instructions
2. Extracts the .text section to create raw shellcode
3. Can be used with byvalver to test RET immediate transformation
"""

import os
import subprocess
import sys

def run_command(cmd, description):
    """Run a shell command and handle errors"""
    print(f"[*] {description}")
    print(f"    Command: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Error: {description} failed")
        print(f"    stdout: {result.stdout}")
        print(f"    stderr: {result.stderr}")
        return False
    if result.stdout:
        print(f"    stdout: {result.stdout}")
    return True

def main():
    test_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(test_dir)
    test_bins_dir = os.path.join(project_root, ".test_bins")

    # Create test bins directory if it doesn't exist
    os.makedirs(test_bins_dir, exist_ok=True)

    asm_file = os.path.join(test_dir, "test_ret_immediate.asm")
    obj_file = os.path.join(test_bins_dir, "ret_test.o")
    bin_file = os.path.join(test_bins_dir, "ret_test.bin")

    print("[+] Testing RET immediate null-byte elimination strategy")
    print(f"    Test directory: {test_dir}")
    print(f"    Output directory: {test_bins_dir}")

    # Step 1: Assemble the test file
    if not run_command(
        f"nasm -f elf32 {asm_file} -o {obj_file}",
        "Assembling test_ret_immediate.asm"
    ):
        return 1

    # Step 2: Extract .text section as raw binary
    if not run_command(
        f"objcopy -O binary --only-section=.text {obj_file} {bin_file}",
        "Extracting .text section to raw binary"
    ):
        return 1

    # Step 3: Display the generated shellcode
    print("\n[+] Generated shellcode:")
    with open(bin_file, "rb") as f:
        shellcode = f.read()
        hex_dump = " ".join(f"{b:02x}" for b in shellcode)
        print(f"    Size: {len(shellcode)} bytes")
        print(f"    Hex:  {hex_dump}")

    # Step 4: Check for null bytes in original
    null_count = shellcode.count(b'\x00')
    print(f"\n[+] Null byte analysis (original):")
    print(f"    Null bytes found: {null_count}")

    if null_count > 0:
        print(f"    Null byte positions:")
        for i, b in enumerate(shellcode):
            if b == 0:
                print(f"      Position {i}: 0x00")

    print(f"\n[+] Test shellcode created: {bin_file}")
    print(f"[+] You can now process it with byvalver:")
    print(f"    ./bin/byvalver {bin_file}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
