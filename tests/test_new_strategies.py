#!/usr/bin/env python3
"""
Test suite for newly discovered byvalver strategies:
1. PUSHW 16-bit immediate (Priority 87)
2. CLTD zero extension (Priority 82)
"""

import subprocess
import sys
import os

def test_pushw_strategy():
    """Test PUSHW 16-bit immediate strategy for port numbers"""
    print("\n" + "="*60)
    print("TEST 1: PUSHW 16-bit Immediate Strategy")
    print("="*60)

    # Test case: PUSH with port number 4444 (0x115C in network byte order)
    # Original encoding: 68 5C 11 00 00 (contains null bytes)
    # Expected: PUSHW transformation to remove nulls

    test_shellcode = bytes([
        0x68, 0x5C, 0x11, 0x00, 0x00,  # PUSH 0x115C (port 4444)
        0x68, 0x01, 0x02, 0x00, 0x00,  # PUSH 0x0201 (another test value)
    ])

    input_file = '/tmp/test_pushw_input.bin'
    output_file = '/tmp/test_pushw_output.bin'

    # Write test shellcode
    with open(input_file, 'wb') as f:
        f.write(test_shellcode)

    print(f"Input:  {test_shellcode.hex()}")
    print(f"Nulls in input: {test_shellcode.count(0x00)} null bytes")

    # Run byvalver
    result = subprocess.run(
        ['./bin/byvalver', '-v', input_file, output_file],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"❌ FAIL: byvalver returned {result.returncode}")
        print(f"STDERR: {result.stderr}")
        return False

    # Read output
    with open(output_file, 'rb') as f:
        output = f.read()

    print(f"Output: {output.hex()}")
    print(f"Nulls in output: {output.count(0x00)} null bytes")

    # Verify no null bytes
    if b'\x00' in output:
        print(f"❌ FAIL: Output still contains {output.count(0x00)} null bytes")
        return False

    # Check if PUSHW encoding was used (0x66 0x68)
    if b'\x66\x68' in output:
        print("✓ PUSHW encoding detected (0x66 0x68 prefix)")

    print("✅ PASS: PUSHW strategy successfully eliminated null bytes")
    return True


def test_cltd_strategy():
    """Test CLTD zero extension optimization strategy"""
    print("\n" + "="*60)
    print("TEST 2: CLTD Zero Extension Strategy")
    print("="*60)

    # Test case: XOR EDX, EDX to zero register
    # Original encoding: 31 D2 (2 bytes)
    # Expected: CLTD (0x99, 1 byte) when safe

    test_shellcode = bytes([
        0xB8, 0x01, 0x00, 0x00, 0x00,  # MOV EAX, 1 (sets EAX to positive value)
        0x31, 0xD2,                     # XOR EDX, EDX (should transform to CLTD)
        0xB8, 0x0B, 0x00, 0x00, 0x00,  # MOV EAX, 0xB (syscall number)
        0x31, 0xD2,                     # XOR EDX, EDX (another instance)
    ])

    input_file = '/tmp/test_cltd_input.bin'
    output_file = '/tmp/test_cltd_output.bin'

    # Write test shellcode
    with open(input_file, 'wb') as f:
        f.write(test_shellcode)

    print(f"Input:  {test_shellcode.hex()}")
    print(f"Nulls in input: {test_shellcode.count(0x00)} null bytes")
    print(f"Input size: {len(test_shellcode)} bytes")

    # Run byvalver
    result = subprocess.run(
        ['./bin/byvalver', '-v', input_file, output_file],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"❌ FAIL: byvalver returned {result.returncode}")
        print(f"STDERR: {result.stderr}")
        return False

    # Read output
    with open(output_file, 'rb') as f:
        output = f.read()

    print(f"Output: {output.hex()}")
    print(f"Nulls in output: {output.count(0x00)} null bytes")
    print(f"Output size: {len(output)} bytes")
    print(f"Size reduction: {len(test_shellcode) - len(output)} bytes")

    # Verify no null bytes
    if b'\x00' in output:
        print(f"❌ FAIL: Output still contains {output.count(0x00)} null bytes")
        return False

    # Check if CLTD was used (0x99)
    if b'\x99' in output:
        cltd_count = output.count(0x99)
        print(f"✓ CLTD instruction detected ({cltd_count} instances of 0x99)")

    print("✅ PASS: CLTD strategy successfully eliminated null bytes")
    return True


def test_combined_strategies():
    """Test both strategies working together in realistic shellcode"""
    print("\n" + "="*60)
    print("TEST 3: Combined Strategies (Socket Bind Shellcode Pattern)")
    print("="*60)

    # Realistic pattern from socket bind shellcode
    test_shellcode = bytes([
        # Socket setup
        0xB8, 0x66, 0x00, 0x00, 0x00,  # MOV EAX, 0x66 (socketcall)
        0xBB, 0x01, 0x00, 0x00, 0x00,  # MOV EBX, 1 (socket)
        0x31, 0xD2,                     # XOR EDX, EDX (zero register)

        # Port number (4444)
        0x68, 0x5C, 0x11, 0x00, 0x00,  # PUSH 0x115C (port 4444)

        # More setup
        0x31, 0xC9,                     # XOR ECX, ECX
        0x31, 0xD2,                     # XOR EDX, EDX (another instance)
    ])

    input_file = '/tmp/test_combined_input.bin'
    output_file = '/tmp/test_combined_output.bin'

    # Write test shellcode
    with open(input_file, 'wb') as f:
        f.write(test_shellcode)

    print(f"Input:  {test_shellcode.hex()}")
    print(f"Nulls in input: {test_shellcode.count(0x00)} null bytes")
    print(f"Input size: {len(test_shellcode)} bytes")

    # Run byvalver with verbose output
    result = subprocess.run(
        ['./bin/byvalver', '-V', input_file, output_file],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"❌ FAIL: byvalver returned {result.returncode}")
        print(f"STDERR: {result.stderr}")
        return False

    print("\n--- Transformation Log ---")
    print(result.stderr)
    print("--- End Log ---\n")

    # Read output
    with open(output_file, 'rb') as f:
        output = f.read()

    print(f"Output: {output.hex()}")
    print(f"Nulls in output: {output.count(0x00)} null bytes")
    print(f"Output size: {len(output)} bytes")

    # Calculate metrics
    null_elimination_rate = (1 - output.count(0x00) / test_shellcode.count(0x00)) * 100 if test_shellcode.count(0x00) > 0 else 100
    size_change = ((len(output) - len(test_shellcode)) / len(test_shellcode)) * 100

    print(f"\n📊 Metrics:")
    print(f"   Null elimination: {null_elimination_rate:.1f}%")
    print(f"   Size change: {size_change:+.1f}%")

    # Verify no null bytes
    if b'\x00' in output:
        print(f"❌ FAIL: Output still contains {output.count(0x00)} null bytes")
        return False

    print("✅ PASS: Combined strategies successfully eliminated all null bytes")
    return True


def main():
    print("\n" + "="*60)
    print("BYVALVER NEW STRATEGIES TEST SUITE")
    print("Testing newly discovered strategies (2025-12-16)")
    print("="*60)

    # Check if byvalver exists
    if not os.path.exists('./bin/byvalver'):
        print("❌ ERROR: byvalver binary not found. Run 'make' first.")
        return 1

    results = []

    # Run tests
    results.append(("PUSHW 16-bit Immediate", test_pushw_strategy()))
    results.append(("CLTD Zero Extension", test_cltd_strategy()))
    results.append(("Combined Strategies", test_combined_strategies()))

    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")

    print(f"\nTotal: {passed}/{total} tests passed ({passed/total*100:.1f}%)")

    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
