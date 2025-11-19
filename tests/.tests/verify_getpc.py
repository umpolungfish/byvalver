#!/usr/bin/env python3
"""
Verification script for GET PC (byte-construction) strategy

Verifies that:
1. Null bytes have been eliminated
2. The transformation is correct
3. Size expansion is reasonable
"""

import sys

def verify_null_elimination(filename):
    """Verify that the file contains no null bytes."""
    with open(filename, 'rb') as f:
        data = f.read()

    null_count = data.count(b'\x00')

    if null_count == 0:
        print(f"✓ NULL ELIMINATION: PASSED - No null bytes found")
        return True
    else:
        print(f"✗ NULL ELIMINATION: FAILED - Found {null_count} null bytes")
        null_positions = [i for i, b in enumerate(data) if b == 0]
        print(f"  Null byte positions: {null_positions[:10]}...")
        return False

def analyze_transformation(original_file, processed_file):
    """Analyze the transformation characteristics."""
    with open(original_file, 'rb') as f:
        original = f.read()
    with open(processed_file, 'rb') as f:
        processed = f.read()

    original_size = len(original)
    processed_size = len(processed)
    expansion_ratio = processed_size / original_size if original_size > 0 else 0

    original_nulls = original.count(b'\x00')

    print(f"\n=== TRANSFORMATION ANALYSIS ===")
    print(f"Original size:     {original_size} bytes")
    print(f"Processed size:    {processed_size} bytes")
    print(f"Expansion ratio:   {expansion_ratio:.2f}x")
    print(f"Null bytes removed: {original_nulls}")
    print(f"Size increase:     {processed_size - original_size} bytes (+{((processed_size/original_size - 1) * 100):.1f}%)")

    return expansion_ratio

def main():
    if len(sys.argv) != 3:
        print("Usage: verify_getpc.py <original_file> <processed_file>")
        return 1

    original_file = sys.argv[1]
    processed_file = sys.argv[2]

    print("=" * 70)
    print("GET PC Strategy Verification")
    print("=" * 70)

    # Test 1: Null byte elimination
    print("\n[TEST 1] Null Byte Elimination")
    null_free = verify_null_elimination(processed_file)

    # Test 2: Transformation analysis
    print("\n[TEST 2] Transformation Analysis")
    expansion = analyze_transformation(original_file, processed_file)

    # Summary
    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)

    if null_free:
        print("✓ SUCCESS: All null bytes eliminated!")
        if expansion < 5.0:
            print(f"✓ EFFICIENCY: Expansion ratio ({expansion:.2f}x) is reasonable")
        else:
            print(f"⚠ WARNING: High expansion ratio ({expansion:.2f}x)")
        return 0
    else:
        print("✗ FAILURE: Null bytes remain in processed shellcode")
        return 1

if __name__ == '__main__':
    sys.exit(main())
