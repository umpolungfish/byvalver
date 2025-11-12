#!/usr/bin/env python3
"""
Enterprise-grade null byte verification for BYVALVER-processed shellcode.
Provides comprehensive analysis of null byte presence and potential issues.
"""
import sys
import os
from typing import List, Tuple
import argparse


def analyze_shellcode_nulls(shellcode: bytes) -> Tuple[List[int], int, float]:
    """
    Analyze shellcode for null byte occurrences and provide statistics
    """
    null_positions = []
    for i, byte in enumerate(shellcode):
        if byte == 0:
            null_positions.append(i)

    total_bytes = len(shellcode)
    null_count = len(null_positions)
    null_percentage = (null_count / total_bytes * 100) if total_bytes > 0 else 0

    return null_positions, null_count, null_percentage


def find_null_sequences(shellcode: bytes, max_sequence=10) -> List[Tuple[int, int]]:
    """
    Find sequences of consecutive null bytes and return (start_pos, length) tuples
    """
    sequences = []
    i = 0
    while i < len(shellcode):
        if shellcode[i] == 0:
            start = i
            while i < len(shellcode) and shellcode[i] == 0:
                i += 1
            length = i - start
            if length <= max_sequence:  # Only return sequences up to max_sequence
                sequences.append((start, length))
        else:
            i += 1
    return sequences


def get_context_around_position(shellcode: bytes, pos: int, context_size: int = 10) -> bytes:
    """
    Get context bytes around a specific position
    """
    start = max(0, pos - context_size)
    end = min(len(shellcode), pos + context_size + 1)
    return shellcode[start:end]


def generate_detailed_report(filename: str, shellcode: bytes, null_positions: List[int], 
                           null_count: int, null_percentage: float) -> str:
    """
    Generate a detailed analysis report
    """
    report = []
    report.append(f"NULL BYTE ANALYSIS REPORT")
    report.append(f"=" * 50)
    report.append(f"File: {filename}")
    report.append(f"Size: {len(shellcode)} bytes")
    report.append(f"Null bytes: {null_count} ({null_percentage:.2f}%)")
    
    if null_count == 0:
        report.append("\n✓ SUCCESS: No null bytes found in shellcode!")
        return "\n".join(report)
    
    # Analyze null byte distribution
    if null_positions:
        report.append(f"\nFirst null byte at position: {null_positions[0]}")
        report.append(f"Last null byte at position: {null_positions[-1]}")
        
        # Check for null byte sequences
        sequences = find_null_sequences(shellcode)
        if sequences:
            report.append(f"\nConsecutive null byte sequences found: {len(sequences)}")
            for start_pos, length in sequences[:10]:  # Show first 10 sequences
                report.append(f"  Position {start_pos}: {length} consecutive nulls")
            if len(sequences) > 10:
                report.append(f"  ... and {len(sequences) - 10} more sequences")
        
        # Show context around first few null bytes
        report.append(f"\nContext around first 5 null bytes:")
        for i, pos in enumerate(null_positions[:5]):
            context = get_context_around_position(shellcode, pos, 5)
            hex_context = context.hex()
            report.append(f"  Position {pos}: ...{hex_context}...")
    
    # Risk assessment
    if null_percentage > 10:
        report.append(f"\n⚠️  HIGH RISK: Null byte percentage > 10%")
    elif null_percentage > 5:
        report.append(f"\n⚠️  MEDIUM RISK: Null byte percentage > 5%")
    else:
        report.append(f"\nℹ️  LOW RISK: Null byte percentage <= 5%")
    
    # Recommendation
    if null_count > 0:
        report.append(f"\n🔧 RECOMMENDATION: Process with BYVALVER to remove null bytes")
    else:
        report.append(f"\n✅ RECOMMENDATION: Shellcode is ready for use - no null bytes present")
    
    return "\n".join(report)


def verify_null_bytes(filename: str, detailed: bool = False) -> int:
    """
    Main verification function
    """
    if not os.path.exists(filename):
        print(f"Error: File {filename} does not exist", file=sys.stderr)
        return 2

    try:
        with open(filename, 'rb') as f:
            data = f.read()

        null_positions, null_count, null_percentage = analyze_shellcode_nulls(data)

        if detailed:
            report = generate_detailed_report(filename, data, null_positions, null_count, null_percentage)
            print(report)
        else:
            print(f"File: {filename}")
            print(f"Size: {len(data)} bytes")
            print(f"Found {null_count} null bytes at positions: {null_positions[:10]}{'...' if len(null_positions) > 10 else ''}")

            if null_count == 0:
                print("SUCCESS: No null bytes found in output!")
                return 0
            else:
                print("ISSUE: Null bytes still present in output")
                # Show context around the first null byte
                if null_positions:
                    pos = null_positions[0]
                    context = get_context_around_position(data, pos, 5)
                    print(f"Context around first null byte: {context.hex()}")
        
        return 1 if null_count > 0 else 0

    except Exception as e:
        print(f"Error analyzing file {filename}: {e}", file=sys.stderr)
        return 2


def main():
    parser = argparse.ArgumentParser(description='Verify null bytes in shellcode files')
    parser.add_argument('filename', help='Shellcode file to analyze')
    parser.add_argument('-d', '--detailed', action='store_true', 
                       help='Show detailed analysis report')
    
    args = parser.parse_args()
    
    return verify_null_bytes(args.filename, args.detailed)


if __name__ == "__main__":
    sys.exit(main())