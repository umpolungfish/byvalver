#!/usr/bin/env python3
"""
Simple but robust shellcode extractor for BYVALVER project
Focuses on efficiency and reliability for common formats
"""

import re
import sys
import os


def extract_shellcode_from_c_file(file_path: str) -> bytes:
    """
    Extract shellcode from C source file with multiple format support
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Define multiple patterns for different shellcode formats
    patterns = [
        # Standard char array
        r'char\s+shellcode\s*\[\s*\]\s*=\s*"((?:[^"]|\\.)*)"\s*;',
        # Unsigned char array
        r'unsigned\s+char\s+shellcode\s*\[\s*\]\s*=\s*"((?:[^"]|\\.)*)"\s*;',
        # Payload format
        r'unsigned\s+char\s+payload\s*\[\s*\]\s*=\s*"((?:[^"]|\\.)*)"\s*;',
        # Code format
        r'unsigned\s+char\s+code\s*\[\s*\]\s*=\s*"((?:[^"]|\\.)*)"\s*;',
        # Alternative: just hex string in quotes
        r'"((?:\\x[0-9a-fA-F]{2})+)"'
    ]

    for pattern in patterns:
        matches = re.findall(pattern, content, re.DOTALL)
        if matches:
            # Process the first match
            shellcode_str = matches[0]
            
            # Remove whitespace and handle multi-line strings
            shellcode_str = re.sub(r'\s+', '', shellcode_str)
            
            # Extract hex values in \x format
            if '\\x' in shellcode_str:
                hex_values = re.findall(r'\\x[0-9a-fA-F]{2}', shellcode_str)
                shellcode_bytes = [int(hv[2:], 16) for hv in hex_values]
                return bytes(shellcode_bytes)
            else:
                # Handle direct hex format (without \x)
                try:
                    clean_hex = re.sub(r'[^0-9a-fA-F]', '', shellcode_str)
                    if len(clean_hex) % 2 == 0:
                        return bytes.fromhex(clean_hex)
                except ValueError:
                    continue

    # If no patterns matched, try a more general approach
    # Look for sequences that look like shellcode
    hex_sequences = re.findall(r'(\\x[0-9a-fA-F]{2})+', content, re.IGNORECASE)
    if hex_sequences:
        # Take the longest sequence
        longest_seq = max(hex_sequences, key=len)
        hex_values = re.findall(r'\\x[0-9a-fA-F]{2}', longest_seq)
        if hex_values:
            shellcode_bytes = [int(hv[2:], 16) for hv in hex_values]
            return bytes(shellcode_bytes)

    raise ValueError(f"Could not extract shellcode from {file_path}")


def safe_shellcode_length_check(shellcode: bytes, expected_min_length: int = 1) -> bool:
    """
    Perform safety check on shellcode length
    """
    return len(shellcode) >= expected_min_length


def main():
    if len(sys.argv) != 3:
        print("Usage: python simple_extract.py <input_file> <output_file>")
        print("Example: python simple_extract.py shellcode.c shellcode.bin")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        shellcode = extract_shellcode_from_c_file(input_file)
        
        if not safe_shellcode_length_check(shellcode):
            print(f"Error: Extracted shellcode is too short (< 1 byte)", file=sys.stderr)
            sys.exit(1)

        with open(output_file, 'wb') as f:
            f.write(shellcode)

        print(f"Shellcode extracted successfully to {output_file}")
        print(f"Shellcode length: {len(shellcode)} bytes")

        # Check for null bytes
        null_count = shellcode.count(0)
        print(f"Null bytes found: {null_count}")
        
        if null_count > 0:
            print("WARNING: Shellcode contains null bytes that may interfere with execution")
        
        # Additional analysis
        printable_chars = sum(1 for b in shellcode if 32 <= b <= 126)
        print(f"Printable ASCII characters: {printable_chars} ({(printable_chars/len(shellcode)*100):.1f}%)")
        
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()