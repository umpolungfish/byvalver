#!/usr/bin/env python3
"""
Enterprise-grade shellcode extractor for BYVALVER project
Extracts and processes shellcode from various formats
"""

import re
import sys
import os
from typing import Optional, Tuple


def extract_shellcode_from_content(content: str, file_path: str) -> Optional[bytes]:
    """
    Extract shellcode from content using multiple pattern matching strategies
    """
    # Pattern 1: Standard shellcode array formats
    patterns = [
        r'char\s+shellcode\[\]\s*=\s*("(?:[^"]|\\.)*")\s*;',  # char shellcode[] = "..."
        r'unsigned\s+char\s+shellcode\[\]\s*=\s*("(?:[^"]|\\.)*")\s*;',  # unsigned char shellcode[] = "..."
        r'unsigned\s+char\s+payload\[\]\s*=\s*("(?:[^"]|\\.)*")\s*;',  # unsigned char payload[] = "..."
        r'unsigned\s+char\s+code\[\]\s*=\s*("(?:[^"]|\\.)*")\s*;',  # unsigned char code[] = "..."
        r'"((?:\\x[0-9a-fA-F]{2})+)"',  # Raw hex string patterns
    ]

    for pattern in patterns:
        matches = re.findall(pattern, content, re.DOTALL | re.IGNORECASE)
        if matches:
            # Process the first match
            matched_str = matches[0]
            
            # Clean the matched string
            clean_str = re.sub(r'\s+', '', matched_str)
            clean_str = clean_str.strip('"\'')
            
            # Handle escape sequences and multi-line strings
            clean_str = clean_str.replace('\\"', '"').replace("\\'", "'")
            
            # Remove \\x prefixes and extract hex values
            if '\\x' in clean_str:
                hex_values = re.findall(r'\\x[0-9a-fA-F]{2}', clean_str)
                if hex_values:
                    try:
                        shellcode_bytes = [int(hv[2:], 16) for hv in hex_values]
                        return bytes(shellcode_bytes)
                    except ValueError:
                        continue
            else:
                # Direct hex string without \\x prefixes
                try:
                    # Clean up any non-hex characters
                    clean_hex = re.sub(r'[^0-9a-fA-F]', '', clean_str)
                    if len(clean_hex) % 2 == 0:
                        shellcode_bytes = bytes.fromhex(clean_hex)
                        return shellcode_bytes
                except ValueError:
                    continue

    return None


def validate_shellcode(shellcode: bytes) -> Tuple[bool, str]:
    """
    Validate shellcode for common issues
    """
    if not shellcode:
        return False, "Shellcode is empty"
    
    if len(shellcode) == 0:
        return False, "Shellcode length is zero"
    
    # Check for excessive null byte percentage (warn if > 20%)
    null_count = shellcode.count(0)
    null_percentage = (null_count / len(shellcode)) * 100 if len(shellcode) > 0 else 0
    
    if null_percentage > 20:
        return True, f"Warning: Shellcode has high null byte percentage ({null_percentage:.2f}%)"
    
    return True, "Shellcode validated successfully"


def extract_shellcode(file_path: str, output_path: str) -> bool:
    """
    Main function to extract shellcode from a file and write to output
    """
    if not os.path.exists(file_path):
        print(f"Error: Input file {file_path} does not exist", file=sys.stderr)
        return False

    try:
        # Read the input file with multiple encoding attempts
        encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
        content = None
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue
        
        if content is None:
            print(f"Error: Could not read file {file_path} with any encoding", file=sys.stderr)
            return False

        # Extract shellcode from content
        shellcode = extract_shellcode_from_content(content, file_path)
        
        if shellcode is None:
            print(f"Error: Could not extract shellcode from {file_path}", file=sys.stderr)
            return False

        # Validate the extracted shellcode
        is_valid, message = validate_shellcode(shellcode)
        if not is_valid:
            print(f"Error: {message}", file=sys.stderr)
            return False
        
        if "Warning" in message:
            print(f"Validation: {message}")

        # Write to output file
        with open(output_path, 'wb') as f:
            f.write(shellcode)

        print(f"Shellcode extracted successfully to {output_path}")
        print(f"Shellcode length: {len(shellcode)} bytes")
        
        # Report statistics
        null_count = shellcode.count(0)
        print(f"Null bytes found: {null_count} ({(null_count / len(shellcode) * 100):.2f}%)")
        
        # Report non-printable bytes
        printable_count = sum(1 for byte in shellcode if 32 <= byte <= 126 or byte in (9, 10, 13))
        print(f"Printable bytes: {printable_count} ({(printable_count / len(shellcode) * 100):.2f}%)")
        
        return True

    except Exception as e:
        print(f"Error processing file {file_path}: {str(e)}", file=sys.stderr)
        return False


def main():
    if len(sys.argv) < 3:
        print("Usage: python extract_hex.py <input_file> <output_file>")
        print("Example: python extract_hex.py shellcode.c shellcode.bin")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    success = extract_shellcode(input_file, output_file)
    
    if not success:
        print("Shellcode extraction failed", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()