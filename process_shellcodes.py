#!/usr/bin/env python3
"""
Script to extract shellcode from C files in the SHELLSTORM_DUMP directory
and convert them to raw format for testing with byvalver.
"""

import os
import re
import binascii
from pathlib import Path


def extract_shellcode_from_file(file_path):
    """
    Extract shellcode from a C file.
    Looks for common patterns like:
    - char shellcode[] = "...";
    - unsigned char scode[] = "...";
    - Raw hex strings in the file
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Look for common shellcode patterns
    patterns = [
        # Pattern for char shellcode[] = "\xXX\xXX...";
        r'(?:char|unsigned char)\s+\w+\s*\[\s*\]\s*=\s*("(?:[^"]|\\")*?;)',
        # Pattern for direct hex strings like \xXX\xXX
        r'("((?:\\x[0-9a-fA-F]{2})+))',
        # Pattern for hex strings in shellcode: format
        r'(shellcode:\s*((?:\\x[0-9a-fA-F]{2})+))',
        # Pattern for hex strings in comments or other formats
        r'((?:\\x[0-9a-fA-F]{2}){4,})',  # At least 4 hex bytes
    ]

    for pattern in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            # If it's a tuple (from first pattern), take the second element
            if isinstance(match, tuple):
                match = match[0] if match[0] else match[1]
            
            # Clean up the match to extract just the hex part
            hex_part = match.strip('"\'')
            if hex_part.startswith('"') and hex_part.endswith('"'):
                hex_part = hex_part[1:-1]
            
            # Check if it contains hex escapes
            if '\\x' in hex_part:
                return hex_part
    
    # If no shellcode found in standard format, look for hex strings in comments
    # Pattern for hex strings in comments like ;Shellcode: \xXX\xXX...
    comment_pattern = r'[;/\*#]\s*Shellcode:\s*((?:\\x[0-9a-fA-F]{2})+)'
    comment_matches = re.findall(comment_pattern, content, re.IGNORECASE)
    for match in comment_matches:
        return match
    
    # Pattern for hex strings in assembly format
    asm_pattern = r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2})+'
    asm_matches = re.findall(asm_pattern, content)
    if asm_matches:
        return asm_matches[0]  # Return the first match
    
    return None


def convert_shellcode_to_bytes(shellcode_str):
    """
    Convert a shellcode string like "\\xXX\\xXX..." to bytes.
    """
    if not shellcode_str:
        return b""
    
    # Remove any extra quotes
    shellcode_str = shellcode_str.strip('"\'')
    
    # Convert \xXX format to bytes
    try:
        # Replace \x with % to use unhexlify
        hex_str = shellcode_str.replace('\\x', '').replace('\\X', '')
        # Ensure even length
        if len(hex_str) % 2 != 0:
            print(f"Warning: Odd length hex string: {hex_str}")
            hex_str = hex_str.zfill(len(hex_str) + 1)
        
        byte_data = bytes.fromhex(hex_str)
        return byte_data
    except ValueError as e:
        print(f"Error converting shellcode to bytes: {e}")
        print(f"Problematic shellcode string: {shellcode_str}")
        return b""


def process_shellcode_files(input_dir, output_dir):
    """
    Process all .c files in the input directory and extract shellcode.
    """
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    
    # Create output directory if it doesn't exist
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Find all .c files
    c_files = list(input_path.glob("*.c"))
    print(f"Found {len(c_files)} .c files to process")
    
    processed_count = 0
    failed_count = 0
    
    for c_file in c_files:
        print(f"Processing: {c_file.name}")
        
        # Extract shellcode from the file
        shellcode_str = extract_shellcode_from_file(c_file)
        
        if shellcode_str:
            print(f"  Found shellcode: {shellcode_str[:100]}{'...' if len(shellcode_str) > 100 else ''}")
            
            # Convert to bytes
            shellcode_bytes = convert_shellcode_to_bytes(shellcode_str)
            
            if shellcode_bytes:
                # Write to output file with .bin extension
                output_file = output_path / f"{c_file.stem}.bin"
                with open(output_file, 'wb') as f:
                    f.write(shellcode_bytes)
                
                print(f"  Saved to: {output_file} ({len(shellcode_bytes)} bytes)")
                processed_count += 1
            else:
                print(f"  Failed to convert shellcode to bytes")
                failed_count += 1
        else:
            print(f"  No shellcode found")
            failed_count += 1
    
    print(f"\nProcessing complete!")
    print(f"Successfully processed: {processed_count} files")
    print(f"Failed to process: {failed_count} files")


if __name__ == "__main__":
    input_directory = "/home/mrnob0dy666/byvalver/assets/shellcodes/SHELLSTORM/SHELLSTORM_DUMP"
    output_directory = "/home/mrnob0dy666/byvalver/processed_shellcodes"
    
    process_shellcode_files(input_directory, output_directory)