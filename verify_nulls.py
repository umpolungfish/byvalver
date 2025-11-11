#!/usr/bin/env python3
"""
Verify that null bytes were removed from the processed shellcode
"""
import sys

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <shellcode_file>")
        sys.exit(1)
        
    filename = sys.argv[1]
    
    with open(filename, 'rb') as f:
        data = f.read()
    
    null_positions = []
    for i, byte in enumerate(data):
        if byte == 0:
            null_positions.append(i)

    print(f"File: {filename}")
    print(f"Size: {len(data)} bytes")
    print(f"Found {len(null_positions)} null bytes at positions: {null_positions}")
    
    if len(null_positions) == 0:
        print("SUCCESS: No null bytes found in output!")
    else:
        print("ISSUE: Null bytes still present in output")
        # Show context around the first null byte
        if null_positions:
            pos = null_positions[0]
            start = max(0, pos - 5)
            end = min(len(data), pos + 6)
            context = data[start:end]
            print(f"Context around first null byte: {context.hex()}")
            print(f"Null byte at position {pos} in context: {start}-{end-1}")

if __name__ == "__main__":
    main()