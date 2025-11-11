#!/usr/bin/env python3
"""
Check the output of BYVALVER to verify that all null bytes
are part of embedded immediate values from the GET PC technique.
"""

with open('final_test_output.bin', 'rb') as f:
    data = f.read()

null_positions = []
for i, byte in enumerate(data):
    if byte == 0:
        null_positions.append(i)

print(f"Found {len(null_positions)} null bytes at positions: {null_positions}")

# Check the context around each null byte to see if it's part of embedded immediate values
for pos in null_positions:
    print(f"Null byte at position {pos}: context = {data[max(0, pos-4):pos+5].hex()}")