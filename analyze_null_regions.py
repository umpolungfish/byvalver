#!/usr/bin/env python3
"""
Analyze regions with null bytes and disassemble them
"""

import sys
from capstone import *

def analyze_null_region(filename, offset, context_size=20):
    """Disassemble region around null bytes"""
    with open(filename, 'rb') as f:
        f.seek(max(0, offset - context_size))
        data = f.read(context_size * 2)

    # Try disassembly
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print(f"\n=== Region at offset {offset} (0x{offset:x}) ===")
    print(f"Raw bytes: {data.hex()}")
    print("\nDisassembly:")

    start_offset = max(0, offset - context_size)
    for insn in md.disasm(data, start_offset):
        # Check if instruction contains null bytes
        null_count = insn.bytes.count(0x00)
        marker = " ⚠️ HAS NULLS" if null_count > 0 else ""
        print(f"  0x{insn.address:04x}: {insn.bytes.hex():20s} {insn.mnemonic:8s} {insn.op_str}{marker}")

        if null_count > 0:
            print(f"         └─> Null bytes: {null_count} at positions {[i for i, b in enumerate(insn.bytes) if b == 0x00]}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 analyze_null_regions.py <file> <offset1> [offset2] ...")
        sys.exit(1)

    filename = sys.argv[1]
    offsets = [int(x) for x in sys.argv[2:]]

    for offset in offsets:
        analyze_null_region(filename, offset)
