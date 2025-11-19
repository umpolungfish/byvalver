#!/usr/bin/env python3
"""
Analyze null bytes in processed files and identify the instructions causing them.
"""

import sys
from capstone import *
from capstone.x86 import *

def analyze_file(filepath):
    """Analyze a file for null bytes and identify the instructions containing them."""
    with open(filepath, 'rb') as f:
        data = f.read()

    # Find all null byte positions
    null_positions = [i for i, byte in enumerate(data) if byte == 0]

    if not null_positions:
        print(f"✓ No null bytes found in {filepath}")
        return

    print(f"\n{'='*80}")
    print(f"Analysis of: {filepath}")
    print(f"{'='*80}")
    print(f"Total null bytes: {len(null_positions)}")
    print(f"File size: {len(data)} bytes")
    print(f"Null byte positions: {null_positions[:20]}")  # First 20

    # Initialize Capstone disassembler (try both 32-bit and 64-bit)
    for mode, mode_name in [(CS_MODE_32, "32-bit"), (CS_MODE_64, "64-bit")]:
        print(f"\n{'-'*80}")
        print(f"Disassembly ({mode_name}):")
        print(f"{'-'*80}")

        md = Cs(CS_ARCH_X86, mode)
        md.detail = True

        # Group consecutive null positions
        null_groups = []
        current_group = [null_positions[0]]
        for pos in null_positions[1:]:
            if pos == current_group[-1] + 1:
                current_group.append(pos)
            else:
                null_groups.append(current_group)
                current_group = [pos]
        null_groups.append(current_group)

        # Analyze each group
        for group in null_groups[:10]:  # First 10 groups
            start_pos = group[0]
            end_pos = group[-1]

            print(f"\nNull byte(s) at position {start_pos}-{end_pos} ({len(group)} bytes):")

            # Show hex context
            context_start = max(0, start_pos - 10)
            context_end = min(len(data), end_pos + 10)
            hex_context = data[context_start:context_end].hex()

            # Highlight null bytes
            highlight_start = (start_pos - context_start) * 2
            highlight_end = (end_pos - context_start + 1) * 2

            print(f"  Hex context: {hex_context[:highlight_start]}"
                  f"[{hex_context[highlight_start:highlight_end]}]"
                  f"{hex_context[highlight_end:]}")

            # Try to disassemble the region containing nulls
            disasm_start = max(0, start_pos - 20)
            disasm_data = data[disasm_start:end_pos + 20]

            print(f"  Instructions around null byte(s):")
            found_null_insn = False
            for insn in md.disasm(disasm_data, disasm_start):
                # Check if this instruction contains any null bytes
                insn_bytes = bytes(insn.bytes)
                contains_null = b'\x00' in insn_bytes

                marker = "  >>> " if contains_null else "      "
                print(f"{marker}0x{insn.address:04x}: {insn.bytes.hex():20s} {insn.mnemonic:8s} {insn.op_str}")

                if contains_null:
                    found_null_insn = True
                    # Detailed analysis
                    print(f"          ^ NULL-CONTAINING INSTRUCTION")
                    print(f"          Bytes: {' '.join(f'{b:02x}' for b in insn.bytes)}")
                    print(f"          Size: {insn.size} bytes")

                    # Show which bytes are null
                    null_byte_indices = [i for i, b in enumerate(insn.bytes) if b == 0]
                    print(f"          Null at byte indices: {null_byte_indices}")

                    # Analyze operands
                    if len(insn.operands) > 0:
                        print(f"          Operands:")
                        for i, op in enumerate(insn.operands):
                            if op.type == X86_OP_IMM:
                                print(f"            Op{i}: Immediate = 0x{op.imm:x}")
                            elif op.type == X86_OP_REG:
                                print(f"            Op{i}: Register = {insn.reg_name(op.reg)}")
                            elif op.type == X86_OP_MEM:
                                print(f"            Op{i}: Memory [base={insn.reg_name(op.mem.base) if op.mem.base != 0 else 'none'}, "
                                      f"index={insn.reg_name(op.mem.index) if op.mem.index != 0 else 'none'}, "
                                      f"scale={op.mem.scale}, disp=0x{op.mem.disp:x}]")

if __name__ == "__main__":
    files = [
        "/home/mrnob0dy666/byvalver_PUBLIC/.binzzz/processed/EHS.bin",
        "/home/mrnob0dy666/byvalver_PUBLIC/.binzzz/processed/ouroboros_core.bin",
        "/home/mrnob0dy666/byvalver_PUBLIC/.binzzz/processed/cutyourmeat-static.bin",
        "/home/mrnob0dy666/byvalver_PUBLIC/.binzzz/processed/cheapsuit.bin"
    ]

    for filepath in files:
        try:
            analyze_file(filepath)
        except Exception as e:
            print(f"Error analyzing {filepath}: {e}")
            import traceback
            traceback.print_exc()
