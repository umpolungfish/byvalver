#!/usr/bin/env python3
import sys
try:
    from capstone import *
    
    def disassemble_file(filename):
        with open(filename, 'rb') as f:
            code = f.read()
        print(f"File size: {len(code)} bytes")
        print(f"Raw bytes: {code.hex()}")
        
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        
        print("Disassembly:")
        for insn in md.disasm(code, 0x1000):
            print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str} ({len(insn.bytes)} bytes: {insn.bytes.hex()})")
            
            # Check specifically for NEG instructions
            if insn.mnemonic == 'neg':
                print(f"  -> NEG instruction found! Operands: {insn.op_str}")
        
        print()
        
    print("Original file:")
    disassemble_file("test_neg_strategy.bin")
    
    print("Processed file:")
    disassemble_file("output_neg_test.bin")
    
except ImportError:
    print("Capstone library not available. Install with: pip install capstone")