#!/usr/bin/env python3
import sys
try:
    from capstone import *
    
    def disassemble_file(filename, label):
        with open(filename, 'rb') as f:
            code = f.read()
        print(f"\n{label} file ({filename}):")
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
        
        # Check for null bytes
        null_count = code.count(0)
        print(f"Null byte count: {null_count}")
        
    print("Test NEG Simple:")
    disassemble_file("test_neg_simple.bin", "Original")
    disassemble_file("output_neg_simple.bin", "Processed")
    
    print("\nTest NEG 32:")
    disassemble_file("test_neg_32.bin", "Original") 
    disassemble_file("output_neg_32.bin", "Processed")
    
    print("\nTest NEG Definite:")
    disassemble_file("test_neg_definite.bin", "Original") 
    disassemble_file("output_neg_definite.bin", "Processed")
    
except ImportError:
    print("Capstone library not available. Install with: pip install capstone")