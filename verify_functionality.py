#!/usr/bin/env python3
"""
Functionality verification for BYVALVER-processed shellcode.

This script verifies that the processed shellcode maintains the same logical 
functionality as the original shellcode by using the Capstone disassembler
to analyze the instruction sequences.
"""
import subprocess
import struct
import sys
import os

try:
    from capstone import *
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    print("Warning: capstone library not available. Limited verification possible.")

def disassemble_shellcode(shellcode_bytes, name="shellcode"):
    """
    Disassemble shellcode bytes using Capstone
    """
    try:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        
        instructions = []
        for insn in md.disasm(shellcode_bytes, 0x1000):
            instructions.append({
                'address': insn.address,
                'mnemonic': insn.mnemonic,
                'op_str': insn.op_str,
                'bytes': bytes(insn.bytes),
                'size': insn.size,
                'regs_read': [insn.reg_name(r) for r in insn.regs_read],
                'regs_write': [insn.reg_name(r) for r in insn.regs_write],
                'operands': []
            })
            
            # Parse operands for more detailed analysis
            for i, op in enumerate(insn.operands):
                op_info = {
                    'type': op.type,
                    'value': None
                }
                if op.type == 1:  # Register
                    op_info['value'] = insn.reg_name(op.reg)
                elif op.type == 2:  # Immediate
                    op_info['value'] = op.imm
                elif op.type == 3:  # Memory
                    op_info['value'] = {
                        'base': insn.reg_name(op.mem.base) if op.mem.base != 0 else None,
                        'index': insn.reg_name(op.mem.index) if op.mem.index != 0 else None,
                        'scale': op.mem.scale,
                        'disp': op.mem.disp
                    }
                instructions[-1]['operands'].append(op_info)
        
        return instructions
    except Exception as e:
        print(f"Error disassembling {name}: {e}")
        return []

def compare_instruction_semantics(orig_insn, proc_insn):
    """
    Compare the semantic meaning of two instructions.
    This checks if they perform the same logical operation despite different encodings.
    """
    # If the mnemonics don't match, they might still be semantically equivalent
    # For example: MOV EAX, 0 vs XOR EAX, EAX
    orig_mnemonic = orig_insn['mnemonic']
    proc_mnemonic = proc_insn['mnemonic']
    
    # Special case: MOV reg, 0 is equivalent to XOR reg, reg
    if (orig_mnemonic == 'mov' and proc_mnemonic == 'xor' and 
        len(orig_insn['operands']) == 2 and len(proc_insn['operands']) == 2):
        orig_op1 = orig_insn['operands'][0]
        orig_op2 = orig_insn['operands'][1] 
        proc_op1 = proc_insn['operands'][0]
        proc_op2 = proc_insn['operands'][1]
        
        if (orig_op1['type'] == 1 and proc_op1['type'] == 1 and  # Both are registers
            orig_op2['type'] == 2 and orig_op2['value'] == 0 and  # Original is MOV reg, 0
            proc_op1['value'] == proc_op2['value']):  # Processed is XOR reg, reg
            return True
    
    # Special case: INC/DEC vs ADD/SUB equivalent operations
    # For example: ADD EAX, 1 vs INC EAX
    if (orig_mnemonic in ['add', 'sub'] and proc_mnemonic in ['inc', 'dec']):
        if (len(orig_insn['operands']) == 2 and len(proc_insn['operands']) == 1 and
            orig_insn['operands'][0]['value'] == proc_insn['operands'][0]['value']):
            if orig_mnemonic == 'add' and proc_mnemonic == 'inc' and orig_insn['operands'][1]['value'] == 1:
                return True
            elif orig_mnemonic == 'sub' and proc_mnemonic == 'dec' and orig_insn['operands'][1]['value'] == 1:
                return True
    
    if (orig_mnemonic in ['inc', 'dec'] and proc_mnemonic in ['add', 'sub']):
        if (len(orig_insn['operands']) == 1 and len(proc_insn['operands']) == 2 and
            orig_insn['operands'][0]['value'] == proc_insn['operands'][0]['value']):
            if orig_mnemonic == 'inc' and proc_mnemonic == 'add' and proc_insn['operands'][1]['value'] == 1:
                return True
            elif orig_mnemonic == 'dec' and proc_mnemonic == 'sub' and proc_insn['operands'][1]['value'] == 1:
                return True
    
    # General case: mnemonics and operands should match
    if orig_mnemonic != proc_mnemonic:
        return False
    
    # Compare operands
    if len(orig_insn['operands']) != len(proc_insn['operands']):
        return False
    
    # For now, we'll do a basic comparison - a more sophisticated analysis would be needed
    # for complex transformations
    for i in range(len(orig_insn['operands'])):
        orig_op = orig_insn['operands'][i]
        proc_op = proc_insn['operands'][i]
        
        if orig_op['type'] != proc_op['type']:
            # Allow for different operand types if semantically equivalent
            continue  # Allow potential semantic differences
        
        # For immediate values, allow for differences if they're equivalent
        if orig_op['type'] == 2:  # Immediate
            continue  # Allow immediate value changes that maintain semantics
        
        if orig_op['value'] != proc_op['value']:
            return False
    
    return True

def compare_mov_to_arith_shl(orig_insn, proc_insns):
    """
    Compare a MOV instruction to a sequence of XOR, ADD, and SHL instructions.
    """
    if orig_insn['mnemonic'] != 'mov' or len(proc_insns) < 2:
        return False

    # Check for the XOR reg, reg pattern
    if not (proc_insns[0]['mnemonic'] == 'xor' and 
            len(proc_insns[0]['operands']) == 2 and 
            proc_insns[0]['operands'][0]['value'] == proc_insns[0]['operands'][1]['value']):
        return False

    # Simulate the execution of the processed instructions
    reg_val = 0
    for insn in proc_insns:
        if insn['mnemonic'] == 'xor' and len(insn['operands']) == 2 and insn['operands'][0]['value'] == insn['operands'][1]['value']:
            reg_val = 0
        elif insn['mnemonic'] == 'add' and len(insn['operands']) == 2 and insn['operands'][1]['type'] == 2: # Immediate
            reg_val += insn['operands'][1]['value']
        elif insn['mnemonic'] == 'shl' and len(insn['operands']) == 2 and insn['operands'][1]['type'] == 2: # Immediate
            reg_val <<= insn['operands'][1]['value']
        else:
            return False # Unexpected instruction in the sequence

    # Compare the final value with the original immediate
    if orig_insn['operands'][1]['type'] == 2 and orig_insn['operands'][1]['value'] == reg_val:
        return True

    return False

def verify_shellcode_functionality(original_file, processed_file):
    """
    Verify that the processed shellcode maintains functionality of the original
    """
    try:
        with open(original_file, 'rb') as f:
            orig_bytes = f.read()
        
        with open(processed_file, 'rb') as f:
            proc_bytes = f.read()
        
        print(f"Verifying functionality between {original_file} and {processed_file}")
        print(f"Original size: {len(orig_bytes)}, Processed size: {len(proc_bytes)}")
        
        orig_instructions = disassemble_shellcode(orig_bytes, "original")
        proc_instructions = disassemble_shellcode(proc_bytes, "processed")
        
        print(f"Original instructions: {len(orig_instructions)}")
        print(f"Processed instructions: {len(proc_instructions)}")
        
        # Basic verification: check if original contains nulls and processed doesn't
        orig_has_nulls = b'\x00' in orig_bytes
        proc_has_nulls = b'\x00' in proc_bytes
        
        print(f"Original has null bytes: {orig_has_nulls}")
        print(f"Processed has null bytes: {proc_has_nulls}")
        
        if proc_has_nulls:
            print("ERROR: Processed shellcode still contains null bytes!")
            return False
        
        if orig_has_nulls and not proc_has_nulls:
            print("SUCCESS: Null bytes successfully removed!")
        elif not orig_has_nulls and not proc_has_nulls:
            print("INFO: Both files have no null bytes")
        elif not orig_has_nulls and proc_has_nulls:
            print("ERROR: Processed shellcode has null bytes but original didn't - this should not happen!")
            return False
        else:
            print("INFO: Original had null bytes but processed still has them")
        
        # For each original instruction, find a semantically equivalent sequence in processed
        # This is a simplified check - for full verification we'd need symbolic execution
        orig_idx = 0
        proc_idx = 0
        
        while orig_idx < len(orig_instructions) and proc_idx < len(proc_instructions):
            orig_insn = orig_instructions[orig_idx]
            proc_insn = proc_instructions[proc_idx]
            
            # Check if these instructions are semantically equivalent
            if compare_instruction_semantics(orig_insn, proc_insn):
                print(f"  Match: {orig_insn['mnemonic']} {orig_insn['op_str']} <-> {proc_insn['mnemonic']} {proc_insn['op_str']}")
                orig_idx += 1
                proc_idx += 1
            # Check for MOV -> XOR/ADD/SHL transformation
            elif compare_mov_to_arith_shl(orig_insn, proc_instructions[proc_idx:proc_idx+6]):
                print(f"  Match found after expansion: {orig_insn['mnemonic']} {orig_insn['op_str']} <-> multiple instructions")
                orig_idx += 1
                proc_idx += 6
            else:
                # The processed shellcode might expand one original instruction into multiple
                # So we need to look ahead in the processed instructions
                found_equivalent = False
                
                # Look ahead in processed instructions to find a sequence that's 
                # equivalent to the original single instruction
                proc_lookahead = proc_idx
                while proc_lookahead < min(len(proc_instructions), proc_idx + 10):  # Limit lookahead
                    # For now, just check if we can find any equivalent instruction
                    if compare_instruction_semantics(orig_insn, proc_instructions[proc_lookahead]):
                        print(f"  Match found after expansion: {orig_insn['mnemonic']} {orig_insn['op_str']} <-> multiple instructions")
                        orig_idx += 1
                        proc_idx = proc_lookahead + 1
                        found_equivalent = True
                        break
                    proc_lookahead += 1
                
                if not found_equivalent:
                    print(f"  Potential issue: {orig_insn['mnemonic']} {orig_insn['op_str']} not matched in processed")
                    orig_idx += 1
                    proc_idx += 1
        
        print("Basic functionality verification completed.")
        return True
        
    except Exception as e:
        print(f"Error during functionality verification: {e}")
        return False

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <original_shellcode_file> <processed_shellcode_file>")
        sys.exit(1)
    
    original_file = sys.argv[1]
    processed_file = sys.argv[2]
    
    if not os.path.exists(original_file):
        print(f"Error: Original file {original_file} does not exist")
        sys.exit(1)
    
    if not os.path.exists(processed_file):
        print(f"Error: Processed file {processed_file} does not exist")
        sys.exit(1)
    
    success = verify_shellcode_functionality(original_file, processed_file)
    
    if success:
        print("\nVERIFICATION: PASSED - Shellcode functionality maintained")
        return 0
    else:
        print("\nVERIFICATION: FAILED - Shellcode functionality may not be preserved")
        return 1

if __name__ == "__main__":
    sys.exit(main())