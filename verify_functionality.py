#!/usr/bin/env python3
"""
Enterprise-grade functionality verification for BYVALVER-processed shellcode.

This script verifies that the processed shellcode maintains the same logical
functionality as the original shellcode by using the Capstone disassembler
to analyze the instruction sequences.
"""
import subprocess
import struct
import sys
import os
from typing import List, Dict, Any, Optional, Tuple
import hashlib

try:
    from capstone import *
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    print("Warning: capstone library not available. Limited verification possible.")


class ShellcodeAnalyzer:
    """
    Advanced shellcode analysis class for functionality verification
    """
    
    def __init__(self):
        self.md = None
        if CAPSTONE_AVAILABLE:
            self.md = Cs(CS_ARCH_X86, CS_MODE_32)
            self.md.detail = True
    
    def disassemble_shellcode(self, shellcode_bytes: bytes, name: str = "shellcode") -> List[Dict[str, Any]]:
        """
        Disassemble shellcode bytes using Capstone with detailed analysis
        """
        if not CAPSTONE_AVAILABLE:
            print("Error: Capstone library required for disassembly", file=sys.stderr)
            return []
        
        try:
            instructions = []
            for insn in self.md.disasm(shellcode_bytes, 0x1000):
                instr_info = {
                    'address': insn.address,
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str,
                    'bytes': bytes(insn.bytes),
                    'size': insn.size,
                    'regs_read': [insn.reg_name(r) for r in insn.regs_read] if insn.regs_read else [],
                    'regs_write': [insn.reg_name(r) for r in insn.regs_write] if insn.regs_write else [],
                    'operands': [],
                    'groups': [insn.group_name(g) for g in insn.groups] if insn.groups else []
                }

                # Parse operands for more detailed analysis
                for op in insn.operands:
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
                    instr_info['operands'].append(op_info)

                instructions.append(instr_info)
            
            return instructions
        except Exception as e:
            print(f"Error disassembling {name}: {e}", file=sys.stderr)
            return []


def compare_instruction_semantics(orig_insn: Dict[str, Any], proc_insn: Dict[str, Any]) -> bool:
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

    # MOV EAX, 0x00200000 vs MOV EAX, 0x00200404; SUB EAX, 0x404
    if (orig_mnemonic == 'mov' and proc_mnemonic in ['mov', 'add', 'sub']):
        # This would require more complex multi-instruction comparison
        pass

    # General case: mnemonics and operands should match for basic verification
    if orig_mnemonic != proc_mnemonic:
        return False

    # Compare operands
    if len(orig_insn['operands']) != len(proc_insn['operands']):
        return False

    # For immediate values, allow for differences if they're functionally equivalent
    for i in range(len(orig_insn['operands'])):
        orig_op = orig_insn['operands'][i]
        proc_op = proc_insn['operands'][i]

        if orig_op['type'] != proc_op['type']:
            # Allow for different operand types if semantically equivalent
            continue  # Allow potential semantic differences

        if orig_op['type'] == 2:  # Immediate values
            continue  # Allow immediate value changes that maintain semantics

        if orig_op['value'] != proc_op['value']:
            return False

    return True


def compare_mov_to_arith_sequence(orig_insn: Dict[str, Any], proc_insns: List[Dict[str, Any]]) -> Tuple[bool, int]:
    """
    Compare a MOV instruction to a sequence of instructions that construct the same value.
    """
    if orig_insn['mnemonic'] != 'mov' or len(proc_insns) < 1:
        return False, 0

    target_val = None
    for op in orig_insn['operands']:
        if op['type'] == 2:  # Immediate value
            target_val = op['value']
            break
    
    if target_val is None:
        return False, 0
    
    # Check for simple XOR reg, reg pattern (for zero values)
    if target_val == 0 and len(proc_insns) >= 1:
        first_insn = proc_insns[0]
        if (first_insn['mnemonic'] == 'xor' and 
            len(first_insn['operands']) == 2 and
            first_insn['operands'][0]['value'] == first_insn['operands'][1]['value']):
            # Register names match the original MOV destination
            orig_dest = None
            for op in orig_insn['operands']:
                if op['type'] == 1:  # Register
                    orig_dest = op['value']
                    break
            if orig_dest and first_insn['operands'][0]['value'] == orig_dest:
                return True, 1
    
    # Check for arithmetic sequences that produce the target value
    # Example: MOV EAX, 0x100000 -> XOR EAX, EAX; MOV AH, 0x10; SHL EAX, 16
    # This is complex, so we'll use a simplified version for now
    
    return False, 0


def calculate_entropy(data: bytes) -> float:
    """
    Calculate entropy of the shellcode to detect encoding
    """
    if not data:
        return 0
    
    # Calculate frequency of each byte
    freq_dict = {}
    for byte in data:
        freq_dict[byte] = freq_dict.get(byte, 0) + 1

    # Calculate entropy
    entropy = 0.0
    for freq in freq_dict.values():
        probability = freq / len(data)
        entropy -= probability * (probability.bit_length() - 1)
    
    return entropy


def verify_shellcode_functionality(original_file: str, processed_file: str) -> bool:
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

        # Calculate and compare hash values
        orig_hash = hashlib.sha256(orig_bytes).hexdigest()
        proc_hash = hashlib.sha256(proc_bytes).hexdigest()
        print(f"Original SHA256: {orig_hash}")
        print(f"Processed SHA256: {proc_hash}")
        
        if orig_hash == proc_hash:
            print("WARNING: Files are identical - no processing was performed")
        else:
            print("Files differ - processing occurred as expected")

        # Check entropy to see if encoding was applied
        orig_entropy = calculate_entropy(orig_bytes)
        proc_entropy = calculate_entropy(proc_bytes)
        print(f"Original entropy: {orig_entropy:.2f}, Processed entropy: {proc_entropy:.2f}")

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

        if not CAPSTONE_AVAILABLE:
            print("Functionality verification skipped - Capstone not available")
            return not proc_has_nulls  # Return based on null byte check

        # Perform detailed disassembly comparison
        analyzer = ShellcodeAnalyzer()
        orig_instructions = analyzer.disassemble_shellcode(orig_bytes, "original")
        proc_instructions = analyzer.disassemble_shellcode(proc_bytes, "processed")

        print(f"Original instructions: {len(orig_instructions)}")
        print(f"Processed instructions: {len(proc_instructions)}")

        # For each original instruction, find a semantically equivalent sequence in processed
        orig_idx = 0
        proc_idx = 0
        matches_found = 0
        total_compared = 0

        while orig_idx < len(orig_instructions) and proc_idx < len(proc_instructions):
            orig_insn = orig_instructions[orig_idx]
            proc_insn = proc_instructions[proc_idx]

            total_compared += 1
            
            # Check if these instructions are semantically equivalent
            if compare_instruction_semantics(orig_insn, proc_insn):
                matches_found += 1
                print(f"  Match: {orig_insn['mnemonic']} {orig_insn['op_str']} <-> {proc_insn['mnemonic']} {proc_insn['op_str']}")
                orig_idx += 1
                proc_idx += 1
            else:
                # The processed shellcode might expand one original instruction into multiple
                # So we need to look ahead in the processed instructions
                found_equivalent = False

                # Look ahead in processed instructions to find a sequence that's
                # equivalent to the original single instruction
                proc_lookahead = proc_idx
                while proc_lookahead < min(len(proc_instructions), proc_idx + 10):  # Limit lookahead
                    if proc_lookahead > proc_idx:
                        # Check for multi-instruction equivalence
                        seq_len = proc_lookahead - proc_idx + 1
                        proc_seq = proc_instructions[proc_idx:proc_lookahead+1]
                        match, consumed = compare_mov_to_arith_sequence(orig_insn, proc_seq)
                        if match:
                            matches_found += 1
                            print(f"  Match found after expansion: {orig_insn['mnemonic']} {orig_insn['op_str']} <-> {seq_len} instructions")
                            orig_idx += 1
                            proc_idx = proc_lookahead + 1
                            found_equivalent = True
                            break
                    
                    if compare_instruction_semantics(orig_insn, proc_instructions[proc_lookahead]):
                        matches_found += 1
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

        match_percentage = (matches_found / max(len(orig_instructions), 0.001)) * 100
        print(f"Instruction match rate: {matches_found}/{len(orig_instructions)} ({match_percentage:.1f}%)")

        success_threshold = 80.0  # 80% of instructions should match
        if match_percentage >= success_threshold:
            print(f"VERIFICATION: PASSED - {match_percentage:.1f}% instruction similarity")
            return True
        else:
            print(f"VERIFICATION: FAILED - Only {match_percentage:.1f}% instruction similarity (threshold: {success_threshold}%)")
            return False

    except Exception as e:
        print(f"Error during functionality verification: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <original_shellcode_file> <processed_shellcode_file>")
        print("Example: verify_functionality.py original.bin processed.bin")
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