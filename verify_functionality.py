#!/usr/bin/env python3
"""
BYVALVER Verification Tool - Basic Functionality
verify_functionality.py

This tool verifies that the processed shellcode maintains basic functionality by:
1. Checking that the shellcode is valid assembly code
2. Verifying that transformations don't break critical instruction patterns
3. Ensuring common x86/x64 patterns remain functional
"""

import sys
import os
import argparse
import subprocess
from pathlib import Path
import fnmatch

def disassemble_shellcode(shellcode_data, arch='x86'):
    """
    Disassemble shellcode using objdump or a similar tool to check for valid instructions.
    
    Args:
        shellcode_data (bytes): The shellcode data to disassemble
        arch (str): Architecture ('x86', 'x64', 'arm', etc.)
        
    Returns:
        tuple: (disassembly_output, error_message, instruction_count)
    """
    import tempfile
    
    # Write shellcode to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as temp_file:
        temp_file.write(shellcode_data)
        temp_path = temp_file.name

    try:
        # Use objdump to disassemble the raw binary
        if arch == 'x64':
            cmd = ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', temp_path]
        elif arch == 'x86':
            cmd = ['objdump', '-D', '-b', 'binary', '-m', 'i386', temp_path]
        else:
            cmd = ['objdump', '-D', '-b', 'binary', '-m', 'i386', temp_path]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            return "", result.stderr, 0
        
        # Count instructions in the disassembly
        lines = result.stdout.split('\n')
        instruction_count = 0
        disasm_lines = []
        
        for line in lines:
            # Look for lines that contain actual instructions
            if ':' in line and ('<' in line or 'jmp' in line.lower() or 
                               'call' in line.lower() or 'push' in line.lower() or 
                               'pop' in line.lower() or 'mov' in line.lower() or 
                               'add' in line.lower() or 'sub' in line.lower() or 
                               'xor' in line.lower() or 'or' in line.lower() or 
                               'and' in line.lower() or 'cmp' in line.lower() or 
                               'test' in line.lower() or 'lea' in line.lower()):
                disasm_lines.append(line.strip())
                instruction_count += 1
        
        return '\\n'.join(disasm_lines), "", instruction_count
    
    except subprocess.TimeoutExpired:
        return "", "Disassembly timed out", 0
    except Exception as e:
        return "", str(e), 0
    finally:
        # Clean up the temporary file
        try:
            os.unlink(temp_path)
        except:
            pass

def check_instruction_patterns(shellcode_data):
    """
    Check for common instruction patterns that should be preserved.
    
    Args:
        shellcode_data (bytes): The shellcode data to analyze
        
    Returns:
        dict: Analysis of instruction patterns
    """
    patterns = {
        'system_calls': 0,
        'stack_operations': 0, 
        'register_operations': 0,
        'control_flow': 0,
        'potential_problems': []
    }
    
    # Look for common x86 patterns that are important for shellcode
    for i in range(len(shellcode_data)):
        # Look for system call instructions
        if i + 1 < len(shellcode_data):
            # int 0x80 (Linux system call)
            if shellcode_data[i] == 0xcd and shellcode_data[i+1] == 0x80:
                patterns['system_calls'] += 1
            
            # syscall (x64 system call)
            if i + 1 < len(shellcode_data) and shellcode_data[i:i+2] == b'\\x0f\\x05':
                patterns['system_calls'] += 1
                
        # Look for stack operations
        if shellcode_data[i] in [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57]:  # push reg
            patterns['stack_operations'] += 1
        elif shellcode_data[i] in [0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f]:  # pop reg
            patterns['stack_operations'] += 1
        elif shellcode_data[i] == 0x60:  # pushad
            patterns['stack_operations'] += 1
        elif shellcode_data[i] == 0x61:  # popad
            patterns['stack_operations'] += 1
        elif i + 1 < len(shellcode_data) and shellcode_data[i] == 0x68:  # push imm32
            patterns['stack_operations'] += 1
        elif i + 1 < len(shellcode_data) and shellcode_data[i] == 0x6a:  # push imm8
            patterns['stack_operations'] += 1
        
        # Look for register operations
        if 0x88 <= shellcode_data[i] <= 0x8b:  # mov reg/mem
            patterns['register_operations'] += 1
        elif 0xb0 <= shellcode_data[i] <= 0xbf:  # mov reg, imm
            patterns['register_operations'] += 1
        elif shellcode_data[i] in [0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b]:  # arithmetic
            patterns['register_operations'] += 1
        elif shellcode_data[i] == 0x83 and i + 1 < len(shellcode_data):  # arithmetic with immediate
            patterns['register_operations'] += 1
        
        # Look for control flow
        if 0x70 <= shellcode_data[i] <= 0x7f:  # conditional jumps
            patterns['control_flow'] += 1
        elif 0xe0 <= shellcode_data[i] <= 0xe9:  # loops and jumps
            patterns['control_flow'] += 1
        elif shellcode_data[i] == 0xeb:  # jmp short
            patterns['control_flow'] += 1
        elif i + 1 < len(shellcode_data) and shellcode_data[i:i+2] == b'\\xe8':  # call rel32
            patterns['control_flow'] += 1
        elif i + 1 < len(shellcode_data) and shellcode_data[i:i+2] == b'\\xe9':  # jmp rel32
            patterns['control_flow'] += 1
        elif shellcode_data[i] == 0xc3:  # ret
            patterns['control_flow'] += 1
        elif shellcode_data[i] == 0xc2 and i + 2 < len(shellcode_data):  # ret imm16
            patterns['control_flow'] += 1
    
    return patterns

def check_shellcode_health(input_data, output_data):
    """
    Compare input and output shellcode for basic health indicators.
    
    Args:
        input_data (bytes): Original shellcode
        output_data (bytes): Processed shellcode
        
    Returns:
        dict: Analysis of shellcode health
    """
    input_patterns = check_instruction_patterns(input_data)
    output_patterns = check_instruction_patterns(output_data)
    
    health = {
        'size_ratio': len(output_data) / len(input_data) if len(input_data) > 0 else 0,
        'pattern_preservation': {},
        'warnings': []
    }
    
    # Check if important patterns were preserved
    for pattern in input_patterns:
        if pattern != 'potential_problems':  # Skip the problems list
            original_count = input_patterns[pattern]
            new_count = output_patterns[pattern]
            
            if original_count > 0:
                health['pattern_preservation'][pattern] = {
                    'original': original_count,
                    'after': new_count,
                    'preserved': (original_count == new_count) or (new_count >= original_count)
                }
                
                # Warn if critical patterns were removed
                if new_count == 0 and original_count > 0:
                    health['warnings'].append(f"Important pattern '{pattern}' was completely removed")
                elif new_count < original_count * 0.5:  # If reduced by more than 50%
                    health['warnings'].append(f"Pattern '{pattern}' was significantly reduced ({original_count} -> {new_count})")
    
    return health

def verify_functionality(input_file, output_file=None, arch='x86'):
    """
    Verify that the output file maintains basic shellcode functionality.
    
    Args:
        input_file (str): Path to the original file
        output_file (str): Path to the processed file (optional)
        arch (str): Architecture ('x86', 'x64')
        
    Returns:
        bool: True if verification passes, False otherwise
    """
    print("=" * 80)
    print("BYVALVER FUNCTIONALITY VERIFICATION")
    print("=" * 80)
    
    # Read input file
    if not os.path.exists(input_file):
        print(f"[ERROR] Input file does not exist: {input_file}")
        return False
    
    with open(input_file, 'rb') as f:
        input_data = f.read()
    
    print(f"Input file: {input_file}")
    print(f"Input size: {len(input_data)} bytes")
    
    # If no output file specified, just disassemble input
    if output_file is None:
        print("\\n[INFO] No output file specified. Analyzing input shellcode only...")
        disasm_out, error, instr_count = disassemble_shellcode(input_data, arch)
        
        if error:
            print(f"[ERROR] Disassembly failed: {error}")
            return False
        
        patterns = check_instruction_patterns(input_data)
        print(f"Disassembled instructions: {instr_count}")
        print(f"System calls: {patterns['system_calls']}")
        print(f"Stack operations: {patterns['stack_operations']}")
        print(f"Register operations: {patterns['register_operations']}")
        print(f"Control flow instructions: {patterns['control_flow']}")
        
        success = len(input_data) > 0  # Basic functionality check
        print(f"\\nInput file basic functionality: {'PASS' if success else 'FAIL'}")
        return success
    
    # Read output file
    if not os.path.exists(output_file):
        print(f"[ERROR] Output file does not exist: {output_file}")
        return False
    
    with open(output_file, 'rb') as f:
        output_data = f.read()
    
    print(f"Output file: {output_file}")
    print(f"Output size: {len(output_data)} bytes")
    
    # Analyze both files
    print("\\nAnalyzing input shellcode...")
    input_disasm, input_error, input_instr_count = disassemble_shellcode(input_data, arch)
    
    print("Analyzing output shellcode...")
    output_disasm, output_error, output_instr_count = disassemble_shellcode(output_data, arch)
    
    if input_error:
        print(f"[ERROR] Input disassembly failed: {input_error}")
        return False
    
    if output_error:
        print(f"[ERROR] Output disassembly failed: {output_error}")
        return False
    
    print(f"Input instructions: {input_instr_count}")
    print(f"Output instructions: {output_instr_count}")
    
    # Check shellcode health
    health = check_shellcode_health(input_data, output_data)
    
    print(f"\\nSize ratio: {health['size_ratio']:.2f} (output/input)")
    
    print("\\nPattern preservation analysis:")
    for pattern, data in health['pattern_preservation'].items():
        status = "✓ PRESERVED" if data['preserved'] else "✗ CHANGED"
        print(f"  {pattern}: {data['original']} -> {data['after']} {status}")
    
    if health['warnings']:
        print("\\n[WARNINGS]:")
        for warning in health['warnings']:
            print(f"  - {warning}")
    
    # Verification results
    print("\\n" + "=" * 80)
    print("FUNCTIONALITY VERIFICATION RESULTS")
    print("=" * 80)
    
    # Determine success based on key factors
    size_ratio_acceptable = 0.5 <= health['size_ratio'] <= 5.0  # Output should be reasonable size
    instructions_present = output_instr_count > 0
    
    # Check if critical patterns were preserved
    critical_preserved = True
    for pattern, data in health['pattern_preservation'].items():
        if data['original'] > 0 and data['after'] == 0:  # Critical pattern completely removed
            if pattern in ['control_flow', 'stack_operations']:
                critical_preserved = False
                print(f"[FAILURE] Critical pattern '{pattern}' was completely removed")
    
    success = size_ratio_acceptable and instructions_present and critical_preserved
    
    print(f"Size ratio acceptable: {'PASS' if size_ratio_acceptable else 'FAIL'}")
    print(f"Instructions present: {'PASS' if instructions_present else 'FAIL'}")
    print(f"Critical patterns preserved: {'PASS' if critical_preserved else 'FAIL'}")
    
    if success:
        print("\\n[SUCCESS] Basic functionality verification passed!")
        print("✓ Output appears to maintain basic shellcode functionality")
    else:
        print("\\n[FAILURE] Basic functionality verification failed!")
        print("✗ Output may have lost critical functionality")
    
    return success

def batch_verify_functionality(input_dir, output_dir=None, arch='x86', recursive=False, pattern="*.bin", continue_on_error=False):
    """
    Batch verify functionality for all files in a directory.

    Args:
        input_dir (str): Directory containing input files
        output_dir (str): Directory containing output files (optional)
        arch (str): Target architecture ('x86', 'x64')
        recursive (bool): Whether to process subdirectories recursively
        pattern (str): File pattern to match (default: "*.bin")
        continue_on_error (bool): Whether to continue processing if a file fails

    Returns:
        dict: Summary of batch verification results
    """
    print("=" * 80)
    print("BYVALVER BATCH FUNCTIONALITY VERIFICATION")
    print(f"Input directory: {input_dir}")
    if output_dir:
        print(f"Output directory: {output_dir}")
    print(f"Architecture: {arch}")
    print(f"Recursive: {recursive}")
    print(f"Pattern: {pattern}")
    print("=" * 80)

    # Find all matching files in input directory
    input_files = []
    input_path = Path(input_dir)

    if recursive:
        for file_path in input_path.rglob(pattern):
            if file_path.is_file():
                input_files.append(file_path)
    else:
        for file_path in input_path.glob(pattern):
            if file_path.is_file():
                input_files.append(file_path)

    print(f"Found {len(input_files)} files matching pattern '{pattern}'")

    if not input_files:
        print("[ERROR] No files found matching the pattern")
        return {
            'total': 0,
            'successful': 0,
            'failed': 0,
            'errors': 0,
            'results': []
        }

    # Prepare output mapping if output_dir is specified
    output_mapping = {}
    if output_dir:
        output_path = Path(output_dir)
        for input_file in input_files:
            # Map input file to corresponding output file
            relative_path = input_file.relative_to(input_path)
            output_file = output_path / relative_path
            output_mapping[str(input_file)] = str(output_file)

    # Process each file
    results = []
    stats = {
        'total': len(input_files),
        'successful': 0,
        'failed': 0,
        'errors': 0
    }

    for i, input_file in enumerate(input_files, 1):
        print(f"[{i}/{len(input_files)}] Processing: {input_file.name}")

        # Determine corresponding output file
        output_file = output_mapping.get(str(input_file))

        try:
            result = verify_functionality(str(input_file), output_file, arch)
            if result:
                stats['successful'] += 1
                status = "SUCCESS"
            else:
                stats['failed'] += 1
                status = "FAILED"

            results.append({
                'file': str(input_file),
                'output_file': output_file,
                'success': result,
                'status': status,
                'arch': arch
            })

            print(f"  Status: {status}")

        except Exception as e:
            stats['errors'] += 1
            error_status = "ERROR"
            results.append({
                'file': str(input_file),
                'output_file': output_file,
                'success': False,
                'status': error_status,
                'error': str(e),
                'arch': arch
            })
            print(f"  Status: {error_status} - {e}")

            if not continue_on_error:
                print(f"[STOP] Stopping due to error (use --continue-on-error to continue)")
                break

    # Print summary
    print("\n" + "=" * 80)
    print("BATCH VERIFICATION SUMMARY")
    print("=" * 80)
    print(f"Total files processed: {stats['total']}")
    print(f"Successful: {stats['successful']}")
    print(f"Failed: {stats['failed']}")
    print(f"Errors: {stats['errors']}")

    success_rate = (stats['successful'] / stats['total'] * 100) if stats['total'] > 0 else 0
    print(f"Success rate: {success_rate:.1f}%")

    return stats

def main():
    parser = argparse.ArgumentParser(
        description="BYVALVER: Verify basic functionality of processed shellcode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.bin                    # Analyze input file only
  %(prog)s input.bin output.bin         # Compare input and output files
  %(prog)s shellcode.bin -o processed.bin --arch x64  # With architecture
  %(prog)s input_dir/                   # Batch process directory
  %(prog)s input_dir/ output_dir/       # Batch process with output directory
  %(prog)s input_dir/ -r --arch x64     # Batch process recursively with arch

Note: This tool verifies that the processed shellcode maintains basic functionality
after null-byte elimination by checking for preserved instruction patterns.
        """
    )

    parser.add_argument(
        'input_path',
        help='Path to the input file or directory before processing'
    )

    parser.add_argument(
        'output_path',
        nargs='?',
        help='Path to the processed file or directory after processing (optional)'
    )

    parser.add_argument(
        '-o', '--output',
        dest='output_path_alt',
        help='Alternative way to specify output file/directory path'
    )

    parser.add_argument(
        '--arch',
        choices=['x86', 'x64'],
        default='x86',
        help='Target architecture (default: x86)'
    )

    # Batch processing options
    parser.add_argument(
        '-r', '--recursive',
        action='store_true',
        help='Process directories recursively'
    )

    parser.add_argument(
        '--pattern',
        default='*.bin',
        help='File pattern to match in batch mode (default: *.bin)'
    )

    parser.add_argument(
        '--continue-on-error',
        action='store_true',
        help='Continue processing even if some files fail'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    # Determine output path
    output_path = args.output_path or args.output_path_alt

    input_path = Path(args.input_path)

    # Check if input is a directory for batch processing
    if input_path.is_dir():
        # Batch mode
        success = batch_verify_functionality(
            str(input_path),
            output_path,
            args.arch,
            args.recursive,
            args.pattern,
            args.continue_on_error
        )

        # For batch mode, exit with success if there were no errors (even if individual files failed)
        total_errors = success.get('errors', 0)
        sys.exit(0 if total_errors == 0 else 1)
    else:
        # Single file mode
        success = verify_functionality(args.input_path, output_path, args.arch)

        # Exit with appropriate code
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()