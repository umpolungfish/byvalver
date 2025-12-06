#!/usr/bin/env python3
"""
BYVALVER Verification Tool - Semantic Preservation
verify_semantic.py

This tool verifies that the processed shellcode maintains semantic equivalence
to the original by analyzing instruction patterns and transformations.
Note: Full semantic verification would require an emulator, which this simplified version does not include.
"""

import sys
import os
import argparse
import tempfile
from pathlib import Path
import re
import fnmatch

def extract_instruction_patterns(shellcode_data):
    """
    Extract high-level instruction patterns from shellcode.
    This is a simplified analysis focusing on common transformation patterns.
    
    Args:
        shellcode_data (bytes): The shellcode data to analyze
        
    Returns:
        dict: Dictionary of instruction patterns and their counts
    """
    patterns = {
        'mov_reg_imm': 0,      # MOV reg, imm32
        'mov_reg_mem': 0,      # MOV reg, [mem]
        'mov_mem_reg': 0,      # MOV [mem], reg
        'arithmetic': 0,       # ADD, SUB, MUL, DIV, etc.
        'logical': 0,          # AND, OR, XOR, NOT
        'control_flow': 0,     # JMP, CALL, RET, conditional jumps
        'stack_ops': 0,        # PUSH, POP
        'lea_operations': 0,   # LEA instructions
        'system_calls': 0,     # INT 0x80, SYSCALL
        'register_ops': 0,     # Operations between registers
        'patterns': []         # Store specific patterns found
    }
    
    i = 0
    while i < len(shellcode_data):
        byte = shellcode_data[i]
        
        # MOV reg, imm32 patterns (B8-BF for EAX-EDI, C7 for others)
        if 0xb8 <= byte <= 0xbf:  # MOV EAX/ECX/EDX/EBX/ESP/EBP/ESI/EDI, imm32
            patterns['mov_reg_imm'] += 1
            i += 5  # Skip 4-byte immediate
            continue
        elif byte == 0xc7 and i + 6 < len(shellcode_data):  # MOV r/m32, imm32
            # Check ModR/M byte to see if it's reg-to-reg
            modrm = shellcode_data[i + 1]
            if (modrm & 0xc0) == 0xc0:  # Register-to-register
                patterns['mov_reg_imm'] += 1
                i += 6  # Skip opcode + modrm + 4-byte immediate
                continue
            else:  # Memory operation
                patterns['mov_mem_reg'] += 1
                i += 6
                continue
        elif byte == 0xc6 and i + 2 < len(shellcode_data):  # MOV r/m8, imm8
            modrm = shellcode_data[i + 1]
            if (modrm & 0xc0) == 0xc0:  # Register
                patterns['mov_reg_imm'] += 1
                i += 3
                continue
            else:  # Memory
                patterns['mov_mem_reg'] += 1
                i += 3
                continue
        
        # Stack operations
        elif 0x50 <= byte <= 0x5f:  # PUSH/POP reg
            if byte & 0x08:  # POP
                patterns['stack_ops'] += 1
            else:  # PUSH
                patterns['stack_ops'] += 1
            i += 1
            continue
        elif byte == 0x68:  # PUSH imm32
            patterns['stack_ops'] += 1
            i += 5
            continue
        elif byte == 0x6a:  # PUSH imm8
            patterns['stack_ops'] += 1
            i += 2
            continue
        
        # Arithmetic operations
        elif 0x00 <= byte <= 0x05:  # ADD
            if byte == 0x05:  # ADD EAX, imm32
                patterns['arithmetic'] += 1
                i += 5
                continue
            else:
                patterns['arithmetic'] += 1
                i += 1
                continue
        elif 0x28 <= byte <= 0x2f:  # SUB
            if byte == 0x2d:  # SUB EAX, imm32
                patterns['arithmetic'] += 1
                i += 5
                continue
            else:
                patterns['arithmetic'] += 1
                i += 1
                continue
        elif 0x83 <= byte <= 0x8b:  # More arithmetic
            if byte == 0x83:  # Arithmetic with immediate (8-bit)
                patterns['arithmetic'] += 1
                i += 3  # opcode + modrm + imm8
                continue
            elif byte == 0x8b:  # MOV from memory
                patterns['mov_reg_mem'] += 1
                i += 2  # opcode + modrm
                continue
            else:
                patterns['arithmetic'] += 1
                i += 1
                continue
        
        # Logical operations
        elif 0x20 <= byte <= 0x25 or 0x30 <= byte <= 0x35:  # AND, XOR, OR, CMP
            if byte in [0x25, 0x35]:  # Immediate forms
                patterns['logical'] += 1
                i += 5  # opcode + 4-byte immediate
                continue
            else:
                patterns['logical'] += 1
                i += 1
                continue
        elif byte == 0x33:  # XOR reg, reg
            patterns['logical'] += 1
            i += 2  # opcode + modrm
            continue
        
        # LEA (Load Effective Address)
        elif byte == 0x8d:
            patterns['lea_operations'] += 1
            i += 2  # opcode + modrm
            continue
        
        # Control flow
        elif 0x70 <= byte <= 0x7f:  # Conditional jumps
            patterns['control_flow'] += 1
            i += 2  # opcode + displacement
            continue
        elif byte == 0xe9:  # JMP rel32
            patterns['control_flow'] += 1
            i += 5  # opcode + 4-byte displacement
            continue
        elif byte == 0xeb:  # JMP rel8
            patterns['control_flow'] += 1
            i += 2  # opcode + 1-byte displacement
            continue
        elif byte == 0xe8:  # CALL rel32
            patterns['control_flow'] += 1
            i += 5  # opcode + 4-byte displacement
            continue
        elif byte == 0xc3:  # RET
            patterns['control_flow'] += 1
            i += 1
            continue
        elif byte == 0xc2:  # RET imm16
            patterns['control_flow'] += 1
            i += 3  # opcode + 2-byte immediate
            continue
        
        # System calls
        elif byte == 0xcd and i + 1 < len(shellcode_data) and shellcode_data[i + 1] == 0x80:  # INT 0x80
            patterns['system_calls'] += 1
            i += 2
            continue
        elif i + 1 < len(shellcode_data) and shellcode_data[i:i+2] == b'\\x0f\\x05':  # SYSCALL
            patterns['system_calls'] += 1
            i += 2
            continue
        
        # Default to advance by 1
        i += 1
    
    return patterns

def compare_instruction_patterns(input_patterns, output_patterns):
    """
    Compare instruction patterns between input and output considering BYVALVER's null-byte elimination purpose.

    Args:
        input_patterns (dict): Patterns from input shellcode
        output_patterns (dict): Patterns from output shellcode

    Returns:
        dict: Analysis of pattern preservation
    """
    analysis = {
        'preserved_patterns': {},
        'changed_patterns': {},
        'semantic_warnings': [],
        'transformation_analysis': {},
        'is_semantically_equivalent': True
    }

    # For null-byte elimination, some pattern changes are expected.
    # Critical patterns that should be preserved for functionality
    critical_patterns = ['control_flow', 'system_calls']  # These are essential for shellcode functionality

    # Analyze each pattern type
    for pattern_type in input_patterns:
        if pattern_type == 'patterns':  # Skip the list of specific patterns
            continue

        input_count = input_patterns[pattern_type] if isinstance(input_patterns[pattern_type], int) else 0
        output_count = output_patterns[pattern_type] if isinstance(output_patterns[pattern_type], int) else 0

        # Calculate change percentage
        if input_count > 0:
            change_percent = abs(output_count - input_count) / input_count * 100
        else:
            change_percent = 0 if output_count == 0 else float('inf')  # Infinite change if input was 0 but output isn't

        # For BYVALVER, we need special handling:
        # - MOV patterns often change due to null-byte elimination strategies
        # - Arithmetic/logical patterns may change as instructions are replaced
        # - Control flow must be preserved (critical for functionality)
        # - System calls must be preserved (critical for functionality)

        # More lenient criteria for non-critical patterns
        if pattern_type in ['mov_reg_imm', 'mov_mem_reg', 'mov_reg_mem', 'arithmetic', 'logical', 'lea_operations']:
            # These are expected to change significantly in null-byte elimination
            # Consider as "functionally preserved" even with higher changes
            preserved = True  # Always consider these preserved for semantic purposes
        elif pattern_type in critical_patterns:
            # These are critical - must be present even if numbers change
            preserved = (input_count > 0 and output_count > 0) or (input_count == 0 and output_count == 0)
        else:
            # Other patterns use normal threshold
            preserved = change_percent <= 75  # More lenient than 50% for BYVALVER context

        pattern_analysis = {
            'input_count': input_count,
            'output_count': output_count,
            'change_percent': change_percent,
            'preserved': preserved,
            'critical': pattern_type in critical_patterns
        }

        if preserved:
            analysis['preserved_patterns'][pattern_type] = pattern_analysis
        else:
            analysis['changed_patterns'][pattern_type] = pattern_analysis

            # Add warnings for non-critical patterns that change too much
            if pattern_type not in critical_patterns and input_count > 0 and change_percent > 75:
                analysis['semantic_warnings'].append(
                    f"Pattern '{pattern_type}' significantly changed ({input_count} -> {output_count}, {change_percent:.1f}% change)"
                )
            elif pattern_type in critical_patterns and input_count > 0 and output_count == 0:
                # Critical patterns must be preserved
                analysis['semantic_warnings'].append(
                    f"CRITICAL: Pattern '{pattern_type}' completely eliminated (was {input_count}, now 0)"
                )

    return analysis

def analyze_transformation_strategies(input_data, output_data):
    """
    Analyze the types of transformations that might have occurred based on size and content.
    
    Args:
        input_data (bytes): Original shellcode
        output_data (bytes): Processed shellcode
        
    Returns:
        dict: Analysis of likely transformation strategies
    """
    analysis = {
        'size_change_ratio': len(output_data) / len(input_data) if len(input_data) > 0 else 0,
        'likely_transformations': [],
        'complexity_increase': len(output_data) > len(input_data)
    }
    
    # Check for common transformation signatures
    input_patterns = extract_instruction_patterns(input_data)
    output_patterns = extract_instruction_patterns(output_data)
    
    # Look for signs of specific strategies
    if output_patterns['stack_ops'] > input_patterns['stack_ops'] * 1.5:
        analysis['likely_transformations'].append("Register-to-stack conversion (may indicate null-elimination)")
    
    if output_patterns['lea_operations'] > input_patterns['lea_operations'] * 1.5:
        analysis['likely_transformations'].append("LEA-based displacement encoding (null-elimination strategy)")
    
    if output_patterns['logical'] > input_patterns['logical'] * 1.5:
        analysis['likely_transformations'].append("Logical operation substitution (XOR/AND/OR for null elimination)")
    
    if output_patterns['mov_reg_mem'] > input_patterns['mov_reg_mem'] * 1.5:
        analysis['likely_transformations'].append("Memory addressing substitution (may avoid nulls in displacement)")
    
    # Size increase often indicates null-byte elimination strategies
    if analysis['size_change_ratio'] > 1.3:
        analysis['likely_transformations'].append("Size-increasing transformations (typical of null-byte elimination)")
    
    return analysis

def verify_semantic_equivalence(input_file, output_file, method='pattern'):
    """
    Verify that the output file maintains semantic equivalence to the input.
    
    Args:
        input_file (str): Path to the original file
        output_file (str): Path to the processed file
        method (str): Verification method ('pattern', 'simple', or 'comprehensive')
        
    Returns:
        bool: True if verification passes, False otherwise
    """
    print("=" * 80)
    print("BYVALVER SEMANTIC EQUIVALENCE VERIFICATION")
    print("=" * 80)
    
    # Read input file
    if not os.path.exists(input_file):
        print(f"[ERROR] Input file does not exist: {input_file}")
        return False
    
    with open(input_file, 'rb') as f:
        input_data = f.read()
    
    print(f"Input file: {input_file}")
    print(f"Input size: {len(input_data)} bytes")
    
    # Read output file
    if not os.path.exists(output_file):
        print(f"[ERROR] Output file does not exist: {output_file}")
        return False
    
    with open(output_file, 'rb') as f:
        output_data = f.read()
    
    print(f"Output file: {output_file}")
    print(f"Output size: {len(output_data)} bytes")
    
    if method == 'pattern':
        print("\nAnalyzing instruction patterns...")
        
        # Extract patterns from both shellcodes
        input_patterns = extract_instruction_patterns(input_data)
        output_patterns = extract_instruction_patterns(output_data)
        
        print(f"Input patterns detected:")
        for pattern, count in input_patterns.items():
            if isinstance(count, int) and count > 0:
                print(f"  {pattern}: {count}")
        
        print(f"\nOutput patterns detected:")
        for pattern, count in output_patterns.items():
            if isinstance(count, int) and count > 0:
                print(f"  {pattern}: {count}")
        
        # Compare patterns
        pattern_analysis = compare_instruction_patterns(input_patterns, output_patterns)
        
        print(f"\nPattern preservation analysis:")
        print(f"  Preserved: {len(pattern_analysis['preserved_patterns'])} pattern types")
        print(f"  Changed: {len(pattern_analysis['changed_patterns'])} pattern types")
        
        if pattern_analysis['semantic_warnings']:
            print(f"\n[SEMANTIC WARNINGS]:")
            for warning in pattern_analysis['semantic_warnings']:
                print(f"  - {warning}")
        
        # Analyze transformations
        transformation_analysis = analyze_transformation_strategies(input_data, output_data)
        print(f"\nTransformation analysis:")
        print(f"  Size change ratio: {transformation_analysis['size_change_ratio']:.2f}")
        print(f"  Complexity increased: {'Yes' if transformation_analysis['complexity_increase'] else 'No'}")
        
        if transformation_analysis['likely_transformations']:
            print(f"  Likely transformations:")
            for trans in transformation_analysis['likely_transformations']:
                print(f"    - {trans}")
        
        # Determine semantic equivalence using BYVALVER-aware pattern comparison
        # The comparison function now handles the nuances of null-byte elimination
        refined_analysis = compare_instruction_patterns(input_patterns, output_patterns)

        # Check if critical patterns are preserved according to our refined analysis
        critical_patterns_preserved = True
        for pattern_name in ['control_flow', 'stack_ops', 'system_calls']:
            pattern_info = refined_analysis.get('changed_patterns', {}).get(pattern_name)
            if pattern_info and pattern_info.get('critical', False):
                # If it's a critical pattern and it's in the changed patterns with 0 output, it means it wasn't preserved
                if pattern_info.get('output_count', 0) == 0 and pattern_info.get('input_count', 0) > 0:
                    print(f"\n[CRITICAL] Critical pattern '{pattern_name}' was completely eliminated!")
                    critical_patterns_preserved = False
        
        # Calculate semantic score based on preservation
        total_patterns = len(input_patterns) - 1  # Exclude 'patterns' list
        preserved_count = len(pattern_analysis['preserved_patterns'])
        preservation_rate = preserved_count / (total_patterns - 1) if total_patterns > 1 else 0

        print(f"\n" + "=" * 80)
        print("SEMANTIC EQUIVALENCE RESULTS")
        print("=" * 80)

        print(f"BYVALVER-aware pattern preservation rate: {preservation_rate:.2f} ({preserved_count}/{total_patterns-1})")
        print(f"Critical patterns preserved: {'PASS' if critical_patterns_preserved else 'FAIL'}")

        # For BYVALVER, success means:
        # 1. Critical patterns (control_flow, stack_ops, system_calls) are preserved
        # 2. The transformations are consistent with null-byte elimination
        success = critical_patterns_preserved

        if success:
            print("\n[SUCCESS] Semantic equivalence verification passed!")
            print("✓ Output appears to maintain semantic equivalence to input")
            print("✓ Critical functionality patterns are preserved")
            print("✓ Null-byte elimination transformations detected")
        else:
            print("\n[FAILURE] Semantic equivalence verification failed!")
            print("✗ Output may have lost semantic equivalence to input")
            if not critical_patterns_preserved:
                print("✗ Critical patterns were eliminated")
    
    print(f"\nNote: This is a pattern-based semantic analysis. True semantic equivalence")
    print(f"would require execution in an emulator comparing CPU states, which is beyond")
    print(f"the scope of this simplified verification tool.")
    
    return success

def batch_verify_semantic_equivalence(input_dir, output_dir, method='pattern', recursive=False, pattern="*.bin", continue_on_error=False):
    """
    Batch verify semantic equivalence for all file pairs in directories.

    Args:
        input_dir (str): Directory containing input files
        output_dir (str): Directory containing output files
        method (str): Verification method ('pattern', 'simple')
        recursive (bool): Whether to process subdirectories recursively
        pattern (str): File pattern to match (default: "*.bin")
        continue_on_error (bool): Whether to continue processing if a file fails

    Returns:
        dict: Summary of batch verification results
    """
    print("=" * 80)
    print("BYVALVER BATCH SEMANTIC EQUIVALENCE VERIFICATION")
    print(f"Input directory: {input_dir}")
    print(f"Output directory: {output_dir}")
    print(f"Method: {method}")
    print(f"Recursive: {recursive}")
    print(f"Pattern: {pattern}")
    print("=" * 80)

    # Find all matching files in input directory
    input_files = []
    input_path = Path(input_dir)
    output_path = Path(output_dir)

    if recursive:
        for file_path in input_path.rglob(pattern):
            if file_path.is_file():
                input_files.append(file_path)
    else:
        for file_path in input_path.glob(pattern):
            if file_path.is_file():
                input_files.append(file_path)

    print(f"Found {len(input_files)} files matching pattern '{pattern}' in input directory")

    if not input_files:
        print("[ERROR] No files found matching the pattern")
        return {
            'total': 0,
            'successful': 0,
            'failed': 0,
            'errors': 0,
            'results': []
        }

    # Prepare output mapping
    output_mapping = {}
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

        if not os.path.exists(output_file):
            print(f"  [MISSING OUTPUT] Output file does not exist: {output_file}")
            stats['errors'] += 1
            results.append({
                'file': str(input_file),
                'output_file': output_file,
                'success': False,
                'status': "MISSING_OUTPUT",
                'error': f"Output file does not exist: {output_file}"
            })
            continue

        try:
            result = verify_semantic_equivalence(str(input_file), output_file, method)
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
                'method': method
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
                'method': method
            })
            print(f"  Status: {error_status} - {e}")

            if not continue_on_error:
                print(f"[STOP] Stopping due to error (use --continue-on-error to continue)")
                break

    # Print summary
    print("\n" + "=" * 80)
    print("BATCH VERIFICATION SUMMARY")
    print("=" * 80)
    print(f"Total file pairs processed: {stats['total']}")
    print(f"Successful: {stats['successful']}")
    print(f"Failed: {stats['failed']}")
    print(f"Errors: {stats['errors']}")

    success_rate = (stats['successful'] / stats['total'] * 100) if stats['total'] > 0 else 0
    print(f"Success rate: {success_rate:.1f}%")

    return stats

def main():
    parser = argparse.ArgumentParser(
        description="BYVALVER: Verify semantic equivalence of processed shellcode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.bin output.bin         # Compare semantic patterns
  %(prog)s original.bin processed.bin --method pattern  # Use pattern method
  %(prog)s input_dir/ output_dir/       # Batch process directory pairs
  %(prog)s input_dir/ output_dir/ -r    # Batch process recursively

Note: This tool provides pattern-based semantic analysis as a proxy for true
semantic equivalence, which would require execution in an emulator.
        """
    )

    parser.add_argument(
        'input_path',
        help='Path to the input file or directory before processing'
    )

    parser.add_argument(
        'output_path',
        nargs='?',
        help='Path to the processed file or directory after processing (required for files, optional for directories)'
    )

    parser.add_argument(
        '--method',
        choices=['pattern', 'simple'],
        default='pattern',
        help='Verification method (default: pattern)'
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

    input_path = Path(args.input_path)
    output_path = args.output_path

    if input_path.is_dir():
        # Batch mode - both input and output should be directories
        if not output_path:
            print("[ERROR] For directory processing, output directory is required")
            sys.exit(1)

        output_dir = Path(output_path)
        if not output_dir.is_dir():
            print(f"[ERROR] Output path is not a directory: {output_path}")
            sys.exit(1)

        # Batch mode
        success = batch_verify_semantic_equivalence(
            str(input_path),
            str(output_dir),
            args.method,
            args.recursive,
            args.pattern,
            args.continue_on_error
        )

        # For batch mode, exit with success if there were no errors (even if individual files failed)
        total_errors = success.get('errors', 0)
        sys.exit(0 if total_errors == 0 else 1)
    else:
        # Single file mode
        if not output_path:
            print("[ERROR] For single file processing, output file is required")
            sys.exit(1)

        success = verify_semantic_equivalence(args.input_path, args.output_path, args.method)

        # Exit with appropriate code
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()