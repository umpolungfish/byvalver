#!/usr/bin/env python3
"""
BYVALVER Verification Tool - Null Byte Elimination
verify_denulled.py

This tool verifies that the output file from byvalver has successfully eliminated all null bytes.
"""

import sys
import os
import argparse
from pathlib import Path
import fnmatch

def analyze_shellcode_for_nulls(shellcode_data):
    """
    Analyze shellcode data to count null bytes and provide detailed information.
    
    Args:
        shellcode_data (bytes): The shellcode data to analyze
        
    Returns:
        dict: Information about null bytes in the data
    """
    null_count = 0
    null_positions = []
    null_sequences = []  # Track sequences of consecutive nulls
    
    i = 0
    while i < len(shellcode_data):
        if shellcode_data[i] == 0:
            null_count += 1
            null_positions.append(i)
            
            # Track consecutive null sequences
            seq_start = i
            while i < len(shellcode_data) and shellcode_data[i] == 0:
                i += 1
            seq_length = i - seq_start
            null_sequences.append((seq_start, seq_length))
        else:
            i += 1
    
    return {
        'total_bytes': len(shellcode_data),
        'null_count': null_count,
        'null_percentage': (null_count / len(shellcode_data)) * 100 if len(shellcode_data) > 0 else 0,
        'null_positions': null_positions,
        'null_sequences': null_sequences,
        'max_consecutive_nulls': max([seq[1] for seq in null_sequences], default=0)
    }

def verify_null_elimination(input_file, output_file=None):
    """
    Verify that the output file has eliminated all null bytes.

    Args:
        input_file (str): Path to the original file
        output_file (str): Path to the processed file (optional)

    Returns:
        bool: True if verification passes, False otherwise
    """
    print("=" * 80)
    print("BYVALVER NULL-BYTE ELIMINATION VERIFICATION")
    print("=" * 80)

    # Analyze input file
    if not os.path.exists(input_file):
        print(f"[ERROR] Input file does not exist: {input_file}")
        return False

    with open(input_file, 'rb') as f:
        input_data = f.read()

    input_analysis = analyze_shellcode_for_nulls(input_data)

    print(f"Input file: {input_file}")
    print(f"Input size: {input_analysis['total_bytes']} bytes")
    print(f"Null bytes in input: {input_analysis['null_count']} ({input_analysis['null_percentage']:.2f}%)")

    if input_analysis['null_count'] > 0:
        print(f"Null byte positions in input: {input_analysis['null_positions'][:10]}{'...' if len(input_analysis['null_positions']) > 10 else ''}")
        if input_analysis['max_consecutive_nulls'] > 1:
            print(f"Longest consecutive null sequence in input: {input_analysis['max_consecutive_nulls']} bytes")

    # If no output file specified, just report on input
    if output_file is None:
        print("\n[INFO] No output file specified. Only analyzed input file.")
        success = input_analysis['null_count'] == 0
        print(f"Input file {'PASSES' if success else 'FAILS'} null-byte elimination: {'PASS' if success else 'FAIL'}")
        return success

    # Analyze output file
    if not os.path.exists(output_file):
        print(f"[ERROR] Output file does not exist: {output_file}")
        return False

    with open(output_file, 'rb') as f:
        output_data = f.read()

    output_analysis = analyze_shellcode_for_nulls(output_data)

    print(f"\nOutput file: {output_file}")
    print(f"Output size: {output_analysis['total_bytes']} bytes")
    print(f"Null bytes in output: {output_analysis['null_count']} ({output_analysis['null_percentage']:.2f}%)")

    if output_analysis['null_count'] > 0:
        print(f"Null byte positions in output: {output_analysis['null_positions'][:10]}{'...' if len(output_analysis['null_positions']) > 10 else ''}")
        if output_analysis['max_consecutive_nulls'] > 1:
            print(f"Longest consecutive null sequence in output: {output_analysis['max_consecutive_nulls']} bytes")

    # Verification results
    print("\n" + "=" * 80)
    print("VERIFICATION RESULTS")
    print("=" * 80)

    original_null_count = input_analysis['null_count']
    remaining_null_count = output_analysis['null_count']
    size_change = output_analysis['total_bytes'] - input_analysis['total_bytes']

    print(f"Original null bytes: {original_null_count}")
    print(f"Remaining null bytes: {remaining_null_count}")
    print(f"Size change: {size_change:+d} bytes")

    if remaining_null_count == 0:
        print("\n[SUCCESS] All null bytes have been successfully eliminated!")
        print("✓ VERIFICATION PASSED: Output contains zero null bytes")
        return True
    else:
        print(f"\n[FAILURE] {remaining_null_count} null bytes remain in the output!")
        print("✗ VERIFICATION FAILED: Output still contains null bytes")
        return False

def batch_verify_null_elimination(input_dir, output_dir=None, recursive=False, pattern="*.bin", continue_on_error=False):
    """
    Batch verify null elimination for all files in a directory.

    Args:
        input_dir (str): Directory containing input files
        output_dir (str): Directory containing output files (optional)
        recursive (bool): Whether to process subdirectories recursively
        pattern (str): File pattern to match (default: "*.bin")
        continue_on_error (bool): Whether to continue processing if a file fails

    Returns:
        dict: Summary of batch verification results
    """
    print("=" * 80)
    print("BYVALVER BATCH NULL-BYTE ELIMINATION VERIFICATION")
    print(f"Input directory: {input_dir}")
    if output_dir:
        print(f"Output directory: {output_dir}")
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
            result = verify_null_elimination(str(input_file), output_file)
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
                'status': status
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
                'error': str(e)
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
        description="BYVALVER: Verify null-byte elimination in processed shellcode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.bin                    # Analyze input file only
  %(prog)s input.bin output.bin         # Compare input and output files
  %(prog)s shellcode.bin -o processed.bin  # With explicit output file
  %(prog)s input_dir/                   # Batch process directory
  %(prog)s input_dir/ output_dir/       # Batch process with output directory
  %(prog)s input_dir/ -r                # Batch process recursively

Note: This tool verifies that the output has no null bytes after processing with byvalver.
        """
    )

    parser.add_argument(
        'input_path',
        help='Path to the input file or directory before null-byte elimination'
    )

    parser.add_argument(
        'output_path',
        nargs='?',
        help='Path to the processed file or directory after null-byte elimination (optional)'
    )

    parser.add_argument(
        '-o', '--output',
        dest='output_path_alt',
        help='Alternative way to specify output file/directory path'
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
        success = batch_verify_null_elimination(
            str(input_path),
            output_path,
            args.recursive,
            args.pattern,
            args.continue_on_error
        )

        # For batch mode, exit with success if there were no errors (even if individual files failed)
        total_errors = success.get('errors', 0)
        sys.exit(0 if total_errors == 0 else 1)
    else:
        # Single file mode
        success = verify_null_elimination(args.input_path, output_path)

        # Exit with appropriate code
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()