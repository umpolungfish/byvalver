#!/usr/bin/env python3
"""
BYVALVER Verification Tool - Bad Character Elimination
verify_denulled.py

This tool verifies that the output file from byvalver has successfully eliminated all specified bad characters.
Updated in v3.0 to support generic bad character checking (not just null bytes).
Updated in v3.0.3 to support bad-character profiles matching byvalver's --profile option.
"""

import sys
import os
import argparse
from pathlib import Path
import fnmatch

# =============================================================================
# BAD-CHARACTER PROFILE DEFINITIONS
# Matches the profiles defined in src/badchar_profiles.h
# =============================================================================

BADCHAR_PROFILES = {
    'null-only': {
        'name': 'null-only',
        'description': 'Eliminate NULL bytes only (classic denullification)',
        'context': 'Most buffer overflows, string-based exploits',
        'bad_chars': [0x00],
        'difficulty': 1,  # Trivial
    },
    'http-newline': {
        'name': 'http-newline',
        'description': 'Eliminate NULL, LF, and CR (line terminators)',
        'context': 'HTTP headers, FTP, SMTP, line-based protocols',
        'bad_chars': [0x00, 0x0A, 0x0D],
        'difficulty': 2,  # Low
    },
    'http-whitespace': {
        'name': 'http-whitespace',
        'description': 'Eliminate NULL and all whitespace characters',
        'context': 'HTTP parameters, command injection contexts',
        'bad_chars': [0x00, 0x09, 0x0A, 0x0D, 0x20],
        'difficulty': 2,  # Low
    },
    'url-safe': {
        'name': 'url-safe',
        'description': 'Eliminate URL-unsafe characters',
        'context': 'URL parameters, GET requests, query strings',
        'bad_chars': [
            0x00, 0x20, 0x22, 0x23, 0x24, 0x25, 0x26, 0x2B, 0x2C, 0x2F,
            0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x5B, 0x5D, 0x5C,
            0x7B, 0x7D, 0x7C
        ],
        'difficulty': 3,  # Medium
    },
    'sql-injection': {
        'name': 'sql-injection',
        'description': 'Eliminate SQL metacharacters',
        'context': 'SQL injection via string literals',
        'bad_chars': [0x00, 0x22, 0x27, 0x2D, 0x3B],
        'difficulty': 3,  # Medium
    },
    'xml-html': {
        'name': 'xml-html',
        'description': 'Eliminate XML/HTML special characters',
        'context': 'XML/HTML injection, XSS payloads',
        'bad_chars': [0x00, 0x22, 0x26, 0x27, 0x3C, 0x3E],
        'difficulty': 3,  # Medium
    },
    'json-string': {
        'name': 'json-string',
        'description': 'Eliminate JSON-unsafe characters',
        'context': 'JSON API injection, JavaScript contexts',
        'bad_chars': list(range(0x00, 0x20)) + [0x22, 0x5C],  # Control chars + quote + backslash
        'difficulty': 3,  # Medium
    },
    'format-string': {
        'name': 'format-string',
        'description': 'Eliminate format string specifiers',
        'context': 'Format string vulnerabilities (printf, etc.)',
        'bad_chars': [0x00, 0x20, 0x25],
        'difficulty': 3,  # Medium
    },
    'buffer-overflow': {
        'name': 'buffer-overflow',
        'description': 'Common buffer overflow bad characters',
        'context': 'Stack/heap overflows with character filtering',
        'bad_chars': [0x00, 0x09, 0x0A, 0x0D, 0x20],
        'difficulty': 3,  # Medium
    },
    'command-injection': {
        'name': 'command-injection',
        'description': 'Eliminate shell metacharacters',
        'context': 'Shell command injection, system() calls',
        'bad_chars': [
            0x00, 0x09, 0x0A, 0x0D, 0x20, 0x21, 0x22, 0x24, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2F, 0x3B, 0x3C, 0x3E, 0x5C, 0x60, 0x7C
        ],
        'difficulty': 3,  # Medium
    },
    'ldap-injection': {
        'name': 'ldap-injection',
        'description': 'Eliminate LDAP special characters',
        'context': 'LDAP injection attacks',
        'bad_chars': [0x00, 0x28, 0x29, 0x2A, 0x5C],
        'difficulty': 3,  # Medium
    },
    'printable-only': {
        'name': 'printable-only',
        'description': 'Allow only printable ASCII (0x20-0x7E)',
        'context': 'Text-based protocols, printable character requirements',
        'bad_chars': list(range(0x00, 0x20)) + [0x7F] + list(range(0x80, 0x100)),
        'difficulty': 4,  # High
    },
    'alphanumeric-only': {
        'name': 'alphanumeric-only',
        'description': 'Allow only alphanumeric chars (0-9, A-Z, a-z)',
        'context': 'Strict input filters, alphanumeric-only shellcode',
        'bad_chars': [i for i in range(256) if not (
            (0x30 <= i <= 0x39) or  # 0-9
            (0x41 <= i <= 0x5A) or  # A-Z
            (0x61 <= i <= 0x7A)     # a-z
        )],
        'difficulty': 5,  # Extreme
    },
}

DIFFICULTY_LABELS = {
    1: 'Trivial',
    2: 'Low',
    3: 'Medium',
    4: 'High',
    5: 'Extreme'
}

def list_profiles():
    """List all available bad-character profiles."""
    print("=" * 80)
    print("AVAILABLE BAD-CHARACTER PROFILES")
    print("=" * 80)
    print()

    for profile_name in sorted(BADCHAR_PROFILES.keys()):
        profile = BADCHAR_PROFILES[profile_name]

        # Difficulty indicator
        difficulty_bar = '█' * profile['difficulty'] + '░' * (5 - profile['difficulty'])

        print(f"  {profile['name']:<22}  [{difficulty_bar}]  ({len(profile['bad_chars'])} bad chars)")
        print(f"      {profile['description']}")
        print(f"      Context: {profile['context']}")
        print()

    print("Difficulty Legend: [█░░░░]=Trivial  [███░░]=Medium  [█████]=Extreme")
    print()
    print("Usage: verify_denulled.py --profile <name> input.bin [output.bin]")
    print("   or: verify_denulled.py --list-profiles  (show this list)")
    print()

def get_profile_bad_chars(profile_name):
    """
    Get bad characters from a profile name.

    Args:
        profile_name (str): Name of the profile

    Returns:
        set: Set of bad byte values, or None if profile not found
    """
    if profile_name not in BADCHAR_PROFILES:
        return None

    return set(BADCHAR_PROFILES[profile_name]['bad_chars'])

def show_profile_details(profile_name):
    """Show detailed information about a specific profile."""
    if profile_name not in BADCHAR_PROFILES:
        print(f"[ERROR] Unknown profile: {profile_name}")
        return False

    profile = BADCHAR_PROFILES[profile_name]

    print("=" * 80)
    print(f"PROFILE: {profile['name'].upper()}")
    print("=" * 80)
    print()
    print(f"Description: {profile['description']}")
    print(f"Context:     {profile['context']}")
    print(f"Difficulty:  {'█' * profile['difficulty']}{'░' * (5 - profile['difficulty'])} ({DIFFICULTY_LABELS[profile['difficulty']]})")
    print()
    print(f"Bad Characters ({len(profile['bad_chars'])} total):")

    # Show first 20 bytes
    hex_list = [f"0x{b:02X}" for b in profile['bad_chars'][:20]]
    print(f"  Hex: {', '.join(hex_list)}", end='')
    if len(profile['bad_chars']) > 20:
        print(f" ... ({len(profile['bad_chars']) - 20} more)")
    else:
        print()
    print()

    return True

def parse_bad_chars(bad_chars_str):
    """
    Parse comma-separated hex string into a set of bad byte values.

    Args:
        bad_chars_str (str): Comma-separated hex bytes (e.g., "00,0a,0d")

    Returns:
        set: Set of bad byte values
    """
    bad_chars = set()
    if not bad_chars_str:
        return {0x00}  # Default: null byte only

    for part in bad_chars_str.split(','):
        part = part.strip()
        if not part:
            continue
        try:
            byte_val = int(part, 16)
            if 0 <= byte_val <= 255:
                bad_chars.add(byte_val)
            else:
                print(f"[WARNING] Byte value out of range (0-255): {part}")
        except ValueError:
            print(f"[WARNING] Invalid hex value: {part}")

    return bad_chars if bad_chars else {0x00}

def analyze_shellcode_for_bad_chars(shellcode_data, bad_chars=None):
    """
    Analyze shellcode data to count bad characters and provide detailed information.

    Args:
        shellcode_data (bytes): The shellcode data to analyze
        bad_chars (set): Set of bad byte values (default: {0x00})

    Returns:
        dict: Information about bad characters in the data
    """
    if bad_chars is None:
        bad_chars = {0x00}

    bad_char_count = 0
    bad_char_positions = {}  # Map byte value to list of positions
    bad_char_sequences = []  # Track sequences of consecutive bad chars

    for bad_byte in bad_chars:
        bad_char_positions[bad_byte] = []

    i = 0
    while i < len(shellcode_data):
        if shellcode_data[i] in bad_chars:
            # Track consecutive bad char sequences
            seq_start = i
            seq_bytes = []
            while i < len(shellcode_data) and shellcode_data[i] in bad_chars:
                # Count each bad character individually
                bad_char_count += 1
                bad_char_positions[shellcode_data[i]].append(i)
                seq_bytes.append(shellcode_data[i])
                i += 1
            seq_length = i - seq_start
            bad_char_sequences.append((seq_start, seq_length, bytes(seq_bytes)))
        else:
            i += 1

    return {
        'total_bytes': len(shellcode_data),
        'bad_char_count': bad_char_count,
        'bad_char_percentage': (bad_char_count / len(shellcode_data)) * 100 if len(shellcode_data) > 0 else 0,
        'bad_char_positions': bad_char_positions,
        'bad_char_sequences': bad_char_sequences,
        'max_consecutive_bad_chars': max([seq[1] for seq in bad_char_sequences], default=0),
        'bad_chars_used': bad_chars
    }

def verify_bad_char_elimination(input_file, output_file=None, bad_chars=None):
    """
    Verify that the output file has eliminated all specified bad characters.

    Args:
        input_file (str): Path to the original file
        output_file (str): Path to the processed file (optional)
        bad_chars (set): Set of bad byte values (default: {0x00})

    Returns:
        bool: True if verification passes, False otherwise
    """
    if bad_chars is None:
        bad_chars = {0x00}

    # Format bad chars for display
    bad_chars_str = ','.join([f"0x{b:02x}" for b in sorted(bad_chars)])

    print("=" * 80)
    print("BYVALVER BAD CHARACTER ELIMINATION VERIFICATION")
    print(f"Bad characters: {bad_chars_str}")
    print("=" * 80)

    # Analyze input file
    if not os.path.exists(input_file):
        print(f"[ERROR] Input file does not exist: {input_file}")
        return False

    with open(input_file, 'rb') as f:
        input_data = f.read()

    input_analysis = analyze_shellcode_for_bad_chars(input_data, bad_chars)

    print(f"Input file: {input_file}")
    print(f"Input size: {input_analysis['total_bytes']} bytes")
    print(f"Bad characters in input: {input_analysis['bad_char_count']} ({input_analysis['bad_char_percentage']:.2f}%)")

    if input_analysis['bad_char_count'] > 0:
        # Show positions grouped by byte value
        for byte_val in sorted(bad_chars):
            positions = input_analysis['bad_char_positions'].get(byte_val, [])
            if positions:
                print(f"  0x{byte_val:02x}: {len(positions)} occurrences at positions {positions[:10]}{'...' if len(positions) > 10 else ''}")

        if input_analysis['max_consecutive_bad_chars'] > 1:
            print(f"Longest consecutive bad char sequence in input: {input_analysis['max_consecutive_bad_chars']} bytes")

    # If no output file specified, just report on input
    if output_file is None:
        print("\n[INFO] No output file specified. Only analyzed input file.")
        success = input_analysis['bad_char_count'] == 0
        print(f"Input file {'PASSES' if success else 'FAILS'} bad character check: {'PASS' if success else 'FAIL'}")
        return success

    # Analyze output file
    if not os.path.exists(output_file):
        print(f"[ERROR] Output file does not exist: {output_file}")
        return False

    with open(output_file, 'rb') as f:
        output_data = f.read()

    output_analysis = analyze_shellcode_for_bad_chars(output_data, bad_chars)

    print(f"\nOutput file: {output_file}")
    print(f"Output size: {output_analysis['total_bytes']} bytes")
    print(f"Bad characters in output: {output_analysis['bad_char_count']} ({output_analysis['bad_char_percentage']:.2f}%)")

    if output_analysis['bad_char_count'] > 0:
        # Show positions grouped by byte value
        for byte_val in sorted(bad_chars):
            positions = output_analysis['bad_char_positions'].get(byte_val, [])
            if positions:
                print(f"  0x{byte_val:02x}: {len(positions)} occurrences at positions {positions[:10]}{'...' if len(positions) > 10 else ''}")

        if output_analysis['max_consecutive_bad_chars'] > 1:
            print(f"Longest consecutive bad char sequence in output: {output_analysis['max_consecutive_bad_chars']} bytes")

    # Verification results
    print("\n" + "=" * 80)
    print("VERIFICATION RESULTS")
    print("=" * 80)

    original_bad_char_count = input_analysis['bad_char_count']
    remaining_bad_char_count = output_analysis['bad_char_count']
    size_change = output_analysis['total_bytes'] - input_analysis['total_bytes']

    print(f"Original bad characters: {original_bad_char_count}")
    print(f"Remaining bad characters: {remaining_bad_char_count}")
    print(f"Size change: {size_change:+d} bytes")

    if remaining_bad_char_count == 0:
        print("\n[SUCCESS] All bad characters have been successfully eliminated!")
        print("✓ VERIFICATION PASSED: Output contains zero bad characters")
        return True
    else:
        print(f"\n[FAILURE] {remaining_bad_char_count} bad characters remain in the output!")
        print("✗ VERIFICATION FAILED: Output still contains bad characters")
        return False

# Backward compatibility wrapper
def verify_null_elimination(input_file, output_file=None):
    """
    DEPRECATED: Use verify_bad_char_elimination() instead.
    Maintained for backward compatibility - checks for null bytes only.
    """
    return verify_bad_char_elimination(input_file, output_file, {0x00})

def batch_verify_bad_char_elimination(input_dir, output_dir=None, recursive=False, pattern="*.bin",
                                      continue_on_error=False, bad_chars=None):
    """
    Batch verify bad character elimination for all files in a directory.

    Args:
        input_dir (str): Directory containing input files
        output_dir (str): Directory containing output files (optional)
        recursive (bool): Whether to process subdirectories recursively
        pattern (str): File pattern to match (default: "*.bin")
        continue_on_error (bool): Whether to continue processing if a file fails
        bad_chars (set): Set of bad byte values (default: {0x00})

    Returns:
        dict: Summary of batch verification results
    """
    if bad_chars is None:
        bad_chars = {0x00}

    bad_chars_str = ','.join([f"0x{b:02x}" for b in sorted(bad_chars)])

    print("=" * 80)
    print("BYVALVER BATCH BAD CHARACTER ELIMINATION VERIFICATION")
    print(f"Input directory: {input_dir}")
    if output_dir:
        print(f"Output directory: {output_dir}")
    print(f"Recursive: {recursive}")
    print(f"Pattern: {pattern}")
    print(f"Bad characters: {bad_chars_str}")
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
            result = verify_bad_char_elimination(str(input_file), output_file, bad_chars)
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

# Backward compatibility wrapper
def batch_verify_null_elimination(input_dir, output_dir=None, recursive=False, pattern="*.bin", continue_on_error=False):
    """
    DEPRECATED: Use batch_verify_bad_char_elimination() instead.
    Maintained for backward compatibility - checks for null bytes only.
    """
    return batch_verify_bad_char_elimination(input_dir, output_dir, recursive, pattern, continue_on_error, {0x00})

def main():
    parser = argparse.ArgumentParser(
        description="BYVALVER: Verify bad character elimination in processed shellcode (v3.0+)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Manual bad-char specification
  %(prog)s input.bin                                # Analyze input file only (null bytes)
  %(prog)s input.bin output.bin                     # Compare input and output files
  %(prog)s input.bin output.bin --bad-chars 00,0a,0d  # Check for newlines too
  %(prog)s shellcode.bin -o processed.bin           # With explicit output file

  # Profile-based (NEW in v3.0.3)
  %(prog)s --list-profiles                          # List all available profiles
  %(prog)s --profile http-newline input.bin output.bin  # Use HTTP newline profile
  %(prog)s --profile sql-injection input.bin output.bin # Use SQL injection profile
  %(prog)s --profile alphanumeric-only test.bin     # Verify alphanumeric-only

  # Batch processing
  %(prog)s input_dir/                               # Batch process directory
  %(prog)s input_dir/ output_dir/ --profile http-whitespace  # Batch with profile
  %(prog)s input_dir/ -r --bad-chars 00             # Batch recursive with bad chars

Note: This tool verifies that the output has no bad characters after processing with byvalver.
      Use --profile for predefined sets or --bad-chars for manual specification.
      Default: null bytes (0x00) only.
        """
    )

    parser.add_argument(
        'input_path',
        nargs='?',
        help='Path to the input file or directory before bad character elimination'
    )

    parser.add_argument(
        'output_path',
        nargs='?',
        help='Path to the processed file or directory after bad character elimination (optional)'
    )

    parser.add_argument(
        '-o', '--output',
        dest='output_path_alt',
        help='Alternative way to specify output file/directory path'
    )

    # Profile options
    parser.add_argument(
        '--profile',
        type=str,
        metavar='NAME',
        help='Use predefined bad-character profile (e.g., http-newline, sql-injection, alphanumeric-only). Use --list-profiles to see all available profiles.'
    )

    parser.add_argument(
        '--list-profiles',
        action='store_true',
        help='List all available bad-character profiles and exit'
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

    parser.add_argument(
        '--bad-chars',
        type=str,
        metavar='BYTES',
        help='Comma-separated hex bytes to check for elimination (default: "00" for null bytes only). Example: "00,0a,0d" for null and newlines. Note: --profile takes precedence if both are specified.'
    )

    args = parser.parse_args()

    # Handle --list-profiles
    if args.list_profiles:
        list_profiles()
        sys.exit(0)

    # Validate that input_path is provided (unless --list-profiles was used)
    if not args.input_path:
        parser.error("the following arguments are required: input_path")

    # Determine output path
    output_path = args.output_path or args.output_path_alt

    # Determine bad characters - profile takes precedence
    if args.profile:
        bad_chars = get_profile_bad_chars(args.profile)
        if bad_chars is None:
            print(f"[ERROR] Unknown profile: {args.profile}")
            print(f"Use --list-profiles to see available profiles")
            sys.exit(1)

        if args.verbose or True:  # Always show which profile is being used
            profile = BADCHAR_PROFILES[args.profile]
            print(f"Using profile: {args.profile} ({len(bad_chars)} bad characters)")
            print(f"Description: {profile['description']}")
            print()
    else:
        # Use manual --bad-chars specification (or default)
        bad_chars_str = args.bad_chars if args.bad_chars else '00'
        bad_chars = parse_bad_chars(bad_chars_str)

    input_path = Path(args.input_path)

    # Check if input is a directory for batch processing
    if input_path.is_dir():
        # Batch mode
        success = batch_verify_bad_char_elimination(
            str(input_path),
            output_path,
            args.recursive,
            args.pattern,
            args.continue_on_error,
            bad_chars
        )

        # For batch mode, exit with success if there were no errors (even if individual files failed)
        total_errors = success.get('errors', 0)
        sys.exit(0 if total_errors == 0 else 1)
    else:
        # Single file mode
        success = verify_bad_char_elimination(args.input_path, output_path, bad_chars)

        # Exit with appropriate code
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()