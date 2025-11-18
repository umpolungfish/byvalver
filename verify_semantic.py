#!/usr/bin/env python3
"""
Semantic verification tool for byvalver.

Uses symbolic/concrete execution to verify that null-byte elimination
transformations preserve functional semantics.
"""

import sys
import argparse
from pathlib import Path

# Add verify_semantic to path
sys.path.insert(0, str(Path(__file__).parent))

from verify_semantic.disassembler import disassemble_file
from verify_semantic.equivalence_checker import EquivalenceChecker


def main():
    parser = argparse.ArgumentParser(
        description='Verify semantic equivalence between original and processed shellcode',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 verify_semantic.py original.bin processed.bin
  python3 verify_semantic.py original.bin processed.bin --verbose
  python3 verify_semantic.py original.bin processed.bin --format json

This tool uses concrete execution with multiple test vectors to verify that
byvalver's null-byte elimination transformations preserve functionality.
"""
    )

    parser.add_argument('original', help='Original shellcode binary file')
    parser.add_argument('processed', help='Processed shellcode binary file')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed execution trace')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--threshold', type=float, default=80.0,
                       help='Pass threshold percentage (default: 80.0)')

    args = parser.parse_args()

    # Verify files exist
    if not Path(args.original).exists():
        print(f"Error: Original file not found: {args.original}", file=sys.stderr)
        return 1

    if not Path(args.processed).exists():
        print(f"Error: Processed file not found: {args.processed}", file=sys.stderr)
        return 1

    # Disassemble both files
    print(f"Disassembling original: {args.original}")
    try:
        original_insns = disassemble_file(args.original)
    except Exception as e:
        print(f"Error disassembling original file: {e}", file=sys.stderr)
        return 1

    print(f"Disassembling processed: {args.processed}")
    try:
        processed_insns = disassemble_file(args.processed)
    except Exception as e:
        print(f"Error disassembling processed file: {e}", file=sys.stderr)
        return 1

    print(f"\nOriginal:  {len(original_insns)} instructions")
    print(f"Processed: {len(processed_insns)} instructions")
    print(f"Expansion: {len(processed_insns) / len(original_insns):.2f}x\n")

    # Verify equivalence
    print("Running semantic verification...")
    checker = EquivalenceChecker()
    checker.debug = args.verbose
    result = checker.verify(original_insns, processed_insns)

    # Output results
    if args.format == 'json':
        print_json_result(result)
    else:
        print_text_result(result, args.threshold)

    # Exit code based on pass/fail
    if result.get_score() >= args.threshold:
        print(f"\n✓ VERIFICATION PASSED (threshold: {args.threshold}%)")
        return 0
    else:
        print(f"\n✗ VERIFICATION FAILED (threshold: {args.threshold}%)")
        return 1


def print_text_result(result, threshold):
    """Print result in human-readable text format."""
    print("\n" + "=" * 60)
    print("SEMANTIC VERIFICATION RESULTS")
    print("=" * 60)
    print()
    print(str(result))
    print()

    if result.details and len(result.details) > 0:
        print("\nDetailed Results:")
        for detail in result.details[:10]:  # Show first 10
            print(f"  • {detail}")
        if len(result.details) > 10:
            print(f"  ... and {len(result.details) - 10} more")


def print_json_result(result):
    """Print result in JSON format."""
    import json

    output = {
        "passed": result.passed,
        "score": result.get_score(),
        "total_instructions": result.total_instructions,
        "verified_instructions": result.verified_instructions,
        "transformations": result.transformation_stats,
        "register_mismatches": len(result.register_mismatches),
        "flag_mismatches": len(result.flag_mismatches),
        "memory_mismatches": len(result.memory_mismatches),
        "details": result.details
    }

    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    sys.exit(main())
