#!/usr/bin/env python3
"""
Comprehensive test script to run byvalver on all .bin files in BIG_BIN directory
and collect detailed statistics and results.
"""

import subprocess
import os
import json
import time
from pathlib import Path
from datetime import datetime

# Configuration
BIG_BIN_DIR = os.path.expanduser("~/RUBBISH/BIG_BIN")
BYVALVER_BIN = "./bin/byvalver"
OUTPUT_DIR = "./test_results"
RESULTS_FILE = f"{OUTPUT_DIR}/byvalver_bins_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
SUMMARY_FILE = f"{OUTPUT_DIR}/bins_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

def ensure_output_dir():
    """Create output directory if it doesn't exist."""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

def get_bin_files():
    """Get all .bin files from BIG_BIN directory."""
    bin_files = []
    for file in sorted(os.listdir(BIG_BIN_DIR)):
        if file.endswith('.bin'):
            full_path = os.path.join(BIG_BIN_DIR, file)
            size = os.path.getsize(full_path)
            bin_files.append({
                'name': file,
                'path': full_path,
                'size': size
            })
    return bin_files

def run_byvalver(bin_path, timeout=120):
    """Run byvalver on a single binary and capture results."""
    result = {
        'success': False,
        'output': '',
        'error': '',
        'exit_code': None,
        'execution_time': 0,
        'timed_out': False
    }

    start_time = time.time()

    try:
        process = subprocess.run(
            [BYVALVER_BIN, bin_path],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        result['exit_code'] = process.returncode
        result['output'] = process.stdout
        result['error'] = process.stderr
        result['success'] = (process.returncode == 0)

    except subprocess.TimeoutExpired:
        result['timed_out'] = True
        result['error'] = f"Process timed out after {timeout} seconds"
    except Exception as e:
        result['error'] = str(e)

    result['execution_time'] = time.time() - start_time
    return result

def parse_byvalver_output(output, error):
    """Parse byvalver output to extract statistics."""
    stats = {
        'original_size': 0,
        'modified_size': 0,
        'instructions_disassembled': 0,
        'null_bytes_found': 0,
        'strategies_applied': [],
        'warnings': [],
        'has_nulls_eliminated': False
    }

    # Parse output
    for line in output.split('\n'):
        if 'Original shellcode size:' in line:
            stats['original_size'] = int(line.split(':')[1].strip())
        elif 'Modified shellcode size:' in line:
            stats['modified_size'] = int(line.split(':')[1].strip())

    # Parse error/debug output
    for line in error.split('\n'):
        if '[DISASM] Disassembled' in line:
            parts = line.split()
            if len(parts) >= 3:
                stats['instructions_disassembled'] = int(parts[2])

        if '[TRACE] Using strategy' in line:
            if "'" in line:
                strategy_name = line.split("'")[1]
                stats['strategies_applied'].append(strategy_name)

        if '[WARNING]' in line:
            warning = line.split('[WARNING]')[1].strip()[:100]
            stats['warnings'].append(warning)

        if 'has_null=1' in line:
            stats['null_bytes_found'] += 1

        if 'eliminated' in line.lower() or 'transformed' in line.lower():
            stats['has_nulls_eliminated'] = True

    return stats

def main():
    """Main test execution."""
    print("=" * 80)
    print("BYVALVER .BIN FILES COMPREHENSIVE ASSESSMENT")
    print("=" * 80)
    print()

    ensure_output_dir()

    # Get all binaries
    bin_files = get_bin_files()
    total_count = len(bin_files)
    total_size = sum(f['size'] for f in bin_files)

    print(f"Found {total_count} .bin files")
    print(f"Total size: {total_size / (1024*1024):.2f} MB")
    print(f"Output will be saved to: {RESULTS_FILE}")
    print()

    # Test results storage
    results = {
        'metadata': {
            'test_date': datetime.now().isoformat(),
            'total_files': total_count,
            'total_size_bytes': total_size,
            'byvalver_path': BYVALVER_BIN,
            'source_directory': BIG_BIN_DIR
        },
        'tests': []
    }

    # Statistics
    stats = {
        'total': total_count,
        'successful': 0,
        'failed': 0,
        'timed_out': 0,
        'errors': 0,
        'total_instructions': 0,
        'total_null_bytes_found': 0,
        'files_with_nulls': 0,
        'strategies_used': {}
    }

    # Run tests
    print("Starting tests...")
    print("-" * 80)

    for idx, bin_file in enumerate(bin_files, 1):
        name = bin_file['name']
        path = bin_file['path']
        size = bin_file['size']

        print(f"[{idx}/{total_count}] Testing: {name} ({size/1024:.1f} KB)...", end=' ', flush=True)

        # Run byvalver
        test_result = run_byvalver(path)

        # Parse output for statistics
        parsed_stats = parse_byvalver_output(test_result['output'], test_result['error'])

        # Update statistics
        if test_result['timed_out']:
            stats['timed_out'] += 1
            status = "TIMEOUT"
        elif test_result['success']:
            stats['successful'] += 1
            status = "SUCCESS"
        elif test_result['error']:
            stats['errors'] += 1
            status = "ERROR"
        else:
            stats['failed'] += 1
            status = "FAILED"

        # Aggregate stats
        stats['total_instructions'] += parsed_stats['instructions_disassembled']
        stats['total_null_bytes_found'] += parsed_stats['null_bytes_found']

        if parsed_stats['null_bytes_found'] > 0:
            stats['files_with_nulls'] += 1

        for strategy in parsed_stats['strategies_applied']:
            stats['strategies_used'][strategy] = stats['strategies_used'].get(strategy, 0) + 1

        print(f"{status} ({test_result['execution_time']:.3f}s, {parsed_stats['instructions_disassembled']} insns, {parsed_stats['null_bytes_found']} nulls)")

        # Store detailed result
        results['tests'].append({
            'index': idx,
            'filename': name,
            'path': path,
            'size_bytes': size,
            'status': status,
            'execution_time': test_result['execution_time'],
            'exit_code': test_result['exit_code'],
            'timed_out': test_result['timed_out'],
            'output': test_result['output'],
            'error': test_result['error'][:2000] if test_result['error'] else '',  # Truncate long outputs
            'parsed_stats': parsed_stats
        })

    # Save results
    print()
    print("-" * 80)
    print("Saving results...")

    results['statistics'] = stats

    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=2)

    # Generate summary report
    summary = []
    summary.append("=" * 80)
    summary.append("BYVALVER .BIN FILES ASSESSMENT SUMMARY")
    summary.append("=" * 80)
    summary.append("")
    summary.append(f"Test Date: {results['metadata']['test_date']}")
    summary.append(f"Total Files Tested: {total_count}")
    summary.append(f"Total Size: {total_size / (1024*1024):.2f} MB")
    summary.append("")
    summary.append("RESULTS:")
    summary.append(f"  Successful: {stats['successful']} ({stats['successful']/total_count*100:.1f}%)")
    summary.append(f"  Failed:     {stats['failed']} ({stats['failed']/total_count*100:.1f}%)")
    summary.append(f"  Errors:     {stats['errors']} ({stats['errors']/total_count*100:.1f}%)")
    summary.append(f"  Timeouts:   {stats['timed_out']} ({stats['timed_out']/total_count*100:.1f}%)")
    summary.append("")

    # Calculate averages
    avg_time = sum(t['execution_time'] for t in results['tests']) / total_count
    avg_insns = stats['total_instructions'] / total_count

    summary.append(f"Average Execution Time: {avg_time:.3f} seconds")
    summary.append(f"Total Instructions Disassembled: {stats['total_instructions']}")
    summary.append(f"Average Instructions per File: {avg_insns:.1f}")
    summary.append("")

    # Null byte statistics
    summary.append("NULL BYTE ANALYSIS:")
    summary.append(f"  Total null bytes found: {stats['total_null_bytes_found']}")
    summary.append(f"  Files with null bytes: {stats['files_with_nulls']} ({stats['files_with_nulls']/total_count*100:.1f}%)")
    summary.append("")

    # Strategy usage
    if stats['strategies_used']:
        summary.append("STRATEGIES APPLIED:")
        for strategy, count in sorted(stats['strategies_used'].items(), key=lambda x: -x[1]):
            summary.append(f"  {strategy}: {count} times")
        summary.append("")

    # List problematic files
    if stats['failed'] > 0 or stats['errors'] > 0 or stats['timed_out'] > 0:
        summary.append("ISSUES FOUND:")
        summary.append("")
        for test in results['tests']:
            if test['status'] in ['FAILED', 'ERROR', 'TIMEOUT']:
                summary.append(f"  {test['filename']}:")
                summary.append(f"    Status: {test['status']}")
                summary.append(f"    Time: {test['execution_time']:.3f}s")
                if test['error']:
                    summary.append(f"    Error: {test['error'][:200]}")
                summary.append("")

    summary.append("=" * 80)
    summary.append(f"Detailed results saved to: {RESULTS_FILE}")
    summary.append("=" * 80)

    summary_text = "\n".join(summary)

    # Save summary
    with open(SUMMARY_FILE, 'w') as f:
        f.write(summary_text)

    # Print summary
    print()
    print(summary_text)

if __name__ == "__main__":
    main()
