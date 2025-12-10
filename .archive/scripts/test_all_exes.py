#!/usr/bin/env python3
"""
Comprehensive test script to run byvalver on all executables in BIG_EXE directory
and collect detailed statistics and results.
"""

import subprocess
import os
import json
import time
from pathlib import Path
from datetime import datetime

# Configuration
BIG_EXE_DIR = os.path.expanduser("~/RUBBISH/BIG_EXE")
BYVALVER_BIN = "./bin/byvalver"
OUTPUT_DIR = "./test_results"
RESULTS_FILE = f"{OUTPUT_DIR}/byvalver_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
SUMMARY_FILE = f"{OUTPUT_DIR}/summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

def ensure_output_dir():
    """Create output directory if it doesn't exist."""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

def get_exe_files():
    """Get all .exe files from BIG_EXE directory."""
    exe_files = []
    for file in sorted(os.listdir(BIG_EXE_DIR)):
        if file.endswith('.exe'):
            full_path = os.path.join(BIG_EXE_DIR, file)
            size = os.path.getsize(full_path)
            exe_files.append({
                'name': file,
                'path': full_path,
                'size': size
            })
    return exe_files

def run_byvalver(exe_path, timeout=120):
    """Run byvalver on a single executable and capture results."""
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
            [BYVALVER_BIN, exe_path],
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

def parse_byvalver_output(output):
    """Parse byvalver output to extract statistics."""
    stats = {
        'null_bytes_found': False,
        'null_bytes_eliminated': False,
        'strategies_applied': [],
        'transformation_successful': False
    }

    # Look for key indicators in output
    if 'null byte' in output.lower() or '0x00' in output:
        stats['null_bytes_found'] = True

    if 'eliminated' in output.lower() or 'removed' in output.lower():
        stats['null_bytes_eliminated'] = True

    if 'success' in output.lower() or 'transformed' in output.lower():
        stats['transformation_successful'] = True

    # Extract strategy names if present
    for line in output.split('\n'):
        if 'strategy' in line.lower() or 'applying' in line.lower():
            stats['strategies_applied'].append(line.strip())

    return stats

def main():
    """Main test execution."""
    print("=" * 80)
    print("BYVALVER COMPREHENSIVE ASSESSMENT")
    print("=" * 80)
    print()

    ensure_output_dir()

    # Get all executables
    exe_files = get_exe_files()
    total_count = len(exe_files)
    total_size = sum(f['size'] for f in exe_files)

    print(f"Found {total_count} executables")
    print(f"Total size: {total_size / (1024*1024):.2f} MB")
    print(f"Output will be saved to: {RESULTS_FILE}")
    print()

    # Test results storage
    results = {
        'metadata': {
            'test_date': datetime.now().isoformat(),
            'total_executables': total_count,
            'total_size_bytes': total_size,
            'byvalver_path': BYVALVER_BIN
        },
        'tests': []
    }

    # Statistics
    stats = {
        'total': total_count,
        'successful': 0,
        'failed': 0,
        'timed_out': 0,
        'errors': 0
    }

    # Run tests
    print("Starting tests...")
    print("-" * 80)

    for idx, exe_file in enumerate(exe_files, 1):
        name = exe_file['name']
        path = exe_file['path']
        size = exe_file['size']

        print(f"[{idx}/{total_count}] Testing: {name} ({size/1024:.1f} KB)...", end=' ', flush=True)

        # Run byvalver
        test_result = run_byvalver(path)

        # Parse output for statistics
        parsed_stats = parse_byvalver_output(test_result['output'])

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

        print(f"{status} ({test_result['execution_time']:.2f}s)")

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
            'output': test_result['output'][:1000],  # Truncate long outputs
            'error': test_result['error'][:1000] if test_result['error'] else '',
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
    summary.append("BYVALVER ASSESSMENT SUMMARY")
    summary.append("=" * 80)
    summary.append("")
    summary.append(f"Test Date: {results['metadata']['test_date']}")
    summary.append(f"Total Executables Tested: {total_count}")
    summary.append(f"Total Size: {total_size / (1024*1024):.2f} MB")
    summary.append("")
    summary.append("RESULTS:")
    summary.append(f"  Successful: {stats['successful']} ({stats['successful']/total_count*100:.1f}%)")
    summary.append(f"  Failed:     {stats['failed']} ({stats['failed']/total_count*100:.1f}%)")
    summary.append(f"  Errors:     {stats['errors']} ({stats['errors']/total_count*100:.1f}%)")
    summary.append(f"  Timeouts:   {stats['timed_out']} ({stats['timed_out']/total_count*100:.1f}%)")
    summary.append("")

    # Calculate average execution time
    avg_time = sum(t['execution_time'] for t in results['tests']) / total_count
    summary.append(f"Average Execution Time: {avg_time:.2f} seconds")
    summary.append("")

    # List failed tests
    if stats['failed'] > 0 or stats['errors'] > 0 or stats['timed_out'] > 0:
        summary.append("ISSUES FOUND:")
        summary.append("")
        for test in results['tests']:
            if test['status'] in ['FAILED', 'ERROR', 'TIMEOUT']:
                summary.append(f"  {test['filename']}:")
                summary.append(f"    Status: {test['status']}")
                summary.append(f"    Time: {test['execution_time']:.2f}s")
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
