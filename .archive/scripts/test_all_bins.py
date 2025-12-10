#!/usr/bin/env python3
"""
Comprehensive test script to run byvalver on all .bin files in BIG_BIN directory
and collect detailed statistics and results for non-biphasic mode only.
"""

import subprocess
import os
import json
import time
from pathlib import Path
from datetime import datetime
import tempfile

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

def analyze_shellcode_for_nulls(shellcode_data):
    """Analyze shellcode data to count null bytes."""
    null_count = 0
    for byte in shellcode_data:
        if byte == 0:
            null_count += 1
    return null_count

def run_byvalver(input_path, output_path, args=None, timeout=120):
    """Run byvalver on a single binary and capture results."""
    result = {
        'success': False,
        'output': '',
        'error': '',
        'exit_code': None,
        'execution_time': 0,
        'timed_out': False,
        'output_data': None,
        'nulls_remaining': -1,  # -1 means not determined yet
        'nulls_in_original': -1
    }

    start_time = time.time()

    # Prepare command
    cmd = [BYVALVER_BIN]
    if args:
        cmd.extend(args)
    # Use only input path and explicitly specify output with -o flag to avoid confusion
    cmd.extend([input_path, "-o", output_path])

    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        result['exit_code'] = process.returncode
        result['output'] = process.stdout
        result['error'] = process.stderr

        # Check if process exited successfully
        if process.returncode == 0:
            # Read the output file to check for nulls
            if os.path.exists(output_path):
                with open(output_path, 'rb') as f:
                    result['output_data'] = f.read()
                    result['nulls_remaining'] = analyze_shellcode_for_nulls(result['output_data'])

                # Also analyze original file for comparison
                with open(input_path, 'rb') as f:
                    original_data = f.read()
                    result['nulls_in_original'] = analyze_shellcode_for_nulls(original_data)

                # Determine true success - process must exit 0 AND eliminate all nulls
                result['success'] = (process.returncode == 0 and result['nulls_remaining'] == 0)
            else:
                # Output file wasn't created, so it's not successful
                result['success'] = False
        else:
            result['success'] = False

    except subprocess.TimeoutExpired:
        result['timed_out'] = True
        result['error'] = f"Process timed out after {timeout} seconds"
    except Exception as e:
        result['error'] = str(e)
        result['success'] = False

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
                if strategy_name not in stats['strategies_applied']:
                    stats['strategies_applied'].append(strategy_name)

        if '[WARNING]' in line:
            warning = line.split('[WARNING]')[1].strip()[:100]
            if warning not in stats['warnings']:
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
    print("Testing non-biphasic mode only")
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

        print(f"[{idx}/{total_count}] Testing: {name} ({size/1024:.1f} KB)")

        file_result = {
            'index': idx,
            'filename': name,
            'path': path,
            'size_bytes': size,
            'test': None
        }

        # Test without biphasic mode
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as out:
            out_path = out.name

        print(f"  Testing non-biphasic mode...", end=' ', flush=True)
        result = run_byvalver(path, out_path)

        # Parse output for statistics
        parsed_stats = parse_byvalver_output(result['output'], result['error'])
        result['parsed_stats'] = parsed_stats

        # Determine status for test
        if result['timed_out']:
            status = "TIMEOUT"
            stats['timed_out'] += 1
        elif result['success']:
            status = "SUCCESS"  # Process completed AND nulls eliminated
            stats['successful'] += 1
        elif result['exit_code'] == 0 and result['nulls_remaining'] > 0:
            status = "NULLS_REMAINING"  # Process completed but nulls remain
            stats['failed'] += 1
        elif result['exit_code'] != 0:
            status = "ERROR"
            stats['errors'] += 1
        else:
            status = "FAILED"
            stats['failed'] += 1

        time_taken = result['execution_time']
        nulls = result['nulls_remaining']
        original_nulls = result['nulls_in_original']
        instructions = parsed_stats['instructions_disassembled']

        print(f"{status} ({time_taken:.3f}s, {instructions} insns, {original_nulls}->{nulls} nulls)")

        # Update stats
        stats['total_instructions'] += instructions
        stats['total_null_bytes_found'] += nulls

        if nulls > 0:
            stats['files_with_nulls'] += 1

        for strategy in parsed_stats['strategies_applied']:
            stats['strategies_used'][strategy] = stats['strategies_used'].get(strategy, 0) + 1

        # Clean up output file
        try:
            os.unlink(out_path)
        except:
            pass

        # Store detailed results
        file_result['test'] = {
            'status': status,
            'execution_time': time_taken,
            'exit_code': result['exit_code'],
            'timed_out': result['timed_out'],
            'output': result['output'],
            'error': result['error'][:2000] if result['error'] else '',
            'nulls_remaining': nulls,
            'nulls_in_original': original_nulls,
            'parsed_stats': parsed_stats
        }

        results['tests'].append(file_result)

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
    summary.append("Testing non-biphasic mode only")
    summary.append("=" * 80)
    summary.append("")
    summary.append(f"Test Date: {results['metadata']['test_date']}")
    summary.append(f"Total Files Tested: {total_count}")
    summary.append(f"Total Size: {total_size / (1024*1024):.2f} MB")
    summary.append("")
    summary.append("NON-BIPHASIC MODE RESULTS:")
    summary.append(f"  Successful (all nulls eliminated): {stats['successful']} ({stats['successful']/total_count*100:.1f}%)")
    summary.append(f"  Failed (nulls remain):             {stats['failed']} ({stats['failed']/total_count*100:.1f}%)")
    summary.append(f"  Errors:                            {stats['errors']} ({stats['errors']/total_count*100:.1f}%)")
    summary.append(f"  Timeouts:                          {stats['timed_out']} ({stats['timed_out']/total_count*100:.1f}%)")
    summary.append("")

    # Calculate averages
    avg_time = sum(t['test']['execution_time'] for t in results['tests']) / total_count

    summary.append(f"Average Execution Time:              {avg_time:.3f} seconds")
    summary.append("")

    # Null byte statistics
    summary.append("NULL BYTE ANALYSIS:")
    summary.append(f"  Total null bytes found:            {stats['total_null_bytes_found']}")
    summary.append(f"  Files with nulls remaining:        {stats['files_with_nulls']} ({stats['files_with_nulls']/total_count*100:.1f}%)")
    summary.append("")

    # Strategy usage
    summary.append("STRATEGIES APPLIED:")
    for strategy, count in sorted(stats['strategies_used'].items(), key=lambda x: -x[1])[:20]:  # Top 20
        summary.append(f"  {strategy}: {count} times")
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