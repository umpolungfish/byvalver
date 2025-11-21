#!/usr/bin/env python3
import subprocess
import glob

processed_files = glob.glob('.binzz/*_processed.bin')
success_count = 0

for f in processed_files:
    result = subprocess.run(['python3', 'verify_nulls.py', f],
                          capture_output=True, text=True)
    if 'SUCCESS' in result.stdout or 'SUCCESS' in result.stderr:
        success_count += 1

print(f"Total processed files: {len(processed_files)}")
print(f"Null-free files: {success_count}")
if len(processed_files) > 0:
    print(f"Success rate: {success_count*100//len(processed_files)}%")
