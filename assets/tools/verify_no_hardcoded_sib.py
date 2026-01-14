#!/usr/bin/env python3
"""
Verify that no strategy files contain hardcoded SIB byte 0x20
without proper profile checks

This tool scans all C source files in src/ directory to detect
hardcoded SIB byte 0x20 (SPACE character) that would fail for
http-whitespace and similar profiles.
"""

import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def check_file(filepath: Path) -> List[Dict]:
    """Check a single file for hardcoded SIB issues"""
    issues = []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
    except Exception as e:
        print(f"{YELLOW}Warning: Could not read {filepath}: {e}{RESET}")
        return issues

    # Pattern 1: Direct array initialization with 0x20 in SIB position
    # Examples: {0x8B, 0x04, 0x20}, {0x89, 0x04, 0x20}, {0x8D, 0x04, 0x20}
    pattern1 = re.compile(r'\{[^}]*0x04,\s*0x20[^}]*\}')

    # Pattern 2: Assignment to array index that looks like SIB byte
    # code[2] = 0x20;
    pattern2 = re.compile(r'\[\s*2\s*\]\s*=\s*0x20\s*;')

    # Pattern 3: Direct hex constant 0x20 in SIB context
    # Look for comments mentioning SIB nearby
    pattern3 = re.compile(r'SIB.*0x20|0x20.*SIB', re.IGNORECASE)

    for i, line in enumerate(lines, 1):
        # Skip comments
        if line.strip().startswith('//') or line.strip().startswith('*'):
            continue

        # Check for hardcoded SIB patterns
        if pattern1.search(line):
            # Check if there's a safety check nearby
            context_start = max(0, i-10)
            context_end = min(len(lines), i+5)
            context = '\n'.join(lines[context_start:context_end])

            # Look for evidence this is safe
            safe_indicators = [
                'profile_aware_sib',
                'generate_safe_',
                'select_sib_encoding',
                'is_sib_byte_safe',
                'FIXED',
                'profile-safe',
                'old code',
                'deprecated'
            ]

            is_safe = any(indicator in context for indicator in safe_indicators)

            if not is_safe:
                issues.append({
                    'line': i,
                    'content': line.strip(),
                    'type': 'Hardcoded SIB array initialization (0x04, 0x20)',
                    'severity': 'HIGH'
                })

        if pattern2.search(line):
            # Check context
            context_start = max(0, i-5)
            context_end = min(len(lines), i+5)
            context = '\n'.join(lines[context_start:context_end])

            if 'profile_aware_sib' not in context and 'generate_safe_' not in context:
                issues.append({
                    'line': i,
                    'content': line.strip(),
                    'type': 'Hardcoded SIB assignment',
                    'severity': 'MEDIUM'
                })

        if pattern3.search(line) and '0x20' in line:
            # Check if this is in a comment explaining the fix
            if not (line.strip().startswith('//') or line.strip().startswith('*')):
                context_start = max(0, i-3)
                context_end = min(len(lines), i+3)
                context = '\n'.join(lines[context_start:context_end])

                if 'generate_safe_' not in context:
                    issues.append({
                        'line': i,
                        'content': line.strip(),
                        'type': 'Potential hardcoded SIB in context',
                        'severity': 'LOW'
                    })

    return issues

def print_summary(all_issues: Dict[str, List[Dict]]):
    """Print summary of issues found"""
    total_files = len(all_issues)
    total_issues = sum(len(issues) for issues in all_issues.values())

    high_severity = sum(1 for issues in all_issues.values()
                       for issue in issues if issue['severity'] == 'HIGH')
    medium_severity = sum(1 for issues in all_issues.values()
                         for issue in issues if issue['severity'] == 'MEDIUM')
    low_severity = sum(1 for issues in all_issues.values()
                      for issue in issues if issue['severity'] == 'LOW')

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"Files with issues:     {RED}{total_files}{RESET}")
    print(f"Total issues:          {RED}{total_issues}{RESET}")
    print(f"  HIGH severity:       {RED}{high_severity}{RESET}")
    print(f"  MEDIUM severity:     {YELLOW}{medium_severity}{RESET}")
    print(f"  LOW severity:        {BLUE}{low_severity}{RESET}")
    print(f"{'='*70}\n")

def main():
    src_dir = Path('src')

    if not src_dir.exists():
        print(f"{RED}Error: src/ directory not found{RESET}")
        return 1

    print(f"{BLUE}Scanning for hardcoded SIB byte 0x20...{RESET}\n")

    all_issues = {}
    scanned_files = 0

    for c_file in sorted(src_dir.glob('*.c')):
        scanned_files += 1
        issues = check_file(c_file)
        if issues:
            all_issues[str(c_file)] = issues

    print(f"Scanned {scanned_files} C files\n")

    if not all_issues:
        print(f"{GREEN}✓ No hardcoded SIB byte 0x20 issues found!{RESET}")
        print(f"{GREEN}All strategies appear to use profile-aware SIB generation.{RESET}")
        return 0

    print(f"{RED}✗ Found hardcoded SIB byte 0x20 in the following files:{RESET}\n")

    for filepath, issues in sorted(all_issues.items()):
        print(f"{YELLOW}{filepath}:{RESET}")
        for issue in issues:
            severity_color = RED if issue['severity'] == 'HIGH' else (YELLOW if issue['severity'] == 'MEDIUM' else BLUE)
            print(f"  {severity_color}Line {issue['line']:4d} [{issue['severity']}]:{RESET} {issue['type']}")
            print(f"    {issue['content']}")
        print()

    print_summary(all_issues)

    print(f"{YELLOW}Recommendations:{RESET}")
    print(f"  1. Replace hardcoded SIB bytes with generate_safe_mov_reg_mem()")
    print(f"  2. Replace hardcoded SIB bytes with generate_safe_mov_mem_reg()")
    print(f"  3. Replace hardcoded SIB bytes with generate_safe_lea_reg_mem()")
    print(f"  4. Add #include \"profile_aware_sib.h\" to affected files")
    print(f"  5. Update size estimation functions to account for compensation bytes")
    print()

    return 1

if __name__ == '__main__':
    sys.exit(main())
