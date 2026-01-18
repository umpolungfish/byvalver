# verify_denulled.py Update Summary (v3.0.3)

## Overview
Updated `verify_denulled.py` to support bad-byte profiles matching byvalver's `--profile` option, providing a consistent verification workflow for the generic bad-byte elimination framework.

## Changes Made

### 1. Profile Support
- **Added 13 bad-byte profiles** matching those in `src/badbyte_profiles.h`:
  - `null-only` (1 byte) - Trivial
  - `http-newline` (3 bytes) - Low difficulty
  - `http-whitespace` (5 bytes) - Low difficulty
  - `url-safe` (23 bytes) - Medium difficulty
  - `sql-injection` (5 bytes) - Medium difficulty
  - `xml-html` (6 bytes) - Medium difficulty
  - `json-string` (34 bytes) - Medium difficulty
  - `format-string` (3 bytes) - Medium difficulty
  - `buffer-overflow` (5 bytes) - Medium difficulty
  - `command-injection` (20 bytes) - Medium difficulty
  - `ldap-injection` (5 bytes) - Medium difficulty
  - `printable-only` (161 bytes) - High difficulty
  - `alphanumeric-only` (194 bytes) - Extreme difficulty

### 2. New Command-Line Options
- `--profile NAME`: Use a predefined bad-byte profile
- `--list-profiles`: Display all available profiles with descriptions, contexts, and difficulty ratings

### 3. Enhanced Functionality
- **Profile listing** with visual difficulty indicators (█ bars)
- **Profile details** showing description, context, and byte counts
- **Automatic profile detection** when using `--profile` option
- **Backward compatibility** maintained - existing `--bad-bytes` option still works

### 4. Bug Fixes
- **Fixed consecutive bad byte counting**: Previously, consecutive bad bytes (e.g., `\x00\x0a`) were counted as a single bad byte. Now each byte is counted individually with correct position tracking.

## Usage Examples

### List Available Profiles
```bash
python3 verify_denulled.py --list-profiles
```

### Verify Using Profiles
```bash
# Verify with HTTP newline profile
python3 verify_denulled.py --profile http-newline input.bin output.bin

# Verify with SQL injection profile
python3 verify_denulled.py --profile sql-injection payload.bin clean.bin

# Verify with alphanumeric-only profile
python3 verify_denulled.py --profile alphanumeric-only test.bin
```

### Verify Using Manual Specification (backward compatible)
```bash
# Manual bad-byte specification (still works as before)
python3 verify_denulled.py --bad-bytes "00,0a,0d" input.bin output.bin

# Default null-byte only
python3 verify_denulled.py input.bin output.bin
```

### Batch Processing with Profiles
```bash
# Batch verify with profile
python3 verify_denulled.py --profile http-whitespace -r input_dir/ output_dir/

# Batch verify with manual specification
python3 verify_denulled.py --bad-bytes "00,0a" -r input_dir/ output_dir/
```

## Workflow Integration

The updated tool now integrates seamlessly with byvalver's generic bad-byte elimination:

```bash
# Process with byvalver using profile
byvalver --profile http-newline input.bin output.bin

# Verify with matching profile
python3 verify_denulled.py --profile http-newline input.bin output.bin
```

## Technical Details

### Profile Definitions
Profiles are defined in `BADCHAR_PROFILES` dictionary at the top of `verify_denulled.py`, mirroring the C definitions in `src/badbyte_profiles.h` to ensure consistency.

### Profile Precedence
When both `--profile` and `--bad-bytes` are specified, `--profile` takes precedence (with a warning in the help text).

### Profile Validation
The tool validates profile names and provides helpful error messages if an unknown profile is specified, suggesting the use of `--list-profiles`.

## Compatibility

- **Fully backward compatible** - existing scripts using `--bad-bytes` continue to work
- **API stable** - all existing functions maintain their signatures
- **Python 3.6+** - no new dependencies required

## Testing

Verified functionality with:
- All 13 profiles listed correctly
- Profile-based verification works with test shellcode
- Manual `--bad-bytes` specification still works
- Batch processing works with both profiles and manual specification
- Consecutive bad byte bug fix validated

## Files Modified

- `verify_denulled.py` - Updated with profile support and bug fixes

## Version History

- **v3.0.3** (2025-12-19): Added profile support and fixed consecutive bad byte counting bug
- **v3.0** (2025): Added generic bad byte elimination support
- **v2.x**: Original null-byte only verification
