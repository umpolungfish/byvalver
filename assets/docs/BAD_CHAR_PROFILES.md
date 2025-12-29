# Bad-Character Profiles Guide

**Version**: 3.0+
**Last Updated**: 2025-12-17

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Profile Reference](#profile-reference)
4. [Usage Examples](#usage-examples)
5. [Creating Custom Profiles](#creating-custom-profiles)
6. [Compatibility Matrix](#compatibility-matrix)
7. [Performance Considerations](#performance-considerations)
8. [Troubleshooting](#troubleshooting)

---

## Overview

### What Are Bad-Character Profiles?

Bad-character profiles are pre-configured sets of bytes that byvalver will eliminate from your shellcode. Instead of manually specifying hex values with `--bad-chars`, you can use profile names that match common exploit scenarios.

### Why Use Profiles?

- **Convenience**: Single flag instead of long hex strings
- **Accuracy**: Pre-tested character sets for specific contexts
- **Best Practices**: Encoded domain knowledge from real-world exploits
- **Consistency**: Standardized configurations across team/projects

### Architecture

```
User Input:  --profile http-newline
     ↓
Profile DB:  Matches "http-newline" → [0x00, 0x0A, 0x0D]
     ↓
Config:      Loads bad_char_config_t with bitmap
     ↓
Pipeline:    All strategies respect these bad characters
     ↓
Output:      Shellcode free of 0x00, 0x0A, 0x0D
```

---

## Quick Start

### List Available Profiles

```bash
$ ./bin/byvalver --list-profiles
```

Output:
```
Available Bad-Character Profiles:

  null-only             [█░░░░]  (1 bad chars)
      Eliminate NULL bytes only (classic denullification)
      Context: Most buffer overflows, string-based exploits

  http-newline          [██░░░]  (3 bad chars)
      Eliminate NULL, LF, and CR (line terminators)
      Context: HTTP headers, FTP, SMTP, line-based protocols

  alphanumeric-only     [█████]  (194 bad chars)
      Allow only alphanumeric chars (0-9, A-Z, a-z)
      Context: Strict input filters, alphanumeric-only shellcode

Difficulty Legend: [█░░░░]=Trivial  [███░░]=Medium  [█████]=Extreme
```

### Use a Profile

```bash
# Instead of:
$ ./bin/byvalver --bad-chars "00,0a,0d" input.bin output.bin

# Use:
$ ./bin/byvalver --profile http-newline input.bin output.bin
```

---

## Profile Reference

### 1. **null-only** (Default)

**Difficulty**: ░░░░░ Trivial
**Bad Characters**: `0x00` (1 byte)

**Context**:
- Classic buffer overflows
- String-based exploits (strcpy, sprintf, etc.)
- Most common scenario (90%+ of cases)

**Strategies**:
- XOR-based register zeroing
- Arithmetic construction
- PUSH/POP immediate alternatives

**Example**:
```bash
./bin/byvalver --profile null-only shellcode.bin output.bin
# Equivalent to: ./bin/byvalver shellcode.bin output.bin (default)
```

**Success Rate**: ~95% (highly reliable)

---

### 2. **http-newline**

**Difficulty**: █░░░░ Low
**Bad Characters**: `0x00, 0x0A, 0x0D` (3 bytes)

**Context**:
- HTTP headers (Host, User-Agent, Cookie, etc.)
- Line-based protocols (FTP, SMTP, POP3, IMAP)
- Text-based network protocols
- Anywhere CRLF (`\r\n`) terminates input

**Why These Characters**:
- `0x00`: String terminator
- `0x0A`: Line Feed (LF, `\n`)
- `0x0D`: Carriage Return (CR, `\r`)

**Example**:
```bash
# Inject into HTTP Cookie header
./bin/byvalver --profile http-newline exploit.bin http_payload.bin
```

**Use Cases**:
- HTTP parameter pollution
- HTTP request smuggling
- FTP command injection
- SMTP command injection

**Success Rate**: ~92%

---

### 3. **http-whitespace**

**Difficulty**: █░░░░ Low
**Bad Characters**: `0x00, 0x09, 0x0A, 0x0D, 0x20` (5 bytes)

**Context**:
- HTTP parameters with space restrictions
- Command-line argument injection
- Shell command injection
- Contexts where whitespace is filtered

**Why These Characters**:
- `0x00`: NULL
- `0x09`: Horizontal Tab (`\t`)
- `0x0A`: Line Feed (`\n`)
- `0x0D`: Carriage Return (`\r`)
- `0x20`: Space (` `)

**Example**:
```bash
# Inject into query parameter that filters whitespace
./bin/byvalver --profile http-whitespace payload.bin filtered_payload.bin
```

**Success Rate**: ~90%

---

### 4. **url-safe**

**Difficulty**: ███░░ Medium
**Bad Characters**: 23 bytes

**Full Set**:
```
0x00 (NULL), 0x20 (Space), 0x22 ("), 0x23 (#), 0x24 ($),
0x25 (%), 0x26 (&), 0x2B (+), 0x2C (,), 0x2F (/),
0x3A (:), 0x3B (;), 0x3C (<), 0x3D (=), 0x3E (>),
0x3F (?), 0x40 (@), 0x5B ([), 0x5D (]), 0x5C (\),
0x7B ({), 0x7D (}), 0x7C (|)
```

**Context**:
- URL query parameters (`?param=value`)
- GET request parameters
- URL paths
- Anywhere URL encoding is required

**Why These Characters**:
All are reserved or unsafe in URLs per RFC 3986

**Example**:
```bash
# Payload for GET parameter injection
./bin/byvalver --profile url-safe shellcode.bin url_encoded_payload.bin
```

**Use Cases**:
- XSS in URL parameters
- Open redirect exploitation
- URL-based injection attacks

**Success Rate**: ~75% (many restrictions make this challenging)

---

### 5. **sql-injection**

**Difficulty**: ███░░ Medium
**Bad Characters**: `0x00, 0x22, 0x27, 0x2D, 0x3B` (5 bytes)

**Context**:
- SQL injection via string literals
- Database query injection
- ORM injection vulnerabilities

**Why These Characters**:
- `0x00`: NULL terminator
- `0x22`: Double quote (`"`)
- `0x27`: Single quote (`'`) - most important!
- `0x2D`: Hyphen/dash (`--`) - SQL comments
- `0x3B`: Semicolon (`;`) - statement terminator

**Example**:
```bash
# Shellcode injection in SQL context
./bin/byvalver --profile sql-injection payload.bin sql_safe_payload.bin
```

**Typical Scenario**:
```sql
-- Vulnerable query
SELECT * FROM users WHERE username = '$input';

-- Without elimination (fails):
' OR '1'='1'; -- shellcode_with_quotes

-- With sql-injection profile (works):
... shellcode_without_quotes ...
```

**Success Rate**: ~88%

---

### 6. **xml-html**

**Difficulty**: ███░░ Medium
**Bad Characters**: `0x00, 0x22, 0x26, 0x27, 0x3C, 0x3E` (6 bytes)

**Context**:
- XML injection
- HTML injection
- XSS payloads
- SVG injection
- XML entity expansion attacks

**Why These Characters**:
- `0x00`: NULL
- `0x22`: Double quote (`"`)
- `0x26`: Ampersand (`&`) - entity prefix
- `0x27`: Single quote (`'`)
- `0x3C`: Less than (`<`) - tag start
- `0x3E`: Greater than (`>`) - tag end

**Example**:
```bash
# XSS payload injection
./bin/byvalver --profile xml-html xss_payload.bin safe_xss.bin
```

**Use Cases**:
- Stored XSS
- Reflected XSS
- XML external entity (XXE) attacks
- SVG-based exploits

**Success Rate**: ~85%

---

### 7. **json-string**

**Difficulty**: ███░░ Medium
**Bad Characters**: 34 bytes (all control characters + `"` + `\`)

**Full Set**:
```
0x00-0x1F (all control characters)
0x22 (")
0x5C (\)
```

**Context**:
- JSON API injection
- JavaScript string contexts
- JSON Web Token (JWT) manipulation
- RESTful API exploitation

**Why These Characters**:
- Control chars: Invalid in JSON strings
- `"`: String delimiter
- `\`: Escape sequence initiator

**Example**:
```bash
# Payload for JSON API
./bin/byvalver --profile json-string api_payload.bin json_safe.bin
```

**Typical Scenario**:
```json
// Vulnerable API endpoint
{"username": "$input", "role": "user"}

// Shellcode must not break JSON syntax
```

**Success Rate**: ~80%

---

### 8. **format-string**

**Difficulty**: ███░░ Medium-High
**Bad Characters**: `0x00, 0x20, 0x25` (3 bytes)

**Context**:
- Format string vulnerabilities (printf, sprintf, etc.)
- Format string arbitrary write exploits

**Why These Characters**:
- `0x00`: NULL terminator
- `0x20`: Space (sometimes filtered)
- `0x25`: Percent (`%`) - format specifier

**Example**:
```bash
# Shellcode for format string exploit
./bin/byvalver --profile format-string fsb_payload.bin safe_fsb.bin
```

**Special Considerations**:
- Percent sign (`%`) is critical to avoid
- May need to chain with format string primitives
- Often combined with stack manipulation

**Success Rate**: ~82%

---

### 9. **buffer-overflow**

**Difficulty**: ███░░ Medium
**Bad Characters**: `0x00, 0x09, 0x0A, 0x0D, 0x20` (5 bytes)

**Context**:
- Stack buffer overflows with character filtering
- Heap buffer overflows
- Buffer overflows in text processing functions

**Why These Characters**:
Common characters filtered by vulnerable functions like `gets()`, `scanf()`, etc.

**Example**:
```bash
# Classic buffer overflow scenario
./bin/byvalver --profile buffer-overflow exploit.bin bof_payload.bin
```

**Success Rate**: ~90%

---

### 10. **command-injection**

**Difficulty**: ███░░ Medium
**Bad Characters**: 20 bytes (shell metacharacters)

**Full Set**:
```
0x00 (NULL), 0x09 (Tab), 0x0A (LF), 0x0D (CR), 0x20 (Space),
0x21 (!), 0x22 ("), 0x24 ($), 0x26 (&), 0x27 ('),
0x28 ((), 0x29 ()), 0x2A (*), 0x2F (/), 0x3B (;),
0x3C (<), 0x3E (>), 0x5C (\), 0x60 (`), 0x7C (|)
```

**Context**:
- Shell command injection
- `system()`, `exec()`, `popen()` calls
- OS command execution vulnerabilities

**Why These Characters**:
All are shell metacharacters that could break command syntax

**Example**:
```bash
# Payload for command injection
./bin/byvalver --profile command-injection cmd_payload.bin safe_cmd.bin
```

**Success Rate**: ~78%

---

### 11. **ldap-injection**

**Difficulty**: ███░░ Medium
**Bad Characters**: `0x00, 0x28, 0x29, 0x2A, 0x5C` (5 bytes)

**Context**:
- LDAP injection attacks
- Active Directory exploitation
- Directory service queries

**Why These Characters**:
- `0x00`: NULL
- `0x28`: Left paren `(`
- `0x29`: Right paren `)`
- `0x2A`: Asterisk `*` (wildcard)
- `0x5C`: Backslash `\` (escape)

**Example**:
```bash
# LDAP injection payload
./bin/byvalver --profile ldap-injection ldap_payload.bin safe_ldap.bin
```

**Success Rate**: ~86%

---

### 12. **printable-only**

**Difficulty**: ████░ High
**Bad Characters**: 161 bytes (all non-printable)

**Allowed Characters**: Only `0x20-0x7E` (printable ASCII)

**Context**:
- Text-based protocols requiring printable chars
- Some WAF/IDS evasion scenarios
- Email-based exploits (MIME, SMTP DATA)
- Printable shellcode requirements

**Eliminated**:
- Control characters: `0x00-0x1F`
- DEL: `0x7F`
- Extended ASCII: `0x80-0xFF`

**Example**:
```bash
# Generate printable-only shellcode
./bin/byvalver --profile printable-only payload.bin printable.bin
```

**Challenges**:
- Very restrictive (only 95 characters available)
- Many x86 opcodes are non-printable
- Often requires encoding/decoder stub
- Size overhead can be significant (+150-300%)

**Success Rate**: ~65% (difficult profile)

**Recommended Approach**:
Often better to use an encoder with a printable decoder stub

---

### 13. **alphanumeric-only** ⚠️

**Difficulty**: █████ **EXTREME**
**Bad Characters**: 194 bytes (everything except alphanumeric)

**Allowed Characters**: Only `0-9, A-Z, a-z` (62 bytes)

**Context**:
- Extremely strict input filters
- Alphanumeric shellcode challenges (CTF)
- Some WAF bypass scenarios
- Ultra-restrictive application firewalls

**Eliminated**:
Everything except:
- Digits: `0x30-0x39` (0-9)
- Uppercase: `0x41-0x5A` (A-Z)
- Lowercase: `0x61-0x7A` (a-z)

**Example**:
```bash
# WARNING: Extreme difficulty
./bin/byvalver --profile alphanumeric-only payload.bin alphanum.bin
```

**Challenges**:
- **EXTREMELY DIFFICULT** (only 24% of byte space available)
- Most x86 instructions are NOT alphanumeric
- Requires advanced techniques:
  - Venetian shellcode
  - Self-modifying code
  - Complex arithmetic construction
  - Polymorphic decoders
- Size explosion (often 3-10x original size)

**Success Rate**: ~30-40% (many payloads cannot be converted)

**Recommended Approach**:
1. Start with small, simple shellcode
2. Consider using an alphanumeric encoder/decoder
3. May require multi-stage decoding
4. Test thoroughly - highly fragile

**References**:
- "Alphanumeric Shellcode" by rix
- "Building IA32 'Unicode-Proof' Shellcodes" by obscou

---

## Usage Examples

### Basic Profile Usage

```bash
# List all profiles
./bin/byvalver --list-profiles

# Use a specific profile
./bin/byvalver --profile http-newline input.bin output.bin

# Verbose output with profile
./bin/byvalver --profile sql-injection --verbose input.bin output.bin
```

### Combining with Other Options

```bash
# Profile + Biphasic processing
./bin/byvalver --profile url-safe --biphasic payload.bin output.bin

# Profile + XOR encoding
./bin/byvalver --profile http-newline --xor-encode 0xDEADBEEF input.bin output.bin

# Profile + ML strategy selection
./bin/byvalver --profile json-string --ml payload.bin output.bin

# Profile + Output format
./bin/byvalver --profile command-injection --format c input.bin output.c
```

### Batch Processing with Profiles

```bash
# Process entire directory with profile
./bin/byvalver -r --profile http-newline shellcodes/ output/

# Batch with pattern matching
./bin/byvalver -r --pattern "*.bin" --profile sql-injection input/ output/
```

### Validation

```bash
# Process and validate
./bin/byvalver --profile http-newline --validate input.bin output.bin

# Show statistics
./bin/byvalver --profile url-safe --stats input.bin output.bin
```

---

## Creating Custom Profiles

### Method 1: Using `--bad-chars` Directly

If you have a one-off bad-character set:

```bash
# Custom set: eliminate 0x00, 0x41 ('A'), 0x42 ('B')
./bin/byvalver --bad-chars "00,41,42" input.bin output.bin
```

### Method 2: Adding to Profile Database

To create a permanent profile, edit `src/badchar_profiles.h`:

```c
// 1. Define the character array
static const uint8_t PROFILE_CUSTOM_CHARS[] = {
    0x00,  // NULL
    0x41,  // 'A'
    0x42,  // 'B'
    // ... your characters
};

// 2. Add to BADCHAR_PROFILES array
{
    .name = "custom-profile",
    .description = "My custom bad-character set",
    .context = "Specific application vulnerability",
    .bad_chars = PROFILE_CUSTOM_CHARS,
    .bad_char_count = sizeof(PROFILE_CUSTOM_CHARS),
    .examples = "byvalver --profile custom-profile input.bin output.bin",
    .difficulty = DIFFICULTY_MEDIUM
}
```

Then recompile:
```bash
make clean && make
```

---

## Compatibility Matrix

### Profile Compatibility with Processing Modes

| Profile           | Biphasic | PIC | ML | XOR Encode | Notes |
|-------------------|----------|-----|----|-----------:|-------|
| null-only         | ✅       | ✅  | ✅ | ✅         | Full compatibility |
| http-newline      | ✅       | ✅  | ✅ | ✅         | Full compatibility |
| http-whitespace   | ✅       | ✅  | ✅ | ⚠️         | XOR decoder may contain whitespace |
| url-safe          | ✅       | ⚠️  | ✅ | ⚠️         | High restrictions |
| sql-injection     | ✅       | ✅  | ✅ | ✅         | Full compatibility |
| xml-html          | ✅       | ✅  | ✅ | ✅         | Full compatibility |
| json-string       | ✅       | ✅  | ✅ | ⚠️         | Decoder may have control chars |
| format-string     | ✅       | ✅  | ✅ | ✅         | Full compatibility |
| buffer-overflow   | ✅       | ✅  | ✅ | ✅         | Full compatibility |
| command-injection | ✅       | ⚠️  | ✅ | ⚠️         | Many restrictions |
| ldap-injection    | ✅       | ✅  | ✅ | ✅         | Full compatibility |
| printable-only    | ⚠️       | ⚠️  | ✅ | ⚠️         | Very restrictive |
| alphanumeric-only | ⚠️       | ⚠️  | ⚠️ | ⚠️         | Extremely restrictive |

**Legend**:
- ✅ Fully compatible
- ⚠️ May have issues, test carefully
- ❌ Not recommended

---

## Performance Considerations

### Size Overhead by Profile

| Profile           | Avg Overhead | Range      | Notes |
|-------------------|--------------|------------|-------|
| null-only         | +15%         | +5-30%     | Baseline |
| http-newline      | +20%         | +10-40%    | Moderate |
| http-whitespace   | +25%         | +15-50%    | More challenging |
| url-safe          | +80%         | +50-150%   | High restrictions |
| sql-injection     | +22%         | +10-45%    | Similar to http-newline |
| xml-html          | +25%         | +12-50%    | Moderate |
| json-string       | +40%         | +20-80%    | Many control chars |
| format-string     | +18%         | +8-35%     | Moderate |
| buffer-overflow   | +25%         | +15-50%    | Similar to http-whitespace |
| command-injection | +60%         | +30-120%   | Many restrictions |
| ldap-injection    | +22%         | +10-45%    | Moderate |
| printable-only    | +200%        | +100-400%  | Very restrictive |
| alphanumeric-only | +500%        | +200-1000% | Extreme, often fails |

**Notes**:
- Overhead depends heavily on original shellcode structure
- More bad characters = more transformations = larger output
- Complex shellcode suffers more overhead
- Simple shellcode (few instructions) has lower overhead

### Processing Time

| Profile           | Relative Speed | Notes |
|-------------------|----------------|-------|
| null-only         | 1.0x (baseline)| Fastest |
| http-newline      | ~1.2x          | Slightly slower |
| url-safe          | ~2.5x          | Much slower (many chars to check) |
| printable-only    | ~4.0x          | Very slow (many transformations) |
| alphanumeric-only | ~8.0x          | Extremely slow (often iterative) |

---

## Troubleshooting

### Issue: Profile Not Found

**Symptom**:
```
Error: Unknown profile: my-profile
Use --list-profiles to see available profiles.
```

**Solution**:
- Check spelling: profile names are case-sensitive and use hyphens
- List available profiles: `./bin/byvalver --list-profiles`
- Ensure you've recompiled if you added a custom profile

---

### Issue: Output Still Contains Bad Characters

**Symptom**:
```
WARNING: Output shellcode still contains bad characters!
Bad character 0x0a found at offset 0x42 (from instruction: mov eax, 0x0a)
```

**Causes**:
1. **Strategy Gap**: No strategy can handle this specific instruction pattern
2. **Multi-pass Issue**: One strategy introduces chars another eliminates
3. **Decoder Stub**: If using encoding, decoder may violate constraints

**Solutions**:
1. Check if this instruction pattern is documented as unsupported
2. Try different processing modes: `--biphasic`, `--ml`
3. Try encoding with `--xor-encode`
4. Consider breaking shellcode into smaller pieces
5. Report as issue with example shellcode

---

### Issue: Size Explosion

**Symptom**:
Output is 10x larger than input

**Causes**:
- Using high-difficulty profile (printable-only, alphanumeric-only)
- Shellcode has many instructions requiring transformation
- Recursive transformations creating overhead

**Solutions**:
1. Start with simpler shellcode
2. Use encoding approach instead: `--xor-encode`
3. Consider relaxing constraints if possible
4. Optimize original shellcode to use fewer "problem" instructions

---

### Issue: Alphanumeric-Only Fails

**Symptom**:
```
Error: Could not eliminate all bad characters
Failed on instruction: syscall
```

**Explanation**:
Alphanumeric-only is **extremely difficult**. Many instructions cannot be represented alphanumerically.

**Solutions**:
1. This is expected for complex shellcode
2. Use smaller, simpler shellcode
3. Consider alphanumeric encoder/decoder approach
4. May require manual shellcode crafting
5. Research venetian shellcode techniques

---

### Issue: Profile Too Restrictive

**Symptom**:
Many transformation failures, large overhead

**Solutions**:
1. Verify you're using the right profile for your context
2. Consider custom profile with fewer restrictions
3. Use encoding with compliant decoder
4. Test with simpler shellcode first

---

## Advanced Topics

### Profile Priority

If multiple options conflict:
```bash
# --profile takes precedence over --bad-chars
./bin/byvalver --bad-chars "00" --profile http-newline ...
# Result: Uses http-newline profile (0x00, 0x0A, 0x0D)
```

### Profile Validation

To verify a profile's character set:
```bash
# List profiles (shows character counts)
./bin/byvalver --list-profiles

# Verbose mode shows which profile is active
./bin/byvalver --profile sql-injection --verbose input.bin output.bin
```

### Encoding vs. Inline Transformation

**When to use profiles (inline transformation)**:
- Few bad characters (<10)
- Moderate size overhead acceptable
- Need to preserve overall shellcode structure

**When to use encoding**:
- Many bad characters (>20)
- Size overhead is critical
- Decoder stub can meet constraints

**Hybrid approach**:
```bash
# Use profile to minimize bad chars, then encode the rest
./bin/byvalver --profile http-whitespace --xor-encode 0xAA input.bin output.bin
```

---

## References

### Internal Documentation
- [DENULL_STRATS.md](./DENULL_STRATS.md) - Denullification strategies
- [OBFUSCATION_STRATS.md](./OBFUSCATION_STRATS.md) - Obfuscation techniques
- [README.md](../README.md) - Main documentation

### External Resources
- RFC 3986 (URI Generic Syntax) - URL encoding
- OWASP Testing Guide - Injection attacks
- "Alphanumeric Shellcode" by rix
- "Building IA32 'Unicode-Proof' Shellcodes" by obscou
- Phrack Magazine - Various shellcode techniques

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────┐
│                  BYVALVER PROFILE QUICK REFERENCE               │
├──────────────────────┬──────────────┬────────────┬──────────────┤
│ Profile              │ Difficulty   │ Bad Chars  │ Use Case     │
├──────────────────────┼──────────────┼────────────┼──────────────┤
│ null-only            │ ░░░░░        │ 1          │ Default      │
│ http-newline         │ █░░░░        │ 3          │ HTTP/Network │
│ http-whitespace      │ █░░░░        │ 5          │ HTTP params  │
│ url-safe             │ ███░░        │ 23         │ GET requests │
│ sql-injection        │ ███░░        │ 5          │ SQL context  │
│ xml-html             │ ███░░        │ 6          │ XSS/XML      │
│ json-string          │ ███░░        │ 34         │ JSON APIs    │
│ format-string        │ ███░░        │ 3          │ Printf bugs  │
│ buffer-overflow      │ ███░░        │ 5          │ BOF exploits │
│ command-injection    │ ███░░        │ 20         │ Shell cmds   │
│ ldap-injection       │ ███░░        │ 5          │ LDAP queries │
│ printable-only       │ ████░        │ 161        │ Text only    │
│ alphanumeric-only    │ █████        │ 194        │ Extreme CTF  │
└──────────────────────┴──────────────┴────────────┴──────────────┘

USAGE:
  ./bin/byvalver --profile <name> input.bin output.bin
  ./bin/byvalver --list-profiles

COMBINING:
  --profile <name> --biphasic --ml --xor-encode 0xKEY

DIFFICULTY: ░ = Easy, █ = Hard (more bars = harder)
```

---

**Document Version**: 1.0
**Author**: byvalver development team
**License**: Same as byvalver project
