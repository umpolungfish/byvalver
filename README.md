<div align="center">
  <h1>byvalver (·𐑚𐑲𐑝𐑨𐑤𐑝𐑼)</h1>
  <p><b>THE SHELLCODE BAD-BYTE BANISHER</b></p>

<img src="assets/images/byvalver_logo.png" alt="byvalver banishes bad-bytes with extreme prejudice">

</div>

<div align="center">
  <img src="https://img.shields.io/badge/C-%2300599C.svg?style=flat&color=blue" alt="C">
  <img src="https://img.shields.io/badge/shellcode-scrubbing-%238300FF.svg?style=flat&color=black" alt="shellcode scrubbing">
   <img src="https://img.shields.io/badge/cross--platform-windows%20%7C%20linux%20%7C%20macOS-%230071C5.svg?style=flat&color=green" alt="cross-platform">
   <img src="https://img.shields.io/badge/Architectures-x86%7Cx64%7CARM%7CARM64-%230071C5.svg?style=flat&color=red" alt="architectures">
   <img src="https://img.shields.io/badge/build-clean-%23000000.svg?style=flat&color=grey" alt="build clean">
  <img src="https://img.shields.io/github/stars/umpolungfish/byvalver?style=flat&color=cyan" alt="GitHub stars">
  <img src="https://img.shields.io/github/forks/umpolungfish/byvalver?style=flat&color=teal" alt="GitHub forks">
  <a href="https://github.com/sponsors/umpolungfish"><img src="https://img.shields.io/badge/sponsor-%E2%9D%A4-ea4aaa?style=flat&color=pink" alt="sponsor on gitHub"></a>
  <a href="https://ko-fi.com/umpolungfish"><img src="https://img.shields.io/badge/ko--fi-support-%23FF5E5B?style=flat&color=brown" alt="support on ko-fi"></a>
</div>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#interactive-tui">Interactive TUI</a> •
  <a href="#targeted-bad-byte-elimination">Targeted Bad-Byte Elimination</a> •
  <a href="#bad-byte-profiles">Bad-Byte Profiles</a> •
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#system-requirements">System Requirements</a> •
  <a href="#dependencies">Dependencies</a> •
  <a href="#building">Building</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#obfuscation-strategies">Obfuscation Strategies</a> •
  <a href="#denullification-strategies">Denullification Strategies</a> •
  <a href="#ml-training--validation">ML Training</a> •
  <a href="#agent-menagerie">Agent Menagerie</a> •
  <a href="#development">Development</a> •
  <a href="#troubleshooting">Troubleshooting</a> •
  <a href="#license">License</a>
</p>

<hr>

## Table of Contents

- [Overview](#overview)
- [Quick-Start](#quick-start)
  - [Installation](#installation)
  - [Basic Usage](#basic-usage)
  - [Verification](#verification)
  - [Cross-Architecture Support](#cross-architecture-support)
  - [Batch Processing](#batch-processing)
- [Interactive TUI](#interactive-tui)
- [Targeted Bad-Byte Banishment](#targeted-bad-byte-banishment)
- [Bad-Byte Profiles](#bad-byte-profiles)
- [Features](#features)
  - [Advanced Transformation Engine](#advanced-transformation-engine)
  - [Performance Metrics](#performance-metrics)
  - [Obfuscation Layer](#obfuscation-layer)
  - [ML-Powered Strategy Selection](#ml-powered-strategy-selection)
  - [Output Options](#output-options)
  - [Verification Suite](#verification-suite)
- [Architecture](#architecture)
- [System Requirements](#system-requirements)
- [Dependencies](#dependencies)
- [Building](#building)
- [Installation](#installation-1)
- [Usage](#usage)
- [Obfuscation Strategies](#obfuscation-strategies)
- [Denullification Strategies](#denullification-strategies)
- [ML Training & Validation](#ml-training--validation)
- [Agent Menagerie](#agent-menagerie)
- [Development](#development)
- [Documentation](#documentation)
- [Troubleshooting](#troubleshooting)
- [License](#license)

<hr>

## Overview

`byvalver` is a CLI tool built in `C` for automatically eliminating (or **"banishing"**) `bad-bytes` from x86/x64/ARM/ARM64 shellcode while maintaining complete functional equivalence

**NEW in v4.0: Cross-Architecture Support**

| Architecture | Maturity | Strategies | Notes |
|---|---|---|---|
| **x86** (32-bit Intel/AMD) | Stable v4.2 | 150+ | Production-tested, full coverage |
| **x64** (64-bit Intel/AMD) | Stable v4.2 | 150+ | Default architecture, production-tested |
| **ARM** (32-bit) | Experimental v0.1 | 7 core | Limited testing, core instructions only |
| **ARM64** (AArch64) | Experimental v0.1 | Basic | Framework ready, minimal strategies |
- Automatic Capstone mode selection via `--arch` flag

**v4.0.1 Bug Fixes:**
- Fixed ARM SUB instruction encoding (correct opcode 0x2 with I=1 bit)
- Fixed ARM64 strategy `can_handle` logic for pass-through strategies
- Added experimental warnings when ARM/ARM64 architecture is selected
- Added architecture mismatch detection heuristics
- Improved code organization (includes moved to file scope)

**NEW in v4.2: Enhanced x64 Support**
- **x86/x64 Strategy Compatibility Layer**: 128+ x86 strategies now work on x64 shellcode
- **5 New x64-Specific Strategy Files**: MOVABS, SBB, TEST, SSE Memory, LEA Displacement
- **Extended Register Encoding**: Full R8-R15 support with proper REX prefix handling
- **REX Prefix Utilities**: `is_64bit_register()`, `is_extended_register()`, `build_rex_prefix()`
- Resolves 100% failure rate on x64-only shellcode samples

The tool uses the `Capstone` disassembly framework to analyze instructions and applies over 175+ ranked transformation strategies to replace `bad-byte`-containing code with equivalent alternatives  

The generic `bad-byte` banishment framework provides 2x usage modes:

1. **Direct specification**: The `--bad-bytes` option allows specification of arbitrary bytes to banish (e.g., `--bad-bytes "00,0a,0d"` for newline-safe shellcode)
2. **Profile-based**: The `--profile` option uses pre-configured bad-byte sets for common exploit scenarios (e.g., `--profile http-newline`, `--profile sql-injection`, `--profile alphanumeric-only`)

Supports `Windows`, `Linux`, and `macOS`

**CORE TECH:**
- Pure `C` implementation for efficiency and low-level control
- `Capstone` for precise disassembly
- `NASM` for generating decoder stubs
- Modular strategy pattern for extensible transformations (153+ strategy implementations)
- Neural network integration for intelligent strategy selection
- Biphasic processing: Obfuscation followed by denullification

> [!NOTE]
> **Null-byte elimination** (`--bad-bytes "00"` or default): WELL-TESTED / **Generic bad-byte elimination** (`--bad-bytes "00,0a,0d"` etc.): NEWLY IMPLEMENTED

### BAD-BYTE BANISHMENT IN ACTION

<img src="assets/images/denulling.gif" alt="bad-byte banishment in action">

## QUICK-START

Get started with `byvalver` in minutes:

### INSTALLATION

**OPTION 1: FROM GITHUB (RECOMMENDED)**
```bash
curl -sSL https://raw.githubusercontent.com/umpolungfish/byvalver/main/install.sh | bash
```

**OPTION 2: BUILD FROM SOURCE**
```bash
git clone https://github.com/umpolungfish/byvalver.git
cd byvalver
make
sudo make install
sudo make install-man  # Install man page
```

### Basic Usage

**banish NULL BYTES (DEFAULT):**
```bash
byvalver input.bin output.bin
```

**USING BAD-BYTE PROFILES:**
```bash
# HTTP contexts (removes null, newline, carriage return)
byvalver --profile http-newline input.bin output.bin

# SQL injection contexts
byvalver --profile sql-injection input.bin output.bin

# Alphanumeric-only shellcode (most restrictive)
byvalver --profile alphanumeric-only input.bin output.bin
```

**MANUAL BAD-BYTE SPECIFICATION:**
```bash
# banish null bytes and newlines
byvalver --bad-bytes "00,0a,0d" input.bin output.bin
```

**ADVANCED FEATURES:**
```bash
# Add obfuscation layer before denullification
byvalver --biphasic input.bin output.bin

# Enable ML-powered strategy selection
byvalver --ml input.bin output.bin

# Generate XOR-encoded shellcode with decoder stub
byvalver --xor-encode DEADBEEF input.bin output.bin

# Output in different formats
byvalver --format c input.bin output.c      # C array
byvalver --format python input.bin output.py # Python bytes
byvalver --format hexstring input.bin output.hex # Hex string
```

### VERIFICATION

Always verify your transformed shellcode:
```bash
# Check for remaining bad bytes
python3 verify_denulled.py --bad-bytes "00,0a,0d" output.bin

# Verify functional equivalence
python3 verify_functionality.py input.bin output.bin
```

### CROSS-ARCHITECTURE SUPPORT

`byvalver` supports multiple architectures via the `--arch` flag:

**x86 (32-bit Intel/AMD)** - Fully supported with 150+ strategies
```bash
byvalver --arch x86 --bad-bytes "00" x86_shellcode.bin output.bin
```

**x64 (64-bit Intel/AMD)** - Fully supported (default)
```bash
byvalver --arch x64 --bad-bytes "00,0a,0d" x64_shellcode.bin output.bin
```

**ARM (32-bit)** - Experimental support with basic strategies
```bash
byvalver --arch arm --bad-bytes "00" arm_shellcode.bin output.bin
```

**ARM64 (AArch64)** - Experimental support with basic strategies
```bash
byvalver --arch arm64 --bad-bytes "00,0a" arm64_shellcode.bin output.bin
```

**Notes:**
- ARM/ARM64 support focuses on core instructions (MOV, arithmetic, loads/stores)
- Use simpler bad-byte profiles for ARM (e.g., null-byte only)
- Experimental warnings are displayed when ARM/ARM64 is selected
- Basic architecture mismatch detection warns if shellcode appears to be wrong architecture
- Automatic architecture detection is planned for future releases

### BATCH PROCESSING

Process entire directories:
```bash
# Process all .bin files recursively
byvalver -r --pattern "*.bin" input_dir/ output_dir/

# Apply HTTP profile to all shellcode in directory
byvalver -r --profile http-newline input_dir/ output_dir/
```

## INTERACTIVE TUI

<div align="center">
<img src="assets/images/menu_main.png" alt="TUI main menu">
</div>

---

<div align="center">
<img src="assets/images/menu_proc.png" alt="TUI batch processing">
</div>

---

`byvalver` includes an **interactive TUI** (Text User Interface) with **1:1 CLI feature parity**.  

The TUI provides an intuitive, visual interface for all `bad-byte` banishment operations, including:  

+ batch processing with live statistics
+ ML configuration &
+ comprehensive file browsing

Launch the TUI with the `--menu` flag:

```bash
byvalver --menu
```

### MAIN FEATURES:

The TUI provides 9x main menu options covering all CLI functionality:

1. **Process Single File** - Process individual shellcode files with visual feedback
2. **Batch Process Directory** - Process entire directories with live progress tracking
3. **Configure Processing Options** - Toggle biphasic mode, PIC generation, ML, verbose, dry-run
4. **Set Bad Bytes** - Manual entry or select from 13 predefined profiles
5. **Output Format Settings** - Choose from 5 output formats (raw, C, Python, PowerShell, hexstring)
6. **ML Metrics Configuration** - Configure ML strategy selection and metrics tracking
7. **Advanced Options** - XOR encoding, timeouts, limits, validation settings
8. **Load/Save Configuration** - INI-style configuration file management
9. **About byvalver** - Version and help information

### VISUAL FILE BROWSER:

- **Directory navigation** with arrow keys or vi-style j/k keys
- **File/directory distinction** with [FILE] and [DIR] indicators
- **File size display** with human-readable formats (B, KB, MB, GB)
- **Extension filtering** (e.g., *.bin)
- **Intelligent path handling** - Automatically navigates to parent directory if file path is provided
- **Sorted display** - Directories first, then alphabetical
- **Multiple selection modes**:
  - File selection mode: Navigate into directories, select files only
  - Directory selection mode: Select directories for batch processing
  - Both mode: Select either files or directories

### BATCH PROCESSING WITH LIVE UPDATES:

The batch processing screen provides **real-time feedback**:

- **Progress bar** showing files processed (e.g., `[==============        ] 52/100 files`)
- **Configuration display** showing active settings:
  - Bad bytes count and profile used
  - Processing options (`Biphasic`, `PIC`, `XOR`, ML)
  - Output format
- **Live file statistics** with color-coded status:
  - Completed: X / Y (files attempted / total)
  - ✅ Successful (GREEN) - zero bad bytes remaining
  - ❌ Failed (RED) - errors or remaining bad bytes
  - Success rate percentage
- **Current file display** in bold text
- **Next file preview** in yellow/dim text
- **Dynamic strategy statistics table** showing:
  - **All active strategies** (no 10-strategy limit)
  - **Full strategy names** (up to 50 characters, no truncation)
  - Success/failure counts per strategy
  - Success rate percentages
  - Color-coded by performance (green ≥80%, yellow 50-79%, red <50%)
  - Real-time updates every 50ms

### CONFIGURATION MANAGEMENT:

Load and save configurations in **INI-style format**:

```ini
[general]
verbose = 0
quiet = 0
show_stats = 1

[processing]
use_biphasic = 0
use_pic_generation = 0
encode_shellcode = 0
xor_key = 0xDEADBEEF

[output]
output_format = raw

[bad_bytes]
bad_bytes = 00

[ml]
use_ml_strategist = 0
metrics_enabled = 0

[batch]
file_pattern = *.bin
recursive = 0
preserve_structure = 1
```

See `example.conf` for a complete configuration template.

### BAD BYTE CONFIGURATION:

2x input methods available:

1. **MANUAL ENTRY** - Comma-separated hex values (e.g., `00,0a,0d`)
2. **PREDEFINED PROFILES** - 13 profiles for common scenarios:
   - null-only, http-newline, http-whitespace
   - url-safe, sql-injection, xml-html
   - json-string, format-string, buffer-overflow
   - command-injection, ldap-injection
   - printable-only, alphanumeric-only

### NAVIGATION:

- **Arrow Keys** (↑↓) or **j/k** (vi-style): Navigate between menu options
- **Enter**: Select highlighted option
- **q**: Quit the application or cancel operation
- **0-9**: Quick select menu option by number
- **Space**: Select current directory (in file browser directory mode)

### REQUIREMENTS:

Interactive mode requires the `ncurses` library to be installed on your system:

```bash
# Ubuntu/Debian
sudo apt install libncurses-dev

# CentOS/RHEL/Fedora
sudo dnf install ncurses-devel

# macOS (with Homebrew)
brew install ncurses
```

The application will automatically detect if ncurses is available and enable TUI support accordingly.

### BUILD OPTIONS:

The TUI support is conditionally compiled based on ncurses availability:

- Default build: `make` - Includes TUI if ncurses is available
- Force TUI build: `make with-tui` - Builds with TUI support (fails if ncurses not available)
- Exclude TUI: `make no-tui` - Builds without TUI support for smaller binary

### EXAMPLE WORKFLOWS:

**SINGLE FILE PROCESSING:**
1. Launch TUI: `byvalver --menu`
2. Select "1. Process Single File"
3. Browse for input file using visual file browser
4. Browse for output file location
5. Start processing and view results

**BATCH PROCESSING:**
1. Launch TUI: `byvalver --menu`
2. Select "2. Batch Process Directory"
3. Browse for input directory containing shellcode files
4. Browse for output directory
5. Configure file pattern (default: <file>.bin) and recursive option
6. Start batch processing and watch live progress with strategy statistics

**CONFIGURATION MANAGEMENT:**
1. Configure all options in the TUI (bad bytes, output format, ML, etc.)
2. Select "8. Load/Save Configuration"
3. Save current configuration to a file (e.g., `my_config.conf`)
4. Later: Load the configuration file to restore all settings

### PERFORMANCE NOTES:

- **Single file processing**: Instant visual feedback, <1 second for typical shellcode
- **Batch processing**: 50ms delay between files for visual updates
- **Large directories (100+ files)**: Scanning may take 1-2 seconds
- **Strategy initialization**: 2-5 seconds on first run (one-time cost per session)

### TERMINAL COMPATIBILITY:

The TUI has been tested with:
- GNOME Terminal
- Konsole
- xterm
- iTerm2 (macOS)
- Windows Terminal (WSL)
- tmux/screen (works but may have color limitations)

**Minimum recommended terminal size**: 80x24 characters (100x30 or larger recommended for full strategy table during batch processing)

For complete TUI documentation, troubleshooting, and advanced usage, see [TUI_README.md](TUI_README.md).

## TARGETED BAD-BYTE BANISHMENT

### OVERVIEW

The `--bad-bytes` option allows you to specify any set of bytes to banish from your shellcode.

### IMPLEMENTATION DETAILS

`byvalver` operates by:
1. Parsing the comma-separated hex byte list (e.g., `"00,0a,0d"`)
2. Using an O(1) bitmap lookup to identify bad bytes in instructions
3. Applying the same 153+ transformation strategies used for null-byte elimination
4. Verifying that the output does not contain the specified bad bytes

### EXPECTED BEHAVIOR

- **Null bytes only** (`--bad-bytes "00"` or default): High success rate (100% on test corpus)
- **Multiple bad bytes** (`--bad-bytes "00,0a,0d"`): Success rate may vary significantly depending on:
  - Which specific bytes are marked as bad
  - Complexity of the input shellcode
  - Frequency of bad bytes in the original shellcode
  - Whether effective alternative encodings exist for the specific bad byte set

### RECOMMENDATIONS

1. **For production use:** Stick with default null-byte banishment mode
2. **For experimentation:** Test the `--bad-bytes` feature with your specific use case and validate the output
3. **Always verify:** Use `verify_denulled.py --bad-bytes "XX,YY"` to confirm all bad bytes were eliminated
4. **Expect variability:** Some shellcode may not be fully cleanable with certain bad byte sets

### FUTURE IMPROVEMENTS

The generic bad-byte feature provides a foundation for:
- Strategy optimization for specific bad byte patterns
- Automated discovery of new strategies targeting common bad byte combinations
- ML model retraining with diverse bad byte training data
- Extended testing and validation

> [!CAUTION]
> Using `--bad-bytes` with multiple bad bytes significantly increases the complexity of the transformation task. Some shellcode may become impossible to transform if too many bytes are marked as bad, as the tool may run out of alternative encodings. Start with small bad byte sets (e.g., `"00,0a"`) and expand gradually while testing the output. Always verify the result with `verify_denulled.py` before deployment.

## BAD-BYTE PROFILES

### OVERVIEW

Users can also choose **bad-byte profiles** - pre-configured sets of bytes for common exploit scenarios. Instead of manually specifying hex values, use profile names that match your context.

### AVAILABLE PROFILES

| Profile | Difficulty | Bad Bytes | Use Case |
|---------|-----------|-----------|----------|
| `null-only` | ░░░░░ Trivial | 1 | Classic buffer overflows (default) |
| `http-newline` | █░░░░ Low | 3 | `HTTP` headers, line-based protocols |
| `http-whitespace` | █░░░░ Low | 5 | `HTTP` parameters, command injection |
| `url-safe` | ███░░ Medium | 23 | `URL` parameters, `GET` requests |
| `sql-injection` | ███░░ Medium | 5 | `SQL` injection contexts |
| `xml-html` | ███░░ Medium | 6 | `XML`/`HTML` injection, `XSS` |
| `json-string` | ███░░ Medium | 34 | `JSON` API injection |
| `format-string` | ███░░ Medium | 3 | Format string vulnerabilities |
| `buffer-overflow` | ███░░ Medium | 5 | Stack/heap overflows with filtering |
| `command-injection` | ███░░ Medium | 20 | Shell command injection |
| `ldap-injection` | ███░░ Medium | 5 | `LDAP` queries |
| `printable-only` | ████░ High | 161 | Text-based protocols (printable ASCII only) |
| `alphanumeric-only` | █████ Extreme | 194 | Alphanumeric-only shellcode (0-9, A-Z, a-z) |

### USAGE

```bash
# List all available profiles
byvalver --list-profiles

# Use a specific profile
byvalver --profile http-newline input.bin output.bin

# Combine with other options
byvalver --profile sql-injection --biphasic --format c input.bin output.c
```

### PROFILE EXAMPLES

**HTTP Contexts** (eliminates NULL, LF, CR):
```bash
byvalver --profile http-newline payload.bin http_safe.bin
```

**SQL Injection** (eliminates NULL, quotes, semicolons):
```bash
byvalver --profile sql-injection payload.bin sql_safe.bin
```

**Alphanumeric-Only** (extreme difficulty - only allows 0-9, A-Z, a-z):
```bash
byvalver --profile alphanumeric-only payload.bin alphanum.bin
```

For detailed profile documentation, see [docs/BAD_BYTE_PROFILES.md](docs/BAD_BYTE_PROFILES.md).


## FEATURES

### HIGH NULL-BYTE banishment SUCCESS RATE
<div align="center">
  <strong>Achieved 100% null-byte banishment on a diverse test corpus representing common and complex null sources.</strong>
</div>

> This success rate applies specifically to null-byte (`\x00`) elimination, which has been extensively tested and optimized.

### ADVANCED TRANSFORMATION ENGINE
170+ strategy implementations covering virtually all common null-byte sources and general bad-byte patterns (multiple new strategy families added in v3.0, v3.6, v3.7, v3.8, v4.0, and v4.1):
- `CALL/POP` and stack-based immediate loading
- `PEB` traversal with hashed API resolution
- Advanced hash-based API resolution with complex algorithms
- Multi-stage `PEB` traversal for multiple DLL loading
- `SALC`, `XCHG`, and flag-based zeroing
- `LEA` for arithmetic substitution
- `Shift` and arithmetic value construction
- Multi-`PUSH` string building
- Stack-based structure construction for Windows structures
- Stack-based string construction with advanced patterns
- `SIB` and displacement rewriting
- Conditional jump displacement handling
- Register remapping and chaining
- Enhanced `SALC`+`REP STOSB` for buffer initialization
- Advanced string operation transformations
- Atomic operation encoding chains
- `FPU` stack-based immediate encoding
- `XLAT` table-based byte translation
- `LAHF`/`SAHF` flag preservation chains
- **NEW in v3.6**: `BCD` arithmetic obfuscation (`AAM`/`AAD`)
- **NEW in v3.6**: `ENTER`/`LEAVE` stack frame alternatives
- **NEW in v3.6**: `POPCNT`/`LZCNT`/`TZCNT` bit counting for constants
- **NEW in v3.6**: `SIMD` `XMM` register immediate loading
- **NEW in v3.6**: `JECXZ`/`JRCXZ` zero-test jump transformations
- **NEW in v3.7**: Conditional jump opcode bad-byte elimination (JE/JNE/JG/JL with bad opcodes)
- **NEW in v3.7**: Register-to-register transfer bad-byte opcodes (MOV/XCHG alternatives)
- **NEW in v3.7**: Stack frame pointer bad-byte elimination (PUSH/POP EBP alternatives)
- **NEW in v3.7**: ModR/M and SIB byte bad-byte elimination (alternative register combinations)
- **NEW in v3.7**: Multi-byte immediate partial bad-byte (rotation optimization)
- **NEW in v3.7**: Bitwise operation immediate bad-byte (AND/OR/XOR/TEST with registers)
- **NEW in v3.7**: One-byte opcode substitution (INC/DEC/PUSH/POP alternatives)
- **NEW in v3.7**: String instruction prefix bad-byte (REP prefix to loop conversion)
- **NEW in v3.7**: Operand size prefix bad-byte (16-bit to 32-bit conversion)
- **NEW in v3.7**: Segment register bad-byte detection (FS/GS prefix detection)
- **NEW in v3.8**: Profile-aware SIB generation system (eliminates hardcoded 0x20 SIB byte)
- **NEW in v3.8**: Critical fixes for conditional jump handling and partial register optimization
 - **NEW in v3.9**: Polymorphic NOP insertion with multiple NOP equivalents
 - **NEW in v3.9**: Constant unfolding for immediate value obfuscation
 - **NEW in v3.9**: Register renaming obfuscation with XCHG patterns
 - **NEW in v3.9**: Stack spill obfuscation for arithmetic operations
 - **NEW in v3.9**: Instruction reordering with NOP insertion
 - **NEW in v3.9**: Runtime self-modification strategy (basic implementation)
 - **NEW in v3.9**: Overlapping instruction generation
  - **NEW in v4.0**: ARM/ARM64 cross-architecture support with Capstone dynamic mode selection
  - **NEW in v4.0**: ARM immediate encoding with MVN transformations
  - **NEW in v4.0**: ARM MOV strategies (original, MVN-based null avoidance)
  - **NEW in v4.0**: ARM arithmetic strategies (ADD with SUB transformations)
  - **NEW in v4.0**: ARM memory strategies (LDR/STR pass-through)
  - **NEW in v4.0**: ARM branch strategies (B/BL pass-through)
  - **NEW in v4.1**: SETcc Flag Accumulation Chains (conditional jump elimination)
  - **NEW in v4.1**: Polymorphic Immediate Value Construction (multiple encoding variants)
  - **NEW in v4.1**: Register Dependency Chain Optimization (multi-instruction patterns)
  - **NEW in v4.1**: RIP-Relative Addressing Optimization (x64 PIC improvements)
  - **NEW in v4.1**: Negative Displacement Memory Addressing (displacement alternatives)
  - **NEW in v4.1**: Multi-Byte NOP Interlacing (obfuscation NOP variants)
  - **NEW in v4.1**: Bit Manipulation Constant Construction (BSWAP, BSF, POPCNT, BMI2)
  - **NEW in v4.2**: x86/x64 Strategy Compatibility Layer (enables 128+ x86 strategies on x64)
  - **NEW in v4.2**: MOVABS 64-bit Immediate Strategies (REX.W MOV with XOR/ADD construction)
  - **NEW in v4.2**: SBB Immediate Zero Strategies (SBB AL/AX/EAX, 0 transformation)
  - **NEW in v4.2**: TEST Large Immediate Strategies (TEST EAX/RAX, imm32 with register operands)
  - **NEW in v4.2**: SSE Memory Operation Strategies (MOVUPS/MOVAPS/MOVDQU/MOVDQA null elimination)
  - **NEW in v4.2**: LEA x64 Displacement Strategies (large displacement handling with REX prefixes)
  - **NEW in v4.2**: Extended Register Support (R8-R15 register encoding utilities)
 - Comprehensive support for `MOV`, `ADD/SUB`, `XOR`, `LEA`, `CMP`, `PUSH`, and more

The engine employs multi-pass processing (obfuscation → denulling) with robust fallback mechanisms for edge cases

**v3.8 CRITICAL IMPROVEMENTS**: Multi-Strategy Fix for http-whitespace Profile
- **Problem**: Hardcoded bad bytes caused 79.1% failure rate (125/158 files failed)
- **Root Causes Identified**:
  - 45+ instances of hardcoded SIB byte 0x20 (SPACE) across 15 strategy files
  - Conditional jump core logic using bad byte skip offsets without validation
  - Partial register optimization writing bad bytes directly
  - Additional hardcoded bad bytes in 5 HIGH priority strategy files
- **Solutions Implemented**:
  - Centralized profile-aware SIB generation with 3-tier fallback (STANDARD → DISP8 → PUSHPOP)
  - Dynamic NOP padding for conditional jump skip offsets to avoid bad bytes
  - Intelligent byte construction for partial register values using decomposition
  - Systematic replacement of hardcoded bytes with profile-aware alternatives
- **Impact**: **79.1% failure → 35.4% failure** (success rate: **20.9% → 64.6%**)
- **Files Fixed**: 102 files now process successfully (+69 files, 3.09x improvement)
- **Strategy Success Rates**:
  - Partial Register Optimization: 25% → **100%** (12/12 transformations)
  - mov_mem_disp_enhanced: 0% → **98.5%** (1605/1629 transformations)
  - indirect_call_mem: 0% → **98.5%** (135/137 transformations)
  - indirect_jmp_mem: 0% → **98.5%** (134/136 transformations)
- **Performance**: Zero overhead through intelligent caching, <2% average size increase

### PERFORMANCE METRICS

Real-world performance data from processing 184 diverse shellcode samples:

```
📊 Batch Processing Statistics:

Success Rate:            184/184             █████████████████████████   100.00%
Files Processed:         184                 █████████████████████████   100.00%
Failed:                  0                   ░░░░░░░░░░░░░░░░░░░░░░░░░   00.00%
Skipped:                 0                   ░░░░░░░░░░░░░░░░░░░░░░░░░   00.00%
```

```
🧠 ML Strategy Selection Performance:

Processing Speed:
Instructions/sec:        19.5 inst/sec       ████████████░░░░░░░░░░░░░
Total Instructions:      20,760
Session Duration:        1,067 seconds

Null-Byte Elimination:
Eliminated:              18,636/20,760       ██████████████████████░░░   89.77%
Strategies Applied:      20,129
Success Rate:            92.57%              ███████████████████████░░   92.57%

Learning Progress:
Positive Feedback:       18,636              ███████████████████████░░   92.57%
Negative Feedback:       1,493               █░░░░░░░░░░░░░░░░░░░░░░░░   07.43%
Total Iterations:        40,889
Avg Confidence:          0.0015              ░░░░░░░░░░░░░░░░░░░░░░░░░   00.15%
```

```
🏆 Top Performing Denullification Strategies:

Strategy                                  Attempts    Success%    Confidence
--------                                  --------    --------    ----------
ret_immediate                                  134    █████████████░░░░░░░░░░░░   50.00%
MOVZX/MOVSX Null-Byte banishment              162    █████████████░░░░░░░░░░░░   50.00%
transform_mov_reg_mem_self                     774    █████████████░░░░░░░░░░░░   50.00%
cmp_mem_reg_null                                96    ████████████░░░░░░░░░░░░░   46.88%
cmp_mem_reg                                    264    ████████████░░░░░░░░░░░░░   46.97%
lea_disp_null                                 3900    ███████████░░░░░░░░░░░░░░   45.38%
transform_add_mem_reg8                        2012    ███████████░░░░░░░░░░░░░░   43.49%
Push Optimized                                4214    ███████░░░░░░░░░░░░░░░░░░   29.31%
ModRM Byte Null Bypass                          82    ██████░░░░░░░░░░░░░░░░░░░   25.61%
conservative_arithmetic                       5172    █████░░░░░░░░░░░░░░░░░░░░   21.37%
arithmetic_addsub_enhanced                    1722    ████░░░░░░░░░░░░░░░░░░░░░   18.12%
PUSH Immediate Null-Byte banishment          3066    ████░░░░░░░░░░░░░░░░░░░░░   16.54%
SIB Addressing                                9560    ████░░░░░░░░░░░░░░░░░░░░░   16.03%
generic_mem_null_disp_enhanced               22130    ███░░░░░░░░░░░░░░░░░░░░░░   15.52%
SALC-based Zero Comparison                    1654    ███░░░░░░░░░░░░░░░░░░░░░░   12.88%
```

```
⚡ Processing Efficiency:

Learning Rate:           1.97 feedback/instruction
Weight Update Avg:       0.042650
Weight Update Max:       0.100000
Total Weight Updates:    1724.68

Strategy Coverage:
Total Strategies:        153+
Strategies Activated:    117                 ████████████████████████░   95.90%
Zero-Attempt:            5                   █░░░░░░░░░░░░░░░░░░░░░░░░   04.10%
```

### OBFUSCATION LAYER
`--biphasic` mode adds anti-analysis obfuscation prior to denulling:
- Control flow flattening
- Dispatcher patterns
- Register reassignment
- State obfuscation
- Dead code insertion
- NOP sleds
- Instruction substitution
- Equivalent operations
- Stack frame manipulation
- API resolution hiding
- String Encoding
- Constant Encoding
- Anti-debugging
- VM detection techniques

### ML-POWERED STRATEGY SELECTION

> **Maturity: Beta v2.0** — Trained on null-byte elimination datasets. Needs retraining for generic bad-byte use cases.

**Architecture**:
- **One-hot instruction encoding** (51 dims) replaces scalar instruction IDs
- **Context window** with sliding buffer of 4 instructions (current + 3 previous)
- **Fixed feature extraction** with stable 84-dimensional layout per instruction
- **Stable strategy registry** ensuring consistent NN output mapping
- **Full backpropagation** through all layers (input→hidden→output)
- **Correct gradient computation** for softmax + cross-entropy loss
- **Output masking** filters invalid strategies before softmax
- **He/Xavier initialization** for proper weight initialization
- 3-layer feedforward neural network (336→512→200)
- Adaptive learning from success/failure feedback
- Tracks predictions, accuracy, and confidence
- Graceful fallback to deterministic ordering

> [!WARNING]
> ML mode is experimental and requires further training/validation with the new architecture.

### BATCH PROCESSING
- Recursive directory traversal (`-r`)
- Custom file patterns (`--pattern "*.bin"`)
- Structure preservation or flattening
- Continue-on-error or strict modes
- Compatible with all options (biphasic, PIC, `XOR`, etc.)
- **Enhanced output**:
  - Per-file size transformations with ratios
  - Detailed bad byte identification on failures
  - Success/failure percentages in summary
  - Failed files list (first 10 shown inline)
  - Strict success definition: files with remaining bad bytes marked as failed

**BATCH PROCESSING OUTPUT EXAMPLE:**
```
===== BATCH PROCESSING SUMMARY =====
Total files:       8
Successfully processed: 1 (12.5%)
Failed:            7 (87.5%)
Skipped:           0

Total input size:  650 bytes
Total output size: 764 bytes
Average size ratio: 1.18x

Bad bytes:    5 configured
Configured set:    0x00, 0x09, 0x0a, 0x0d, 0x20

FAILED FILES (7):
  - shellcode1.bin
  - shellcode2.bin
  ...
```

> [!TIP]
> For batch processing large shellcode collections, use `--no-continue-on-error` to identify problematic files early, then process successfully with `--pattern` to exclude failures. The `--verbose` flag helps track progress and identify which strategies work best for your specific shellcode corpus. Files are only counted as successful when they contain **zero remaining bad bytes** - partial success is treated as failure.

### OUTPUT OPTIONS
- Formats: raw binary, `C` array, Python bytes, hex string
- `XOR` encoding with decoder stub (`--xor-encode 0xDEADBEEF`)
- Position-independent code (`--pic`)
- Automatic output directory creation

### STATISTICS
When using `--stats` flag, `byvalver` provides detailed analytics:

**STRATEGY USAGE STATISTICS:**
- Shows which transformation strategies were applied
- Success/failure rates for each strategy
- Applications count and average output size per strategy

**FILE COMPLEXITY ANALYSIS:**
- Most complex files (by instruction count)
- Largest/smallest files by input size
- Files with largest expansion ratios
- Bad byte banishment statistics per file

**BATCH PROCESSING SUMMARY:**
- Success/failure percentages
- Detailed bad byte configuration
- Failed files list with options to save full list

**EXAMPLE OUTPUT:**
```
===== BATCH PROCESSING SUMMARY =====
Total files:       162
Successfully processed: 131 (80.9%)
Failed:            31 (19.1%)
Skipped:           0

Total input size:  35772920 bytes
Total output size: 81609 bytes
Average size ratio: 0.00x

Bad bytes:    3 configured
Configured set:    0x00, 0x0a, 0x0d
====================================

FAILED FILES (31):
  - ./winwin.bin
  - ./stairslide_secure.bin
  ...

📊 DETAILED STATISTICS
=====================
STRATEGY USAGE STATISTICS:
┌─────────────────────────────────────────┬─────────┬─────────┬──────────────┬────────────────┐
│ Strategy Name                           │ Success │ Failure │ Applications │ Avg Output Size│
├─────────────────────────────────────────┼─────────┼─────────┼──────────────┼────────────────┤
│ push_immediate_strategy                 │      45 │       3 │           48 │          12.34 │
│ mov_reg_mem_self                        │      32 │       1 │           33 │           8.21 │
│ ...                                     │     ... │     ... │          ... │           ... │
└─────────────────────────────────────────┴─────────┴─────────┴──────────────┴────────────────┘

FILE COMPLEXITY ANALYSIS:
Most Complex Files (by instruction count):
  - ./complex_payload.bin: 1245 instructions, 4096 -> 5201 bytes (1.27x)

Largest Files (by input size):
  - ./large_payload.bin: 8192 bytes input, 10485 bytes output (1.28x)

Smallest Files (by input size):
  - ./tiny_shellcode.bin: 64 bytes input, 89 bytes output (1.39x)

Largest Expansion (by size ratio):
  - ./expanded.bin: 512 -> 1024 bytes (2.00x expansion)
```

### VERIFICATION SUITE
Python tools for validation:
- `verify_denulled.py`: Ensures zero bad bytes (supports `--bad-bytes` for custom verification)
- `verify_functionality.py`: Checks execution patterns
- `verify_semantic.py`: Validates equivalence

## ARCHITECTURE

`byvalver` employs a modular strategy-pattern design:
- Pass 1: (Optional) Obfuscation for anti-analysis
- Pass 2: Denullification for null-byte removal
- ML layer for strategy optimization
- Batch system for scalable processing

<div align="center">
  <img src="./assets/images/Strategy_Categories_Taxonomy_Compact.png" alt="Strategy Categories Taxonomy" width="700">
</div>

## SYSTEM REQUIREMENTS

- **OS**: Linux (Ubuntu/Debian/Fedora), macOS (with Homebrew), Windows (via WSL/MSYS2)
- **CPU**: x86/x64 with modern instructions
- **RAM**: 1GB free
- **Disk**: 50MB free
- **Tools**: `C` compiler, Make, Git (recommended)

## DEPENDENCIES

- **Core**: GCC/Clang, GNU Make, `Capstone` (v4.0+), `NASM` (v2.13+), xxd
- **Optional**: Clang-Format, Cppcheck, Valgrind
- **ML Training**: Math libraries (included)

### INSTALLATION COMMANDS

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install build-essential nasm xxd pkg-config libcapstone-dev clang-format cppcheck valgrind
```

**macOS (Homebrew) — macOS Tahoe 26 (AND NEWER):**
```bash
# Core build deps
brew install capstone nasm pkg-config

# xxd is typically already present at /usr/bin/xxd on macOS.
# If it isn't available for some reason, install Vim (xxd is bundled with it):
brew install vim
```

### macOS/Homebrew BUILD FIXES (REPO CHANGES)
Recent changes were made to improve macOS/Homebrew compatibility (notably on Apple silicon + Homebrew prefix `/opt/homebrew`):
- Updated `Makefile` and `makefile` to **use `CPPFLAGS` during compilation** and **`LDLIBS` during linking**, so `pkg-config`-discovered Capstone flags are honored.
- Normalized the Capstone include path emitted by Homebrew’s `pkg-config` from `.../include/capstone` to `.../include` so the project’s `#include <capstone/capstone.h>` resolves correctly.

Diff summary (high level):
- `$(CC) $(CFLAGS) -c ...` → `$(CC) $(CFLAGS) $(CPPFLAGS) -c ...`
- `$(CC) $(CFLAGS) -o ... $(LDFLAGS)` → `$(CC) $(CFLAGS) $(CPPFLAGS) -o ... $(LDFLAGS) $(LDLIBS)`
- `CAPSTONE_CFLAGS := pkg-config --cflags capstone` → normalized to an include path compatible with `<capstone/capstone.h>`

### TROUBLESHOOTING (macOS)
```bash
# Verify xxd is available (macOS usually ships /usr/bin/xxd)
command -v xxd

# Verify Capstone is discoverable via pkg-config
pkg-config --cflags capstone
pkg-config --libs capstone

# Clean rebuild
make clean
make
```

**Windows (WSL):**
Same as Ubuntu/Debian.

## BUILDING

Use the Makefile for builds:

- Default: `make` (optimized executable)
- Debug: `make debug` (symbols, sanitizers)
- Release: `make release` (-O3, native)
- Static: `make static` (self-contained)
- ML Trainer: `make train` (bin/train_model)
- Clean: `make clean` or `make clean-all`

Customization:
```bash
make CC=clang CFLAGS="-O3 -march=native" CPPFLAGS="$(pkg-config --cflags capstone)"
```

View config: `make info`

## INSTALLATION

Global install:
```bash
sudo make install
sudo make install-man
```

Uninstall:
```bash
sudo make uninstall
```

From GitHub:
```bash
curl -sSL https://raw.githubusercontent.com/umpolungfish/byvalver/main/install.sh | bash
```

## USAGE

```bash
byvalver [OPTIONS] <input> [output]
```

- Input/output can be files or directories (auto-batch)

**KEY OPTIONS:**
- `-h, --help`: Help
- `-v, --version`: Version
- `-V, --verbose`: Verbose
- `-q, --quiet`: Quiet
- `--bad-bytes BYTES`: Comma-separated hex bytes to banish (default: "00")
- `--profile NAME`: Use predefined bad-byte profile (e.g., http-newline, sql-injection)
- `--list-profiles`: List all available bad-byte profiles
- `--biphasic`: Obfuscate + denull
- `--pic`: Position-independent
- `--ml`: ML strategy selection
- `--xor-encode KEY`: `XOR` with stub
- `--format FORMAT`: raw|c|python|hexstring
- `-r, --recursive`: Recursive batch
- `--pattern PATTERN`: File glob
- `--no-preserve-structure`: Flatten output
- `--no-continue-on-error`: Stop on error
- `--menu`: Launch interactive TUI menu

**EXAMPLES:**
```bash
# Default: banish null bytes only (well-tested, recommended)
byvalver shellcode.bin clean.bin

# v3.0 NEW: List available bad-byte profiles
byvalver --list-profiles

# v3.0 NEW: Use predefined profile for HTTP contexts (eliminates 0x00, 0x0A, 0x0D)
byvalver --profile http-newline shellcode.bin clean.bin

# v3.0 NEW: Use profile for SQL injection contexts
byvalver --profile sql-injection shellcode.bin clean.bin

# v3.0 NEW: Use profile for URL-safe shellcode
byvalver --profile url-safe shellcode.bin clean.bin

# v3.0 NEW: Manual bad-byte specification (experimental - not extensively tested)
byvalver --bad-bytes "00,0a,0d" shellcode.bin clean.bin

# Combined with other features
byvalver --profile http-newline --biphasic --ml input.bin output.bin

# Batch processing with profile
byvalver -r --profile http-whitespace --pattern "*.bin" shellcodes/ output/

# Launch interactive TUI mode
byvalver --menu
```

## OBFUSCATION STRATEGIES

The obfuscation pass of `byvalver` (enabled via `--biphasic`) applies anti-analysis techniques:

### CORE OBFUSCATION TECHNIQUES

- **`MOV Register Exchange`**: `XCHG`/push-pop patterns
- **`MOV Immediate`**: Arithmetic decomposition
- **`Arithmetic Substitution`**: Complex equivalents
- **`Memory Access`**: Indirection and `LEA`
- **`Stack Operations`**: Manual `ESP` handling
- **`Conditional Jumps`**: `SETcc` and moves
- **`Unconditional Jumps`**: Indirect mechanisms
- **`Calls`**: `PUSH` + `JMP`
- **`Control Flow Flattening`**: Dispatcher states
- **`Instruction Substitution`**: Equivalent ops
- **`Dead Code`**: Harmless insertions
- **`Register Reassignment`**: Data flow hiding
- **`Multiplication by One`**: `IMUL` patterns
- **`NOP Sleds`**: Variable padding
- **`Polymorphic NOP Insertion`**: Multiple NOP equivalents (XCHG EAX,EAX, LEA, MOV)
- **`Constant Unfolding`**: Break immediates into arithmetic operations
- **`Register Renaming`**: XCHG-based register substitution
- **`Stack Spill Obfuscation`**: Stack-based arithmetic operations
- **`Instruction Reordering`**: NOP-inserted instruction shuffling
- **`Runtime Self-Modification`**: Self-modifying code generation
- **`Overlapping Instructions`**: Multi-interpretation byte sequences
- **`Jump Decoys`**: Fake targets
- **`Relative Offsets`**: Calculated jumps
- **`Switch-Based`**: Computed flow
- **`Boolean Expressions`**: De Morgan equivalents
- **`Variable Encoding`**: Reversible transforms
- **`Timing Variations`**: Delays
- **`Register State`**: Complex manipulations
- **`Stack Frames`**: Custom management
- **`API Resolution`**: Complex hashing
- **`String Encoding`**: Runtime decoding
- **`Constants`**: Expression generation
- **`Debugger Detection`**: Obfuscated checks
- **`VM Detection`**: Concealed methods

Priorities favor anti-analysis (high) over simple substitutions (low).

See [OBFUSCATION_STRATS](docs/OBFUSCATION_STRATS.md) for detailed strategy documentation.

## DENULLIFICATION STRATEGIES

The core denull pass uses over 170 strategies:

### `MOV` STRATEGIES
- Original pass-through
- `NEG`, `NOT`, `XOR`, `Shift`, `ADD/SUB` decompositions

### ARITHMETIC
- Original, `NEG`, `XOR`, `ADD/SUB`

### JUMPS/CONTROL
- `CALL/JMP` indirects
- Generic memory displacement
- Conditional offset elimination

### ADVANCED
- ModR/M bypass
- Flag-preserving `TEST`
- `SIB` addressing
- `PUSH` optimizations
- Windows-specific: `CALL/POP`, `PEB` hashing, `SALC`, `LEA` arithmetic, `shifts`, stack strings, etc.

### MODERN x64 FEATURES
- **RIP-Relative Optimization**: Offset decomposition, double-RIP calculation, stack-based methods
- **Bit Manipulation**: BSWAP byte reordering, BSF/BSR power-of-2 construction, POPCNT bit counting, BMI2 PEXT/PDEP
- **Flag Accumulation**: SETcc-based conditional jump elimination with linear flag operations

### OBFUSCATION ENHANCEMENT
- **Multi-Byte NOP Interlacing**: Arithmetic NOPs, register rotation, conditional NOPs, FPU operations
- **Register Dependency Chains**: Multi-instruction pattern optimization, instruction reordering
- **Negative Displacement Addressing**: Base register adjustments, alternative addressing modes

### MEMORY/DISPLACEMENT
- Displacement null handling
- `LEA` alternatives

Strategies are prioritized and selected via ML or deterministic order  

The modular registry allows easy addition of new strategies to handle emerging shellcode patterns.

See [DENULL_STRATS](docs/DENULL_STRATS.md) for detailed strategy documentation.

## ML TRAINING & VALIDATION

### TRAINING

Build trainer: `make train`

Run: `./bin/train_model`

- Data: `./shellcodes/`
- Output: `./ml_models/byvalver_ml_model.bin`
- Config: 10k samples, 50 epochs, 20% validation, LR 0.001, batch 32

Model auto-loaded at runtime with path resolution.

### TESTING ML MODE

```bash
# Smoke test
./bin/byvalver --ml shellcodes/linux_x86/execve.bin output.bin

# Check registry initialization
./bin/byvalver --ml test.bin output.bin 2>&1 | grep "ML Registry"
# Expected: "ML Registry] Initialized with XXX strategies"

# Batch processing with learning
./bin/byvalver --ml --batch shellcodes/linux_x86/*.bin output/

# View metrics
cat ml_metrics.log
```

**RECOMMENDATION:** ML mode needs retraining with diverse bad-byte datasets before production use. Currently optimized for null-byte banishment only.

## AGENT MENAGERIE

`byvalver` ships an **AI-powered agent pipeline** (`agents/`) that can autonomously discover gaps in the strategy registry, propose a novel bad-byte elimination technique, generate a complete C implementation, and wire it into the project — all in a single command.

The pipeline is built on the [AjintK](AjintK/) multi-provider agent framework and supports **Anthropic**, **DeepSeek**, **Qwen**, **Mistral**, and **Google** as LLM backends.

### QUICK START

```bash
# Requires API key for your chosen provider
export ANTHROPIC_API_KEY="..."   # or DEEPSEEK_API_KEY, QWEN_API_KEY, etc.

# Full pipeline: discover → propose → generate → implement + build
python3 run_technique_generator.py

# Dry-run: discover and propose only, no files written
python3 run_technique_generator.py --dry-run

# Target a specific architecture
python3 run_technique_generator.py --arch x64

# Use a different provider / model
python3 run_technique_generator.py --provider deepseek --model deepseek-chat
python3 run_technique_generator.py --provider anthropic --model claude-opus-4-6
```

### PIPELINE STAGES

| Stage | Agent | What it does |
|---|---|---|
| 1 | `StrategyDiscoveryAgent` | Scans `src/`, extracts all 340+ strategy names and categories, asks the LLM to summarise coverage gaps |
| 2 | `TechniqueProposalAgent` | Given the catalog, proposes one genuinely novel technique with rationale, target instruction, and approach |
| 3 | `CodeGenerationAgent` | Generates a complete `.h` + `.c` implementation conforming to `strategy_t` using `strategy.h`/`utils.h`/`mov_strategies.c` as reference |
| 4 | `ImplementationAgent` | Writes files to `src/`, patches `strategy_registry.c` (include → forward decl → register call), runs `make` |

### OPTIONS

```
--dry-run          Stop after Stage 2 — print proposal, write nothing
--arch             x86 | x64 | both  (default: both)
--provider         anthropic | deepseek | qwen | mistral | google  (default: anthropic)
--model            Model ID (provider-specific default applied if omitted)
--verbose          Print full LLM responses at each stage
```

### REQUIREMENTS

```bash
# Install Python dependencies (uses AjintK framework)
pip install anthropic tenacity httpx pyyaml

# Or with uv (faster)
uv pip install -r AjintK/requirements.txt
```

The pipeline has been validated with **DeepSeek** (`deepseek-chat`) and **Anthropic** (`claude-sonnet-4-6`).
On a typical run it discovers 340+ strategies, proposes a technique (e.g. VEX prefix re-encoding for SSE/AVX instructions), generates ~200 lines of C, and produces a clean build — fully unattended.

See [docs/AGENT_MENAGERIE.md](docs/AGENT_MENAGERIE.md) for architecture details and extending the pipeline with new agents.

## DEVELOPMENT

- Modern `C` with modularity
- Test suite: `bash tests/run_tests.sh` (see [tests/README.md](tests/README.md))
- Code style: Clang-Format (config: [.clang-format](.clang-format)), run `make format`
- Analysis: Cppcheck, Valgrind
- Docker: `docker build -t byvalver .` (see [Dockerfile](Dockerfile))
- Contributing: See [CONTRIBUTING.md](CONTRIBUTING.md)
- Roadmap: See [ROADMAP.md](ROADMAP.md)

## DOCUMENTATION

Full documentation is available in the [docs/](docs/) directory:

| Document | Description |
|---|---|
| [docs/USAGE.md](docs/USAGE.md) | Comprehensive usage guide with examples |
| [docs/BUILD.md](docs/BUILD.md) | Build instructions and platform-specific notes |
| [docs/TUI_README.md](docs/TUI_README.md) | Interactive TUI documentation |
| [docs/DENULL_STRATS.md](docs/DENULL_STRATS.md) | Denullification strategy catalog |
| [docs/OBFUSCATION_STRATS.md](docs/OBFUSCATION_STRATS.md) | Obfuscation technique documentation |
| [docs/BAD_BYTE_PROFILES.md](docs/BAD_BYTE_PROFILES.md) | Bad-byte profile reference |
| [docs/BADBYTEELIM_STRATS.md](docs/BADBYTEELIM_STRATS.md) | Extended elimination strategies |
| [docs/STRATEGY_HIERARCHY.md](docs/STRATEGY_HIERARCHY.md) | Strategy organization and priority |
| [docs/ADVANCED_STRATEGIES.md](docs/ADVANCED_STRATEGIES.md) | Advanced transformation techniques |
| [docs/WHITEPAPER.md](docs/WHITEPAPER.md) | Technical whitepaper |
| [docs/AGENT_MENAGERIE.md](docs/AGENT_MENAGERIE.md) | Agent pipeline: auto-technique generation |

## TROUBLESHOOTING

- Dependencies: Verify `Capstone`/`NASM`/xxd
- Builds: Check PATH_MAX, headers
- ML: Ensure model path
- Nulls: Confirm input format, dependencies

For persistent issues, use verbose mode and check logs  

If bad-byte banishment fails on specific shellcode, consider adding targeted strategies to the registry.

## LICENSE

`byvalver` is sicced freely upon the Earth under the [UNLICENSE](./UNLICENSE).

</DOCUMENT>