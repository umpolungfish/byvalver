# byvalver TUI (Text User Interface) Documentation

## Overview

byvalver includes a fully-featured interactive TUI mode with **complete CLI feature parity**. The TUI provides an intuitive, visual interface for all bad-character elimination operations, including advanced features like batch processing with live statistics, ML configuration, and comprehensive file browsing.

## Recent Improvements (December 2025)

### Latest Updates (v3.6.2)
- ✅ **Dual-Panel Batch Processing Layout**: Split-screen design for better information density
  - Left panel: Progress bar, configuration, file statistics, current/next file
  - Right panel: Strategy usage statistics table
  - Vertical separator (ASCII `|`) divides the panels
  - Maximizes visible information without scrolling
- ✅ **Arrow-Key Profile Navigation**: Improved bad-character profile selection
  - Navigate all 13 profiles with arrow keys or j/k (vi-style)
  - Fixes number input limitation (typing "10" was interpreted as "1")
  - Wrap-around navigation (top↔bottom)
  - Selection indicator shows current choice
- ✅ **Smart Bad Character Display**: Shows actual hex values when space permits
  - Displays hex values (e.g., "00,22,27,2d,3b") if ≤25 characters
  - Falls back to count (e.g., "5 configured") for longer sets
  - Eliminates confusion from displaying wrong values
- ✅ **Tilde Path Replacement**: Home directory paths collapsed for readability
  - `/home/username/path/to/file` → `~/path/to/file`
  - Saves screen space in file display sections
  - Maintains full path functionality
- ✅ **Improved Visual Spacing**: Better layout alignment
  - Added spacing between progress bar and strategy statistics
  - Cleaner separation of information sections

### Previous Updates (v3.6.1)

#### Critical Bug Fixes
- ✅ **Exit to Main Menu**: Fixed bug where processing completion would exit to command line instead of returning to main menu
  - Affects both single file and batch processing modes
  - Now properly returns to main menu, allowing continued operations

#### Display Enhancements
- ✅ **Full Strategy Names**: Strategy names no longer truncated (50 character display, previously 30)
  - Example: "Multi-Stage PEB Traversal Strategy" now fully visible
- ✅ **All Strategies Shown**: Removed artificial 10-strategy limit
  - All active strategies displayed in statistics table
- ✅ **Configuration Display**: Added real-time configuration display during batch processing
  - Shows bad chars count, biphasic mode, PIC generation, XOR encoding, ML status, output format
- ✅ **Improved Statistics**: Clearer progress tracking
  - "Completed: X / Y" format shows files attempted vs total
  - Success rate percentage calculated from completions
  - Eliminated confusing "Successful: 0" messages during processing

#### Re-Implemented Features
- ✅ **Graphical File Browser**: Restored file/directory browsing functionality
  - Available in both single file and batch processing screens
  - Browse input/output files and directories visually
- ✅ **Bad-Character Profiles**: Restored profile selection interface
  - Access to all 13 pre-configured profiles (http-newline, sql-injection, etc.)
  - Arrow-key navigation with visual selection indicator
  - Load profile option in Bad Characters screen

## Getting Started

To access the TUI menu, run byvalver with the `--menu` flag:

```bash
byvalver --menu
```

This launches the interactive text-based menu system. Make sure the ncurses library is installed on your system (see Requirements section below).

## Features

### 1. Main Menu Navigation (9 Options)
- **Process Single File** - Process individual shellcode files with visual feedback
- **Batch Process Directory** - Process entire directories with live progress tracking
- **Configure Processing Options** - Toggle biphasic mode, PIC generation, ML, verbose, dry-run
- **Set Bad Characters** - Manual entry or select from 13 predefined profiles
- **Output Format Settings** - Choose from 5 output formats (raw, C, Python, PowerShell, hexstring)
- **ML Metrics Configuration** - Configure ML strategy selection and metrics tracking
- **Advanced Options** - XOR encoding, timeouts, limits, validation settings
- **Load/Save Configuration** - INI-style configuration file management
- **About byvalver** - Version and help information

### 2. Visual File Browser
- **Directory navigation** with arrow keys (or vi-style j/k)
- **File/directory distinction** with [FILE] and [DIR] indicators
- **File size display** with human-readable formats (B, KB, MB, GB)
- **Extension filtering** (e.g., *.bin)
- **Intelligent path handling** - Automatically navigates to parent directory if file path is provided
- **Sorted display** - Directories first, then alphabetical
- **Multiple selection modes**:
  - `BROWSER_MODE_SELECT_FILE` - Only allows file selection (directories are navigated, not selected)
  - `BROWSER_MODE_SELECT_DIRECTORY` - Only allows directory selection
  - `BROWSER_MODE_SELECT_BOTH` - Allows either files or directories
- **Keyboard controls**:
  - ENTER: Select file or navigate into directory
  - SPACE: Select current directory (in directory mode)
  - q: Cancel and return

### 3. Batch Processing with Live Updates

The batch processing screen uses a **dual-panel layout** for maximum information density:

```
Left Panel (cols 2-58)          |  Right Panel (cols 62+)
                                |
Progress: [=============    ]   |  Strategy Usage Statistics:
                                |  Strategy              Total Succ  Rate
Configuration:                  |  -------------------------
  Bad chars: 00,0a,0d           |  lea_disp_enhanced       93   92  98.9%
  PIC Generation: ON            |  mov_mem_disp_null       66   65  98.5%
  Output format: raw            |  mov_imm_enhanced       106  106 100.0%
                                |  indirect_call_mem       23   23 100.0%
File Statistics:                |  arithmetic_imm          31   31 100.0%
  Completed:  7 / 12            |  mov_mem_disp_enhanced   83   83 100.0%
  Successful: 3                 |  Multi-Stage PEB         35   35 100.0%
  Failed:     4                 |  ... (all strategies)
  Success rate: 42.9%           |
                                |
Current file:                   |
  ~/RUBBISH/BIG_SAMPLE/file.bin |
                                |
Next file:                      |
  ~/RUBBISH/BIG_SAMPLE/next.bin |
```

#### Left Panel Contents

**Progress Bar**
```
Progress: [==========================                    ] 52/100
```

**Configuration Display** - Shows active processing configuration with actual bad char values:
- Bad characters: Displays hex values (e.g., `00,22,27,2d,3b`) if ≤25 chars, otherwise shows count
- Biphasic mode status (ON/OFF)
- PIC Generation status (ON/OFF)
- XOR Encoding with key (if enabled)
- ML Strategist status (ON/OFF)
- Output format

**Live File Statistics** (Color-Coded)
- **Completed**: Shows progress as "X / Y" (files attempted / total files)
- ✅ **Successful**: Green text - files with zero bad characters remaining
- ❌ **Failed**: Red text - files with errors or remaining bad characters
- **Success rate**: Percentage calculated from successful completions

**Current File Display**
- Shows the file currently being processed in **bold text**
- Home directory replaced with `~` for readability (e.g., `~/path/to/file` instead of `/home/user/path/to/file`)
- Truncated with `...` prefix if longer than 54 characters

**Next File Preview**
- Shows the next file in queue with **yellow/dim** text
- Also uses tilde notation for home directory paths

#### Right Panel Contents

**Dynamic Strategy Statistics Table**
```
Strategy Usage Statistics:
  Strategy                                            Total   Success      Rate
  ---------------------------------------------------------------------------------
  Multi-Stage PEB Traversal Strategy                  234       234    100.0%  (Green)
  Advanced Hash-Based API Resolution                  145       142     97.9%  (Green)
  Stack-Based Structure Construction                   89        67     75.3%  (Yellow)
  Enhanced LEA Arithmetic Substitution                 45        22     48.9%  (Red)
```

**Features**:
- **Full strategy names** displayed (up to 50 characters, no truncation)
- **All strategies shown** (not limited to top 10)
- **Color-coded by success rate**:
  - 🟢 Green: ≥80% success rate
  - 🟡 Yellow: 50-79% success rate
  - 🔴 Red: <50% success rate
- **Real-time updates** every 50ms during processing

#### Final Summary Screen
- Total files processed
- Success/failure/skipped counts with percentages
- Total input/output bytes
- Average size ratio
- **Press any key to return to main menu**
  - ✅ **Fixed**: Properly returns to main menu (no longer exits to command line)
  - Allows continuing with additional operations or configuration changes

### 4. Output Format Selection
Choose from 5 supported formats with descriptions:
- **raw** - Raw binary output
- **c** - C array format (`unsigned char shellcode[]`)
- **python** - Python bytes format (`shellcode = b"\x..."`)
- **powershell** - PowerShell array format (`$shellcode = @(0x..)`)
- **hexstring** - Hexadecimal string (AABBCCDD...)

### 5. ML Metrics Configuration
- **ML Strategy Selection** - Toggle ML-powered strategy selection
- **Enable Metrics Tracking** - Track strategy performance
- **Export JSON Metrics** - Export metrics to JSON format
- **Export CSV Metrics** - Export metrics to CSV format
- **Show Live Metrics** - Display live metrics during processing
- **Set Metrics Output File** - Configure output file path

### 6. Advanced Options
- **XOR Encoding** - Enable/disable XOR encoding with custom key (hex format)
- **Show Statistics** - Display detailed statistics after processing
- **Validate Output** - Verify output for bad characters
- **Set Strategy Limit** - Limit number of strategies (0 = unlimited)
- **Set Timeout** - Configure timeout in seconds (0 = no timeout)
- **Set Max File Size** - Maximum file size in bytes

### 7. Bad Character Configuration
Two input methods:
1. **Manual Entry** - Comma-separated hex values (e.g., `00,0a,0d`)
2. **Predefined Profiles** - 13 profiles for common scenarios:
   - null-only (default)
   - http-newline, http-whitespace
   - url-safe, sql-injection
   - xml-html, json-string
   - format-string, buffer-overflow
   - command-injection, ldap-injection
   - printable-only, alphanumeric-only

### 8. Configuration Management

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

[bad_characters]
bad_chars = 00

[ml]
use_ml_strategist = 0
metrics_enabled = 0

[batch]
file_pattern = *.bin
recursive = 0
preserve_structure = 1
```

## Navigation

- **Arrow Keys** (↑↓) or **j/k** (vi-style): Navigate between menu options
- **Enter**: Select highlighted option
- **q**: Quit the application or cancel operation
- **0-9**: Quick select menu option by number
- **Space**: Select current directory (in file browser directory mode)

## Requirements

Interactive mode requires the `ncurses` library to be installed on your system:

```bash
# Ubuntu/Debian
sudo apt install libncurses-dev

# CentOS/RHEL/Fedora
sudo dnf install ncurses-devel

# macOS (with Homebrew)
brew install ncurses
```

## Architecture

The TUI is built using a modular architecture:

```
src/tui/
├── tui_menu.h/c           # Main menu controller and navigation
├── tui_screens.h/c        # Screen implementations (13 screens total)
├── tui_file_browser.h/c   # Visual file/directory browser
├── tui_config_builder.h/c # Configuration management utilities
└── tui_widgets.h/c        # UI widget components
```

### Screen Components

1. **Main Screen** - Entry point with 9 navigation options
2. **Input Screen** - Single file selection with visual browser
3. **Batch Screen** - Directory selection and batch configuration
4. **Options Screen** - Processing option toggles (biphasic, PIC, ML, verbose, dry-run)
5. **Bad Characters Screen** - Manual entry or profile selection
6. **Output Format Screen** - Format selection with descriptions
7. **ML Metrics Screen** - ML configuration and metrics settings
8. **Advanced Options Screen** - XOR encoding, timeouts, limits
9. **Config Screen** - Load/save configuration files
10. **Processing Screen** - Live batch processing or single file processing
11. **Results Screen** - Processing results and statistics
12. **About Screen** - Version and help information
13. **Exit Screen** - Confirmation and cleanup

## Real Processing vs Mock Code

**All processing is 100% real and functional:**

- Uses the actual `process_single_file()` function from `src/processing.h`
- Calls real `find_files()`, `init_strategies()`, `init_obfuscation_strategies()`
- Tracks actual `batch_stats_t` with real strategy usage
- Creates real output files in the specified directory
- **No simulated progress** - all statistics are from actual processing

**Stdout/stderr handling during batch processing:**
- Verbose debug output is redirected to `/dev/null` during processing
- Prevents console output from overwriting the clean ncurses display
- Screen remains stable with only the progress UI visible
- After processing, stdout/stderr are restored for the summary

## Integration

The TUI integrates seamlessly with the core byvalver functionality:

- **Same processing engine** as CLI mode
- **All 165+ transformation strategies** available
- **Full bad-character elimination** capabilities
- **Identical output** to CLI mode
- **Supports all output formats** (raw, C, Python, PowerShell, hexstring)
- **Configuration file compatibility** between TUI and CLI
- **ML metrics** and statistics tracking
- **Batch processing** with same capabilities as CLI `-r` flag

## Build Options

The TUI is conditionally compiled based on ncurses availability:

- `make` - Builds with TUI support if ncurses is available
- `make no-tui` - Builds without TUI support (smaller binary)
- `make with-tui` - Forces TUI build (fails if ncurses not available)

## Troubleshooting

### Common Issues

1. **TUI not available**: Ensure ncurses library is installed
   ```bash
   sudo apt install libncurses-dev  # Ubuntu/Debian
   ```

2. **Display issues**: Resize terminal window or try different terminal emulator
   - Minimum recommended: 80x24 characters
   - For batch processing: 100x30 or larger for full strategy table

3. **Input not responding**: Check terminal settings for proper input handling

4. **File browser shows "Cannot read directory"**:
   - Verify directory permissions
   - Check that the path exists
   - Ensure you have read access to the directory

5. **Batch processing appears to hang**:
   - Screen updates are intentionally throttled (50ms delay between files)
   - Strategy initialization can take 2-5 seconds on first run
   - Watch for progress messages: "Scanning directory... Found X files"

### Terminal Compatibility

The TUI has been tested with:
- GNOME Terminal
- Konsole
- xterm
- iTerm2 (macOS)
- Windows Terminal (WSL)
- tmux/screen (works but may have color limitations)

### Performance Notes

- **Single file processing**: Instant visual feedback, <1 second for typical shellcode
- **Batch processing**: 50ms delay between files for visual updates
- **Large directories (100+ files)**: Scanning may take 1-2 seconds
- **Strategy initialization**: 2-5 seconds on first run (one-time cost per session)

## Development

### Adding New Screens

To add a new screen:
1. Add screen ID to `screen_id_t` enum in `tui_screens.h`
2. Add function declaration to `tui_screens.h`
3. Implement screen function in `tui_screens.c`
4. Update `run_tui_menu()` in `tui_menu.c` to handle new screen ID
5. Add navigation logic from existing screens

### Widget Customization

Custom widgets can be created by extending the existing widget framework:
1. Define widget structure in `tui_widgets.h`
2. Implement creation/drawing/handling functions
3. Add widget to the widget registry

### Color Pairs

The TUI uses the following color pairs:
- `COLOR_PAIR(1)`: White on Blue - Headers and footers
- `COLOR_PAIR(2)`: Black on White - Selected menu items
- `COLOR_PAIR(3)`: White on Red - Error messages, failed items
- `COLOR_PAIR(4)`: Green on Black - Success messages, high success rates
- `COLOR_PAIR(5)`: Yellow on Black - Warnings, medium success rates

## Example Workflow

### Single File Processing
1. Launch TUI: `byvalver --menu`
2. Select "1. Process Single File"
3. Select "1. Browse for Input File"
4. Navigate to your shellcode file and press ENTER
5. Select "2. Browse for Output File" (or enter path manually)
6. Select "3. Start Processing"
7. View results and statistics
8. Return to main menu

### Batch Processing
1. Launch TUI: `byvalver --menu`
2. Select "2. Batch Process Directory"
3. Select "1. Browse for Input Directory"
4. Navigate to your shellcode directory and press ENTER (or SPACE to select current directory)
5. Select "2. Browse for Output Directory"
6. Configure file pattern (default: *.bin)
7. Toggle recursive if needed
8. Select "6. Start Batch Processing"
9. Watch live progress with strategy statistics
10. Review final summary

### Configuration Management
1. Configure all options in the TUI (bad chars, output format, ML, etc.)
2. Select "8. Load/Save Configuration"
3. Select "2. Save Current Configuration"
4. Enter filename (e.g., `my_config.conf`)
5. Later: Select "1. Load Configuration File" to restore settings

## License

The TUI implementation is part of byvalver and is released under the same UNLICENSE terms.
