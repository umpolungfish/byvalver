# BYVALVER Usage Guide

## Overview

BYVALVER is an advanced command-line tool for automated removal of null bytes from shellcode while preserving functional equivalence. The tool leverages the Capstone disassembly framework to analyze x86/x64 assembly instructions and applies sophisticated transformation strategies.

**NEW in v3.0:** BYVALVER now supports generic bad-byte elimination via the `--bad-bytes` option, allowing users to specify arbitrary bytes to eliminate beyond just null bytes. This feature is functional but newly implemented - the 122+ transformation strategies were originally designed and optimized specifically for null-byte elimination.

## What's New in v4.3 — Agent Menagerie (February 2026)

### Auto-Technique Generator Pipeline

`byvalver` now ships an **AI-powered agent pipeline** that autonomously extends the strategy registry with new bad-byte elimination techniques.

#### Overview

Running a single command causes the pipeline to:

1. **Discover** all existing strategies by scanning `src/` and summarising coverage gaps
2. **Propose** a genuinely novel technique not already in the registry
3. **Generate** a complete C implementation (`.h` + `.c` files) conforming to the `strategy_t` interface
4. **Implement** — writes the files to `src/`, patches `strategy_registry.c`, and verifies with `make`

#### Usage

```bash
# Install Python dependencies
pip install anthropic tenacity httpx pyyaml

# Set your provider API key
export ANTHROPIC_API_KEY="..."    # Anthropic
export DEEPSEEK_API_KEY="..."     # DeepSeek (alternative)

# Full pipeline — runs all four stages
python3 run_technique_generator.py

# Preview mode — discover and propose, no code written
python3 run_technique_generator.py --dry-run

# Target a specific architecture
python3 run_technique_generator.py --arch x64

# Use DeepSeek instead of Anthropic
python3 run_technique_generator.py --provider deepseek

# Full option list
python3 run_technique_generator.py --help
```

#### Command-Line Options

| Option | Default | Description |
|---|---|---|
| `--dry-run` | off | Stop after Stage 2; print proposal, write nothing |
| `--arch` | `both` | Architecture hint passed to proposal agent: `x86`, `x64`, `both` |
| `--provider` | `anthropic` | LLM provider: `anthropic`, `deepseek`, `qwen`, `mistral`, `google` |
| `--model` | *(provider default)* | Model ID; omit to use the provider's recommended default |
| `--verbose` | off | Print full LLM responses at each pipeline stage |

#### Agent Architecture

The pipeline is built on the **AjintK** multi-provider async agent framework (`AjintK/`). Each stage is an independent `BaseAgent` subclass:

| File | Agent | Role |
|---|---|---|
| `agents/strategy_discovery_agent.py` | `StrategyDiscoveryAgent` | Scans `src/`, catalogs strategies, summarises gaps |
| `agents/technique_proposal_agent.py` | `TechniqueProposalAgent` | Proposes one novel technique as a structured JSON object |
| `agents/code_generation_agent.py` | `CodeGenerationAgent` | Generates `.h` + `.c` using `strategy.h`/`utils.h` as reference |
| `agents/implementation_agent.py` | `ImplementationAgent` | Writes files, patches registry (3 anchors), runs `make` |

#### Registry Patching

The `ImplementationAgent` applies exactly three targeted patches to `strategy_registry.c`:

1. `#include "NAME_strategies.h"` inserted before `#include <stdlib.h>`
2. `void register_NAME_strategies();` forward declaration inserted before `void init_strategies(...)`
3. `register_NAME_strategies();` call inserted before `register_remaining_null_elimination_strategies()`

#### Example Run

```
============================================================
  BYVALVER Auto-Technique Generator
============================================================
  Provider: deepseek
  Model   : deepseek-chat
  Arch    : both

[1/4] Discovering existing strategies...
  Found 343 strategies in 207 files across 136 categories

[2/4] Proposing novel technique...
  Strategy : vex_encoding_byte_evasion_strategies
  Name     : VEX Prefix Byte Substitution for SSE/AVX Instructions
  Targets  : MOVAPS, MOVUPS, XORPS, PADDB, VEX-encodable SSE/AVX
  Approach : Re-encode legacy SSE instructions using VEX C4/C5 prefix to
             shift the byte layout and eliminate bad bytes in opcode fields.

[3/4] Generating C implementation...
  Header : vex_encoding_byte_evasion_strategies.h (312 chars)
  Source : vex_encoding_byte_evasion_strategies.c (4821 chars)

[4/4] Writing files and registering strategy...

============================================================
  Result
============================================================
  SUCCESS: 'vex_encoding_byte_evasion' implemented and compiled!
    Wrote: src/vex_encoding_byte_evasion_strategies.h
    Wrote: src/vex_encoding_byte_evasion_strategies.c
  Patches: include=added, forward_decl=added, register_call=added
```

#### Supported Providers

| Provider | Env Var | Default Model |
|---|---|---|
| `anthropic` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-6` |
| `deepseek` | `DEEPSEEK_API_KEY` | `deepseek-chat` |
| `qwen` | `QWEN_API_KEY` | `qwen3-max` |
| `mistral` | `MISTRAL_API_KEY` | `codestral-2508` |
| `google` | `GOOGLE_API_KEY` | `gemini-pro` |

---

## What's New in v3.0.3 (December 2025)

### Partial Register Optimization Strategy Repair

**CRITICAL BUG FIX**: The "Partial Register Optimization" strategy has been completely repaired after being non-functional with a 100% failure rate.

#### Problem Summary

The strategy was designed to handle 8-bit register MOV instructions (e.g., `MOV AL, 0x42`) but had five critical bugs that caused every transformation to fail:

1. **Null Byte Injection**: Strategy was INTRODUCING null bytes instead of eliminating them
2. **Over-Broad Scope**: Claimed to handle all partial register instructions but only implemented MOV
3. **Zero Value Handling**: Even the initial fix still contained null bytes for zero immediates
4. **Priority Conflict**: Lower priority (89) than competing strategy (160), never got evaluated
5. **Register Coverage**: Only handled 2 out of 8 registers due to incorrect enum range check

#### Solution Implemented

The strategy now uses a proper null-free transformation approach:

**For zero values:**
```assembly
; Original: MOV AL, 0x00 (B0 00 - contains null)
; Fixed:    XOR EAX, EAX (31 C0 - no nulls, same size!)
```

**For non-zero values:**
```assembly
; Original: MOV AL, 0x42 (B0 42 - no nulls in this case)
; Fixed:    XOR EAX, EAX    (31 C0)
;           ADD AL, 0x42    (80 C0 42)
; Total: 5 bytes (was 2 bytes, but handles bad chars in immediate)
```

#### Results

**Before Fix:**
- Success Rate: 0% (0 successes, 139 failures)
- All transformations rolled back to fallback strategies
- Effectively a dead strategy in the registry

**After Fix:**
- Success Rate: 100% (all transformations succeed)
- Size Ratio: 1.00 for zero values (no expansion!)
- Coverage: All 8 8-bit registers (AL, BL, CL, DL, AH, BH, CH, DH)
- Priority: Increased to 165 (higher than generic MOV handler)

#### Performance Characteristics

**Comparison to Previous Handler (`mov_imm_enhanced`):**
- Previous: PUSH/MOV/POP sequence (~12-15 bytes)
- New: XOR/ADD sequence (2-5 bytes)
- **Improvement: 60-87% size reduction** for 8-bit MOV instructions

**Size Expansion:**
- `MOV r8, 0x00` → 0% expansion (2 bytes → 2 bytes)
- `MOV r8, imm8` → 150% expansion (2 bytes → 5 bytes)

#### Technical Details

**Files Modified:**
- `src/partial_register_optimization_strategies.c`
  - Added `get_reg_index_8bit()` helper for proper ModR/M encoding
  - Fixed `can_handle()` to only claim MOV r8, imm8 instructions
  - Fixed `generate()` with conditional ADD emission
  - Updated priority from 89 to 165

**Test Coverage:**
- Created `test_partial_reg.asm` with 25 test instructions
- 12 `MOV r8, 0x00` patterns (with null bytes)
- 8 `MOV r8, non-zero` patterns
- All tests pass with 0 null bytes in output

#### Impact on Users

**Transparent Fix:** No configuration changes or migration required. The fix automatically improves shellcode processing for:
- Any shellcode using 8-bit register moves
- Legacy shellcode with `MOV AL/BL/CL/DL, 0` patterns
- Compact shellcode requiring minimal size expansion

**When You'll See It:** The strategy primarily benefits specialized shellcode that uses 8-bit registers. Most modern shellcode uses 32-bit MOV instructions, so you may not see this strategy in typical batch processing results, but it's now ready when needed.

## What's New in v2.1.1

### Automatic Output Directory Creation

BYVALVER now automatically creates parent directories for output files, eliminating the need for manual directory setup:

**Features:**
- **Recursive Creation**: Automatically creates entire directory paths as needed
- **Deep Nesting Support**: Handles complex directory structures like `data/experiments/2025/batch_001/output.bin`
- **mkdir -p Behavior**: Works similar to Unix `mkdir -p` command
- **Improved Error Messages**: Shows exact file paths and specific error reasons when failures occur

**Example:**
```bash
# These commands now work without pre-creating directories
byvalver input.bin results/processed/output.bin
byvalver input.bin experiments/2025/december/run_042/shellcode.bin
```

**Benefits:**
- No more "No such file or directory" errors for output files
- Streamlines batch processing workflows
- Reduces manual directory management
- Ideal for automated scripts and pipelines

## What's New in v2.2

### Batch Directory Processing

**New in v2.2**: BYVALVER now includes comprehensive batch directory processing with full compatibility for all existing options.

#### New Command-Line Options

- `-r, --recursive` - Process directories recursively
- `--pattern PATTERN` - File pattern to match (default: *.bin)
- `--no-preserve-structure` - Flatten output (don't preserve directory structure)
- `--no-continue-on-error` - Stop processing on first error (default is to continue)

#### Auto-Detection

Batch mode is automatically enabled when the input is a directory:

```bash
# Single file mode (automatic)
byvalver input.bin output.bin

# Batch mode (automatic)
byvalver input_dir/ output_dir/
```

#### Compatibility with All Existing Options

All options work seamlessly with batch processing:
- `--biphasic` - Applies biphasic processing to all files
- `--pic` - Generates PIC code for all files
- `--ml` - Uses ML strategy selection for all files
- `--xor-encode KEY` - XOR encodes all processed files
- `--metrics, --metrics-json, --metrics-csv` - Aggregates metrics across all files
- `--quiet, --verbose` - Controls output level for batch operations
- `--dry-run` - Validates all files without processing

#### Usage Examples

Process all .bin files in a directory (non-recursive):
```bash
byvalver shellcodes/ output/
```

Process recursively with all subdirectories:
```bash
byvalver -r shellcodes/ output/
```

Process only .txt files recursively:
```bash
byvalver -r --pattern "*.txt" input/ output/
```

Process with biphasic mode and XOR encoding:
```bash
byvalver -r --biphasic --xor-encode 0x12345678 input/ output/
```

Flatten output (don't preserve directory structure):
```bash
byvalver -r --no-preserve-structure input/ output/
```

Stop processing on first error (default is to continue):
```bash
byvalver -r --no-continue-on-error input/ output/
```

#### Implementation Details

**New Files:**
- `src/batch_processing.h` - Batch processing API
- `src/batch_processing.c` - Directory traversal, file discovery, and statistics

**Key Features:**
- **Automatic directory creation** - Parent directories created automatically (preserves existing functionality)
- **Pattern matching** - Uses fnmatch for flexible file pattern matching
- **Directory structure preservation** - Optional preservation of input directory hierarchy
- **Comprehensive statistics** - Tracks total files, processed, failed, skipped, and size metrics
- **Progress reporting** - Shows progress as [N/Total] filename
- **Error handling** - Configurable error handling (stop or continue on errors)

#### Tested Scenarios

✅ Non-recursive batch processing
✅ Recursive batch processing
✅ Directory structure preservation
✅ Flattened output (--no-preserve-structure)
✅ Custom file patterns (--pattern)
✅ Compatibility with --biphasic
✅ Compatibility with --xor-encode
✅ Error handling with --no-continue-on-error
✅ Empty file handling

All existing single-file functionality remains unchanged and fully compatible!

## What's New in v2.2.1

### ML Prediction Tracking System

**New in v2.2.1**: BYVALVER now properly tracks and records ML predictions with outcome-based accuracy metrics.

#### Problem Fixed

Previous versions showed "Predictions Made: 0" in ML metrics even when the neural network was actively reprioritizing strategies. The ML model was performing inference and learning from feedback, but predictions were never being recorded in the metrics system.

**Root Cause:** The `ml_reprioritize_strategies()` function performed neural network inference to reorder strategies but never called `ml_metrics_record_prediction()`. Learning happened (feedback iterations were tracked), but prediction counts remained at zero.

#### Solution Implemented

A comprehensive three-component prediction tracking system:

##### 1. **Prediction State Tracking**
Global state variables track the ML model's prediction for each instruction:
```c
static strategy_t* g_last_predicted_strategy = NULL;
static double g_last_prediction_confidence = 0.0;
```

##### 2. **Prediction Storage**
When the ML model reprioritizes strategies (`ml_reprioritize_strategies()`):
- The top-ranked strategy (index 0) is stored as the prediction
- The ML confidence score for that strategy is saved
- Prediction is held in pending state until outcome is known

##### 3. **Outcome-Based Recording**
When strategy application completes (`ml_provide_feedback()`):
- Compares applied strategy against stored prediction
- Determines if prediction was correct:
  - **Correct**: Predicted strategy was used AND succeeded
  - **Incorrect**: Different strategy used OR predicted strategy failed
- Records prediction with actual outcome via `ml_metrics_record_prediction()`
- Clears prediction state for next instruction

#### Implementation Architecture

**Key Files Modified:**
- `src/ml_strategist.c:39-41` - Added prediction state variables
- `src/ml_strategist.c:398-407` - Store predictions in `ml_reprioritize_strategies()`
- `src/ml_strategist.c:537-562` - Verify and record predictions in `ml_provide_feedback()`

**Processing Flow:**
```
Instruction Analysis
       ↓
ML Neural Network Inference (reprioritize)
       ↓
Store Top Strategy + Confidence
       ↓
Apply Strategy
       ↓
Compare Outcome vs Prediction
       ↓
Record Prediction (correct/incorrect)
       ↓
Update Accuracy Metrics
```

#### Before vs After

**Before Fix:**
```
=== ML STRATEGIST PERFORMANCE SUMMARY ===
Instructions Processed: 3702
Strategies Applied: 3693
Null Bytes Eliminated: 3693 / 3702 (99.76%)

--- Model Performance ---
Predictions Made: 0          ← No predictions recorded
Current Accuracy: 0.00%      ← No accuracy tracking
Avg Prediction Confidence: 0.0000

--- Learning Progress ---
Learning Enabled: YES
Total Feedback Iterations: 7395  ← Learning WAS happening
Positive Feedback: 3693
```

**After Fix:**
```
=== ML STRATEGIST PERFORMANCE SUMMARY ===
Instructions Processed: 4
Strategies Applied: 4
Null Bytes Eliminated: 4 / 4 (100.00%)

--- Model Performance ---
Predictions Made: 4          ← Predictions now tracked
Current Accuracy: 100.00%    ← Real accuracy metrics
Avg Prediction Confidence: 0.0062  ← Actual confidence values

--- Learning Progress ---
Learning Enabled: YES
Total Feedback Iterations: 8
Positive Feedback: 4
```

#### Benefits

- **Accurate Metrics**: Prediction counts now reflect actual ML model usage
- **Real Accuracy**: Accuracy percentages based on actual prediction outcomes
- **Confidence Tracking**: Average confidence reflects true ML model confidence scores
- **Learning Validation**: Confirms ML model is making predictions, not just learning
- **Performance Analysis**: Enables evaluation of ML model effectiveness over time
- **Debugging Support**: Provides visibility into ML decision-making process

## What's New in v2.5

### Windows-Specific Denull Strategies

**New in v2.5**: BYVALVER now includes 10 new Windows-specific denull strategies identified from analysis of real Windows shellcode patterns:

#### CALL/POP Immediate Loading Strategy
- **Description**: Use the CALL/POP technique to load immediate values that contain null bytes by pushing the value onto the stack and retrieving it without directly encoding the nulls.
- **Usage**: Automatically applied to MOV reg, imm32 where immediate contains null bytes.
- **Example**: MOV EAX, 0x00123456 → PUSH 0x00123456; POP EAX (with null-free construction)

#### PEB API Hashing Strategy
- **Description**: Use PEB (Process Environment Block) traversal to find kernel32.dll base address, then use hash-based API resolution to call functions without hardcoded addresses containing nulls.
- **Usage**: Automatically applied to CALL immediate_address where address contains null bytes.
- **Example**: CALL 0x7C86114D → PEB traversal + hash-based resolution + call via register

#### SALC + Conditional Flag Manipulation Strategy
- **Description**: Use SALC (Set AL on Carry) instruction combined with flag manipulation to set AL register efficiently, avoiding MOV AL, 0x00.
- **Usage**: Automatically applied to MOV AL, 0x00 or MOV AL, 0xFF patterns.
- **Example**: MOV AL, 0x00 → CLC; SALC (F8 D6 - no nulls)

#### LEA Arithmetic Substitution Strategy
- **Description**: Use LEA (Load Effective Address) instruction to perform arithmetic operations like addition and multiplication without using immediate values that contain nulls.
- **Usage**: Automatically applied to ADD reg, imm32 / SUB reg, imm32 where immediate contains null bytes.
- **Example**: ADD EAX, 0x00000040 → LEA EAX, [EAX + 0x40]

#### Shift-Based Value Construction Strategy
- **Description**: Use bit shift operations combined with arithmetic to construct values that contain null bytes in their direct encoding.
- **Usage**: Automatically applied to MOV reg, imm32 where immediate contains null bytes that could be constructed via shifts.
- **Example**: MOV EAX, 0x00200000 → XOR EAX, EAX; MOV AL, 0x20; SHL EAX, 12

#### Stack-Based String Construction Strategy
- **Description**: Construct strings on the stack using multiple PUSH operations with non-null byte chunks, avoiding direct string literals.
- **Usage**: Automatically applied to PUSH operations with immediate values representing string constants containing null bytes.
- **Example**: PUSH 0x00646D63 (pushing "cmd\0") → multiple PUSH operations of non-null chunks

#### Enhanced Immediate Encoding Strategies
- **Description**: Multiple new approaches for immediate value construction including byte-by-byte construction and alternative displacement handling.
- **Usage**: Applied to various MOV and arithmetic operations with null-containing immediate values.

#### Register Swapping with Immediate Loading Strategy
- **Description**: Use register exchange operations (XCHG) to load immediate values by first loading null-free partial values and then exchanging them.
- **Usage**: Applied contextually when register swapping is appropriate.

#### Alternative LEA Complex Displacement Strategy
- **Description**: Alternative approach to handle LEA and MOV instructions with null-containing displacements using complex addressing.
- **Usage**: Applied to MOV reg, [disp32] where displacement contains null bytes.

#### String Instruction Byte Construction Strategy
- **Description**: Use STOSB, STOSD, or similar string instructions with loops to construct immediate values containing nulls in memory rather than through direct immediate encoding.
- **Usage**: Applied to MOV reg, imm32 where immediate contains null bytes.

## What's New in v2.4

### Comprehensive Strategy Repair

**New in v2.4**: BYVALVER now includes comprehensive fixes for critical bugs across 15+ transformation strategies that showed 0% success rates despite high attempt counts.

#### The Critical Root Causes and Fixes:

**Issue 1: Register Indexing Problems Across Multiple Files**
- **Problem**: Many strategies used `reg - X86_REG_EAX` instead of `get_reg_index(reg)` causing improper register encoding
- **Impact**: Strategies like `generic_mem_null_disp`, `mov_mem_disp_null`, and others failed due to incorrect MOD/RM byte construction
- **Fix**: Replaced all occurrences with proper `get_reg_index()` function
- **Files Affected**: `src/jump_strategies.c`, `src/memory_displacement_strategies.c`, `src/cmp_strategies.c`, `src/syscall_number_strategies.c`

## What's New in v3.0

### Generic Bad-Byte Elimination Framework

**New in v3.0**: BYVALVER now includes a generic bad-byte elimination framework that extends beyond null-byte removal.

#### New Command-Line Option

- `--bad-bytes "XX,YY,ZZ"` - Comma-separated hex bytes to eliminate (e.g., `--bad-bytes "00,0a,0d"`)

#### Auto-Detection

When `--bad-bytes` is not specified, the tool defaults to null-byte-only elimination (identical to v2.x behavior).

```bash
# Default mode (null-byte elimination only)
byvalver input.bin output.bin

# Generic bad-byte mode (experimental)
byvalver --bad-bytes "00,0a,0d" input.bin output.bin
```

#### Usage Examples

Eliminate null bytes only (default, well-tested):
```bash
byvalver samples/calc.bin output.bin
```

Eliminate newlines for network protocols (experimental):
```bash
byvalver --bad-bytes "00,0a,0d" samples/calc.bin output.bin
```

Eliminate multiple bad bytes (experimental):
```bash
byvalver --bad-bytes "00,20,09,0a,0d" samples/calc.bin output.bin
```

> [!IMPORTANT]
> **Null-byte elimination** (default mode or `--bad-bytes "00"`): Well-tested with 100% success rate on test suite
>
> **Generic bad-byte elimination** (`--bad-bytes` with non-null values): Newly implemented in v3.0. The framework is functional and strategies apply generically, but effectiveness for non-null characters has not been comprehensively validated. Strategies were originally designed, tested, and optimized specifically for null-byte elimination.

#### Implementation Details

**Architecture:**
- O(1) bitmap lookup for bad byte checking
- Global context pattern for configuration access
- Backward compatible: no `--bad-bytes` = identical to v2.x behavior

**Python Verification:**
The `verify_denulled.py` script now supports generic bad-byte verification:
```bash
python3 verify_denulled.py output.bin --bad-bytes "00,0a,0d"
```

#### Current Status

**Functional:** The framework is fully implemented and operational. All 122+ strategies have been updated to use the generic bad-byte API.

**Experimental:** The strategies were originally designed, tested, and optimized specifically for null-byte elimination. While they now support generic bad bytes at the implementation level, they have not been:
- Extensively tested with non-null bad byte sets
- Optimized for specific bad byte combinations
- Validated against diverse real-world scenarios with arbitrary bad bytes

**Recommended Usage:** For production use, continue using default mode (null-byte elimination). Use `--bad-bytes` for experimental purposes and report any issues encountered.

## What's New in v3.0.1 (December 2025)

### ML Implementation Comprehensive Fixes

**CRITICAL ARCHITECTURAL OVERHAUL**: The ML-based strategy selection system has undergone a complete rewrite to address all identified architectural issues.

#### Problems Fixed

**Issue 1: Feature Vector Instability (CRITICAL)**
- **Problem**: Feature indices were sliding based on operand count, preventing network from learning stable patterns
- **Example**: Feature[7] could be operand_type[1] OR register[0] depending on instruction
- **Fix**: Implemented fixed 34-dimensional layout with dedicated slots:
  ```
  [0-4]   : Basic features (insn_id, size, has_bad_chars, bad_char_count, op_count)
  [5-8]   : Operand types (ALWAYS 4 slots, 0 if unused)
  [9-12]  : Register operands (ALWAYS 4 slots, 0 if not register)
  [13-16] : Immediate operands (ALWAYS 4 slots, normalized)
  [17-32] : Memory operands (base, index, scale, disp - 16 slots total)
  [33]    : Prefix count
  ```
- **Impact**: Network can now learn consistent patterns across all instructions

**Issue 2: Output Index Mismatch (CRITICAL)**
- **Problem**: Forward pass used sequential indices, training used hash-based indices
- **Example**: Strategy "MOV NEG" predicted using index[5] but trained on index[127]
- **Fix**: Created stable strategy registry (`src/ml_strategy_registry.h/c`)
  - Bidirectional mapping: strategy ↔ stable index
  - Sequential stable indices (0 to N-1)
  - Same index used for forward pass and backpropagation
- **Impact**: Network now trains and predicts using the same indices

**Issue 3: Effectively Single-Layer Network (CRITICAL)**
- **Problem**: Only updated output layer weights; input-to-hidden weights frozen at random initialization
- **Fix**: Implemented full backpropagation through ALL layers
  - Computes gradients for hidden layer
  - Updates input-to-hidden weights
  - Updates hidden-to-output weights
  - Applies ReLU derivative correctly
- **Impact**: Hidden layer can now learn representations; network has full 256-neuron capacity

**Issue 4: Wrong Gradient Calculation (HIGH)**
- **Problem**: Used sigmoid derivative but activation is softmax
- **Fix**: Corrected to softmax + cross-entropy gradient: `delta = actual - target`
- **Impact**: Gradients are now mathematically correct; loss will actually decrease

**Issue 5: No Output Masking (HIGH)**
- **Problem**: 90-95% of output neurons represented invalid strategies, diluting gradients
- **Fix**: Implemented output masking before softmax
  - Sets invalid strategy logits to `-INFINITY`
  - Only applicable strategies contribute to loss
  - Gradients focused on relevant strategies
- **Impact**: Network focuses learning on valid strategies only

#### New Components

**Files Created:**
- `src/ml_strategy_registry.h` (92 lines) - Registry interface
- `src/ml_strategy_registry.c` (146 lines) - Registry implementation
- `docs/ML_FIXES_2025.md` (700+ lines) - Complete technical documentation

**Files Modified:**
- `src/ml_strategist.c` - 5 major functions rewritten
- `src/strategy_registry.c` - Added ML registry initialization

#### Build Status

✅ **Compiles without errors or warnings**
✅ **148 object files built successfully**
✅ **Binary tested and functional**
✅ **ML registry initializes with 184 strategies**

#### Testing Recommendations

```bash
# Phase 1: Smoke Tests
./bin/byvalver --ml shellcodes/linux_x86/execve.bin output.bin
./bin/byvalver --ml test.bin output.bin 2>&1 | grep "ML Registry"

# Phase 2: Validation Tests
./bin/byvalver --ml --batch shellcodes/linux_x86/*.bin output/
cat ml_metrics.log | grep "avg_weight_change"

# Phase 3: Effectiveness Tests
./bin/byvalver shellcodes/*.bin output_baseline/     # Baseline
./bin/byvalver --ml shellcodes/*.bin output_ml/      # ML mode
diff -r output_baseline/ output_ml/                  # Compare
```

#### Known Limitations

**Not Yet Fixed (Future Work):**
1. **Categorical features as scalars** - Instruction IDs still treated as numbers rather than one-hot encoded
2. **No multi-instruction context** - Only sees current instruction, not surrounding code
3. **Random weight initialization** - Not pre-trained on large corpus
4. **No regularization** - No dropout or L2 penalty

**Current Status:** Theoretically sound but requires empirical validation with diverse training data.

**Recommendation:** Use deterministic mode for production. ML mode is ready for research/testing but needs retraining with varied bad-byte datasets.

See `docs/ML_FIXES_2025.md` for complete technical details, benchmarks, and roadmap.

---

## What's New in v3.0.2 (ML Architecture v2.0 - December 2025)

### Complete ML Architecture Overhaul: One-Hot Encoding + Context Window

**CRITICAL ARCHITECTURAL UPDATE**: The ML-based strategy selection system has been upgraded to Architecture v2.0, implementing proper categorical encoding and multi-instruction context awareness.

#### Problems Fixed

**Issue 6: Categorical Data as Scalar (MEDIUM) - ✅ FIXED**
- **Problem**: Instruction IDs were treated as scalar numbers (MOV=634, ADD=9), creating false ordinal relationships
- **Impact**: Network couldn't learn instruction-specific patterns; assumed MOV was "larger" than ADD
- **Fix**: Implemented one-hot encoding for top-50 most common x86 instructions + OTHER bucket
  - 51-dimensional one-hot vectors per instruction
  - Top-50 instructions identified from shellcode frequency analysis: MOV, PUSH, POP, XOR, LEA, ADD, SUB, CALL, JMP, RET, CMP, TEST, AND, OR, SHL, SHR, INC, DEC, IMUL, MUL, NOP, INT, SYSCALL, CDQ, XCHG, NEG, NOT, MOVZX, MOVSX, JE, JNE, JA, JB, JL, JG, JAE, JBE, JLE, JGE, STOSB, LODSB, SCASB, MOVSB, LOOP, LEAVE, ENTER, DIV, IDIV, SAR, ROL
  - "OTHER" bucket (index 50) for remaining ~1,450 instructions
  - O(1) lookup via static array mapping
- **Result**: Network can now learn instruction-specific transformation patterns without scalar bias

**Issue 7: No Context Window (LOW) - ✅ FIXED**
- **Problem**: Model only saw current instruction, not surrounding code context
- **Impact**: Couldn't learn sequential patterns like "PUSH-POP pairs" or "MOV-XOR sequences"
- **Fix**: Implemented sliding context window with 3 previous instructions
  - Context buffer maintains last 3 instructions with full feature vectors
  - Feature input: 4 instructions × 84 features = 336 dimensions
  - Automatic zero-padding for start-of-shellcode (first 1-3 instructions)
  - Circular buffer management with automatic history updates
- **Result**: Network can now learn context-dependent strategy selection

#### New Architecture v2.0

**Previous Architecture (v1.0)**:
```
Input:  128 features (scalar insn_id + operands)
Hidden: 256 neurons (ReLU)
Output: 200 strategies (softmax)
Parameters: ~84,000
Model Size: ~660 KB
```

**Current Architecture (v2.0)**:
```
Input:  336 features (4 instructions × 84 features each)
        - Current instruction: 51 one-hot + 33 other features
        - Previous instruction 1: 51 one-hot + 33 other features
        - Previous instruction 2: 51 one-hot + 33 other features
        - Previous instruction 3: 51 one-hot + 33 other features
Hidden: 512 neurons (ReLU, He initialization)
Output: 200 strategies (softmax, Xavier initialization)
Parameters: ~204,000
Model Size: ~1.66 MB
```

**Feature Layout per Instruction (84 dimensions)**:
```
[0-50]   : One-hot instruction encoding (51 dims)
[51]     : instruction_size (1-15 bytes)
[52]     : has_bad_chars (0 or 1)
[53]     : bad_char_count (0-N)
[54]     : operand_count (0-4)
[55-58]  : operand_type[0-3] (4 slots, always fixed)
[59-62]  : register[0-3] (4 slots, 0 if not register operand)
[63-66]  : immediate[0-3] normalized (4 slots)
[67-70]  : memory_base[0-3] (4 slots)
[71-74]  : memory_index[0-3] (4 slots)
[75-78]  : memory_scale[0-3] (4 slots)
[79-82]  : memory_disp[0-3] normalized (4 slots)
[83]     : prefix_count
```

#### New Components

**Files Created:**
- `src/ml_instruction_map.h` (40 lines) - Instruction one-hot encoding interface
- `src/ml_instruction_map.c` (127 lines) - Fast O(1) instruction-to-index mapping with top-50 lookup table

**Files Modified:**
- `src/ml_strategist.h` - Updated constants (NN_INPUT_SIZE=336, NN_HIDDEN_SIZE=512, added ONEHOT_DIM, FEATURES_PER_INSN, CONTEXT_WINDOW_SIZE)
- `src/ml_strategist.c` - Complete feature extraction rewrite with context management
- `docs/ML_FIXES_2025.md` - Issues 6 & 7 marked as FIXED

#### Breaking Changes

**⚠️ MODEL INCOMPATIBILITY**: v1.0 models are completely incompatible with v2.0 architecture

- **Different Input Dimensions**: 128 → 336 features
- **Different Hidden Layer**: 256 → 512 neurons
- **Different Feature Layout**: Scalar instruction IDs → One-hot encoding
- **Model File Validation**: Automatic architecture mismatch detection on load

**Migration Required**: All existing models must be retrained from scratch:
```bash
# Old v1.0 models will fail to load
./bin/byvalver --load-model old_model_v1.0.bin --ml input.bin output.bin
# Error: Model architecture mismatch!
#   Expected: [336, 512, 200]
#   Got: [128, 256, 200]

# Solution: Retrain with v2.0
./bin/train_model  # Creates new v2.0 model
./bin/byvalver --ml input.bin output.bin
```

#### Performance Characteristics

**Computational Impact**:
- **Inference Speed**: ~3-5× slower per instruction (larger network, more features)
- **Memory Usage**: ~2.5× larger model files (660 KB → 1.66 MB)
- **Training Time**: ~4× slower per training example

**Accuracy Impact (Expected)**:
- **Improvement**: 10-30% better strategy selection accuracy
- **Reason**: Proper categorical encoding + sequential context awareness
- **Validation**: Requires empirical testing on diverse shellcode datasets

#### Usage Examples

Enable ML mode with v2.0 architecture (same command, new architecture):
```bash
# Standard ML mode (uses v2.0 architecture)
./bin/byvalver --ml input.bin output.bin

# Works with all existing options
./bin/byvalver --ml --biphasic --xor-encode 0x12345678 input.bin output.bin

# Batch processing with ML v2.0
./bin/byvalver -r --ml shellcodes/ output/
```

Train new v2.0 model:
```bash
# Training automatically uses v2.0 architecture
./bin/train_model

# Model will be saved with v2.0 dimensions
# Output: ./ml_models/byvalver_ml_model.bin (v2.0)
```

Save and load v2.0 models:
```bash
# Save current v2.0 model state
./bin/byvalver --save-model models/v2.0_checkpoint.bin

# Load v2.0 model (automatic validation)
./bin/byvalver --load-model models/v2.0_checkpoint.bin --ml input.bin output.bin
```

#### Build Status

✅ **Compiles without errors or warnings**
✅ **149 object files built successfully**
✅ **ML instruction map initializes with 50 top instructions + OTHER**
✅ **Context buffer automatically manages history**
✅ **Model save/load includes architecture validation**

#### Current Status

**Functional**: Architecture v2.0 is fully implemented and operational.

**Experimental**: While theoretically superior, the v2.0 architecture:
- Has not been extensively trained on large shellcode corpus
- Requires retraining from scratch (no pre-trained weights)
- Needs empirical validation for accuracy improvements
- Performance characteristics (3-5× slower) need real-world benchmarking

**Recommended Usage**:
- **Research/Testing**: Enable with `--ml` flag to evaluate effectiveness
- **Production**: Continue using deterministic mode until v2.0 is validated
- **Reporting**: Please report accuracy improvements or regressions

See `docs/ML_FIXES_2025.md` for complete technical details, mathematical formulations, and implementation roadmap.

---

## What's New in v2.5

### ML Training Integration

**New in v2.5**: BYVALVER now includes a dedicated training utility and enhanced ML integration with path resolution capabilities.

#### Training Utility

A standalone `train_model` utility has been added to train the ML model on custom shellcode datasets:

```bash
# Build the training utility
make train

# Run training (defaults to shellcodes/ directory and ml_models/ output)
./bin/train_model
```

The training utility includes:
- Data generation from shellcode files in the `./shellcodes/` directory
- Neural network training with configurable parameters
- Model evaluation and performance validation
- Statistics reporting and export

#### Enhanced Path Resolution

The ML model loading now uses enhanced path resolution that dynamically determines the model file location based on the executable path:

- Uses `readlink` on `/proc/self/exe` to determine the executable location
- Constructs the model path relative to the executable location
- Includes fallback to default path if path resolution fails
- Works correctly regardless of where the executable is moved

#### Training Configuration

The training process includes configurable parameters:
- **Training Data Directory**: Defaults to `./shellcodes/`
- **Model Output Path**: Defaults to `./ml_models/byvalver_ml_model.bin`
- **Max Training Samples**: Configurable, default 10,000
- **Training Epochs**: Configurable, default 50
- **Validation Split**: Configurable, default 20% for validation
- **Learning Rate**: Configurable, default 0.001
- **Batch Size**: Configurable, default 32

#### Usage Examples

Build the main executable and training utility:
```bash
# Build main executable
make

# Build training utility
make train
```

Train the ML model:
```bash
# Run training with default configuration
./bin/train_model

# The training utility will:
# - Process shellcode files from ./shellcodes/
# - Train the neural network with 50 epochs
# - Validate on 20% of the data
# - Save the trained model to ./ml_models/
# - Generate training statistics report
```

#### ML Model Integration

The main `byvalver` executable now includes:
- Dynamic model path resolution at runtime
- Fallback to default weights if model file is not found
- Enhanced error reporting for model loading issues
- Path-independent operation regardless of executable location

The ML functionality can be enabled with the `--ml` option:
```bash
# Enable ML-powered strategy selection
byvalver --ml input.bin output.bin

# Works with all other options including batch processing
byvalver -r --ml --biphasic input/ output/
```