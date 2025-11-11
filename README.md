# `byvalver`: THE SHELLCODE NULL-BYTE ELIMINATOR / `·𐑚𐑲𐑝𐑨𐑤𐑝𐑼`: 𐑞 𐑖𐑧𐑤𐑒𐑴𐑛 𐑯𐑫𐑤–𐑚𐑲𐑑 𐑩𐑤𐑦𐑥𐑦𐑯𐑱𐑑𐑼

![vape](./IMAGES/VAPE.png)

## OVERVIEW / 𐑴𐑝𐑻𐑝𐑿

`byvalver` is an automated framework designed to algorithmically remove null bytes from shellcode  

`null-bytes` (`\x00`) often act as `string terminators` in many programming languages & environments 

this causes shellcode containing null-bytes to exit during its own execution

`byvalver`: 

+ (I) takes **raw binary shellcode** as input --> 
+ (II) **replaces instructions** containing null bytes with **functionally equivalent, nullbyte-free alternatives** --> 
+ (III) outputs **clean, nullbyte-free**, read-to-use shellcode  

the core of `byvalver` is a powerful disassembly and reconstruction engine built on the [Capstone disassembly framework](http://www.capstone-engine.org/)  

it meticulously analyzes each instruction and applies a growing set of replacement strategies to ensure the final shellcode is both functional and de-nullified

## BUILDING AND USAGE / 𐑚𐑦𐑤𐑛𐑦𐑙 𐑯 𐑿𐑕𐑦𐑡

### PREREQUISITES / 𐑐𐑮𐑰𐑮𐑧𐑒𐑢𐑦𐑟𐑦𐑑𐑕

*   A C compiler (e.g., `gcc`).
*   The [Capstone disassembly library](http://www.capstone-engine.org/) installed with development headers.
*   GNU Binutils (specifically `objcopy`) if you need to process executables like PE or ELF files.

### BUILDING / 𐑚𐑦𐑤𐑛𐑦𐑙

To build the project, simply run `make` in the root directory:

```bash
make
```
This will compile the source code and create the `byvalver` executable in the `bin` directory.

### USAGE FOR RAW SHELLCODE / 𐑿𐑕𐑦𐑡 𐑓𐑹 𐑮𐑭 𐑖𐑧𐑤𐑒𐑴𐑛

+ **CREATE A SHELLCODE FILE / 𐑒𐑮𐑰𐑱𐑑 𐑩 𐑖𐑧𐑤𐑒𐑴𐑛 𐑓𐑲𐑤:** Place your raw binary shellcode into a file (e.g., `shellcode.bin`)

+ **RUN `byvalver` / 𐑮𐑳𐑯 `·𐑚𐑲𐑝𐑨𐑤𐑝𐑼`:**

    ```bash
    ./bin/byvalver shellcode.bin
    ```
The tool will write the modified, null-free shellcode to `output.bin`

### XOR ENCODING FEATURE / XOR 𐑧𐑯𐑒𐑴𐑛𐑦𐑙 𐑓𐑰𐑗𐑼

`byvalver` includes a powerful XOR encoding feature that allows you to further obfuscate your processed shellcode:

+ **PROCESS SHELLCODE AND APPLY XOR ENCODING / 𐑐𐑮𐑭𐑕𐑧𐑕 𐑖𐑧𐑤𐑒𐑴𐑛 𐑯 𐑩𐑐𐑤𐑲 XOR 𐑧𐑯𐑒𐑴𐑛𐑦𐑙:**

    ```bash
    ./bin/byvalver --xor-encode <key> <input_file> [output_file]
    ```

    Where:

    - `<key>` is a required 32-bit hexadecimal key (e.g., `0x12345678`)
    - `<input_file>` is your shellcode file
    - `[output_file]` is optional, defaults to `output.bin`

+ **EXAMPLE / 𐑧𐑒𐑟𐑨𐑥𐑐𐑫𐑤:**

    ```bash
    ./bin/byvalver --xor-encode 0x12345678 shellcode.bin encoded_output.bin
    ```

+ **NOTE / 𐑯𐑴𐑑:** The XOR key is a required parameter - the command will fail if not provided. The correct syntax is `--xor-encode <key> <input_file> [output_file]`.

    The XOR encoding feature prepends a decoder stub to your processed shellcode. The decoder stub (implemented in `decoder.asm`) uses a JMP-CALL-POP technique to retrieve the XOR key and encoded shellcode length, then decodes the shellcode byte-by-byte before execution. This provides an additional layer of obfuscation on top of null-byte removal.

    The decoder stub uses a null-free length encoding key (`0x11223344`) to store the encoded shellcode length in an XOR-encoded format, ensuring the entire payload remains null-byte free.

## MODULAR ARCHITECTURE / 𐑥𐑭𐑛𐑿𐑤𐑼 𐑸𐑒𐑦𐑑𐑧𐑒𐑑𐑗𐑼

`byvalver` has a clean, modular architecture seamlessly integrating the strategy patterns:

---

![adaptive vertical](./IMAGES/adapvert.png)

---

### CORE COMPONENTS / 𐑒𐑴𐑮 𐑗𐑳𐑥𐑐𐑴𐑯𐑦𐑯𐑑𐑕

- **CORE ENGINE**: `src/core.c` - Contains the main processing logic using a strategy pattern
- **UTILITIES**: `src/utils.c` - All helper functions needed by strategies
- **STRATEGY REGISTRY**: `src/strategy_registry.c` - Manages the collection and selection of strategies
- **STRATEGY MODULES**: Specialized modules for different instruction types:
  - `src/mov_strategies.c` - MOV instruction replacements
  - `src/arithmetic_strategies.c` - Arithmetic operation replacements (ADD, SUB, AND, OR, XOR, CMP)
  - `src/memory_strategies.c` - Memory operation replacements
  - `src/jump_strategies.c` - Jump and call replacements
  - `src/general_strategies.c` - General instruction replacements (PUSH, etc.)
  - `src/anti_debug_strategies.c` - Anti-debugging and analysis detection strategies
  - `src/shift_strategy.c` - Shift-based immediate value construction strategies
  - `src/peb_strategies.c` - PEB (Process Environment Block) traversal strategies including alternative PEB traversal methods
  - `src/hash_utils.c` - Hash utilities for API resolution strategies

### STRATEGY PATTERN DESIGN / 𐑕𐑑𐑮𐑨𐑑𐑩𐑡𐑦 𐑐𐑨𐑑𐑻𐑯 𐑛𐑩𐑟𐑲𐑯

## ARCHITECTURE BENEFITS / 𐑸𐑒𐑦𐑑𐑧𐑒𐑑𐑗𐑼 𐑚𐑧𐑯𐑧𐑓𐑦𐑑𐑕

- **MAINTAINABILITY**: clear separation of concerns with dedicated modules
- **EXTENSIBILITY**: easy to add new replacement strategies
- **TESTABILITY**: individual strategy modules can be tested separately
- **SCALABILITY**: architecture supports growing number of replacement strategies
- **CLEAN BUILD**: all warnings eliminated in the new modular design

## FEATURES / 𐑓𐑰𐑗𐑻𐑟

*   **AUTOMATED NULL-BYTE REMOVAL:** reads raw shellcode from a file and automatically processes it
*   **INSTRUCTION-LEVEL ANALYSIS:** disassembles shellcode to understand its underlying logic
*   **INTELLIGENT REPLACEMENT:** employs a strategy-based approach to replace null-byte-producing instructions
*   **EXTENSIBLE FRAMEWORK:** designed to be easily extended with new replacement strategies for a wider range of instructions
*   **RELATIVE JUMP/CALL PATCHING:** automatically recalculates and patches relative jump and call offsets to maintain control flow integrity after instruction size changes
*   **FILE-BASED OUTPUT:** writes processed shellcode to files instead of terminal output
*   **FUNCTIONALITY VERIFICATION:** includes tools to verify that logical operations are preserved during transformation
*   **UNEXPECTED OPTIMIZATION:** when processing null-free shellcode, byvalver can identify and apply more efficient instruction sequences, resulting in size reduction. For example:
    *   Windows shellcode `51208.asm` was reduced from 373 bytes to 360 bytes (13 bytes smaller)
    *   Windows shellcode `50722.asm` was reduced from 176 bytes to 155 bytes (21 bytes smaller) 
    *   Windows shellcode `49466.asm` was reduced from 84 bytes to 74 bytes (10 bytes smaller)
    *   Linux shellcode `36637.c` was reduced from 84 bytes to 74 bytes (10 bytes smaller)

### CURRENT REPLACEMENT STRATEGIES / 𐑒𐑻𐑧𐑯𐑑 𐑮𐑰𐑐𐑤𐑱𐑕𐑥𐑦𐑯𐑑 𐑕𐑑𐑮𐑨𐑑𐑩𐑡𐑰𐑟

`byvalver` employs a multi-pass architecture to ensure correctness and extensibility. The current strategies include:  

*   **`ADD reg, 1`**: Replaced with `INC reg` for all general-purpose 32-bit registers

*   **`AND reg, 0`**: Replaced with `XOR reg, reg` for all general-purpose 32-bit registers

*   **`ADD/SUB/AND/OR/XOR/CMP reg, imm32`**: For 32-bit immediate values containing null bytes, these are replaced with a null-free sequence using `EAX` as a temporary register (similar to `MOV reg, imm32`)

*   **`CALL imm32`**: Replaced with a null-free sequence using `EAX` as a temporary register, followed by `CALL EAX`

*   **`CMP reg, 0`**: Replaced with `TEST reg, reg` for all general-purpose 32-bit registers

*   **`JMP imm32`**: Replaced with a null-free sequence using `EAX` as a temporary register, followed by `JMP EAX`

*   **`MOV reg, imm32`**: For 32-bit immediate values containing null bytes, this is replaced with a null-free sequence. If `reg` is `EAX`, it uses an optimized byte-wise construction. If `reg` is another general-purpose register, it uses `PUSH EAX`, constructs the immediate in `EAX`, `MOV reg, EAX`, and then `POP EAX`

*   **`MOV reg, 0`**: Replaced with `XOR reg, reg` for all general-purpose 32-bit registers

*   **`MOV reg, [imm32]`**: For direct memory addressing with 32-bit addresses containing null bytes, replaced with a null-free sequence: load the address into `EAX`, then move from `[EAX]`

*   **`OR reg, 0`**: Replaced with `TEST reg, reg` for all general-purpose 32-bit registers

*   **`PUSH imm8`**: Uses the 8-bit immediate push instruction which is null-byte-free by design

*   **`PUSH imm32`**: For 32-bit immediate values containing null bytes, replaced with a null-free sequence using `EAX` to construct the immediate value, then `PUSH EAX`. For 8-bit sign-extended values that can replace the 32-bit immediate, uses the smaller `PUSH imm8` instruction instead

*   **`SUB reg, 1`**: Replaced with `DEC reg` for all general-purpose 32-bit registers

*   **`XOR reg, 0`**: Replaced with `XOR reg, reg` for all general-purpose 32-bit registers

*   **RELATIVE JUMPS/CALLS WITH NULL-BYTE DISPLACEMENTS**: Enhanced handling for relative `JMP` and `CALL` instructions where the displacement contains null bytes after patching. The system now detects when patched displacements still contain null bytes and replaces the instruction with a null-free sequence: `MOV EAX, target_address` followed by `JMP EAX` or `CALL EAX`

*   **CONDITIONAL JUMPS WITH NULL-BYTE DISPLACEMENTS**: Added comprehensive support for conditional jump instructions (JE, JNE, JZ, JNZ, JL, JG, JLE, JGE, JB, JAE, etc.) with null bytes in their displacements. When patched displacements contain null bytes, these are converted to equivalent logic using alternate conditional jumps and unconditional jumps to maintain functionality while eliminating null bytes

*   **EFFICIENT REGISTER ZEROING WITH `CDQ`/`MUL`**: Added support for using `CDQ` (Convert Doubleword to Quadword) to efficiently zero EDX in 1 byte when EAX is known to be zero (vs. 2 bytes for `XOR EDX, EDX`), and `MUL` instruction to zero both EAX and EDX simultaneously when one operand is zero (vs. 4 bytes for two separate XOR operations)

*   **SHIFT-BASED IMMEDIATE VALUE CONSTRUCTION**: Added support for constructing immediate values using shift operations (SHL/SHR) when direct immediate values contain null bytes. For example, instead of `MOV EAX, 0x001FF000` (which contains null bytes), the system can generate `MOV EAX, 0x00001FF0; SHL EAX, 12` if the starting value and shift amount are null-free. This strategy is inspired by hand-crafted shellcode techniques found in exploit-db.

*   **GET PC (GET PROGRAM COUNTER) TECHNIQUE**: Added support for position-independent code using the CALL/POP technique to load immediate values. Instead of direct `MOV reg, imm32` with null bytes, the system can embed the immediate value directly after a CALL instruction and retrieve it using POP and memory access. This creates position-independent and null-free code, and is selected when it yields a more size-efficient result than other approaches.

*   **NULL-FREE IMMEDIATE VALUE CONSTRUCTION WITH NEG OPERATIONS**: Implemented support for using NEG (negation) operations to construct immediate values that contain null bytes by loading the negated value (which may be null-free) and then applying NEG to achieve the target. For example, instead of `MOV EAX, 0x00730071` (which contains null bytes), the system can generate `MOV EAX, 0xFF8CFF8F` (negated, null-free) + `NEG EAX` (to restore the original value). This strategy is inspired by techniques in `windows_x86/51208.asm` and extends to arithmetic operations as well.

*   **NULL-FREE IMMEDIATE VALUE CONSTRUCTION WITH NOT OPERATIONS**: Implemented support for using `NOT` operations to construct immediate values that contain null bytes by loading the bitwise NOT of the value (if it is null-free) and then applying `NOT` to achieve the target. This is analogous to the `NEG` strategy.

*   **ANTI-ANALYSIS TECHNIQUES**: Implemented sophisticated anti-debugging strategies that can be embedded in shellcode to detect analysis environments. These include PEB-based debugger checks (examining the BeingDebugged flag), timing-based analysis detection (using RDTSC to measure execution delays), and INT3-based debugger detection. These strategies are designed to replace NOP instructions and other suitable locations with anti-analysis checks that can alter behavior when running under analysis.

*   **ALTERNATIVE PEB TRAVERSAL METHODS**: Added support for alternative Process Environment Block (PEB) traversal techniques inspired by shellcode from exploit-db collection. These include both standard iterative module searching and alternative direct access methods (as seen in `windows/42016.asm`) to locate kernel32.dll base address without using hardcoded addresses. The strategies provide different approaches to dynamically resolve API functions through PEB parsing with null-byte avoidance.

### ADVANCED STRATEGIES / 𐑨𐑛𐑝𐑨𐑯𐑕𐑑 𐑕𐑑𐑮𐑨𐑑𐑩𐑡𐑰𐑟

`byvalver` includes sophisticated transformation strategies inspired by hand-crafted shellcode from exploit-db:

*   **ARITHMETIC EQUIVALENT REPLACEMENT**: Instead of direct value loading, finds arithmetic combinations (e.g., `SUB EAX, 0x404` after `MOV EAX, 0x00200404`) to achieve target values without null bytes in immediate operands

*   **CONTEXT-AWARE OPTIMIZATIONS**: Selects the most size-efficient strategy based on comparing the potential output sizes of different approaches

*   **ELEGANT MULTI-INSTRUCTION SEQUENCES**: Implements transformations similar to those found in sophisticated hand-written shellcode

*   **NEG-BASED IMMEDIATE VALUE CONSTRUCTION**: Uses NEG (negation) operations to construct immediate values that would otherwise contain null bytes. For example, instead of `MOV EAX, 0x00730071`, the system can generate `MOV EAX, 0xFF8CFF8F` (the negated value) + `NEG EAX`. This strategy is inspired by techniques found in `windows_x86/51208.asm` and extends to arithmetic operations as well.

*   **NOT-BASED IMMEDIATE VALUE CONSTRUCTION**: Uses `NOT` operations to construct immediate values that would otherwise contain null bytes. For example, instead of `MOV EAX, 0x11220033`, the system can generate `MOV EAX, 0xEEDDFFCC` (the `NOT`-ed value) + `NOT EAX`. This strategy is also applied to `XOR` instructions.

*   **ADD/SUB ENCODING**: Uses ADD or SUB operations to construct immediate values. For example, instead of `MOV EAX, 0x00100000`, the system might generate `MOV EAX, 0x00100005; SUB EAX, 5` or `MOV EAX, 0x000FF000; ADD EAX, 0x1000` if the intermediate values are null-free.

*   **XOR ENCODING**: Uses XOR operation with a key to construct immediate values. For example, `MOV EAX, 0x12345678` could become `XOR EAX, EAX; XOR EAX, 0x12345678` or use a more complex XOR encoding approach that avoids null bytes in intermediate values.

*   **ANTI-ANALYSIS TECHNIQUES**: Incorporates anti-debugging and anti-analysis checks that can detect execution in analysis environments and potentially alter behavior. These include PEB-based checks, timing-based analysis detection, and INT3-based debugger detection.


### WORKING WITH EXECUTABLES (E.G., PE FILES) / 𐑢𐑻𐑒𐑦𐑙 𐑢𐑦𐑞 𐑧𐑒𐑕𐑩𐑒𐑿𐑑𐑩𐑚𐑫𐑤𐑟

`byvalver` is designed to work with **RAW BINARY SHELLCODE**. It does not parse complex formats like PE (Windows) or ELF (Linux) directly

you must first extract the executable code from the file

you can use `objcopy` (part of the GNU Binutils package) to easily extract the `.text` section, which usually contains the executable code

**EXAMPLE WORKFLOW FOR A PE FILE / 𐑧𐑒𐑟𐑨𐑥𐑐𐑫𐑤 𐑢𐑻𐑒𐑓𐑤𐑴 𐑓𐑹 𐑩 PE 𐑓𐑲𐑤:**

+ **EXTRACT THE `.text` SECTION FROM THE EXECUTABLE / 𐑧𐑒𐑕𐑑𐑮𐑨𐑒𐑑 𐑞 `.text` 𐑕𐑧𐑒𐑖𐑦𐑯 𐑓𐑮𐑳𐑥 𐑞 𐑧𐑒𐑕𐑩𐑒𐑿𐑑𐑩𐑚𐑫𐑤:**

    ```bash
    objcopy -O binary --only-section=.text my_app.exe shellcode.bin
    ```
    This command extracts the raw code from: 

    `my_app.exe` 

    & saves it as 

    `shellcode.bin`

+ **RUN `byvalver` ON THE EXTRACTED RAW SHELLCODE / 𐑮𐑳𐑯 `·𐑚𐑲𐑝𐑨𐑤𐑝𐑼` 𐑭𐑯 𐑞 𐑧𐑒𐑕𐑑𐑮𐑨𐑒𐑑𐑦𐑛 𐑮𐑷 𐑖𐑱𐑤𐑒𐑴𐑛:**

    ```bash
    ./bin/byvalver shellcode.bin
    ```
    The final, null-free shellcode will be written to `output.bin`

### INSPECTING THE OUTPUT / 𐑦𐑯𐑕𐑐𐑧𐑒𐑑𐑦𐑙 𐑞 𐑬𐑑𐑐𐑫𐑑

The `output.bin` file is a raw binary file

To view its contents in a human-readable hexadecimal format, 

you can use a command-line hex editor like `xxd` or `hexdump`

## VERIFYING DENULLIFICATION & FUNCTIONALITY / 𐑝𐑺𐑦𐑓𐑲𐑦𐑙 𐑛𐑰𐑯𐑳𐑤𐑦𐑓𐑦𐑗𐑱𐑖𐑦𐑯 𐑯 𐑓𐑩𐑯𐑒𐑖𐑦𐑯𐑨𐑤𐑦𐑑𐑦

**VERIFYING DENULLIFICATION / 𐑝𐑺𐑦𐑓𐑲𐑦𐑙 𐑛𐑰𐑯𐑳𐑤𐑦𐑓𐑦𐑗𐑱𐑖𐑦𐑯**

```bash
./verify_nulls.py <specific.bin>
```
**VERIFYING FUNCTIONALITY / 𐑝𐑺𐑦𐑓𐑲𐑦𐑙 𐑓𐑩𐑯𐑒𐑖𐑦𐑯𐑨𐑤𐑦𐑑𐑦**

```bash
./verify_functionality.py <preprocessed.bin> <processed.bin>
```
**WHAT THAT LOOKS LIKE**

![screencap_1](./IMAGES/scap1.png)

![screencap_2](./IMAGES/scap2.png)

## CORE CONCEPTS / 𐑒𐑹 𐑒𐑭𐑯𐑕𐑧𐑐𐑕

The process of removing null bytes without corrupting the shellcode is a complex one  

`byvalver` tackles this with a multi-pass approach:

+ **DISASSEMBLY PASS / 𐑛𐑦𐑕𐑩𐑕𐑧𐑥𐑚𐑤𐑦 𐑐𐑨𐑕:** The Capstone engine is used to disassemble the entire shellcode into a linked list of instruction nodes

        + Each node stores the original instruction details and its offset  

+ **SIZING PASS / 𐑕𐑲𐑟𐑦𐑙 𐑐𐑨𐑕:** Each instruction node is analyzed  

        + If it contains null bytes, a replacement strategy is chosen, and the `new_size` of the replacement instruction(s) is calculated and stored in the node
        + If no null bytes are present, the framework can still apply more efficient strategies or optimizations, and the potentially smaller `new_size` is calculated and stored in the node  

+ **OFFSET CALCULATION PASS / 𐑭𐑓𐑕𐑧𐑑 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑖𐑦𐑯 𐑐𐑨𐑕:** The `new_size` values are used to calculate the `new_offset` for each instruction in the modified shellcode

        + This is crucial for correctly patching relative jumps and calls  

+ **GENERATION AND PATCHING PASS / 𐑡𐑧𐑯𐑻𐑱𐑖𐑦𐑯 𐑯 𐑐𐑨𐑗𐑦𐑙 𐑐𐑨𐑕:** The tool iterates through the instruction nodes again

        + For each instruction:

            *   If it's a relative `JMP` or `CALL`, its immediate operand is patched with the newly calculated relative offset
            *   If it contains null bytes, the corresponding null-free replacement sequence is generated and appended to the output buffer
            *   If it's null-free but an optimization strategy is available (e.g., `INC` instead of `ADD reg, 1`, `XOR reg, reg` instead of `MOV reg, 0`, etc.), the optimized instruction sequence is generated and appended to the output buffer
            *   Otherwise, the original instruction bytes are appended  

+ **OUTPUT / 𐑬𐑑𐑐𐑫𐑑:** The newly constructed, null-free shellcode is printed to the console

___

## LIMITATIONS AND FUTURE DEVELOPMENT / 𐑤𐑦𐑥𐑦𐑑𐑱𐑖𐑦𐑯𐑟 𐑯 𐑓𐑿𐑗𐑼 𐑛𐑩𐑝𐑧𐑤𐑩𐑐𐑥𐑦𐑯𐑑

`byvalver` is a powerful tool, but it is still under development  

**HERE ARE SOME OF THE CURRENT LIMITATIONS AND THE ROADMAP FOR FUTURE IMPROVEMENTS / 𐑣𐑽 𐑸 𐑕𐑳𐑥 𐑝 𐑞 𐑒𐑳𐑮𐑦𐑯𐑑 𐑤𐑦𐑥𐑦𐑑𐑱𐑖𐑦𐑯𐑟 𐑯 𐑞 𐑮𐑴𐑛𐑥𐑨𐑐 𐑓𐑹 𐑓𐑿𐑗𐑼 𐑦𐑥𐑐𐑮𐑵𐑝𐑥𐑦𐑯𐑑𐑕:**

*   **EFFICIENCY OF `generate_mov_eax_imm`** / **𐑩𐑓𐑦𐑖𐑦𐑯𐑕𐑦 𐑝 `generate_mov_eax_imm`**: While improved for single non-zero bytes, the generic `generate_mov_eax_imm` (and thus `generate_op_reg_imm`) could still be optimized for cases with multiple non-zero bytes to produce shorter instruction sequences  

*   **RELATIVE JUMP/CALL SIZE CHANGES / 𐑮𐑧𐑤𐑩𐑑𐑦𐑝 𐑡𐑳𐑥𐑐/𐑒𐑭𐑤 𐑕𐑲𐑟 𐑗𐑨𐑯𐑡𐑦𐑟**: 
    + The current implementation assumes that relative `JMP` and `CALL` instructions do not change their size (e.g., an `EB rel8` becoming an `E9 rel32`)
    + A more advanced solution would dynamically adjust the jump instruction's size if the new relative offset requires a larger encoding, which would necessitate re-running the sizing and offset passes  

*   **INSTRUCTION COVERAGE / 𐑦𐑯𐑕𐑑𐑮𐑩𐑒𐑖𐑦𐑯 𐑗𐑩𐑝𐑮𐑦𐑡**: While many common instructions are covered there are still numerous x86 instructions and addressing modes that could contain null bytes and require specific replacement strategies  

*   **8-BIT AND 16-BIT INSTRUCTIONS / 8-BIT 𐑯 16-BIT 𐑦𐑯𐑕𐑑𐑮𐑩𐑒𐑖𐑦𐑯𐑟**:
    + The current focus is primarily on 32-bit instructions
    + More work is needed to properly handle 8-bit and 16-bit registers and operations

___

## CONTRIBUTING / 𐑒𐑳𐑯𐑑𐑮𐑦𐑚𐑿𐑑𐑦𐑙

Contributions are welcome!

## LICENSE / 𐑤𐑦𐑕𐑦𐑯𐑟

`byvalver`/`·𐑚𐑲𐑝𐑨𐑤𐑝𐑼` is available in the public domain (see ![UNLICENSE](./UNLICENSE.md))