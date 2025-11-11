# New Shellcode Strategies

This file documents new shellcode strategies discovered from the exploit-db shellcode collection.

## 1. Windows API Hashing (Full Implementation)

*   **Description:** Dynamically finding the base address of `kernel32.dll`, iterating its export tables, and resolving API addresses using ROR13 or similar hash functions. This provides portability across different OS versions and service packs.
*   **Example:** `windows_x86/51208.asm`, `windows_x86/13504.asm`
*   **Implementation Idea:** Implement a full function resolution system that can generate hash-based lookups for Windows API functions instead of using hard-coded addresses.

## 2. Polymorphic Encoding with Multiple Techniques

*   **Description:** Using various encoding methods (XOR, ROL/ROR, ADD/SUB, arithmetic combinations) to avoid detection and bypass static analysis. Shellcodes like 51208.asm use NEG operations for string construction to avoid null bytes.
*   **Example:** `windows_x86/51208.asm` uses NEG operations: `mov edx, 0xff8cff8e; neg edx; push edx` to build Unicode strings without nulls.
*   **Implementation Idea:** Implement multiple encoding strategies beyond XOR, including NEG, NOT, arithmetic combinations, and rotation-based approaches for immediate value construction.

## 3. PEB/PEB-based Module Resolution

*   **Description:** Using Process Environment Block (PEB) and Export Directory Table (EDT) to dynamically locate base addresses and resolve API functions without hard-coded addresses. This provides better portability across different OS versions.
*   **Example:** `windows_x86/51208.asm` uses PEB method to locate kernel32.dll base address and then uses hash-based lookup to find function addresses.
*   **Implementation Idea:** Implement strategies to generate dynamic API resolution code that uses PEB traversal and hash-based function lookup instead of hard-coded addresses.

## 4. Stack-Based String Construction with Arithmetic

*   **Description:** Building string constants using arithmetic operations rather than direct string pushes to avoid null bytes. This involves using NEG, XOR, or other operations to construct string values at runtime.
*   **Example:** `windows_x86/51208.asm` uses sequences like `mov edx, 0xff8cff8e; neg edx` to construct string values without embedding null bytes.
*   **Implementation Idea:** Enhance string construction strategies to include arithmetic-based value building techniques.

## 5. Anti-Analysis Techniques

*   **Description:** Incorporating checks within the shellcode to detect the presence of debuggers, virtual machines, or other analysis tools. If detected, the shellcode can alter its behavior, terminate, or trigger a decoy.
*   **Example:** Common in advanced malware to hinder reverse engineering efforts.
*   **Implementation:** IMPLEMENTED in BYVALVER - Strategies include PEB-based checks (BeingDebugged flag), timing-based detection (RDTSC), and INT3-based debugger detection. These strategies can replace NOP instructions with anti-analysis checks and are implemented following the modular strategy pattern.
*   **Status:** COMPLETED - Moved to ADVANCED_STRATEGY_DEVELOPMENT.md

## 6. Indirect System Calls (Linux)

*   **Description:** Performing system calls on Linux by loading syscall numbers and arguments into registers and then executing `int 0x80` (x86) or `syscall` (x86-64), bypassing standard library functions. This is a common technique for compact and null-free Linux shellcode.
*   **Example:** Many `linux_x86` shellcodes in exploit-db.
*   **Implementation Idea:** Develop a strategy to convert standard C library calls (e.g., `execve`, `exit`) into their equivalent indirect system call sequences.

## 7. Process Injection (Windows)

*   **Description:** Techniques to inject shellcode or a malicious DLL into the address space of another running process. This is a fundamental technique in Windows exploitation for privilege escalation or stealth.
*   **Example:** Advanced Windows exploitation techniques.
*   **Implementation Idea:** Implement strategies to generate shellcode that performs process injection, including finding target processes, allocating memory, writing payload, and creating a remote thread.

## 8. Reflective DLL Injection

*   **Description:** A highly sophisticated technique to load a Dynamic Link Library (DLL) from memory into a process without writing it to disk. This is often used to evade detection by endpoint security solutions.
*   **Example:** Custom loaders and advanced post-exploitation frameworks.
*   **Implementation Idea:** Develop a strategy to generate a reflective DLL loader stub that can be embedded within shellcode.

## 9. Shift-Based Immediate Value Construction

*   **Description:** Using shift operations (SHL/SHR) to construct immediate values when direct immediate values contain null bytes. This technique is more sophisticated than simple arithmetic equivalents.
*   **Example:** `linux_x86/37390.asm` uses `push 0x1ff9090; shr $0x10, %ecx` to load `0x1ff` into `ecx` without null bytes in the intermediate representation.
*   **Implementation Idea:** Enhance immediate value construction strategies to include shift-based approaches for building values without null bytes.

## 10. Encoder/Decoder Loop Construction

*   **Description:** Creating self-decoding loops to handle complex payloads. This is often used in position-independent shellcode where the payload needs to be decoded dynamically.
*   **Example:** `linux_x86-64/35205.asm` uses position-independent and alphanumeric encoding with xor-based decoding loops.
*   **Implementation Idea:** Implement strategies to generate decoding loops that can handle encoded payloads, making shellcode more polymorphic.

## 11. Arithmetic Equivalent Substitution

*   **Description:** Using arithmetic operations to achieve the same values as direct MOV operations. For example, using `mov bx,1666; sub bx,1634` to achieve 0x0020 (8192) without null bytes.
*   **Example:** `linux_x86/13339.asm` uses `mov bx,1666; sub bx,1634` to avoid null byte in port specification.
*   **Implementation Idea:** Enhance the arithmetic equivalent replacement strategy to find more complex arithmetic combinations to produce target values.

## 12. Self-Modifying Code Patterns

*   **Description:** Shellcode that modifies parts of its own instruction stream during execution to evade static analysis, signature-based detection, or dynamically adjust its behavior based on runtime conditions.
*   **Example:** `linux_x86-64/35205.asm` uses XOR-based self-decoding where encoded instructions are decoded at runtime.
*   **Implementation Idea:** Implement strategies where certain instructions are initially encoded or obfuscated and then decoded/modified by the shellcode itself before execution.

## 13. Position-Independent Code (PIC) with Call-Pop Technique

*   **Description:** Using the CALL/POP technique to obtain the current program counter, enabling null-free loading of immediate values by embedding them as data after CALL instructions.
*   **Example:** Common in position-independent shellcode to load addresses without hardcoding them.
*   **Implementation Idea:** Implement the GET PC (Get Program Counter) technique as an alternative strategy for loading immediate values that contain null bytes.

## 14. Shellcode for Specific Exploit Types

*   **Description:** Analyzing shellcode specifically designed for particular exploit types (e.g., Structured Exception Handler (SEH) overwrites, format string bugs, heap overflows) and extracting generalizable null-byte avoidance patterns or specialized payload structures.
*   **Example:** Shellcodes targeting specific vulnerabilities in exploit-db.
*   **Implementation Idea:** Develop strategies that generate shellcode optimized for specific exploit contexts, taking into account constraints like limited buffer size or available registers.

## 15. Alternative PEB Traversal Methods

*   **Description:** Different approaches to traversing the Process Environment Block (PEB) beyond the standard method. Some shellcodes use different offsets or traversal techniques to locate kernel32.dll. For example, using InMemoryOrderModuleList instead of InInitializationOrderModuleList.
*   **Example:** `windows/42016.asm` uses a different PEB traversal technique: `mov eax, [eax+ecx]` twice to move two positions ahead in the module list to reach kernel32.
*   **Implementation Idea:** Implement alternative PEB traversal strategies that can bypass security measures that look for standard PEB traversal patterns.

## 16. Function Name Hashing with Custom Algorithms

*   **Description:** Using custom hash algorithms to identify functions in the export table instead of the standard ROR13 or similar methods. Different shellcodes use XOR-based, addition-based or complex mathematical functions to calculate hashes.
*   **Example:** `windows_x86/13504.asm` uses a custom hash algorithm with `XOR AL, hash_xor_value; SUB AH, AL` pattern for function identification.
*   **Implementation Idea:** Implement multiple function name hashing algorithms to generate shellcode that can't be easily fingerprinted by signature-based detection.

## 17. Indirect API Resolution via GetProcAddress

*   **Description:** Instead of directly hashing function names and walking export tables, some shellcodes use GetProcAddress to resolve functions after loading required libraries. This can be more efficient but requires finding GetProcAddress first.
*   **Example:** `windows/42016.asm` finds GetProcAddress via the export table, then uses it to resolve WinExec and ExitThread functions.
*   **Implementation Idea:** Implement strategies that combine PEB traversal to find GetProcAddress, then use it to resolve additional functions rather than walking export tables multiple times.

## 18. String Obfuscation via Stack Manipulation

*   **Description:** Techniques to build string constants on the stack while maintaining alignment and avoiding null bytes. Tricks include adding extra characters and using LEA to adjust pointers.
*   **Example:** `windows/42016.asm` uses "AWinexec" and "AAExitThread" patterns with `lea ecx, [ecx+1]` and `lea ecx, [ecx+2]` to skip the extra 'A' characters.
*   **Implementation Idea:** Enhance string construction strategies to include stack-based obfuscation techniques that maintain proper alignment while avoiding null bytes.

## 19. Process Token Stealing for Privilege Escalation

*   **Description:** Advanced Windows shellcode that navigates kernel structures to steal security tokens from high-privilege processes like SYSTEM (PID 4) to elevate privileges.
*   **Example:** `windows_x86-64/37895.asm` demonstrates token stealing by walking the EPROCESS list, finding the SYSTEM process, and copying its token to the current process.
*   **Implementation Idea:** Implement strategies that can navigate kernel structures to perform privilege escalation via token manipulation.

## 20. Dynamic Module Loading and API Resolution

*   **Description:** Shellcode that dynamically loads additional DLLs using LoadLibrary and then resolves functions from those libraries using the same hashing techniques.
*   **Example:** `windows_x86/50710.asm` uses LoadLibrary to load urlmon.dll, then resolves URLDownloadToFileA function to download files from remote URLs.
*   **Implementation Idea:** Implement strategies that can dynamically load and resolve functions from multiple libraries beyond kernel32.dll, such as user32.dll, ws2_32.dll, urlmon.dll, etc.

## 21. Staged Payload Execution

*   **Description:** Shellcode that executes payloads in multiple stages, often by launching external binaries or downloading additional payloads from remote servers.
*   **Example:** `windows_x86/49466.asm` is a stager that uses mshta.exe to execute a second-stage payload delivered through Metasploit's hta_server.
*   **Implementation Idea:** Implement staged execution strategies that can download and execute payloads from external sources or execute intermediate programs.

## 22. Custom Hash Tables for API Resolution

*   **Description:** Pre-defining hash tables with multiple API function hashes to efficiently resolve several functions at once from the same module.
*   **Example:** `windows_x86/50710.asm` defines hash tables with multiple function hashes (`KERNEL32HASHTABLE`, `URLMONHASHTABLE`) to resolve multiple functions efficiently.
*   **Implementation Idea:** Implement hash table generation strategies that can bundle multiple required function hashes in a structured format for efficient resolution.

## 23. Advanced Register Usage Optimization

*   **Description:** Sophisticated techniques to maximize register utilization while avoiding overwriting critical values and maintaining shellcode compactness.
*   **Example:** `windows_x86/13504.asm` efficiently uses registers to keep function pointers in predetermined locations and uses them in loops for repeated calls to network functions.
*   **Implementation Idea:** Implement register optimization strategies that maximize the use of available registers while preserving critical values throughout execution.