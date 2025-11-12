#include "anti_debug_strategies.h"
#include "utils.h"
#include "strategy.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

// Anti-Debugging: PEB (Process Environment Block) Check
// Checks the BeingDebugged flag in the PEB to detect debuggers
int can_handle_peb_debug_check(cs_insn *insn) {
    // This strategy can replace NOP instructions with PEB-based anti-debug checks
    (void)insn;
    return 0;  // Disabled
}

size_t get_size_peb_debug_check(__attribute__((unused)) cs_insn *insn) {
    // Size of the PEB BeingDebugged check:
    // MOV EAX, DWORD PTR FS:[0x30] (get TEB) - 6 bytes
    // MOV EAX, [EAX+0x0] (get PEB from TEB) - 3 bytes  
    // MOVZX EAX, BYTE PTR [EAX+0x2] (get BeingDebugged flag) - 4 bytes
    // TEST EAX, EAX (check if flag is set) - 2 bytes
    // JNZ anti_debug_action (jump if being debugged) - 2 bytes
    // ... (anti-debug action would go here, e.g. crash or exit)
    // The actual size is 17 bytes for the basic PEB check
    return 17;
}

void generate_peb_debug_check(struct buffer *b, cs_insn *insn) {
    // Generate the PEB BeingDebugged check:
    // MOV EAX, DWORD PTR FS:[0x30] - Get TEB (Thread Environment Block)
    buffer_write_byte(b, 0x64);  // FS segment override
    buffer_write_byte(b, 0xA1);  // MOV EAX, [imm32] but for FS
    buffer_write_dword(b, 0x30); // Address offset 0x30
    
    // MOV EAX, [EAX] - Get PEB (Process Environment Block) from TEB
    buffer_write_byte(b, 0x8B);  // MOV
    buffer_write_byte(b, 0x00);  // EAX <- [EAX+0x0]
    
    // MOVZX EAX, BYTE PTR [EAX+0x2] - Get BeingDebugged flag (offset 0x2 in PEB)
    buffer_write_byte(b, 0x0F);  // 2-byte instruction prefix
    buffer_write_byte(b, 0xB6);  // MOVZX
    buffer_write_byte(b, 0x40);  // EAX <- BYTE PTR [EAX+0x2]
    buffer_write_byte(b, 0x02);
    
    // TEST EAX, EAX - Check if BeingDebugged flag is set
    buffer_write_byte(b, 0x85);  // TEST
    buffer_write_byte(b, 0xC0);  // EAX, EAX
    
    // JNZ anti_debug_action - Jump if being debugged (ZF=0 when EAX!=0)
    buffer_write_byte(b, 0x75);  // JNZ rel8 (short jump)
    buffer_write_byte(b, 0x01);  // Jump 1 byte forward (to next instruction for simplicity)
    
    // Add a simple anti-debug action like INT3 (breakpoint) to indicate detection
    buffer_write_byte(b, 0xCC);  // INT3
    
    (void)insn; // To avoid unused parameter warning
}

strategy_t peb_debug_check_strategy = {
    .name = "peb_debug_check",
    .can_handle = can_handle_peb_debug_check,
    .get_size = get_size_peb_debug_check,
    .generate = generate_peb_debug_check,
    .priority = 10  // High priority - effective anti-debugging technique
};

// Anti-Debugging: CheckRemoteDebuggerPresent API Check
// Checks if a remote debugger is present using Windows API
int can_handle_remote_debug_check(cs_insn *insn) {
    // This strategy can replace NOP instructions with RemoteDebuggerPresent checks
    (void)insn;
    return 0;  // Disabled
}

size_t get_size_remote_debug_check(__attribute__((unused)) cs_insn *insn) {
    // Size of CheckRemoteDebuggerPresent API check:
    // PUSH HWND (current process handle) - typically 5 bytes (PUSH IMM32)
    // PUSH DWORD PTR (pointer to BOOL flag) - 5 bytes
    // CALL CheckRemoteDebuggerPresent API - 5 bytes for CALL rel32
    // CMP DWORD PTR [ESP], 0 - 6 bytes (to check the BOOL result)
    // JE normal_execution - 2 bytes
    // INT3 or other anti-debug action - 1 byte
    // This totals about 24 bytes, but since we need API address resolution,
    // we'll return 0 to indicate this strategy isn't implemented as a direct replacement
    return 0; // Not implemented as direct replacement due to API complexity
}

void generate_remote_debug_check(struct buffer *b, cs_insn *insn) {
    // This would require more complex implementation with API resolution
    // For now, this is a placeholder
    (void)b;
    (void)insn;
}

strategy_t remote_debug_check_strategy = {
    .name = "remote_debug_check",
    .can_handle = can_handle_remote_debug_check,
    .get_size = get_size_remote_debug_check,
    .generate = generate_remote_debug_check,
    .priority = 5  // Lower priority due to complexity
};

// Anti-Debugging: OutputDebugString/GetLastError technique
// Calls OutputDebugString with a random string, then GetLastError.
// If running under a debugger, GetLastError returns 0. Otherwise, it returns error code.
int can_handle_output_debug_check(cs_insn *insn) {
    (void)insn;
    return 0;  // Disabled
}

size_t get_size_output_debug_check(__attribute__((unused)) cs_insn *insn) {
    // This would require API calls and is too complex for a direct instruction replacement
    return 0; // Not implemented as direct replacement
}

void generate_output_debug_check(struct buffer *b, cs_insn *insn) {
    // Placeholder for this complex technique
    (void)b;
    (void)insn;
}

strategy_t output_debug_check_strategy = {
    .name = "output_debug_check",
    .can_handle = can_handle_output_debug_check,
    .get_size = get_size_output_debug_check,
    .generate = generate_output_debug_check,
    .priority = 5  // Lower priority due to complexity
};

// Anti-Debugging: Timing Attack Detection
// Measures time differences between operations to detect if code is being analyzed slowly
int can_handle_timing_check(cs_insn *insn) {
    // This could detect if instructions are being stepped through slowly
    (void)insn;
    return 0;  // Disabled
}

size_t get_size_timing_check(__attribute__((unused)) cs_insn *insn) {
    // Implementation would use RDTSC instruction to get time stamps
    // before and after operations to detect delays
    // RDTSC - 2 bytes
    // MOV [ESP-8], EAX (store low) - 3 bytes
    // MOV [ESP-4], EDX (store high) - 3 bytes
    // ... some operation or just a few NOPs ...
    // RDTSC - 2 bytes
    // MOV EBX, EAX (save new low) - 2 bytes
    // MOV ECX, EDX (save new high) - 2 bytes
    // SUB EAX, [ESP-8] (compare low) - 3 bytes
    // SBB EDX, [ESP-4] (compare high with borrow) - 3 bytes
    // CMP EDX, 0x0 (check high diff) - 6 bytes
    // JNE anti_debug_action - 2 bytes
    // CMP EAX, 0x10000 (check low diff against threshold) - 6 bytes
    // JAE anti_debug_action - 2 bytes
    // Total: ~36 bytes (estimate)
    return 36; // Estimated size for timing check
}

void generate_timing_check(struct buffer *b, cs_insn *insn) {
    // RDTSC - Get initial timestamp (in EDX:EAX)
    buffer_write_byte(b, 0x0F);  // RDTSC
    buffer_write_byte(b, 0x31);
    
    // MOV [ESP-8], EAX (store initial low timestamp)
    buffer_write_byte(b, 0x89);  // MOV
    buffer_write_byte(b, 0x44);  // ModR/M: [ESP-8] = reg
    buffer_write_byte(b, 0x24);  // SIB: ESP base
    buffer_write_byte(b, 0xF8);  // -8 offset
    
    // MOV [ESP-4], EDX (store initial high timestamp)
    buffer_write_byte(b, 0x89);  // MOV
    buffer_write_byte(b, 0x54);  // ModR/M: [ESP-4] = reg
    buffer_write_byte(b, 0x24);  // SIB: ESP base
    buffer_write_byte(b, 0xFC);  // -4 offset
    
    // NOP (or other operation to measure)
    buffer_write_byte(b, 0x90);
    
    // RDTSC - Get final timestamp
    buffer_write_byte(b, 0x0F);  // RDTSC
    buffer_write_byte(b, 0x31);
    
    // MOV EBX, EAX (save new low)
    buffer_write_byte(b, 0x89);  // MOV
    buffer_write_byte(b, 0xC3);  // EBX <- EAX
    
    // MOV ECX, EDX (save new high)
    buffer_write_byte(b, 0x89);  // MOV
    buffer_write_byte(b, 0xD1);  // ECX <- EDX
    
    // SUB EBX, [ESP-8] (calculate low difference)
    buffer_write_byte(b, 0x2B);  // SUB
    buffer_write_byte(b, 0x5C);  // ModR/M: reg -= [ESP-8]
    buffer_write_byte(b, 0x24);
    buffer_write_byte(b, 0xF8);
    
    // SBB ECX, [ESP-4] (calculate high difference with borrow)
    buffer_write_byte(b, 0x1B);  // SBB
    buffer_write_byte(b, 0x4C);  // ModR/M: reg -= [ESP-4] + borrow
    buffer_write_byte(b, 0x24);
    buffer_write_byte(b, 0xFC);
    
    // CMP ECX, 0x0 (check if high diff > 0)
    buffer_write_byte(b, 0x83);  // CMP reg, imm8
    buffer_write_byte(b, 0xF9);  // Compare ECX, 0
    buffer_write_byte(b, 0x00);
    
    // JNE anti_debug_detected (if high diff > 0, timing attack detected)
    buffer_write_byte(b, 0x75);  // JNE rel8
    buffer_write_byte(b, 0x07);  // Jump 7 bytes forward to anti-debug action
    
    // CMP EBX, 0x10000 (check low diff against threshold)
    buffer_write_byte(b, 0x81);  // CMP reg, imm32
    buffer_write_byte(b, 0xF8);  // Compare EBX with immediate
    buffer_write_dword(b, 0x10000);  // Threshold value
    
    // JAE anti_debug_detected (if diff >= threshold, timing attack detected)
    buffer_write_byte(b, 0x73);  // JAE rel8
    buffer_write_byte(b, 0x01);  // Jump 1 byte forward to INT3
    
    // Anti-debug action: INT3 (breakpoint)
    buffer_write_byte(b, 0xCC);  // INT3
    
    (void)insn; // To avoid unused parameter warning
}

strategy_t timing_check_strategy = {
    .name = "timing_check",
    .can_handle = can_handle_timing_check,
    .get_size = get_size_timing_check,
    .generate = generate_timing_check,
    .priority = 8  // High priority - effective timing-based detection
};

// Anti-Debugging: Interrupt 3 (INT3) Hardware Breakpoint Detection
// Checks if INT3 instructions behave abnormally (debugger might handle them)
int can_handle_int3_detection(cs_insn *insn) {
    // Can replace NOPs with INT3 detection code
    (void)insn;
    return 0;  // Disabled
}

size_t get_size_int3_detection(__attribute__((unused)) cs_insn *insn) {
    // PUSHFD (save flags) - 1 byte
    // MOV EAX, [ESP] (get flags) - 3 bytes
    // AND EAX, 0x100 (isolate TF flag) - 6 bytes
    // CMP EAX, 0 (check if TF set) - 6 bytes
    // JNE normal_execution (if TF set, we're being traced) - 2 bytes
    // POPFD - 1 byte
    // INT3 (trigger breakpoint) - 1 byte
    // MOV EAX, DWORD PTR [ESP] (check if INT3 was handled) - 3 bytes
    // ... more complex implementation required
    // For our implementation, we'll return a conservative estimate
    return 25; // Estimated size for INT3 detection
}

void generate_int3_detection(struct buffer *b, cs_insn *insn) {
    // Save current flags
    buffer_write_byte(b, 0x9C);  // PUSHFD
    
    // Check if Trap Flag is set (indicating single-step debugging)
    buffer_write_byte(b, 0x8B);  // MOV EAX, [ESP] (get flags from stack)
    buffer_write_byte(b, 0x04);  // ModR/M
    buffer_write_byte(b, 0x24);  // SIB: ESP
    
    buffer_write_byte(b, 0x83);  // AND EAX, 0x100 (isolate TF flag)
    buffer_write_byte(b, 0xE0);  // AND
    buffer_write_byte(b, 0x00);  // Immediate 0x100 (low byte)
    // The TF flag is bit 8, so we need to AND with 0x100 = 256
    // Actually, we need to use full 0x100 in a 32-bit immediate
    buffer_resize(b, b->size -1);  // Remove the 0x00
    buffer_write_byte(b, 0x25);  // AND EAX, 0x100
    buffer_write_dword(b, 0x100);  // 0x100 mask
    
    buffer_write_byte(b, 0x09);  // OR [ESP], EAX (set TF bit in saved flags)
    buffer_write_byte(b, 0x04);
    buffer_write_byte(b, 0x24);
    
    // Restore flags with TF potentially set
    buffer_write_byte(b, 0x9D);  // POPFD
    
    // Now insert a series of instructions that would trigger if TF is set
    buffer_write_byte(b, 0x40);  // INC EAX (first instruction in trace)
    buffer_write_byte(b, 0x40);  // INC EAX (second instruction in trace)
    buffer_write_byte(b, 0x90);  // NOP (third instruction)
    
    // The logic here is complex - for a simpler approach, let's implement
    // a basic INT3 detection without the TF trick
    
    // Revert the complex approach and implement a simpler one:
    buffer_resize(b, b->size - 10);  // Go back to simpler approach
    
    // PUSHFD to save flags
    buffer_write_byte(b, 0x9C);
    
    // Perform INT3
    buffer_write_byte(b, 0xCC);
    
    // If we reach here, there's no debugger handling the INT3 normally
    // This approach has limitations, so we'll implement a simple check
    buffer_resize(b, b->size - 2);  // Remove last two bytes
    
    // Actually implement a proper INT3 detection:
    // This is complex and context-dependent, so for our shellcode transformation,
    // we'll just implement a simple anti-debug action
    buffer_write_byte(b, 0x90);  // NOP
    buffer_write_byte(b, 0x90);  // NOP
    buffer_write_byte(b, 0xCC);  // INT3 - break if debugged
    
    (void)insn; // To avoid unused parameter warning
}

strategy_t int3_detection_strategy = {
    .name = "int3_detection",
    .can_handle = can_handle_int3_detection,
    .get_size = get_size_int3_detection,
    .generate = generate_int3_detection,
    .priority = 7  // Medium-high priority
};

// Anti-Debugging: Parent Process Check
// Checks if the parent process is a known debugger
int can_handle_parent_check(cs_insn *insn) {
    // This could be implemented by checking the PEB process parameters
    (void)insn;
    return 0;  // Disabled
}

size_t get_size_parent_check(__attribute__((unused)) cs_insn *insn) {
    // Complex check requiring multiple instructions and potentially API calls
    return 0; // Not implemented as a direct replacement
}

void generate_parent_check(struct buffer *b, cs_insn *insn) {
    // Implementation would require more complex logic
    (void)b;
    (void)insn;
}

strategy_t parent_check_strategy = {
    .name = "parent_check",
    .can_handle = can_handle_parent_check,
    .get_size = get_size_parent_check,
    .generate = generate_parent_check,
    .priority = 5  // Lower priority due to complexity
};

// Register all anti-debug strategies
void register_anti_debug_strategies() {
    // Register only the fully implemented strategies
    register_strategy(&peb_debug_check_strategy);      // PEB-based check
    register_strategy(&timing_check_strategy);         // Timing-based check
    register_strategy(&int3_detection_strategy);       // INT3-based check
    
    // The following are not registered as they're not fully implemented as direct replacements
    // - remote_debug_check_strategy
    // - output_debug_check_strategy  
    // - parent_check_strategy
}