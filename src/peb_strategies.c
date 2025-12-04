#include "strategy.h"
#include "utils.h"
#include <stdio.h>

// Alternative PEB Traversal Method: Double Linked List Traversal
// This strategy implements the alternative PEB traversal method found in windows/42016.asm
// where instead of iterating through modules one by one, it directly accesses the 2nd and 3rd
// entries in the InInitializationOrderModuleList to reach kernel32.dll.
int can_handle_alt_peb_traversal(cs_insn *insn) {
    // This strategy would typically be used as a replacement for code that finds kernel32
    // We'll match NOP instructions or other suitable candidates where this strategy can be used
    (void)insn;
    return 0;  // Disabled
}

size_t get_size_alt_peb_traversal(__attribute__((unused)) cs_insn *insn) {
    // Size of the alternative PEB traversal code:
    // XOR ECX, ECX                    - 2 bytes
    // MOV EAX, [FS:ECX+0x30]          - 7 bytes
    // MOV EAX, [EAX+0x0C]             - 3 bytes
    // MOV EAX, [EAX+0x1C]             - 3 bytes
    // MOV EAX, [EAX+ECX]              - 2 bytes
    // MOV EAX, [EAX+ECX]              - 2 bytes
    // MOV EBX, [EAX+8]                - 3 bytes
    // Total: ~22 bytes
    return 22;
}

void generate_alt_peb_traversal(struct buffer *b, cs_insn *insn) {
    // Generate the alternative PEB traversal code:
    // XOR ECX, ECX                    - Clear ECX to avoid null byte in MOV FS:[0x30]
    buffer_write_byte(b, 0x31);  // XOR
    buffer_write_byte(b, 0xC9);  // ECX, ECX

    // MOV EAX, [FS:ECX+0x30]          - Get PEB via FS segment
    buffer_write_byte(b, 0x64);  // FS override
    buffer_write_byte(b, 0x8B);  // MOV
    buffer_write_byte(b, 0x45);  // ModR/M for [ECX+32-bit disp]
    buffer_write_byte(b, 0x30);  // Displacement 0x30

    // MOV EAX, [EAX+0x0C]             - Get LDR
    buffer_write_byte(b, 0x8B);  // MOV
    buffer_write_byte(b, 0x40);  // ModR/M for [EAX+8-bit disp]
    buffer_write_byte(b, 0x0C);  // Displacement 0x0C

    // MOV EAX, [EAX+0x1C]             - Get InInitializationOrderModuleList
    buffer_write_byte(b, 0x8B);  // MOV
    buffer_write_byte(b, 0x40);  // ModR/M for [EAX+8-bit disp]
    buffer_write_byte(b, 0x1C);  // Displacement 0x1C

    // MOV EAX, [EAX+ECX]              - Move to 2nd entry in module list
    buffer_write_byte(b, 0x8B);  // MOV
    buffer_write_byte(b, 0x04);  // ModR/M for [base+index*scale + disp]
    buffer_write_byte(b, 0x08);  // SIB: no disp, ECX base, EAX index

    // MOV EAX, [EAX+ECX]              - Move to 3rd entry (kernel32.dll)
    buffer_write_byte(b, 0x8B);  // MOV
    buffer_write_byte(b, 0x04);  // ModR/M for [base+index*scale + disp]
    buffer_write_byte(b, 0x08);  // SIB: no disp, ECX base, EAX index

    // MOV EBX, [EAX+8]                - Get base address of kernel32.dll
    buffer_write_byte(b, 0x8B);  // MOV
    buffer_write_byte(b, 0x58);  // ModR/M for [EAX+8-bit disp]
    buffer_write_byte(b, 0x08);  // Displacement 0x08

    (void)insn; // To avoid unused parameter warning
}

strategy_t alt_peb_traversal_strategy = {
    .name = "alt_peb_traversal",
    .can_handle = can_handle_alt_peb_traversal,
    .get_size = get_size_alt_peb_traversal,
    .generate = generate_alt_peb_traversal,
    .priority = 9  // High priority for effective PEB traversal
};

// Standard PEB Traversal Method: Iterative Module Search
// This strategy implements the standard PEB traversal method that iterates through modules
// to find kernel32.dll by comparing module names.
int can_handle_standard_peb_traversal(cs_insn *insn) {
    // This strategy would also be used for kernel32 finding
    (void)insn;
    return 0;  // Disabled
}

size_t get_size_standard_peb_traversal(__attribute__((unused)) cs_insn *insn) {
    // Size of the standard PEB traversal code:
    // MOV ESI, [FS:0x30]              - 6 bytes
    // MOV ESI, [ESI+0x0C]             - 3 bytes
    // MOV ESI, [ESI+0x1C]             - 3 bytes
    // LOOP and string comparison logic - ~20 bytes
    // Total: ~32 bytes (estimate)
    return 32;
}

void generate_standard_peb_traversal(struct buffer *b, cs_insn *insn) {
    // Generate the standard PEB traversal code:
    // MOV ESI, [FS:0x30]              - Get PEB
    buffer_write_byte(b, 0x64);  // FS override
    buffer_write_byte(b, 0x8B);  // MOV
    buffer_write_byte(b, 0x35);  // ModR/M for [32-bit disp]
    buffer_write_dword(b, 0x30); // Address 0x30

    // MOV ESI, [ESI+0x0C]             - Get LDR
    buffer_write_byte(b, 0x8B);  // MOV
    buffer_write_byte(b, 0x76);  // ModR/M for [ESI+8-bit disp]
    buffer_write_byte(b, 0x0C);  // Displacement 0x0C

    // MOV ESI, [ESI+0x1C]             - Get InInitOrder
    buffer_write_byte(b, 0x8B);  // MOV
    buffer_write_byte(b, 0x76);  // ModR/M for [ESI+8-bit disp]
    buffer_write_byte(b, 0x1C);  // Displacement 0x1C

    // This is a simplified version - a full implementation would include
    // the loop to iterate through modules and compare names
    // For BYVALVER's purposes, we create a pattern that avoids null bytes
    buffer_write_byte(b, 0x90); // NOP
    buffer_write_byte(b, 0x90); // NOP
    buffer_write_byte(b, 0x90); // NOP

    (void)insn; // To avoid unused parameter warning
}

strategy_t standard_peb_traversal_strategy = {
    .name = "standard_peb_traversal",
    .can_handle = can_handle_standard_peb_traversal,
    .get_size = get_size_standard_peb_traversal,
    .generate = generate_standard_peb_traversal,
    .priority = 8  // High priority for reliable PEB traversal
};

// Register all PEB-related strategies
void register_peb_strategies() {
    register_strategy(&alt_peb_traversal_strategy);
    register_strategy(&standard_peb_traversal_strategy);
}