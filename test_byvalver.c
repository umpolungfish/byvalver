#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/capstone.h>
#include "core.h"

// Test result structure
typedef struct {
    const char *name;
    int passed;
    const char *error_msg;
} test_result_t;

// Helper to disassemble and compare
int verify_semantics(const uint8_t *original, size_t orig_size, 
                     const uint8_t *modified, size_t mod_size) {
    csh handle;
    cs_insn *orig_insn, *mod_insn;
    size_t orig_count, mod_count;
    
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
        return 0;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    orig_count = cs_disasm(handle, original, orig_size, 0, 0, &orig_insn);
    mod_count = cs_disasm(handle, modified, mod_size, 0, 0, &mod_insn);
    
    printf("Original disassembly:\n");
    for (size_t i = 0; i < orig_count; i++) {
        printf("  0x%"PRIx64":\t%s\t\t%s\n", 
               orig_insn[i].address, orig_insn[i].mnemonic, orig_insn[i].op_str);
    }
    
    printf("Modified disassembly:\n");
    for (size_t i = 0; i < mod_count; i++) {
        printf("  0x%"PRIx64":\t%s\t\t%s\n", 
               mod_insn[i].address, mod_insn[i].mnemonic, mod_insn[i].op_str);
    }
    
    if (orig_count > 0) cs_free(orig_insn, orig_count);
    if (mod_count > 0) cs_free(mod_insn, mod_count);
    cs_close(&handle);
    
    return 1; // For now, just print - manual verification needed
}

// Test 1: MOV BYTE PTR [eax], 0x0
test_result_t test_mov_byte_ptr_mem() {
    test_result_t result = {.name = "MOV BYTE PTR [eax], 0x0", .passed = 0, .error_msg = NULL};
    
    // c6 00 00 = mov BYTE PTR [eax], 0x0
    uint8_t shellcode[] = {0xc6, 0x00, 0x00};
    size_t shellcode_size = sizeof(shellcode);
    
    init_strategies();
    struct buffer output = remove_null_bytes(shellcode, shellcode_size);
    
    printf("\n=== Test: %s ===\n", result.name);
    printf("Input:  ");
    for (size_t i = 0; i < sizeof(shellcode); i++) {
        printf("%02x ", shellcode[i]);
    }
    printf("\nOutput: ");
    for (size_t i = 0; i < output.size; i++) {
        printf("%02x ", output.data[i]);
    }
    printf("\n");
    
    verify_semantics(shellcode, sizeof(shellcode), output.data, output.size);
    
    // Check that output doesn't have null bytes
    int has_nulls = 0;
    for (size_t i = 0; i < output.size; i++) {
        if (output.data[i] == 0x00) has_nulls = 1;
    }
    
    if (has_nulls) {
        result.error_msg = "Output still contains null bytes";
    } else {
        // Manual check: should be something like XOR AL,AL; MOV [EAX],AL or similar
        result.passed = 1;
    }
    
    buffer_free(&output);
    return result;
}

// Test 2: CALL with relative offset
test_result_t test_call_relative() {
    test_result_t result = {.name = "CALL 0x5", .passed = 0, .error_msg = NULL};
    
    // e8 00 00 00 00 = call 0x5 (relative)
    uint8_t shellcode[] = {0xe8, 0x00, 0x00, 0x00, 0x00, 0x90};
    
    init_strategies();
    struct buffer output = remove_null_bytes(shellcode, sizeof(shellcode));
    
    printf("\n=== Test: %s ===\n", result.name);
    printf("Input:  ");
    for (size_t i = 0; i < sizeof(shellcode); i++) {
        printf("%02x ", shellcode[i]);
    }
    printf("\nOutput: ");
    for (size_t i = 0; i < output.size; i++) {
        printf("%02x ", output.data[i]);
    }
    printf("\n");
    
    verify_semantics(shellcode, sizeof(shellcode), output.data, output.size);
    
    // Check that CALL wasn't deleted
    if (output.size == 0) {
        result.error_msg = "CALL instruction was deleted";
    } else {
        result.passed = 1;
    }
    
    buffer_free(&output);
    return result;
}

// Test 3: SUB ESP, 0x100
test_result_t test_sub_esp() {
    test_result_t result = {.name = "SUB ESP, 0x100", .passed = 0, .error_msg = NULL};
    
    // 81 ec 00 01 00 00 = sub esp, 0x100
    uint8_t shellcode[] = {0x81, 0xec, 0x00, 0x01, 0x00, 0x00};
    
    init_strategies();
    struct buffer output = remove_null_bytes(shellcode, sizeof(shellcode));
    
    printf("\n=== Test: %s ===\n", result.name);
    printf("Input:  ");
    for (size_t i = 0; i < sizeof(shellcode); i++) {
        printf("%02x ", shellcode[i]);
    }
    printf("\nOutput: ");
    for (size_t i = 0; i < output.size; i++) {
        printf("%02x ", output.data[i]);
    }
    printf("\n");
    
    verify_semantics(shellcode, sizeof(shellcode), output.data, output.size);
    
    // Check for null bytes
    int has_nulls = 0;
    for (size_t i = 0; i < output.size; i++) {
        if (output.data[i] == 0x00) has_nulls = 1;
    }
    
    if (has_nulls) {
        result.error_msg = "Output still contains null bytes";
    } else {
        result.passed = 1;
    }
    
    buffer_free(&output);
    return result;
}

// Test 4: MOV EAX, 0x0 (register, not memory)
test_result_t test_mov_eax_zero() {
    test_result_t result = {.name = "MOV EAX, 0x0", .passed = 0, .error_msg = NULL};
    
    // b8 00 00 00 00 = mov eax, 0x0
    uint8_t shellcode[] = {0xb8, 0x00, 0x00, 0x00, 0x00};
    
    init_strategies();
    struct buffer output = remove_null_bytes(shellcode, sizeof(shellcode));
    
    printf("\n=== Test: %s ===\n", result.name);
    printf("Input:  ");
    for (size_t i = 0; i < sizeof(shellcode); i++) {
        printf("%02x ", shellcode[i]);
    }
    printf("\nOutput: ");
    for (size_t i = 0; i < output.size; i++) {
        printf("%02x ", output.data[i]);
    }
    printf("\n");
    
    verify_semantics(shellcode, sizeof(shellcode), output.data, output.size);
    
    // Should be XOR EAX, EAX (31 c0) or similar
    int has_nulls = 0;
    for (size_t i = 0; i < output.size; i++) {
        if (output.data[i] == 0x00) has_nulls = 1;
    }
    
    if (has_nulls) {
        result.error_msg = "Output still contains null bytes";
    } else {
        result.passed = 1;
    }
    
    buffer_free(&output);
    return result;
}

// Test 5: PUSH 0x0
test_result_t test_push_zero() {
    test_result_t result = {.name = "PUSH 0x0", .passed = 0, .error_msg = NULL};
    
    // 68 00 00 00 00 = push 0x0
    uint8_t shellcode[] = {0x68, 0x00, 0x00, 0x00, 0x00};
    
    init_strategies();
    struct buffer output = remove_null_bytes(shellcode, sizeof(shellcode));
    
    printf("\n=== Test: %s ===\n", result.name);
    printf("Input:  ");
    for (size_t i = 0; i < sizeof(shellcode); i++) {
        printf("%02x ", shellcode[i]);
    }
    printf("\nOutput: ");
    for (size_t i = 0; i < output.size; i++) {
        printf("%02x ", output.data[i]);
    }
    printf("\n");
    
    verify_semantics(shellcode, sizeof(shellcode), output.data, output.size);
    
    int has_nulls = 0;
    for (size_t i = 0; i < output.size; i++) {
        if (output.data[i] == 0x00) has_nulls = 1;
    }
    
    if (has_nulls) {
        result.error_msg = "Output still contains null bytes";
    } else {
        result.passed = 1;
    }
    
    buffer_free(&output);
    return result;
}

// Test 6: No null bytes (should preserve)
test_result_t test_no_nulls() {
    test_result_t result = {.name = "No null bytes (preservation)", .passed = 0, .error_msg = NULL};
    
    // 90 90 90 = nop nop nop
    uint8_t shellcode[] = {0x90, 0x90, 0x90};
    
    init_strategies();
    struct buffer output = remove_null_bytes(shellcode, sizeof(shellcode));
    
    printf("\n=== Test: %s ===\n", result.name);
    printf("Input:  ");
    for (size_t i = 0; i < sizeof(shellcode); i++) {
        printf("%02x ", shellcode[i]);
    }
    printf("\nOutput: ");
    for (size_t i = 0; i < output.size; i++) {
        printf("%02x ", output.data[i]);
    }
    printf("\n");
    
    // Should be identical
    if (output.size == sizeof(shellcode) && 
        memcmp(output.data, shellcode, sizeof(shellcode)) == 0) {
        result.passed = 1;
    } else {
        result.error_msg = "Modified null-free input unnecessarily";
    }
    
    buffer_free(&output);
    return result;
}

int main() {
    printf("BYVALVER Test Suite\n");
    printf("===================\n\n");
    
    test_result_t tests[] = {
        test_mov_byte_ptr_mem(),
        test_call_relative(),
        test_sub_esp(),
        test_mov_eax_zero(),
        test_push_zero(),
        test_no_nulls()
    };
    
    int total = sizeof(tests) / sizeof(tests[0]);
    int passed = 0;
    
    printf("\n\n=== RESULTS ===\n");
    for (int i = 0; i < total; i++) {
        printf("[%s] %s", tests[i].passed ? "PASS" : "FAIL", tests[i].name);
        if (!tests[i].passed && tests[i].error_msg) {
            printf(" - %s", tests[i].error_msg);
        }
        printf("\n");
        if (tests[i].passed) passed++;
    }
    
    printf("\nTotal: %d/%d passed\n", passed, total);
    
    return (passed == total) ? 0 : 1;
}
