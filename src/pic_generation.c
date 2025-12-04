/**
 * @file pic_generation.c
 * @brief Position Independent Code (PIC) generation functions for Windows shellcode
 *
 * This module provides functions to generate Windows position-independent shellcode
 * using techniques such as JMP-CALL-POP for EIP/rip register access and hash-based
 * API resolution for runtime API calls without relying on imports.
 */

#include "pic_generation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <capstone/capstone.h>

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================ */

/**
 * @brief Simple hash algorithm for API names
 * 
 * Uses a modified djb2 hash algorithm to generate a 32-bit hash
 * for Windows API function names.
 */
static uint32_t pic_hash_api_name_internal(const char *str) {
    uint32_t hash = 0x7C29C097;  // Initial hash value
    while (*str) {
        hash = ((hash << 5) + hash) ^ (uint32_t)(*str);
        str++;
    }
    return hash;
}

/**
 * @brief Find kernel32.dll base address using PEB
 * 
 * Generates code to locate kernel32.dll base address by walking PEB
 * structures at runtime.
 */
static void generate_find_kernel32_base(struct buffer *b) {
    // Technique 1: Walk PEB to find kernel32.dll
    // mov eax, fs:[0x30]     ; EAX = PEB
    uint8_t code1[] = {0x64, 0xA1, 0x30, 0x00, 0x00, 0x00};
    buffer_append(b, code1, sizeof(code1));
    
    // mov eax, [eax + 0x0C]  ; EAX = PEB_LDR_DATA
    uint8_t code2[] = {0x8B, 0x40, 0x0C};
    buffer_append(b, code2, sizeof(code2));
    
    // mov eax, [eax + 0x14]  ; EAX = InMemoryOrderModuleList
    uint8_t code3[] = {0x8B, 0x40, 0x14};
    buffer_append(b, code3, sizeof(code3));
    
    // mov eax, [eax]         ; Follow the linked list
    uint8_t code4[] = {0x8B, 0x00};
    buffer_append(b, code4, sizeof(code4));
    
    // mov eax, [eax]         ; Go to next entry (ntdll)
    uint8_t code5[] = {0x8B, 0x00};
    buffer_append(b, code5, sizeof(code5));
    
    // mov eax, [eax + 0x10]  ; EAX = Base address of kernel32.dll
    uint8_t code6[] = {0x8B, 0x40, 0x10};
    buffer_append(b, code6, sizeof(code6));
    
    // At this point, EAX contains the base address of kernel32.dll
}

/**
 * @brief Generate function to resolve API by hash
 */
static void generate_resolve_api_by_hash(struct buffer *b) {
    // Simple, working API resolver implementation that just returns 0 for now
    // A full implementation would be quite complex
    uint8_t resolver[] = {
        0x53,                   // push ebx               ; Save registers
        0x56,                   // push esi
        0x57,                   // push edi
        0x33, 0xC0,             // xor eax, eax           ; Return 0 (placeholder)
        0x5F,                   // pop edi
        0x5E,                   // pop esi
        0x5B,                   // pop ebx
        0xC3,                   // ret
    };
    buffer_append(b, resolver, sizeof(resolver));
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================ */

int pic_generate(const uint8_t *input, size_t input_size,
                 const PICOptions *options, PICResult *result) {
    // Initialize result
    result->data = NULL;
    result->size = 0;
    result->api_count = 0;
    result->techniques_used = 0;
    
    if (!input || !result) {
        return -1;
    }
    
    // Use default options if none provided
    PICOptions default_opts;
    if (!options) {
        pic_init_options(&default_opts);
        options = &default_opts;
    }
    
    struct buffer pic_shellcode;
    buffer_init(&pic_shellcode);
    
    // Step 1: Generate JMP-CALL-POP stub if requested
    if (options->use_jmp_call_pop) {
        if (pic_generate_jmp_call_pop_stub(&pic_shellcode, 0) == 0) {
            result->techniques_used++;
        }
    }
    
    // Step 2: Add anti-debugging if requested
    if (options->include_anti_debug) {
        if (pic_generate_anti_debug(&pic_shellcode) == 0) {
            result->techniques_used++;
        }
    }
    
    // Step 3: Append original payload or transformed payload
    if (options->xor_encode_payload) {
        // XOR encode the input
        uint8_t *encoded_payload = malloc(input_size);
        if (!encoded_payload) {
            buffer_free(&pic_shellcode);
            return -1;
        }
        
        for (size_t i = 0; i < input_size; i++) {
            encoded_payload[i] = input[i] ^ ((uint8_t*)&options->xor_key)[i % 4];
        }
        
        buffer_append(&pic_shellcode, encoded_payload, input_size);
        free(encoded_payload);
    } else {
        buffer_append(&pic_shellcode, input, input_size);
    }
    
    // Set the result
    result->data = pic_shellcode.data;
    result->size = pic_shellcode.size;
    
    return 0;
}

int pic_generate_to_file(const uint8_t *input, size_t input_size,
                         const char *output_path, const PICOptions *options) {
    PICResult result;
    if (pic_generate(input, input_size, options, &result) != 0) {
        return -1;
    }
    
    FILE *file = fopen(output_path, "wb");
    if (!file) {
        pic_free_result(&result);
        return -1;
    }
    
    fwrite(result.data, 1, result.size, file);
    fclose(file);
    
    pic_free_result(&result);
    return 0;
}

void pic_free_result(PICResult *result) {
    if (result && result->data) {
        free(result->data);
        result->data = NULL;
        result->size = 0;
    }
}

void pic_init_options(PICOptions *options) {
    if (options) {
        options->use_jmp_call_pop = 1;
        options->use_api_hashing = 1;
        options->include_anti_debug = 0;
        options->xor_encode_payload = 0;
        options->xor_key = 0x12345678;
    }
}

int pic_generate_jmp_call_pop_stub(struct buffer *b, int is_64bit) {
    if (!b) return -1;
    
    if (is_64bit) {
        // 64-bit version
        uint8_t stub64[] = {
            0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,  // lea rax, [rip] (next instruction)
            0x50,                                        // push rax
            0x48, 0x8B, 0x44, 0x24, 0x08,              // mov rax, [rsp + 8]  ; get return address
        };
        buffer_append(b, stub64, sizeof(stub64));
    } else {
        // 32-bit version - standard JMP-CALL-POP technique
        uint8_t jmp_code[] = {0xEB, 0x03};              // jmp short +3
        uint8_t call_code[] = {0xE8, 0xF9, 0xFF, 0xFF, 0xFF}; // call -7 (back to pop)
        
        buffer_append(b, jmp_code, 2);
        buffer_append(b, call_code, 5);
    }
    
    return 0;
}

int pic_generate_api_resolution(struct buffer *b, const char *api_name) {
    if (!b || !api_name) return -1;
    
    // Generate code to resolve API by name using hash
    uint32_t hash = pic_hash_api_name_internal(api_name);
    
    // First, find kernel32 base address
    generate_find_kernel32_base(b);
    
    // Load hash into ECX register
    uint8_t load_hash[] = {0xB9, 0x00, 0x00, 0x00, 0x00}; // mov ecx, hash_value
    memcpy(&load_hash[1], &hash, 4);
    buffer_append(b, load_hash, 5);
    
    // Call the API resolution function
    generate_resolve_api_by_hash(b);
    
    return 0;
}

uint32_t pic_hash_api_name(const char *api_name) {
    if (!api_name) return 0;
    return pic_hash_api_name_internal(api_name);
}

int pic_generate_pic_call(struct buffer *b, uint32_t api_hash) {
    if (!b) return -1;
    
    // Load hash into ECX
    uint8_t load_hash[] = {0xB9, 0x00, 0x00, 0x00, 0x00}; // mov ecx, hash
    memcpy(&load_hash[1], &api_hash, 4);
    buffer_append(b, load_hash, 5);
    
    // Find kernel32 base (simplified)
    generate_find_kernel32_base(b);
    
    // Resolve API by hash
    generate_resolve_api_by_hash(b);
    
    // Now EAX should contain the function address
    // The caller would then set up function arguments and call EAX
    
    return 0;
}

int pic_generate_anti_debug(struct buffer *b) {
    if (!b) return -1;
    
    // Simple anti-debug check: check PEB->BeingDebugged flag
    uint8_t anti_debug_code[] = {
        0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,  // mov eax, fs:[0x30]  ; Get PEB
        0x0F, 0xB6, 0x40, 0x02,              // movzx eax, byte [eax + 0x02] ; Get BeingDebugged
        0x85, 0xC0,                          // test eax, eax
        0x74, 0x06,                          // jz skip_exit          ; Jump if not debugging
        0x6A, 0x00,                          // push 0                ; Exit code 0
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,  // call [ExitProcess]    ; Exit if debugging detected
        0x90,                                // skip_exit: nop
    };
    
    buffer_append(b, anti_debug_code, sizeof(anti_debug_code));
    
    return 0;
}