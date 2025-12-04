#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h> // For uint8_t, uint32_t
#include "core.h"
#include "obfuscation_strategy_registry.h"
#include "pic_generation.h"
#include "../decoder.h" // Include the generated decoder stub header

size_t find_entry_point(const uint8_t *shellcode, size_t size);

int main(int argc, char *argv[]) {
    int encode_shellcode = 0;
    int use_biphasic = 0;
    int use_pic_generation = 0;
    uint32_t xor_key = 0;
    char *input_file = NULL;
    char *output_file = "output.bin";
    int arg_offset = 1;

    // Parse command-line flags
    if (argc > 1 && strcmp(argv[1], "--biphasic") == 0) {
        use_biphasic = 1;
        arg_offset = 2;
    }

    if (argc > arg_offset && strcmp(argv[arg_offset], "--pic") == 0) {
        use_pic_generation = 1;
        arg_offset++;
    }

    if (argc > arg_offset && strcmp(argv[arg_offset], "--xor-encode") == 0) {
        if (argc < arg_offset + 3) {
            fprintf(stderr, "Usage: %s [--biphasic] [--pic] --xor-encode <key> <input_file> [output_file]\n", argv[0]);
            return 1;
        }
        encode_shellcode = 1;
        xor_key = (uint32_t)strtol(argv[arg_offset + 1], NULL, 16);
        input_file = argv[arg_offset + 2];
        arg_offset += 3;
    } else {
        if (argc < arg_offset + 1) {
            fprintf(stderr, "Usage: %s [--biphasic] [--pic] <input_shellcode_file> [output_file]\n", argv[0]);
            fprintf(stderr, "\n");
            fprintf(stderr, "Options:\n");
            fprintf(stderr, "  --biphasic              Enable biphasic processing (obfuscation + null-elimination)\n");
            fprintf(stderr, "  --pic                   Generate position-independent code\n");
            fprintf(stderr, "  --xor-encode <key>      XOR encode output with 4-byte key (hex)\n");
            fprintf(stderr, "\n");
            fprintf(stderr, "Examples:\n");
            fprintf(stderr, "  %s input.bin output.bin\n", argv[0]);
            fprintf(stderr, "  %s --biphasic input.bin output.bin\n", argv[0]);
            fprintf(stderr, "  %s --pic input.bin output.bin\n", argv[0]);
            fprintf(stderr, "  %s --biphasic --xor-encode 0x12345678 input.bin output.bin\n", argv[0]);
            fprintf(stderr, "  %s --pic --xor-encode 0x12345678 input.bin output.bin\n", argv[0]);
            return 1;
        }
        input_file = argv[arg_offset];
        arg_offset++;
    }

    if (argc > arg_offset) {
        output_file = argv[arg_offset];
    }

    FILE *file = fopen(input_file, "rb");
    if (!file) { perror("fopen"); return 1; }
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t *shellcode = malloc(file_size);
    if (!shellcode) { fprintf(stderr, "Memory allocation failed\n"); fclose(file); return 1; }
    size_t bytes_read = fread(shellcode, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "Warning: Could not read complete file\n");
    }
    fclose(file);

    // Initialize strategy registries
    init_strategies(); // Pass 2: Null-byte elimination strategies

    if (use_biphasic) {
        init_obfuscation_strategies(); // Pass 1: Obfuscation strategies
        fprintf(stderr, "\n🔄 BIPHASIC MODE ENABLED\n");
        fprintf(stderr, "   Pass 1: Obfuscation & Complexification\n");
        fprintf(stderr, "   Pass 2: Null-Byte Elimination\n\n");
    }

    // Process shellcode
    struct buffer new_shellcode;
    if (use_pic_generation) {
        fprintf(stderr, "\n🏗️  PIC GENERATION MODE ENABLED\n");
        fprintf(stderr, "   Converting to position-independent code\n\n");

        // Initialize PIC options
        PICOptions pic_opts;
        pic_init_options(&pic_opts);
        pic_opts.use_jmp_call_pop = 1;
        pic_opts.use_api_hashing = 1;
        pic_opts.include_anti_debug = 0;

        // Generate PIC shellcode
        PICResult pic_result;
        int pic_ret = pic_generate(shellcode, file_size, &pic_opts, &pic_result);
        if (pic_ret != 0) {
            fprintf(stderr, "Error: PIC generation failed\n");
            free(shellcode);
            return 1;
        }

        // Now apply null-byte elimination to the PIC shellcode
        if (use_biphasic) {
            new_shellcode = biphasic_process(pic_result.data, pic_result.size);
        } else {
            new_shellcode = remove_null_bytes(pic_result.data, pic_result.size);
        }

        // Free PIC result
        pic_free_result(&pic_result);
    } else if (use_biphasic) {
        new_shellcode = biphasic_process(shellcode, file_size);
    } else {
        new_shellcode = remove_null_bytes(shellcode, file_size);
    }

    // Verify the shellcode was processed successfully
    if (new_shellcode.data == NULL && new_shellcode.size == 0) {
        fprintf(stderr, "Error: Shellcode processing failed\n");
        free(shellcode);
        return 1;
    }

    struct buffer final_shellcode;
    buffer_init(&final_shellcode);

    if (encode_shellcode) {
        printf("Encoding shellcode with XOR key: 0x%08x\n", xor_key);

        uint8_t *decoder_stub = decoder_bin;
        size_t decoder_len = decoder_bin_len;

        // Append the decoder stub to the final shellcode buffer
        buffer_append(&final_shellcode, decoder_stub, decoder_len);

        // Append the 4-byte key
        buffer_append(&final_shellcode, (uint8_t *)&xor_key, 4);

        // Define the null-free XOR key for the length
        const uint32_t NULL_FREE_LENGTH_XOR_KEY = 0x11223344;
        // Calculate the XOR-encoded length
        uint32_t encoded_length = new_shellcode.size ^ NULL_FREE_LENGTH_XOR_KEY;
        // Append the 4-byte XOR-encoded length of the *original* shellcode (before XOR encoding)
        buffer_append(&final_shellcode, (uint8_t *)&encoded_length, 4);

        // XOR encode the new_shellcode.data with the 4-byte key
        for (size_t i = 0; i < new_shellcode.size; i++) {
            new_shellcode.data[i] ^= ((uint8_t *)&xor_key)[i % 4];
        }

        // Append the XOR-encoded shellcode to the final shellcode buffer
        buffer_append(&final_shellcode, new_shellcode.data, new_shellcode.size);

    } else {
        // If no XOR encoding, just append the new_shellcode directly
        buffer_append(&final_shellcode, new_shellcode.data, new_shellcode.size);
    }

    printf("Original shellcode size: %ld\n", file_size);
    printf("Modified shellcode size: %zu\n", final_shellcode.size);
    
    // Write modified shellcode to output file
    FILE *out_file = fopen(output_file, "wb");
    if (!out_file) {
        perror("fopen output file");
        free(shellcode);
        buffer_free(&new_shellcode);
        buffer_free(&final_shellcode);
        return 1;
    }
    
    fwrite(final_shellcode.data, 1, final_shellcode.size, out_file);
    fclose(out_file);
    
    printf("Modified shellcode written to: %s\n", output_file);
    
    free(shellcode);
    buffer_free(&new_shellcode);
    buffer_free(&final_shellcode);
    return 0;
}