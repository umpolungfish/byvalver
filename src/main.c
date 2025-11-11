#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h> // For uint8_t, uint32_t
#include "core.h"
#include "../decoder.h" // Include the generated decoder stub header

size_t find_entry_point(const uint8_t *shellcode, size_t size);

int main(int argc, char *argv[]) {
    int encode_shellcode = 0;
    uint32_t xor_key = 0;
    char *input_file = NULL;
    char *output_file = "output.bin";
    int arg_offset = 1;

    if (argc > 1 && strcmp(argv[1], "--xor-encode") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s --xor-encode <key> <input_file> [output_file]\n", argv[0]);
            return 1;
        }
        encode_shellcode = 1;
        xor_key = (uint32_t)strtol(argv[2], NULL, 16);
        input_file = argv[3];
        arg_offset = 4;
    } else {
        if (argc < 2) {
            fprintf(stderr, "Usage: %s <input_shellcode_file> [output_file]\n", argv[0]);
            return 1;
        }
        input_file = argv[1];
        arg_offset = 2;
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
    fread(shellcode, 1, file_size, file);
    fclose(file);

    init_strategies(); // Initialize strategies
    struct buffer new_shellcode = remove_null_bytes(shellcode, file_size);

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