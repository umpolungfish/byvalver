#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/byvalver.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_shellcode_file> <expected_output_file>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        perror("fopen input");
        return 1;
    }
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t *shellcode = malloc(file_size);
    if (!shellcode) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return 1;
    }
    fread(shellcode, 1, file_size, file);
    fclose(file);

    struct buffer new_shellcode = remove_null_bytes(shellcode, file_size, 0);

    FILE *expected_file = fopen(argv[2], "rb");
    if (!expected_file) {
        perror("fopen expected output");
        free(shellcode);
        buffer_free(&new_shellcode);
        return 1;
    }
    fseek(expected_file, 0, SEEK_END);
    long expected_file_size = ftell(expected_file);
    fseek(expected_file, 0, SEEK_SET);
    uint8_t *expected_shellcode = malloc(expected_file_size);
    if (!expected_shellcode) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(expected_file);
        free(shellcode);
        buffer_free(&new_shellcode);
        return 1;
    }
    fread(expected_shellcode, 1, expected_file_size, expected_file);
    fclose(expected_file);

    int result = 0;
    if (new_shellcode.size != expected_file_size) {
        fprintf(stderr, "Test failed: size mismatch (expected %ld, got %zu)\n", expected_file_size, new_shellcode.size);
        result = 1;
    } else if (memcmp(new_shellcode.data, expected_shellcode, new_shellcode.size) != 0) {
        fprintf(stderr, "Test failed: content mismatch\n");
        result = 1;
    } else {
        printf("Test passed!\n");
    }

    free(shellcode);
    buffer_free(&new_shellcode);
    free(expected_shellcode);

    return result;
}
