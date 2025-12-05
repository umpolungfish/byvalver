#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h> // For uint8_t, uint32_t
#include "core.h"
#include "obfuscation_strategy_registry.h"
#include "pic_generation.h"
#include "cli.h"
#include "ml_strategist.h"
#include "strategy.h"  // For cleanup_ml_strategist
#include "../decoder.h" // Include the generated decoder stub header

size_t find_entry_point(const uint8_t *shellcode, size_t size);

int main(int argc, char *argv[]) {
    // Create and initialize configuration first
    byvalver_config_t *config = config_create_default();
    if (!config) {
        fprintf(stderr, "Error: Failed to create default configuration\n");
        return EXIT_GENERAL_ERROR;
    }

    // Parse command-line arguments
    int parse_result = parse_arguments(argc, argv, config);

    // Handle special requests (help/version) first
    if (config->help_requested) {
        print_detailed_help(stdout, argv[0]);
        config_free(config);
        return EXIT_SUCCESS;
    }

    if (config->version_requested) {
        print_version(stdout);
        config_free(config);
        return EXIT_SUCCESS;
    }

    // Initialize ML strategist only if ML option is enabled (after parsing arguments)
    ml_strategist_t ml_strategist;
    int ml_initialized = 0;
    if (config->use_ml_strategist) {
        if (ml_strategist_init(&ml_strategist, "./ml_models/byvalver_ml_model.bin") != 0) {
            // If initial model load fails, continue with default weights
            ml_strategist_init(&ml_strategist, "");  // Load with empty path to initialize with default weights
            fprintf(stderr, "[ML] ML Strategist initialized with default weights\n");
        } else {
            fprintf(stderr, "[ML] ML Strategist loaded from model file\n");
        }
        ml_initialized = 1;
    }

    // If there was an error parsing arguments, show usage and exit
    if (parse_result != EXIT_SUCCESS) {
        if (parse_result != EXIT_SUCCESS) {
            print_usage(stderr, argv[0]);
        }
        config_free(config);
        if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
        return parse_result;
    }

    // Load configuration file if specified
    if (config->config_file) {
        int config_load_result = load_config_file(config->config_file, config);
        if (config_load_result != EXIT_SUCCESS) {
            config_free(config);
            if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
            return config_load_result;
        }
    }

    // Validate that input file is provided
    if (!config->input_file) {
        fprintf(stderr, "Error: Input file is required\n\n");
        print_usage(stderr, argv[0]);
        config_free(config);
        if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
        return EXIT_INVALID_ARGUMENTS;
    }

    // Open input file
    FILE *file = fopen(config->input_file, "rb");
    if (!file) {
        perror("fopen input file");
        config_free(config);
        if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
        return EXIT_INPUT_FILE_ERROR;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0) {
        fprintf(stderr, "Error: Input file is empty or invalid\n");
        fclose(file);
        config_free(config);
        if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
        return EXIT_INPUT_FILE_ERROR;
    }

    // Check if file size exceeds max allowed size
    if (config->max_size > 0 && (size_t)file_size > config->max_size) {
        fprintf(stderr, "Error: Input file size (%ld bytes) exceeds maximum allowed size (%zu bytes)\n",
                file_size, config->max_size);
        fclose(file);
        config_free(config);
        if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
        return EXIT_INPUT_FILE_ERROR;
    }

    // Allocate memory for shellcode
    uint8_t *shellcode = malloc(file_size);
    if (!shellcode) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        config_free(config);
        if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
        return EXIT_GENERAL_ERROR;
    }

    // Read shellcode from file
    size_t bytes_read = fread(shellcode, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "Error: Could not read complete file\n");
        free(shellcode);
        fclose(file);
        config_free(config);
        if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
        return EXIT_INPUT_FILE_ERROR;
    }

    fclose(file);

    // In dry-run mode, just exit after reading the file successfully
    if (config->dry_run) {
        if (!config->quiet) {
            printf("✓ Input file validated successfully\n");
            printf("File size: %ld bytes\n", file_size);
        }
        free(shellcode);
        config_free(config);
        return EXIT_SUCCESS;
    }

    // Initialize strategy registries
    init_strategies(); // Pass 2: Null-byte elimination strategies

    if (config->use_biphasic) {
        init_obfuscation_strategies(); // Pass 1: Obfuscation strategies
        if (!config->quiet) {
            fprintf(stderr, "\n🔄 BIPHASIC MODE ENABLED\n");
            fprintf(stderr, "   Pass 1: Obfuscation & Complexification\n");
            fprintf(stderr, "   Pass 2: Null-Byte Elimination\n\n");
        }
    }

    // Process shellcode
    struct buffer new_shellcode;
    if (config->use_pic_generation) {
        if (!config->quiet) {
            fprintf(stderr, "\n🏗️  PIC GENERATION MODE ENABLED\n");
            fprintf(stderr, "   Converting to position-independent code\n\n");
        }

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
            config_free(config);
            if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
            return EXIT_PROCESSING_FAILED;
        }

        // Now apply null-byte elimination to the PIC shellcode
        if (config->use_biphasic) {
            new_shellcode = biphasic_process(pic_result.data, pic_result.size);
        } else {
            new_shellcode = remove_null_bytes(pic_result.data, pic_result.size);
        }

        // Free PIC result
        pic_free_result(&pic_result);
    } else if (config->use_biphasic) {
        new_shellcode = biphasic_process(shellcode, file_size);
    } else {
        new_shellcode = remove_null_bytes(shellcode, file_size);
    }

    // Verify the shellcode was processed successfully
    if (new_shellcode.data == NULL && new_shellcode.size == 0) {
        fprintf(stderr, "Error: Shellcode processing failed\n");
        free(shellcode);
        config_free(config);
        if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
        return EXIT_PROCESSING_FAILED;
    }

    struct buffer final_shellcode;
    buffer_init(&final_shellcode);

    if (config->encode_shellcode) {
        if (!config->quiet) {
            printf("Encoding shellcode with XOR key: 0x%08x\n", config->xor_key);
        }

        uint8_t *decoder_stub = decoder_bin;
        size_t decoder_len = decoder_bin_len;

        // Append the decoder stub to the final shellcode buffer
        buffer_append(&final_shellcode, decoder_stub, decoder_len);

        // Append the 4-byte key
        buffer_append(&final_shellcode, (uint8_t *)&config->xor_key, 4);

        // Define the null-free XOR key for the length
        const uint32_t NULL_FREE_LENGTH_XOR_KEY = 0x11223344;
        // Calculate the XOR-encoded length
        uint32_t encoded_length = new_shellcode.size ^ NULL_FREE_LENGTH_XOR_KEY;
        // Append the 4-byte XOR-encoded length of the *original* shellcode (before XOR encoding)
        buffer_append(&final_shellcode, (uint8_t *)&encoded_length, 4);

        // XOR encode the new_shellcode.data with the 4-byte key
        for (size_t i = 0; i < new_shellcode.size; i++) {
            new_shellcode.data[i] ^= ((uint8_t *)&config->xor_key)[i % 4];
        }

        // Append the XOR-encoded shellcode to the final shellcode buffer
        buffer_append(&final_shellcode, new_shellcode.data, new_shellcode.size);

    } else {
        // If no XOR encoding, just append the new_shellcode directly
        buffer_append(&final_shellcode, new_shellcode.data, new_shellcode.size);
    }

    if (!config->quiet) {
        printf("Original shellcode size: %ld\n", file_size);
        printf("Modified shellcode size: %zu\n", final_shellcode.size);
    }

    // Write modified shellcode to output file
    FILE *out_file = fopen(config->output_file, "wb");
    if (!out_file) {
        perror("fopen output file");
        free(shellcode);
        buffer_free(&new_shellcode);
        buffer_free(&final_shellcode);
        config_free(config);
        if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
        return EXIT_OUTPUT_FILE_ERROR;
    }

    fwrite(final_shellcode.data, 1, final_shellcode.size, out_file);
    fclose(out_file);

    if (!config->quiet) {
        printf("Modified shellcode written to: %s\n", config->output_file);
    }

    free(shellcode);
    buffer_free(&new_shellcode);
    buffer_free(&final_shellcode);
    config_free(config);
    if (ml_initialized) ml_strategist_cleanup(&ml_strategist);

    return EXIT_SUCCESS;
}