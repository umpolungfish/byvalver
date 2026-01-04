#define _GNU_SOURCE  // Need this to get PATH_MAX on some systems
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h> // For uint8_t, uint32_t
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>  // For readlink
#include <limits.h>  // For PATH_MAX
#include "core.h"
#include "obfuscation_strategy_registry.h"
#include "pic_generation.h"
#include "cli.h"
#include "ml_strategist.h"
#include "strategy.h"  // For cleanup_ml_strategist
#include "utils.h"  // For create_parent_dirs
#include "batch_processing.h"  // For batch directory processing
#include "../decoder.h" // Include the generated decoder stub header
#include "processing.h"  // For process_single_file

#ifdef TUI_ENABLED
#include "tui/tui_menu.h"
#endif

size_t find_entry_point(const uint8_t *shellcode, size_t size);

// Helper function to format shellcode based on output format
static char* format_shellcode(const uint8_t *data, size_t size, const char *format) {
    if (strcmp(format, "raw") == 0) {
        // Raw binary - no formatting needed
        return NULL;
    }

    // Calculate buffer size needed
    size_t buffer_size = 0;
    if (strcmp(format, "c") == 0) {
        // C array format: "unsigned char shellcode[] = {\n  0xXX, 0xXX, ...\n};\n"
        buffer_size = 100 + (size * 7); // ~7 chars per byte (0xXX, )
    } else if (strcmp(format, "python") == 0) {
        // Python format: "shellcode = b\"\xXX\xXX...\"\n"
        buffer_size = 50 + (size * 4); // ~4 chars per byte (\xXX)
    } else if (strcmp(format, "powershell") == 0) {
        // PowerShell format: "$shellcode = @(0xXX,0xXX,...)\n"
        buffer_size = 50 + (size * 6); // ~6 chars per byte (0xXX,)
    } else if (strcmp(format, "hexstring") == 0) {
        // Hex string format: "XXYY..."
        buffer_size = size * 2 + 2;
    } else {
        return NULL;
    }

    char *output = malloc(buffer_size);
    if (!output) {
        return NULL;
    }

    size_t pos = 0;

    if (strcmp(format, "c") == 0) {
        pos += snprintf(output + pos, buffer_size - pos, "unsigned char shellcode[] = {\n  ");
        for (size_t i = 0; i < size; i++) {
            pos += snprintf(output + pos, buffer_size - pos, "0x%02x", data[i]);
            if (i < size - 1) {
                pos += snprintf(output + pos, buffer_size - pos, ", ");
                if ((i + 1) % 12 == 0) {
                    pos += snprintf(output + pos, buffer_size - pos, "\n  ");
                }
            }
        }
        pos += snprintf(output + pos, buffer_size - pos, "\n};\n");
        pos += snprintf(output + pos, buffer_size - pos, "unsigned int shellcode_len = %zu;\n", size);
    }
    else if (strcmp(format, "python") == 0) {
        pos += snprintf(output + pos, buffer_size - pos, "shellcode = b\"");
        for (size_t i = 0; i < size; i++) {
            pos += snprintf(output + pos, buffer_size - pos, "\\x%02x", data[i]);
        }
        pos += snprintf(output + pos, buffer_size - pos, "\"\n");
    }
    else if (strcmp(format, "powershell") == 0) {
        pos += snprintf(output + pos, buffer_size - pos, "$shellcode = @(\n  ");
        for (size_t i = 0; i < size; i++) {
            pos += snprintf(output + pos, buffer_size - pos, "0x%02x", data[i]);
            if (i < size - 1) {
                pos += snprintf(output + pos, buffer_size - pos, ",");
                if ((i + 1) % 12 == 0) {
                    pos += snprintf(output + pos, buffer_size - pos, "\n  ");
                }
            }
        }
        pos += snprintf(output + pos, buffer_size - pos, "\n)\n");
    }
    else if (strcmp(format, "hexstring") == 0) {
        for (size_t i = 0; i < size; i++) {
            pos += snprintf(output + pos, buffer_size - pos, "%02x", data[i]);
        }
        pos += snprintf(output + pos, buffer_size - pos, "\n");
    }

    return output;
}

// Process a single file with the given configuration
// Returns EXIT_SUCCESS on success, or an error code on failure
int process_single_file(const char *input_file, const char *output_file,
                        byvalver_config_t *config, size_t *input_size_out,
                        size_t *output_size_out) {
    // Open input file
    FILE *file = fopen(input_file, "rb");
    if (!file) {
        if (!config->quiet) {
            fprintf(stderr, "Error: Cannot open input file '%s': %s\n",
                    input_file, strerror(errno));
        }
        return EXIT_INPUT_FILE_ERROR;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0) {
        if (!config->quiet) {
            fprintf(stderr, "Error: Input file '%s' is empty or invalid\n", input_file);
        }
        fclose(file);
        return EXIT_INPUT_FILE_ERROR;
    }

    // Check if file size exceeds max allowed size
    if (config->max_size > 0 && (size_t)file_size > config->max_size) {
        if (!config->quiet) {
            fprintf(stderr, "Error: Input file '%s' size (%ld bytes) exceeds maximum allowed size (%zu bytes)\n",
                    input_file, file_size, config->max_size);
        }
        fclose(file);
        return EXIT_INPUT_FILE_ERROR;
    }

    // Allocate memory for shellcode
    uint8_t *shellcode = malloc(file_size);
    if (!shellcode) {
        if (!config->quiet) {
            fprintf(stderr, "Error: Memory allocation failed for '%s'\n", input_file);
        }
        fclose(file);
        return EXIT_GENERAL_ERROR;
    }

    // Read shellcode from file
    size_t bytes_read = fread(shellcode, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        if (!config->quiet) {
            fprintf(stderr, "Error: Could not read complete file '%s'\n", input_file);
        }
        free(shellcode);
        fclose(file);
        return EXIT_INPUT_FILE_ERROR;
    }

    fclose(file);

    if (input_size_out) {
        *input_size_out = file_size;
    }

    // In dry-run mode, just exit after reading the file successfully
    if (config->dry_run) {
        free(shellcode);
        return EXIT_SUCCESS;
    }

    // Process shellcode
    struct buffer new_shellcode;
    if (config->use_pic_generation) {
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
            if (!config->quiet) {
                fprintf(stderr, "Error: PIC generation failed for '%s'\n", input_file);
            }
            free(shellcode);
            return EXIT_PROCESSING_FAILED;
        }

        // Now apply null-byte elimination to the PIC shellcode
        if (config->use_biphasic) {
            new_shellcode = biphasic_process(pic_result.data, pic_result.size, config->arch);
        } else {
            new_shellcode = remove_null_bytes(pic_result.data, pic_result.size, config->arch);
        }

        // Free PIC result
        pic_free_result(&pic_result);
    } else if (config->use_biphasic) {
        new_shellcode = biphasic_process(shellcode, file_size, config->arch);
    } else {
        new_shellcode = remove_null_bytes(shellcode, file_size, config->arch);
    }

    // Verify the shellcode was processed successfully
    if (new_shellcode.data == NULL && new_shellcode.size == 0) {
        if (!config->quiet) {
            fprintf(stderr, "Error: Shellcode processing failed for '%s'\n", input_file);
        }
        free(shellcode);
        return EXIT_PROCESSING_FAILED;
    }

    struct buffer final_shellcode;
    buffer_init(&final_shellcode);

    if (config->encode_shellcode) {
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

    if (output_size_out) {
        *output_size_out = final_shellcode.size;
    }

    // Verify that the final shellcode has no bad bytes
    if (!is_bad_byte_free_buffer(final_shellcode.data, final_shellcode.size)) {
        if (!config->quiet) {
            // Count and identify remaining bad bytes
            int bad_byte_found[256] = {0};
            int total_bad_bytes = 0;
            for (size_t i = 0; i < final_shellcode.size; i++) {
                if (!is_bad_byte_free_byte(final_shellcode.data[i])) {
                    if (!bad_byte_found[final_shellcode.data[i]]) {
                        bad_byte_found[final_shellcode.data[i]] = 1;
                        total_bad_bytes++;
                    }
                }
            }

            fprintf(stderr, "Error: Shellcode processing completed but bad bytes still remain in output\n");
            fprintf(stderr, "       Found %d distinct bad byte(s): ", total_bad_bytes);
            int printed = 0;
            for (int i = 0; i < 256; i++) {
                if (bad_byte_found[i]) {
                    if (printed > 0) fprintf(stderr, ", ");
                    fprintf(stderr, "0x%02x", i);
                    printed++;
                }
            }
            fprintf(stderr, "\n");
        }
        free(shellcode);
        buffer_free(&new_shellcode);
        buffer_free(&final_shellcode);
        return EXIT_PROCESSING_FAILED;  // Return failure when bad bytes remain
    }

    // Write modified shellcode to output file
    // First, create parent directories if needed
    if (create_parent_dirs(output_file) != 0) {
        if (!config->quiet) {
            fprintf(stderr, "Error: Cannot create parent directories for output file '%s'\n",
                    output_file);
        }
        free(shellcode);
        buffer_free(&new_shellcode);
        buffer_free(&final_shellcode);
        return EXIT_OUTPUT_FILE_ERROR;
    }

    // Format and write output based on output_format
    char *formatted_output = format_shellcode(final_shellcode.data, final_shellcode.size,
                                              config->output_format);

    const char *write_mode = (formatted_output != NULL) ? "w" : "wb";
    FILE *out_file = fopen(output_file, write_mode);
    if (!out_file) {
        if (!config->quiet) {
            fprintf(stderr, "Error: Cannot open output file '%s': %s\n",
                    output_file, strerror(errno));
        }
        free(shellcode);
        buffer_free(&new_shellcode);
        buffer_free(&final_shellcode);
        if (formatted_output) free(formatted_output);
        return EXIT_OUTPUT_FILE_ERROR;
    }

    if (formatted_output != NULL) {
        // Write formatted text
        fprintf(out_file, "%s", formatted_output);
        free(formatted_output);
    } else {
        // Write raw binary
        fwrite(final_shellcode.data, 1, final_shellcode.size, out_file);
    }
    fclose(out_file);

    free(shellcode);
    buffer_free(&new_shellcode);
    buffer_free(&final_shellcode);

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    // Create and initialize configuration first
    byvalver_config_t *config = config_create_default();
    if (!config) {
        fprintf(stderr, "Error: Failed to create default configuration\n");
        return EXIT_GENERAL_ERROR;
    }

    // Parse command-line arguments
    int parse_result = parse_arguments(argc, argv, config);

    // Initialize ML strategist only if ML option is enabled (after parsing arguments)
    ml_strategist_t ml_strategist;
    int ml_initialized = 0;

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

    // Launch interactive TUI menu if requested
    if (config->interactive_menu) {
#ifdef TUI_ENABLED
        int tui_result = run_tui_menu(config);
        config_free(config);
        if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
        return tui_result;
#else
        fprintf(stderr, "Error: TUI mode not compiled in. Please rebuild with TUI support enabled.\n");
        config_free(config);
        return EXIT_GENERAL_ERROR;
#endif
    }

    if (config->use_ml_strategist) {
        // Determine the absolute path to the ML model file
        char model_path[PATH_MAX];
        char exe_path[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len != -1) {
            exe_path[len] = '\0';
            // Extract directory from executable path
            char *last_slash = strrchr(exe_path, '/');
            if (last_slash) {
                *last_slash = '\0';
                // Safely construct the model path by checking length to avoid truncation warnings
                size_t exe_len = strlen(exe_path);
                size_t suffix_len = strlen("/../ml_models/byvalver_ml_model.bin");
                if (exe_len + suffix_len < sizeof(model_path)) {
                    strcpy(model_path, exe_path);
                    strcat(model_path, "/../ml_models/byvalver_ml_model.bin");
                } else {
                    // Fallback if path would be too long
                    strncpy(model_path, "./ml_models/byvalver_ml_model.bin", sizeof(model_path) - 1);
                    model_path[sizeof(model_path) - 1] = '\0';
                }
            } else {
                strncpy(model_path, "./ml_models/byvalver_ml_model.bin", sizeof(model_path) - 1);
                model_path[sizeof(model_path) - 1] = '\0';
            }
        } else {
            strncpy(model_path, "./ml_models/byvalver_ml_model.bin", sizeof(model_path) - 1);
            model_path[sizeof(model_path) - 1] = '\0';
        }

        if (ml_strategist_init(&ml_strategist, model_path) != 0) {
            // If initial model load fails, continue with default weights
            ml_strategist_init(&ml_strategist, "");  // Load with empty path to initialize with default weights
            fprintf(stderr, "[ML] ML Strategist initialized with default weights\n");
        } else {
            fprintf(stderr, "[ML] ML Strategist loaded from model file: %s\n", model_path);
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

    // Initialize strategy registries (needed for both single and batch mode)
    init_strategies(config->use_ml_strategist); // Pass 2: Null-byte elimination strategies

    if (config->use_biphasic) {
        init_obfuscation_strategies(); // Pass 1: Obfuscation strategies
        if (!config->quiet) {
            fprintf(stderr, "\n🔄 BIPHASIC MODE ENABLED\n");
            fprintf(stderr, "   Pass 1: Obfuscation & Complexification\n");
            fprintf(stderr, "   Pass 2: Null-Byte Elimination\n\n");
        }
    }

    // Check if input is a directory
    if (is_directory(config->input_file)) {
        // BATCH MODE
        config->batch_mode = 1;

        // Validate output is also a directory path
        if (!config->output_file || strcmp(config->output_file, "output.bin") == 0) {
            fprintf(stderr, "Error: Output directory is required for batch processing\n\n");
            print_usage(stderr, argv[0]);
            config_free(config);
            if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
            return EXIT_INVALID_ARGUMENTS;
        }

        if (!config->quiet) {
            printf("\n📁 BATCH PROCESSING MODE\n");
            printf("Input directory:  %s\n", config->input_file);
            printf("Output directory: %s\n", config->output_file);
            printf("File pattern:     %s\n", config->file_pattern);
            printf("Recursive:        %s\n", config->recursive ? "yes" : "no");
            printf("Preserve struct:  %s\n", config->preserve_structure ? "yes" : "no");
            printf("\n");
        }

        // Find all files matching the pattern
        file_list_t file_list;
        file_list_init(&file_list);

        if (find_files(config->input_file, config->file_pattern, config->recursive, &file_list) != 0) {
            fprintf(stderr, "Error: Failed to scan directory '%s'\n", config->input_file);
            file_list_free(&file_list);
            config_free(config);
            if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
            return EXIT_INPUT_FILE_ERROR;
        }

        if (file_list.count == 0) {
            if (!config->quiet) {
                printf("No files found matching pattern '%s'\n", config->file_pattern);
            }
            file_list_free(&file_list);
            config_free(config);
            if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
            return EXIT_SUCCESS;
        }

        if (!config->quiet) {
            printf("Found %zu file(s) to process\n\n", file_list.count);
        }

        // Initialize bad byte context for batch processing
        init_bad_byte_context(config->bad_bytes);

        // Initialize batch statistics
        batch_stats_t stats;
        batch_stats_init(&stats);
        stats.total_files = file_list.count;

        // Set bad byte configuration in stats
        bad_byte_config_t* bad_byte_config = get_bad_byte_config();
        if (bad_byte_config) {
            stats.bad_byte_count = bad_byte_config->bad_byte_count;
            // Convert uint8_t to int for the batch stats
            for (int i = 0; i < 256; i++) {
                stats.bad_byte_set[i] = bad_byte_config->bad_bytes[i];
            }
        }

        // Process each file
        for (size_t i = 0; i < file_list.count; i++) {
            const char *input_path = file_list.paths[i];

            // Construct output path
            char *output_path = construct_output_path(input_path, config->input_file,
                                                     config->output_file, config->preserve_structure);
            if (!output_path) {
                if (!config->quiet) {
                    fprintf(stderr, "Warning: Failed to construct output path for '%s'\n", input_path);
                }
                stats.skipped_files++;
                if (!config->continue_on_error) {
                    break;
                }
                continue;
            }

            if (!config->quiet && config->verbose) {
                printf("[%zu/%zu] Processing: %s\n", i + 1, file_list.count, input_path);
            } else if (!config->quiet) {
                printf("[%zu/%zu] %s\n", i + 1, file_list.count, input_path);
            }

            // Set the batch stats context for strategy tracking
            set_batch_stats_context(&stats);

            // Process the file
            size_t input_size = 0, output_size = 0;
            int result = process_single_file(input_path, output_path, config, &input_size, &output_size);

            if (result == EXIT_SUCCESS) {
                stats.processed_files++;
                stats.total_input_bytes += input_size;
                stats.total_output_bytes += output_size;

                // Count file complexity statistics if we have both input and output
                if (input_size > 0) {
                    // Read the input file to count original stats
                    FILE *input_file = fopen(input_path, "rb");
                    if (input_file) {
                        uint8_t *input_data = malloc(input_size);
                        if (input_data) {
                            if (fread(input_data, 1, input_size, input_file) == input_size) {
                                int instr_count, bad_byte_count;
                                count_shellcode_stats(input_data, input_size, &instr_count, &bad_byte_count);

                                // Add file complexity stats to batch stats
                                batch_stats_add_file_stats(&stats, input_path, input_size,
                                                         output_size, instr_count, bad_byte_count, 1);
                            }
                            free(input_data);
                        }
                        fclose(input_file);
                    }
                }

                if (!config->quiet && config->verbose) {
                    printf("  ✓ Processed: %zu → %zu bytes (%.2fx)\n",
                           input_size, output_size,
                           input_size > 0 ? (double)output_size / (double)input_size : 0.0);
                } else if (!config->quiet) {
                    printf("  ✓ %zu → %zu bytes\n", input_size, output_size);
                }
            } else {
                stats.failed_files++;
                if (!config->quiet) {
                    fprintf(stderr, "  ✗ Failed with error code %d\n", result);
                }

                // Add the failed file to the list if we're tracking them
                batch_stats_add_failed_file(&stats, input_path);

                // Also add file complexity stats for failed files (with success = 0)
                // Read the input file to count original stats
                FILE *input_file = fopen(input_path, "rb");
                if (input_file) {
                    fseek(input_file, 0, SEEK_END);
                    size_t input_size = ftell(input_file);
                    fseek(input_file, 0, SEEK_SET);

                    if (input_size > 0) {
                        uint8_t *input_data = malloc(input_size);
                        if (input_data) {
                            if (fread(input_data, 1, input_size, input_file) == input_size) {
                                int instr_count, bad_byte_count;
                                count_shellcode_stats(input_data, input_size, &instr_count, &bad_byte_count);

                                // Add file complexity stats to batch stats (success = 0)
                                batch_stats_add_file_stats(&stats, input_path, input_size,
                                                         0, instr_count, bad_byte_count, 0);
                            }
                            free(input_data);
                        }
                    }
                    fclose(input_file);
                }

                if (!config->continue_on_error) {
                    free(output_path);
                    break;
                }
            }

            free(output_path);
        }

        // Print statistics
        batch_stats_print(&stats, config->quiet);

        // Write failed files list to file if requested
        if (config->failed_files_output) {
            if (batch_write_failed_files(&stats, config->failed_files_output) == 0) {
                if (!config->quiet) {
                    printf("Failed files list written to: %s\n", config->failed_files_output);
                }
            } else {
                fprintf(stderr, "Warning: Failed to write failed files list to: %s\n", config->failed_files_output);
            }
        }

        // Cleanup
        file_list_free(&file_list);
        batch_stats_free(&stats);

        // Export metrics if requested
        if (ml_initialized && config->metrics_enabled) {
            if (config->metrics_export_json) {
                char json_file[512];
                snprintf(json_file, sizeof(json_file), "%s.json",
                        config->metrics_output_file ? config->metrics_output_file : "./ml_metrics");
                ml_strategist_export_metrics_json(json_file);
            }
            if (config->metrics_export_csv) {
                char csv_file[512];
                snprintf(csv_file, sizeof(csv_file), "%s.csv",
                        config->metrics_output_file ? config->metrics_output_file : "./ml_metrics");
                ml_strategist_export_metrics_csv(csv_file);
            }
        }

        // Show detailed statistics if requested (works with or without ML)
        if (config->show_stats) {
            printf("\n📊 DETAILED STATISTICS\n");
            printf("=====================\n");
            if (ml_initialized) {
                ml_strategist_print_metrics_summary();
                ml_strategist_print_strategy_breakdown();
                ml_strategist_print_bad_byte_breakdown();  // Added bad byte breakdown (v3.0)
                ml_strategist_print_learning_progress();
            } else {
                // Provide enhanced statistics for batch processing even without ML
                printf("Statistics without ML Integration:\n");
                printf("  - Batch processing completed\n");
                printf("  - Total files: %zu\n", stats.total_files);
                printf("  - Processed files: %zu\n", stats.processed_files);
                printf("  - Failed files: %zu\n", stats.failed_files);
                printf("  - Skipped files: %zu\n", stats.skipped_files);
                printf("  - Total input size: %zu bytes\n", stats.total_input_bytes);
                printf("  - Total output size: %zu bytes\n", stats.total_output_bytes);
                if (stats.total_input_bytes > 0) {
                    double ratio = (double)stats.total_output_bytes / (double)stats.total_input_bytes;
                    printf("  - Average size ratio: %.2f\n", ratio);
                }

                // Add bad byte information
                printf("  - Bad character elimination: ENABLED\n");
                printf("  - Configured bad bytes: ");
                int printed = 0;
                for (int i = 0; i < 256; i++) {
                    if (stats.bad_byte_set[i]) {
                        if (printed > 0) printf(", ");
                        printf("0x%02x", i);
                        printed++;
                    }
                }
                if (printed == 0) {
                    printf("0x00 (default null only)");
                }
                printf("\n");
                printf("  - Total bad bytes configured: %d\n", stats.bad_byte_count);
            }
        }

        config_free(config);
        if (ml_initialized) ml_strategist_cleanup(&ml_strategist);

        // Return success if at least one file was processed successfully
        return (stats.processed_files > 0) ? EXIT_SUCCESS : EXIT_PROCESSING_FAILED;
    }

    // SINGLE FILE MODE
    if (config->use_pic_generation && !config->quiet) {
        fprintf(stderr, "\n🏗️  PIC GENERATION MODE ENABLED\n");
        fprintf(stderr, "   Converting to position-independent code\n\n");
    }

    if (config->encode_shellcode && !config->quiet) {
        printf("Encoding shellcode with XOR key: 0x%08x\n", config->xor_key);
    }

    // Initialize bad byte context for single-file processing
    init_bad_byte_context(config->bad_bytes);

    // Process the single file
    size_t input_size = 0, output_size = 0;
    int result = process_single_file(config->input_file, config->output_file,
                                     config, &input_size, &output_size);

    if (result != EXIT_SUCCESS) {
        config_free(config);
        if (ml_initialized) ml_strategist_cleanup(&ml_strategist);
        return result;
    }

    // In dry-run mode, just show validation message
    if (config->dry_run) {
        if (!config->quiet) {
            printf("✓ Input file validated successfully\n");
            printf("File size: %zu bytes\n", input_size);
        }
    } else if (!config->quiet) {
        printf("Original shellcode size: %zu\n", input_size);
        printf("Modified shellcode size: %zu\n", output_size);
        printf("Modified shellcode written to: %s\n", config->output_file);
    }

    // Export metrics if requested
    if (ml_initialized && config->metrics_enabled) {
        if (config->metrics_export_json) {
            char json_file[512];
            snprintf(json_file, sizeof(json_file), "%s.json",
                    config->metrics_output_file ? config->metrics_output_file : "./ml_metrics");
            ml_strategist_export_metrics_json(json_file);
        }
        if (config->metrics_export_csv) {
            char csv_file[512];
            snprintf(csv_file, sizeof(csv_file), "%s.csv",
                    config->metrics_output_file ? config->metrics_output_file : "./ml_metrics");
            ml_strategist_export_metrics_csv(csv_file);
        }
    }

    // Show detailed statistics if requested (works with or without ML)
    if (config->show_stats) {
        printf("\n📊 DETAILED STATISTICS\n");
        printf("=====================\n");
        if (ml_initialized) {
            ml_strategist_print_metrics_summary();
            ml_strategist_print_strategy_breakdown();
            ml_strategist_print_bad_byte_breakdown();  // Added bad byte breakdown (v3.0)
            ml_strategist_print_learning_progress();
        } else {
            // Provide enhanced statistics even without ML, including bad byte info
            printf("Statistics without ML Integration:\n");
            printf("  - Shellcode processing completed\n");
            printf("  - Input size: %zu bytes\n", input_size);
            printf("  - Output size: %zu bytes\n", output_size);
            if (input_size > 0) {
                double ratio = (double)output_size / (double)input_size;
                printf("  - Size ratio: %.2f\n", ratio);
            }

            // Add bad byte information
            bad_byte_config_t* bad_byte_config = get_bad_byte_config();
            if (bad_byte_config) {
                printf("  - Bad character elimination: %s\n",
                       config->bad_bytes ? "ENABLED" : "DISABLED (default: nulls only)");
                printf("  - Configured bad bytes: ");

                int bad_byte_count = 0;
                for (int i = 0; i < 256; i++) {
                    if (bad_byte_config->bad_bytes[i]) {
                        if (bad_byte_count > 0) printf(", ");
                        printf("0x%02x", i);
                        bad_byte_count++;
                    }
                }
                if (bad_byte_count == 0) {
                    printf("0x00 (default null only)");
                }
                printf("\n");
                printf("  - Total bad bytes configured: %d\n", bad_byte_config->bad_byte_count);
            }
        }
    }

    config_free(config);
    if (ml_initialized) ml_strategist_cleanup(&ml_strategist);

    return EXIT_SUCCESS;
}