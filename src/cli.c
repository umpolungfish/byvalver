#define _POSIX_C_SOURCE 200809L
#include "cli.h"
#include "badchar_profiles.h"
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/**
 * Parse bad characters from comma-separated hex string
 * @param input: String like "00,0a,0d"
 * @return: Allocated bad_char_config_t or NULL on error
 */
bad_char_config_t* parse_bad_chars_string(const char *input) {
    if (!input || strlen(input) == 0) {
        return NULL;
    }

    bad_char_config_t *config = calloc(1, sizeof(bad_char_config_t));
    if (!config) {
        return NULL;
    }

    // Duplicate input for strtok
    char *input_copy = strdup(input);
    if (!input_copy) {
        free(config);
        return NULL;
    }

    // Parse comma-separated tokens
    char *token = strtok(input_copy, ",");
    while (token && config->bad_char_count < 256) {
        // Trim leading whitespace
        while (*token && isspace((unsigned char)*token)) {
            token++;
        }

        // Trim trailing whitespace
        char *end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) {
            *end = '\0';
            end--;
        }

        // Skip empty tokens
        if (strlen(token) == 0) {
            token = strtok(NULL, ",");
            continue;
        }

        // Parse hex byte
        unsigned int byte_val;
        if (sscanf(token, "%02x", &byte_val) != 1 && sscanf(token, "%02X", &byte_val) != 1) {
            // Invalid hex format
            fprintf(stderr, "Error: Invalid hex byte: '%s'\n", token);
            fprintf(stderr, "Expected: 2-character hex value (00-FF)\n");
            free(input_copy);
            free(config);
            return NULL;
        }

        if (byte_val > 0xFF) {
            // Out of range
            fprintf(stderr, "Error: Hex value out of range: '%s' (must be 00-FF)\n", token);
            free(input_copy);
            free(config);
            return NULL;
        }

        uint8_t byte = (uint8_t)byte_val;

        // Add to bitmap if not already present (avoid duplicates)
        if (config->bad_chars[byte] == 0) {
            config->bad_chars[byte] = 1;
            config->bad_char_list[config->bad_char_count++] = byte;
        }

        token = strtok(NULL, ",");
    }

    free(input_copy);

    // Default to null byte if no bytes were successfully parsed
    if (config->bad_char_count == 0) {
        fprintf(stderr, "Warning: No valid bad characters specified, defaulting to null byte (00)\n");
        config->bad_chars[0x00] = 1;
        config->bad_char_list[0] = 0x00;
        config->bad_char_count = 1;
    }

    return config;
}

// Create and initialize default configuration
byvalver_config_t* config_create_default(void) {
    byvalver_config_t *config = malloc(sizeof(byvalver_config_t));
    if (!config) {
        return NULL;
    }
    
    // Initialize with default values
    memset(config, 0, sizeof(byvalver_config_t));
    
    // Set default values
    config->output_file = "output.bin";
    config->verbose = 0;
    config->quiet = 0;
    config->no_color = 0;
    config->use_biphasic = 0;
    config->use_pic_generation = 0;
    config->encode_shellcode = 0;
    config->xor_key = 0;
    config->output_format = "raw";
    config->target_arch = "x64";
    config->strategy_limit = 0; // unlimited by default
    config->max_size = 10 * 1024 * 1024; // 10MB default max
    config->timeout_seconds = 0; // no timeout by default
    config->dry_run = 0;
    config->show_stats = 0;
    config->validate_output = 0;
    config->help_requested = 0;
    config->version_requested = 0;
    config->output_file_specified_via_flag = 0;

    // ML Metrics defaults
    config->metrics_enabled = 0;
    config->metrics_output_file = "./ml_metrics.log";
    config->metrics_export_json = 0;
    config->metrics_export_csv = 0;
    config->metrics_show_live = 0;

    // Batch processing defaults
    config->batch_mode = 0;
    config->recursive = 0;
    config->file_pattern = "*.bin";
    config->preserve_structure = 1;  // Preserve by default
    config->continue_on_error = 1;  // Default to continuing on errors
    config->failed_files_output = NULL;  // No failed files output by default

    // Bad character configuration defaults (v3.0)
    // Default: only null byte (0x00) for backward compatibility
    config->bad_chars = calloc(1, sizeof(bad_char_config_t));
    if (config->bad_chars) {
        config->bad_chars->bad_chars[0x00] = 1;      // Mark null byte as bad
        config->bad_chars->bad_char_list[0] = 0x00;  // Add to list
        config->bad_chars->bad_char_count = 1;        // Count = 1
    }

    return config;
}

// Free configuration structure
void config_free(byvalver_config_t *config) {
    if (!config) return;

    // Free bad character configuration (v3.0)
    if (config->bad_chars) {
        free(config->bad_chars);
        config->bad_chars = NULL;
    }

    // Note: We don't free strings that point to argv or are static
    free(config);
}

// Print usage information
void print_usage(FILE *stream, const char *program_name) {
    fprintf(stream, "Usage: %s [OPTIONS] <input_file> [output_file]\n", program_name);
    fprintf(stream, "       %s --help    for detailed help\n", program_name);
    fprintf(stream, "       %s --version for version information\n", program_name);
}

// Print detailed help
void print_detailed_help(FILE *stream, const char *program_name) {
    fprintf(stream, "byvalver v3.0 - Generic Bad-Character Elimination Framework\n\n");

    fprintf(stream, "SYNOPSIS\n");
    fprintf(stream, "    %s [OPTIONS] <input_file> [output_file]\n\n", program_name);

    fprintf(stream, "DESCRIPTION\n");
    fprintf(stream, "    byvalver is an advanced C-based command-line tool designed for automated \n");
    fprintf(stream, "    elimination of bad characters from shellcode while preserving functional \n");
    fprintf(stream, "    equivalence. The tool leverages the Capstone disassembly framework to analyze \n");
    fprintf(stream, "    x86/x64 assembly instructions and applies sophisticated transformation strategies \n");
    fprintf(stream, "    to replace bad-character-containing instructions with functionally equivalent \n");
    fprintf(stream, "    alternatives.\n\n");
    fprintf(stream, "    By default, byvalver eliminates null bytes (0x00). Version 3.0 introduces generic \n");
    fprintf(stream, "    bad character elimination via the --bad-chars option, allowing you to specify \n");
    fprintf(stream, "    any set of bytes to eliminate (e.g., newlines, spaces, CRLF sequences).\n\n");
    
    fprintf(stream, "OPTIONS\n");
    fprintf(stream, "    General Options:\n");
    fprintf(stream, "      -h, --help                    Show this help message and exit\n");
    fprintf(stream, "      -v, --version                 Show version information and exit\n");
    fprintf(stream, "      -V, --verbose                 Enable verbose output\n");
    fprintf(stream, "      -q, --quiet                   Suppress non-essential output\n");
    fprintf(stream, "      --config FILE                 Use custom configuration file\n");
    fprintf(stream, "      --no-color                    Disable colored output\n\n");
    
    fprintf(stream, "    Processing Options:\n");
    fprintf(stream, "      --biphasic                    Enable biphasic processing (obfuscation + null-elimination)\n");
    fprintf(stream, "      --pic                         Generate position-independent code\n");
    fprintf(stream, "      --ml                          Use ML strategy selection\n");
    fprintf(stream, "      --xor-encode KEY              XOR encode output with 4-byte key (hex)\n");
    fprintf(stream, "      --format FORMAT               Output format: raw, c, python, powershell, hexstring\n\n");

    fprintf(stream, "    Bad Character Elimination (v3.0):\n");
    fprintf(stream, "      --bad-chars BYTES             Comma-separated hex bytes to eliminate (e.g., \"00,0a,0d\")\n");
    fprintf(stream, "                                    Default: \"00\" (null bytes only)\n");
    fprintf(stream, "      --profile NAME                Use predefined bad-character profile\n");
    fprintf(stream, "                                    Examples: http-newline, url-safe, sql-injection,\n");
    fprintf(stream, "                                              alphanumeric-only, printable-only\n");
    fprintf(stream, "      --list-profiles               List all available bad-character profiles\n\n");

    fprintf(stream, "    ML Metrics Options (requires --ml):\n");
    fprintf(stream, "      --metrics                     Enable ML metrics tracking and learning\n");
    fprintf(stream, "      --metrics-file FILE           Metrics output file (default: ./ml_metrics.log)\n");
    fprintf(stream, "      --metrics-json                Export metrics in JSON format\n");
    fprintf(stream, "      --metrics-csv                 Export metrics in CSV format\n");
    fprintf(stream, "      --metrics-live                Show live metrics during processing\n\n");

    fprintf(stream, "    Batch Processing Options:\n");
    fprintf(stream, "      -r, --recursive               Process directories recursively\n");
    fprintf(stream, "      --pattern PATTERN             File pattern to match (default: *.bin)\n");
    fprintf(stream, "      --no-preserve-structure       Don't preserve directory structure in output\n");
    fprintf(stream, "      --no-continue-on-error        Stop processing on first error (default is to continue)\n");
    fprintf(stream, "      --failed-files FILE           Output list of failed files to specified file\n\n");

    fprintf(stream, "    Advanced Options:\n");
    fprintf(stream, "      --strategy-limit N            Limit number of strategies to consider per instruction\n");
    fprintf(stream, "      --max-size N                  Maximum output size (in bytes)\n");
    fprintf(stream, "      --timeout SECONDS             Processing timeout (default: no timeout)\n");
    fprintf(stream, "      --dry-run                     Validate input without processing\n");
    fprintf(stream, "      --stats                       Show detailed statistics after processing\n\n");
    
    fprintf(stream, "    Output Options:\n");
    fprintf(stream, "      -o, --output FILE             Output file (alternative to positional argument)\n");
    fprintf(stream, "      --validate                    Validate output is null-byte free\n\n");
    
    fprintf(stream, "EXAMPLES\n");
    fprintf(stream, "    Basic usage:\n");
    fprintf(stream, "      %s shellcode.bin output.bin\n\n", program_name);
    
    fprintf(stream, "    With biphasic processing:\n");
    fprintf(stream, "      %s --biphasic shellcode.bin output.bin\n\n", program_name);
    
    fprintf(stream, "    With XOR encoding:\n");
    fprintf(stream, "      %s --biphasic --xor-encode 0x12345678 shellcode.bin output.bin\n\n", program_name);

    fprintf(stream, "    Generate position-independent code:\n");
    fprintf(stream, "      %s --pic shellcode.bin output.bin\n\n", program_name);

    fprintf(stream, "    Eliminate specific bad characters (v3.0+):\n");
    fprintf(stream, "      # Eliminate null, newline, and carriage return (for network protocols)\n");
    fprintf(stream, "      %s --bad-chars \"00,0a,0d\" shellcode.bin output.bin\n\n", program_name);
    fprintf(stream, "      # Avoid space character (for command injection)\n");
    fprintf(stream, "      %s --bad-chars \"00,20\" shellcode.bin output.bin\n\n", program_name);

    fprintf(stream, "    Use predefined profiles (v3.0+):\n");
    fprintf(stream, "      # List all available profiles\n");
    fprintf(stream, "      %s --list-profiles\n\n", program_name);
    fprintf(stream, "      # Use HTTP newline profile (eliminates 0x00, 0x0A, 0x0D)\n");
    fprintf(stream, "      %s --profile http-newline shellcode.bin output.bin\n\n", program_name);
    fprintf(stream, "      # Use SQL injection profile\n");
    fprintf(stream, "      %s --profile sql-injection shellcode.bin output.bin\n\n", program_name);
    fprintf(stream, "      # Generate alphanumeric-only shellcode (extreme difficulty)\n");
    fprintf(stream, "      %s --profile alphanumeric-only shellcode.bin output.bin\n\n", program_name);

    fprintf(stream, "    Batch process directory:\n");
    fprintf(stream, "      %s input_dir/ output_dir/\n\n", program_name);

    fprintf(stream, "    Batch process recursively with pattern:\n");
    fprintf(stream, "      %s -r --pattern \"*.bin\" --biphasic input_dir/ output_dir/\n\n", program_name);

    fprintf(stream, "EXIT CODES\n");
    fprintf(stream, "    %d: Success\n", EXIT_SUCCESS);
    fprintf(stream, "    %d: General error\n", EXIT_GENERAL_ERROR);
    fprintf(stream, "    %d: Invalid arguments\n", EXIT_INVALID_ARGUMENTS);
    fprintf(stream, "    %d: Input file error\n", EXIT_INPUT_FILE_ERROR);
    fprintf(stream, "    %d: Processing failed\n", EXIT_PROCESSING_FAILED);
    fprintf(stream, "    %d: Output file error\n", EXIT_OUTPUT_FILE_ERROR);
    fprintf(stream, "    %d: Timeout exceeded\n", EXIT_TIMEOUT_EXCEEDED);
    
    fprintf(stream, "\nMORE INFO\n");
    fprintf(stream, "    Full documentation at: https://github.com/mrnob0dy666/byvalver\n");
}

// Print version information
void print_version(FILE *stream) {
    time_t build_time = time(NULL);
    fprintf(stream, "byvalver v%d.%d.%d\n", 
            BYVALVER_VERSION_MAJOR, 
            BYVALVER_VERSION_MINOR, 
            BYVALVER_VERSION_PATCH);
    fprintf(stream, "Built: %s", ctime(&build_time));
    fprintf(stream, "Copyright (c) The Monad (Mo) - Advanced Cyber Security Framework\n");
}

// Parse command line arguments
int parse_arguments(int argc, char *argv[], byvalver_config_t *config) {
    if (!config) {
        return EXIT_INVALID_ARGUMENTS;
    }
    
    int opt;
    int option_index = 0;
    
    static struct option long_options[] = {
        // General options
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"verbose", no_argument, 0, 'V'},
        {"quiet", no_argument, 0, 'q'},
        {"config", required_argument, 0, 0},
        {"no-color", no_argument, 0, 0},
        
        // Processing options
        {"biphasic", no_argument, 0, 0},
        {"pic", no_argument, 0, 0},
        {"xor-encode", required_argument, 0, 0},
        {"format", required_argument, 0, 0},
        {"arch", required_argument, 0, 0},
        {"ml", no_argument, 0, 0},  // EXPERIMENTAL: Known to degrade performance
        {"bad-chars", required_argument, 0, 0},  // NEW in v3.0: Generic bad character elimination
        {"profile", required_argument, 0, 0},    // NEW in v3.0: Use predefined bad-char profile
        {"list-profiles", no_argument, 0, 0},    // NEW in v3.0: List available profiles

        // ML Metrics options
        {"metrics", no_argument, 0, 0},
        {"metrics-file", required_argument, 0, 0},
        {"metrics-json", no_argument, 0, 0},
        {"metrics-csv", no_argument, 0, 0},
        {"metrics-live", no_argument, 0, 0},

        // Batch processing options
        {"recursive", no_argument, 0, 'r'},
        {"pattern", required_argument, 0, 0},
        {"no-preserve-structure", no_argument, 0, 0},
        {"no-continue-on-error", no_argument, 0, 0},
        {"failed-files", required_argument, 0, 0},

        // Advanced options
        {"strategy-limit", required_argument, 0, 0},
        {"max-size", required_argument, 0, 0},
        {"timeout", required_argument, 0, 0},
        {"dry-run", no_argument, 0, 0},
        {"stats", no_argument, 0, 0},
        {"validate", no_argument, 0, 0},
        
        // Output options
        {"output", required_argument, 0, 'o'},
        
        {0, 0, 0, 0}
    };
    
    // Parse arguments using getopt_long
    while ((opt = getopt_long(argc, argv, "h?vVqo:r", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                config->help_requested = 1;
                return EXIT_SUCCESS;
                
            case 'v':
                config->version_requested = 1;
                return EXIT_SUCCESS;
                
            case 'V':
                config->verbose = 1;
                break;
                
            case 'q':
                config->quiet = 1;
                break;
                
            case 'o':
                config->output_file = optarg;
                config->output_file_specified_via_flag = 1;
                break;

            case 'r':
                config->recursive = 1;
                break;

            case 0: // Long options without short equivalents
                {
                    const char *opt_name = long_options[option_index].name;
                    
                    if (strcmp(opt_name, "no-color") == 0) {
                        config->no_color = 1;
                    }
                    else if (strcmp(opt_name, "config") == 0) {
                        config->config_file = optarg;
                    }
                    else if (strcmp(opt_name, "biphasic") == 0) {
                        config->use_biphasic = 1;
                    }
                    else if (strcmp(opt_name, "pic") == 0) {
                        config->use_pic_generation = 1;
                    }
                    else if (strcmp(opt_name, "ml") == 0) {
                        config->use_ml_strategist = 1;
                    }
                    else if (strcmp(opt_name, "metrics") == 0) {
                        config->metrics_enabled = 1;
                    }
                    else if (strcmp(opt_name, "metrics-file") == 0) {
                        config->metrics_output_file = optarg;
                        config->metrics_enabled = 1;  // Auto-enable metrics if file specified
                    }
                    else if (strcmp(opt_name, "metrics-json") == 0) {
                        config->metrics_export_json = 1;
                        config->metrics_enabled = 1;  // Auto-enable metrics
                    }
                    else if (strcmp(opt_name, "metrics-csv") == 0) {
                        config->metrics_export_csv = 1;
                        config->metrics_enabled = 1;  // Auto-enable metrics
                    }
                    else if (strcmp(opt_name, "metrics-live") == 0) {
                        config->metrics_show_live = 1;
                        config->metrics_enabled = 1;  // Auto-enable metrics
                    }
                    else if (strcmp(opt_name, "xor-encode") == 0) {
                        config->encode_shellcode = 1;
                        char *endptr;
                        config->xor_key = (uint32_t)strtol(optarg, &endptr, 16);
                        if (*endptr != '\0') {
                            fprintf(stderr, "Error: Invalid XOR key format: %s\n", optarg);
                            return EXIT_INVALID_ARGUMENTS;
                        }
                    }
                    else if (strcmp(opt_name, "bad-chars") == 0) {
                        // Parse bad characters (v3.0)
                        if (config->bad_chars) {
                            free(config->bad_chars);  // Free default config
                        }
                        config->bad_chars = parse_bad_chars_string(optarg);
                        if (!config->bad_chars) {
                            fprintf(stderr, "Error: Invalid --bad-chars format: %s\n", optarg);
                            fprintf(stderr, "Expected: comma-separated hex bytes (e.g., \"00,0a,0d\")\n");
                            return EXIT_INVALID_ARGUMENTS;
                        }
                    }
                    else if (strcmp(opt_name, "profile") == 0) {
                        // Use predefined profile (v3.0)
                        const badchar_profile_t *profile = find_badchar_profile(optarg);
                        if (!profile) {
                            fprintf(stderr, "Error: Unknown profile: %s\n", optarg);
                            fprintf(stderr, "Use --list-profiles to see available profiles.\n");
                            return EXIT_INVALID_ARGUMENTS;
                        }

                        if (config->bad_chars) {
                            free(config->bad_chars);
                        }
                        config->bad_chars = profile_to_config(profile);
                        if (!config->bad_chars) {
                            fprintf(stderr, "Error: Failed to load profile: %s\n", optarg);
                            return EXIT_INVALID_ARGUMENTS;
                        }

                        if (!config->quiet) {
                            fprintf(stderr, "Using profile '%s': %s\n", profile->name, profile->description);
                            fprintf(stderr, "Eliminating %zu bad characters\n", profile->bad_char_count);
                        }
                    }
                    else if (strcmp(opt_name, "list-profiles") == 0) {
                        // List available profiles
                        list_badchar_profiles(stdout);
                        exit(EXIT_SUCCESS);
                    }
                    else if (strcmp(opt_name, "format") == 0) {
                        config->output_format = optarg;
                        // Validate format
                        if (strcmp(optarg, "raw") != 0 && 
                            strcmp(optarg, "c") != 0 && 
                            strcmp(optarg, "python") != 0 && 
                            strcmp(optarg, "powershell") != 0 && 
                            strcmp(optarg, "hexstring") != 0) {
                            fprintf(stderr, "Error: Invalid output format: %s\n", optarg);
                            fprintf(stderr, "Valid formats: raw, c, python, powershell, hexstring\n");
                            return EXIT_INVALID_ARGUMENTS;
                        }
                    }
                    else if (strcmp(opt_name, "arch") == 0) {
                        config->target_arch = optarg;
                        // Validate architecture
                        if (strcmp(optarg, "x86") != 0 && strcmp(optarg, "x64") != 0) {
                            fprintf(stderr, "Error: Invalid target architecture: %s\n", optarg);
                            fprintf(stderr, "Valid architectures: x86, x64\n");
                            return EXIT_INVALID_ARGUMENTS;
                        }
                    }
                    else if (strcmp(opt_name, "strategy-limit") == 0) {
                        char *endptr;
                        long limit = strtol(optarg, &endptr, 10);
                        if (*endptr != '\0' || limit < 0) {
                            fprintf(stderr, "Error: Invalid strategy limit: %s\n", optarg);
                            return EXIT_INVALID_ARGUMENTS;
                        }
                        config->strategy_limit = (int)limit;
                    }
                    else if (strcmp(opt_name, "max-size") == 0) {
                        char *endptr;
                        long size = strtol(optarg, &endptr, 10);
                        if (*endptr != '\0' || size <= 0) {
                            fprintf(stderr, "Error: Invalid max size: %s\n", optarg);
                            return EXIT_INVALID_ARGUMENTS;
                        }
                        config->max_size = (size_t)size;
                    }
                    else if (strcmp(opt_name, "timeout") == 0) {
                        char *endptr;
                        long timeout = strtol(optarg, &endptr, 10);
                        if (*endptr != '\0' || timeout < 0) {
                            fprintf(stderr, "Error: Invalid timeout value: %s\n", optarg);
                            return EXIT_INVALID_ARGUMENTS;
                        }
                        config->timeout_seconds = (int)timeout;
                    }
                    else if (strcmp(opt_name, "dry-run") == 0) {
                        config->dry_run = 1;
                    }
                    else if (strcmp(opt_name, "stats") == 0) {
                        config->show_stats = 1;
                    }
                    else if (strcmp(opt_name, "validate") == 0) {
                        config->validate_output = 1;
                    }
                    else if (strcmp(opt_name, "pattern") == 0) {
                        config->file_pattern = optarg;
                    }
                    else if (strcmp(opt_name, "no-preserve-structure") == 0) {
                        config->preserve_structure = 0;
                    }
                    else if (strcmp(opt_name, "no-continue-on-error") == 0) {
                        config->continue_on_error = 0;
                    }
                    else if (strcmp(opt_name, "failed-files") == 0) {
                        config->failed_files_output = optarg;
                    }
                }
                break;
                
            case '?':
                // getopt_long already printed an error message
                return EXIT_INVALID_ARGUMENTS;
                
            default:
                fprintf(stderr, "Internal error: getopt returned unexpected value %d\n", opt);
                return EXIT_GENERAL_ERROR;
        }
    }
    
    // Handle positional arguments
    int remaining_args = argc - optind;
    
    if (remaining_args == 0 && !config->help_requested && !config->version_requested) {
        fprintf(stderr, "Error: Input file is required\n\n");
        print_usage(stderr, argv[0]);
        return EXIT_INVALID_ARGUMENTS;
    }
    
    if (remaining_args >= 1) {
        config->input_file = argv[optind];
    }
    
    if (remaining_args >= 2) {
        // If output file was already specified with -o flag, that's an error
        if (config->output_file_specified_via_flag) {
            fprintf(stderr, "Error: Output file specified twice (with -o and as positional argument)\n");
            return EXIT_INVALID_ARGUMENTS;
        }
        // Otherwise, use the positional argument as output file
        config->output_file = argv[optind + 1];
    }
    
    if (remaining_args > 2) {
        fprintf(stderr, "Error: Too many positional arguments\n");
        print_usage(stderr, argv[0]);
        return EXIT_INVALID_ARGUMENTS;
    }
    
    return EXIT_SUCCESS;
}

// Load configuration from file
int load_config_file(const char *config_path, byvalver_config_t *config) {
    // This is a placeholder implementation
    // In a full implementation, this would parse a JSON/YAML config file
    if (!config_path || !config) {
        return EXIT_CONFIG_ERROR;
    }
    
    // Check if file exists
    FILE *file = fopen(config_path, "r");
    if (!file) {
        fprintf(stderr, "Warning: Config file not found: %s\n", config_path);
        return EXIT_SUCCESS; // Not a fatal error, just a warning
    }
    
    fclose(file);
    
    // For now, just acknowledge the config file exists
    if (config->verbose) {
        fprintf(stderr, "Using config file: %s\n", config_path);
    }
    
    return EXIT_SUCCESS;
}