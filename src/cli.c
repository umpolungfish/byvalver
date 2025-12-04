#include "cli.h"
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

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

    return config;
}

// Free configuration structure
void config_free(byvalver_config_t *config) {
    if (!config) return;
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
    fprintf(stream, "byvalver - Advanced Null-Byte Elimination Framework\n\n");
    
    fprintf(stream, "SYNOPSIS\n");
    fprintf(stream, "    %s [OPTIONS] <input_file> [output_file]\n\n", program_name);
    
    fprintf(stream, "DESCRIPTION\n");
    fprintf(stream, "    byvalver is an advanced C-based command-line tool designed for automated \n");
    fprintf(stream, "    removal of null bytes from shellcode while preserving functional equivalence. \n");
    fprintf(stream, "    The tool leverages the Capstone disassembly framework to analyze x86/x64 \n");
    fprintf(stream, "    assembly instructions and applies sophisticated transformation strategies to \n");
    fprintf(stream, "    replace null-containing instructions with functionally equivalent alternatives.\n\n");
    
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
    fprintf(stream, "      --xor-encode KEY              XOR encode output with 4-byte key (hex)\n");
    fprintf(stream, "      --format FORMAT               Output format: raw, c, python, powershell, hexstring\n\n");
    
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
    while ((opt = getopt_long(argc, argv, "h?vVqo:", long_options, &option_index)) != -1) {
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
                    else if (strcmp(opt_name, "xor-encode") == 0) {
                        config->encode_shellcode = 1;
                        char *endptr;
                        config->xor_key = (uint32_t)strtol(optarg, &endptr, 16);
                        if (*endptr != '\0') {
                            fprintf(stderr, "Error: Invalid XOR key format: %s\n", optarg);
                            return EXIT_INVALID_ARGUMENTS;
                        }
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