#ifndef CLI_H
#define CLI_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

// Application version information
#define BYVALVER_VERSION_MAJOR 2
#define BYVALVER_VERSION_MINOR 1
#define BYVALVER_VERSION_PATCH 0
#define BYVALVER_VERSION_STRING "2.1.0"

// Exit codes
#define EXIT_SUCCESS 0
#define EXIT_GENERAL_ERROR 1
#define EXIT_INVALID_ARGUMENTS 2
#define EXIT_INPUT_FILE_ERROR 3
#define EXIT_PROCESSING_FAILED 4
#define EXIT_OUTPUT_FILE_ERROR 5
#define EXIT_TIMEOUT_EXCEEDED 6
#define EXIT_CONFIG_ERROR 7

// Configuration structure
typedef struct {
    // Basic options
    char *input_file;
    char *output_file;
    char *config_file;
    int verbose;
    int quiet;
    int no_color;
    
    // Processing options
    int use_biphasic;
    int use_pic_generation;
    int encode_shellcode;
    uint32_t xor_key;
    int use_ml_strategist;  // Whether to use ML-enhanced strategy selection
    
    // Advanced options
    char *output_format;  // "raw", "c", "python", "powershell", "hexstring"
    char *target_arch;    // "x86", "x64"
    int strategy_limit;
    size_t max_size;
    int timeout_seconds;
    int dry_run;
    int show_stats;
    int validate_output;
    
    // Internal flags
    int help_requested;
    int version_requested;
    int output_file_specified_via_flag;  // Whether -o/--output was used
} byvalver_config_t;

// Function declarations
byvalver_config_t* config_create_default(void);
void config_free(byvalver_config_t *config);
int parse_arguments(int argc, char *argv[], byvalver_config_t *config);
void print_usage(FILE *stream, const char *program_name);
void print_version(FILE *stream);
int load_config_file(const char *config_path, byvalver_config_t *config);
void print_detailed_help(FILE *stream, const char *program_name);

#endif