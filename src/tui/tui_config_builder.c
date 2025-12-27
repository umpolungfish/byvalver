#define _GNU_SOURCE  // Required for strdup function
#include "tui_config_builder.h"
#include <string.h>
#include <stdlib.h>

// Function to convert current state to configuration
byvalver_config_t* build_config_from_state() {
    byvalver_config_t *config = config_create_default();
    if (!config) {
        return NULL;
    }
    
    // Initialize with default values
    reset_config_to_defaults(config);
    
    return config;
}

// Function to apply configuration to current state
void apply_config_to_state(byvalver_config_t *config) {
    if (!config) return;
    
    // This function would typically update the UI state based on the config
    // For now, we'll just ensure the config is properly initialized
}

// Function to validate configuration
int validate_config(byvalver_config_t *config) {
    if (!config) {
        return 0; // Invalid if config is NULL
    }
    
    // Check if required fields are set
    if (!config->input_file) {
        return 0; // Input file is required
    }
    
    // Validate bad character configuration
    if (!config->bad_chars) {
        return 0; // Bad character config should be set
    }
    
    return 1; // Valid configuration
}

// Function to reset configuration to defaults
void reset_config_to_defaults(byvalver_config_t *config) {
    if (!config) return;
    
    // Free existing configuration data
    if (config->input_file) {
        free((char*)config->input_file);
        config->input_file = NULL;
    }
    
    if (config->output_file && strcmp(config->output_file, "output.bin") != 0) {
        free((char*)config->output_file);
        config->output_file = "output.bin"; // Default value
    }
    
    if (config->bad_chars) {
        free(config->bad_chars);
    }
    
    // Create default bad character configuration (null byte only)
    config->bad_chars = calloc(1, sizeof(bad_char_config_t));
    if (config->bad_chars) {
        config->bad_chars->bad_chars[0x00] = 1;
        config->bad_chars->bad_char_list[0] = 0x00;
        config->bad_chars->bad_char_count = 1;
    }
    
    // Reset flags
    config->verbose = 0;
    config->quiet = 0;
    config->use_biphasic = 0;
    config->use_pic_generation = 0;
    config->encode_shellcode = 0;
    config->use_ml_strategist = 0;
    config->dry_run = 0;
    config->show_stats = 0;
    config->validate_output = 0;
    config->interactive_menu = 1; // This is the TUI mode
}

// Function to save configuration to file
int save_config_to_file(byvalver_config_t *config, const char *filename) {
    if (!config || !filename) {
        return -1;
    }
    
    FILE *file = fopen(filename, "w");
    if (!file) {
        return -1;
    }
    
    // This is a simplified implementation - in a real scenario,
    // you'd want to save the configuration in a structured format
    fprintf(file, "# byvalver configuration file\n");
    fprintf(file, "input_file=%s\n", config->input_file ? config->input_file : "");
    fprintf(file, "output_file=%s\n", config->output_file ? config->output_file : "");
    fprintf(file, "verbose=%d\n", config->verbose);
    fprintf(file, "quiet=%d\n", config->quiet);
    fprintf(file, "use_biphasic=%d\n", config->use_biphasic);
    fprintf(file, "use_pic_generation=%d\n", config->use_pic_generation);
    fprintf(file, "use_ml_strategist=%d\n", config->use_ml_strategist);
    fprintf(file, "dry_run=%d\n", config->dry_run);
    fprintf(file, "show_stats=%d\n", config->show_stats);
    fprintf(file, "validate_output=%d\n", config->validate_output);
    
    // Save bad characters
    fprintf(file, "bad_chars=");
    int first = 1;
    for (int i = 0; i < 256; i++) {
        if (config->bad_chars && config->bad_chars->bad_chars[i]) {
            if (!first) fprintf(file, ",");
            fprintf(file, "%02x", i);
            first = 0;
        }
    }
    fprintf(file, "\n");
    
    fclose(file);
    return 0;
}

// Function to load configuration from file
int load_config_from_file(byvalver_config_t *config, const char *filename) {
    if (!config || !filename) {
        return -1;
    }
    
    FILE *file = fopen(filename, "r");
    if (!file) {
        return -1;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), file)) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }
        
        // Parse key-value pairs
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "");
        
        if (!key || !value) continue;
        
        if (strcmp(key, "input_file") == 0) {
            if (config->input_file) free((char*)config->input_file);
            config->input_file = strdup(value);
        }
        else if (strcmp(key, "output_file") == 0) {
            if (config->output_file && strcmp(config->output_file, "output.bin") != 0) {
                free((char*)config->output_file);
            }
            config->output_file = strdup(value);
        }
        else if (strcmp(key, "verbose") == 0) {
            config->verbose = atoi(value);
        }
        else if (strcmp(key, "quiet") == 0) {
            config->quiet = atoi(value);
        }
        else if (strcmp(key, "use_biphasic") == 0) {
            config->use_biphasic = atoi(value);
        }
        else if (strcmp(key, "use_pic_generation") == 0) {
            config->use_pic_generation = atoi(value);
        }
        else if (strcmp(key, "use_ml_strategist") == 0) {
            config->use_ml_strategist = atoi(value);
        }
        else if (strcmp(key, "dry_run") == 0) {
            config->dry_run = atoi(value);
        }
        else if (strcmp(key, "show_stats") == 0) {
            config->show_stats = atoi(value);
        }
        else if (strcmp(key, "validate_output") == 0) {
            config->validate_output = atoi(value);
        }
        else if (strcmp(key, "bad_chars") == 0) {
            // Parse bad characters
            if (config->bad_chars) {
                free(config->bad_chars);
            }
            config->bad_chars = parse_bad_chars_string(value);
        }
    }
    
    fclose(file);
    return 0;
}