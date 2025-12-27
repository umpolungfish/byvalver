#ifndef TUI_CONFIG_BUILDER_H
#define TUI_CONFIG_BUILDER_H

#include "../cli.h"

// Function to convert current state to configuration
byvalver_config_t* build_config_from_state();

// Function to apply configuration to current state
void apply_config_to_state(byvalver_config_t *config);

// Function to validate configuration
int validate_config(byvalver_config_t *config);

// Function to reset configuration to defaults
void reset_config_to_defaults(byvalver_config_t *config);

// Function to save configuration to file
int save_config_to_file(byvalver_config_t *config, const char *filename);

// Function to load configuration from file
int load_config_from_file(byvalver_config_t *config, const char *filename);

#endif