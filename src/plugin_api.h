#ifndef PLUGIN_API_H
#define PLUGIN_API_H

// Plugin system for Byvalver - Extendable strategy plumbing
// Like adding new valves and pipes to the shellcode processing system

#include <stdint.h>
#include <stddef.h>
#include "strategy.h"

// Plugin interface version
#define BYVALVER_PLUGIN_API_VERSION 1

// Plugin types
typedef enum {
    PLUGIN_TYPE_STRATEGY,      // Bad-byte elimination strategy
    PLUGIN_TYPE_OBFUSCATION,   // Obfuscation transformation
    PLUGIN_TYPE_ANALYSIS       // Analysis or verification plugin
} plugin_type_t;

// Plugin information structure
typedef struct {
    const char* name;           // Plugin name
    const char* description;    // Plugin description
    const char* author;         // Plugin author
    const char* version;        // Plugin version
    plugin_type_t type;         // Plugin type
    int api_version;            // API version supported
} plugin_info_t;

// Plugin interface functions
typedef struct {
    // Initialize plugin
    int (*init)(void);

    // Get plugin information
    const plugin_info_t* (*get_info)(void);

    // Register strategies (for strategy plugins)
    void (*register_strategies)(void);

    // Cleanup plugin
    void (*cleanup)(void);
} plugin_interface_t;

// Plugin registration function
int register_plugin(const plugin_interface_t* interface);

// Load plugin from shared library
int load_plugin(const char* path);

// Unload all plugins
void unload_plugins(void);

// Get number of loaded plugins
int get_plugin_count(void);

// List loaded plugins
void list_plugins(void);

#endif /* PLUGIN_API_H */