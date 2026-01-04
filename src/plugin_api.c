#include "plugin_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Plugin registry - like a toolbox of plumbing extensions
#define MAX_PLUGINS 64

static plugin_interface_t* g_plugins[MAX_PLUGINS];
static int g_plugin_count = 0;

// Register a plugin with the system
int register_plugin(const plugin_interface_t* interface) {
    if (!interface || g_plugin_count >= MAX_PLUGINS) {
        return -1;  // Plumbing toolbox is full!
    }

    // Check API version compatibility
    const plugin_info_t* info = interface->get_info();
    if (!info || info->api_version != BYVALVER_PLUGIN_API_VERSION) {
        fprintf(stderr, "[PLUGIN] Incompatible API version for plugin '%s'\n",
                info ? info->name : "unknown");
        return -1;
    }

    // Initialize the plugin
    if (interface->init && interface->init() != 0) {
        fprintf(stderr, "[PLUGIN] Failed to initialize plugin '%s'\n", info->name);
        return -1;
    }

    // Register strategies if it's a strategy plugin
    if (interface->register_strategies) {
        interface->register_strategies();
    }

    g_plugins[g_plugin_count++] = (plugin_interface_t*)interface;

    fprintf(stderr, "[PLUGIN] Registered plumbing extension: %s v%s by %s\n",
            info->name, info->version, info->author);

    return 0;
}

// Load plugin from shared library (placeholder for now)
int load_plugin(const char* path) {
    // TODO: Implement dynamic loading of shared libraries
    // For now, plugins must be statically linked
    fprintf(stderr, "[PLUGIN] Dynamic loading not yet implemented. "
                   "Please link plugins statically.\n");
    return -1;
}

// Unload all plugins
void unload_plugins(void) {
    for (int i = 0; i < g_plugin_count; i++) {
        if (g_plugins[i]->cleanup) {
            g_plugins[i]->cleanup();
        }
    }
    g_plugin_count = 0;
    fprintf(stderr, "[PLUGIN] All plumbing extensions unloaded\n");
}

// Get number of loaded plugins
int get_plugin_count(void) {
    return g_plugin_count;
}

// List loaded plugins
void list_plugins(void) {
    fprintf(stderr, "[PLUGIN] Loaded plumbing extensions (%d):\n", g_plugin_count);
    for (int i = 0; i < g_plugin_count; i++) {
        const plugin_info_t* info = g_plugins[i]->get_info();
        if (info) {
            fprintf(stderr, "  - %s v%s: %s\n", info->name, info->version, info->description);
        }
    }
}