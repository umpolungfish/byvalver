#ifndef TUI_FILE_BROWSER_H
#define TUI_FILE_BROWSER_H

#include <stddef.h>

// File entry structure
typedef struct {
    char *name;           // File or directory name
    char *full_path;      // Full path to the file
    int is_directory;     // 1 if directory, 0 if file
    size_t size;          // File size in bytes (0 for directories)
} file_entry_t;

// File list structure
typedef struct {
    file_entry_t *entries;
    size_t count;
    size_t capacity;
} file_list_browser_t;

// Browser modes
typedef enum {
    BROWSER_MODE_SELECT_FILE,      // Select a single file
    BROWSER_MODE_SELECT_DIRECTORY, // Select a directory
    BROWSER_MODE_SELECT_BOTH       // Can select either
} browser_mode_t;

/**
 * Show file browser and allow user to select a file or directory
 * @param current_path Starting path (NULL for current directory)
 * @param mode Browser mode (file, directory, or both)
 * @param filter File extension filter (e.g., ".bin") or NULL for all files
 * @return Selected path (caller must free), or NULL if cancelled
 */
char* show_file_browser(const char *current_path, browser_mode_t mode, const char *filter);

/**
 * Initialize file list
 */
void file_list_browser_init(file_list_browser_t *list);

/**
 * Free file list
 */
void file_list_browser_free(file_list_browser_t *list);

/**
 * Add entry to file list
 */
void file_list_browser_add(file_list_browser_t *list, const char *name,
                           const char *full_path, int is_directory, size_t size);

/**
 * Load files from directory into list
 * @return 0 on success, -1 on error
 */
int load_directory(const char *path, file_list_browser_t *list, const char *filter);

#endif // TUI_FILE_BROWSER_H
