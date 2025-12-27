#define _GNU_SOURCE
#include "tui_file_browser.h"
#include "tui_screens.h"
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ncurses.h>
#include <limits.h>

// Initialize file list
void file_list_browser_init(file_list_browser_t *list) {
    list->entries = NULL;
    list->count = 0;
    list->capacity = 0;
}

// Free file list
void file_list_browser_free(file_list_browser_t *list) {
    if (!list) return;

    for (size_t i = 0; i < list->count; i++) {
        free(list->entries[i].name);
        free(list->entries[i].full_path);
    }
    free(list->entries);
    list->entries = NULL;
    list->count = 0;
    list->capacity = 0;
}

// Add entry to file list
void file_list_browser_add(file_list_browser_t *list, const char *name,
                           const char *full_path, int is_directory, size_t size) {
    if (!list) return;

    // Expand capacity if needed
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 32 : list->capacity * 2;
        file_entry_t *new_entries = realloc(list->entries, new_capacity * sizeof(file_entry_t));
        if (!new_entries) return;
        list->entries = new_entries;
        list->capacity = new_capacity;
    }

    // Add entry
    list->entries[list->count].name = strdup(name);
    list->entries[list->count].full_path = strdup(full_path);
    list->entries[list->count].is_directory = is_directory;
    list->entries[list->count].size = size;
    list->count++;
}

// Comparison function for qsort (directories first, then alphabetical)
static int compare_entries(const void *a, const void *b) {
    const file_entry_t *ea = (const file_entry_t *)a;
    const file_entry_t *eb = (const file_entry_t *)b;

    // Directories come first
    if (ea->is_directory && !eb->is_directory) return -1;
    if (!ea->is_directory && eb->is_directory) return 1;

    // Alphabetical order
    return strcmp(ea->name, eb->name);
}

// Load files from directory into list
int load_directory(const char *path, file_list_browser_t *list, const char *filter) {
    if (!path || !list) return -1;

    DIR *dir = opendir(path);
    if (!dir) return -1;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip "." entry
        if (strcmp(entry->d_name, ".") == 0) continue;

        // Construct full path
        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        // Get file stats
        struct stat st;
        if (stat(full_path, &st) != 0) continue;

        int is_directory = S_ISDIR(st.st_mode);

        // Apply filter for files (not directories)
        if (!is_directory && filter) {
            size_t name_len = strlen(entry->d_name);
            size_t filter_len = strlen(filter);
            if (name_len < filter_len ||
                strcmp(entry->d_name + name_len - filter_len, filter) != 0) {
                continue;
            }
        }

        // Add to list
        file_list_browser_add(list, entry->d_name, full_path, is_directory,
                             is_directory ? 0 : st.st_size);
    }

    closedir(dir);

    // Sort entries (directories first, then alphabetical)
    if (list->count > 0) {
        qsort(list->entries, list->count, sizeof(file_entry_t), compare_entries);
    }

    return 0;
}

// Format file size for display
static void format_size(size_t size, char *buffer, size_t buffer_size) {
    if (size < 1024) {
        snprintf(buffer, buffer_size, "%zu B", size);
    } else if (size < 1024 * 1024) {
        snprintf(buffer, buffer_size, "%.1f KB", size / 1024.0);
    } else if (size < 1024 * 1024 * 1024) {
        snprintf(buffer, buffer_size, "%.1f MB", size / (1024.0 * 1024.0));
    } else {
        snprintf(buffer, buffer_size, "%.1f GB", size / (1024.0 * 1024.0 * 1024.0));
    }
}

// Show file browser and allow user to select a file or directory
char* show_file_browser(const char *current_path, browser_mode_t mode, const char *filter) {
    char path[PATH_MAX];

    // Initialize current path
    if (current_path) {
        struct stat st;
        // Check if the provided path exists and is a directory
        if (stat(current_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            // Valid directory, use it
            strncpy(path, current_path, sizeof(path) - 1);
            path[sizeof(path) - 1] = '\0';
        } else if (stat(current_path, &st) == 0 && S_ISREG(st.st_mode)) {
            // It's a file, use its parent directory
            strncpy(path, current_path, sizeof(path) - 1);
            path[sizeof(path) - 1] = '\0';
            char *last_slash = strrchr(path, '/');
            if (last_slash && last_slash != path) {
                *last_slash = '\0';
            } else if (last_slash == path) {
                strcpy(path, "/");
            } else {
                // No slash, use current directory
                if (!getcwd(path, sizeof(path))) {
                    strcpy(path, ".");
                }
            }
        } else {
            // Path doesn't exist or is invalid, use current working directory
            if (!getcwd(path, sizeof(path))) {
                strcpy(path, ".");
            }
        }
    } else {
        // No path provided, use current working directory
        if (!getcwd(path, sizeof(path))) {
            strcpy(path, ".");
        }
    }

    int current_selection = 0;
    int scroll_offset = 0;
    char *result = NULL;

    while (1) {
        clear_screen();

        // Draw header
        const char *mode_str = (mode == BROWSER_MODE_SELECT_FILE) ? "Select File" :
                               (mode == BROWSER_MODE_SELECT_DIRECTORY) ? "Select Directory" :
                               "Select File or Directory";
        draw_header(mode_str);

        // Load directory contents
        file_list_browser_t list;
        file_list_browser_init(&list);

        if (load_directory(path, &list, filter) != 0) {
            mvprintw(5, 5, "Error: Cannot read directory '%s'", path);
            mvprintw(7, 5, "Press any key to go back...");
            refresh();
            getch();
            file_list_browser_free(&list);
            return NULL;
        }

        // Display current path
        int row = 3;
        mvprintw(row++, 5, "Current path: %s", path);
        if (filter) {
            mvprintw(row++, 5, "Filter: %s", filter);
        }
        mvprintw(row++, 5, " ");

        // Calculate visible area
        int max_visible = LINES - 10; // Leave room for header and footer
        if (current_selection < scroll_offset) {
            scroll_offset = current_selection;
        }
        if (current_selection >= scroll_offset + max_visible) {
            scroll_offset = current_selection - max_visible + 1;
        }

        // Display files
        for (size_t i = scroll_offset; i < list.count && (int)(i - scroll_offset) < max_visible; i++) {
            file_entry_t *entry = &list.entries[i];
            int selected = (i == (size_t)current_selection);

            char display_name[256];
            if (entry->is_directory) {
                snprintf(display_name, sizeof(display_name), "[DIR]  %s", entry->name);
            } else {
                char size_str[32];
                format_size(entry->size, size_str, sizeof(size_str));
                snprintf(display_name, sizeof(display_name), "[FILE] %s  (%s)",
                        entry->name, size_str);
            }

            draw_menu_item(row++, 5, display_name, selected);
        }

        // Show scroll indicator if needed
        if (list.count > (size_t)max_visible) {
            mvprintw(LINES - 3, 5, "Showing %d-%d of %zu entries",
                    scroll_offset + 1,
                    (int)(scroll_offset + max_visible) < (int)list.count ?
                        scroll_offset + max_visible : (int)list.count,
                    list.count);
        }

        // Draw footer with mode-specific instructions
        attron(COLOR_PAIR(1));
        mvprintw(LINES - 1, 0, "%*s", COLS, " ");
        if (mode == BROWSER_MODE_SELECT_FILE) {
            mvprintw(LINES - 1, 2, "ENTER: Select file | Arrows: Navigate | q: Cancel");
        } else if (mode == BROWSER_MODE_SELECT_DIRECTORY) {
            mvprintw(LINES - 1, 2, "ENTER/SPACE: Select dir | Arrows: Navigate | q: Cancel");
        } else {
            mvprintw(LINES - 1, 2, "ENTER: Select | Arrows: Navigate | SPACE: Select current dir | q: Cancel");
        }
        attroff(COLOR_PAIR(1));
        refresh();

        int ch = getch();

        if (ch == 'q' || ch == 'Q') {
            // Cancel
            file_list_browser_free(&list);
            return NULL;
        } else if (ch == KEY_UP || ch == 'k' || ch == 'K') {
            if (current_selection > 0) {
                current_selection--;
            }
        } else if (ch == KEY_DOWN || ch == 'j' || ch == 'J') {
            if (current_selection < (int)list.count - 1) {
                current_selection++;
            }
        } else if (ch == '\n' || ch == '\r') {
            if (list.count == 0) {
                file_list_browser_free(&list);
                continue;
            }

            file_entry_t *entry = &list.entries[current_selection];

            if (entry->is_directory) {
                // Navigate into directory or select it
                if (strcmp(entry->name, "..") == 0) {
                    // Go up one directory
                    char *last_slash = strrchr(path, '/');
                    if (last_slash && last_slash != path) {
                        *last_slash = '\0';
                    } else if (last_slash == path) {
                        strcpy(path, "/");
                    }
                } else if (mode == BROWSER_MODE_SELECT_DIRECTORY || mode == BROWSER_MODE_SELECT_BOTH) {
                    // Select this directory (only in directory or both mode)
                    result = strdup(entry->full_path);
                    file_list_browser_free(&list);
                    return result;
                } else {
                    // In file-only mode, navigate into directory (don't select it)
                    strncpy(path, entry->full_path, sizeof(path) - 1);
                    path[sizeof(path) - 1] = '\0';
                }
                current_selection = 0;
                scroll_offset = 0;
            } else {
                // Select file (if mode allows)
                if (mode != BROWSER_MODE_SELECT_DIRECTORY) {
                    result = strdup(entry->full_path);
                    file_list_browser_free(&list);
                    return result;
                } else {
                    // In directory-only mode, can't select files
                    // Show a brief error message
                    mvprintw(LINES - 3, 5, "Cannot select files in directory mode");
                    refresh();
                    napms(1000);
                }
            }
        } else if (ch == ' ') {
            // Space to select current directory (in directory mode)
            if (mode == BROWSER_MODE_SELECT_DIRECTORY || mode == BROWSER_MODE_SELECT_BOTH) {
                result = strdup(path);
                file_list_browser_free(&list);
                return result;
            }
        }

        file_list_browser_free(&list);
    }

    return NULL;
}
