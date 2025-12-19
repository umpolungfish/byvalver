#define _POSIX_C_SOURCE 200809L
#include "batch_processing.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <fnmatch.h>

// Check if a path is a directory
int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;
    }
    return S_ISDIR(st.st_mode);
}

// Match a filename against a pattern using fnmatch
int match_pattern(const char *filename, const char *pattern) {
    if (!filename || !pattern) {
        return 0;
    }
    return fnmatch(pattern, filename, 0) == 0;
}

// Initialize a file list
void file_list_init(file_list_t *list) {
    list->paths = NULL;
    list->count = 0;
    list->capacity = 0;
}

// Add a file to the list
int file_list_add(file_list_t *list, const char *path) {
    if (!list || !path) {
        return -1;
    }

    // Resize if needed
    if (list->count >= list->capacity) {
        size_t new_capacity = (list->capacity == 0) ? 16 : (list->capacity * 2);
        char **new_paths = realloc(list->paths, new_capacity * sizeof(char*));
        if (!new_paths) {
            return -1;
        }
        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    // Duplicate the path string
    list->paths[list->count] = strdup(path);
    if (!list->paths[list->count]) {
        return -1;
    }

    list->count++;
    return 0;
}

// Free a file list
void file_list_free(file_list_t *list) {
    if (!list) {
        return;
    }

    for (size_t i = 0; i < list->count; i++) {
        free(list->paths[i]);
    }
    free(list->paths);

    list->paths = NULL;
    list->count = 0;
    list->capacity = 0;
}

// Recursive helper for finding files
static int find_files_recursive(const char *dir_path, const char *pattern,
                                int recursive, file_list_t *list) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        fprintf(stderr, "Warning: Cannot open directory '%s': %s\n",
                dir_path, strerror(errno));
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Construct full path
        size_t path_len = strlen(dir_path) + strlen(entry->d_name) + 2;
        char *full_path = malloc(path_len);
        if (!full_path) {
            closedir(dir);
            return -1;
        }
        snprintf(full_path, path_len, "%s/%s", dir_path, entry->d_name);

        // Check if it's a directory
        if (is_directory(full_path)) {
            if (recursive) {
                find_files_recursive(full_path, pattern, recursive, list);
            }
        } else {
            // Check if the filename matches the pattern
            if (match_pattern(entry->d_name, pattern)) {
                file_list_add(list, full_path);
            }
        }

        free(full_path);
    }

    closedir(dir);
    return 0;
}

// Find all files in a directory matching the pattern
int find_files(const char *dir_path, const char *pattern, int recursive, file_list_t *list) {
    if (!dir_path || !pattern || !list) {
        return -1;
    }

    return find_files_recursive(dir_path, pattern, recursive, list);
}

// Construct output path from input path
char* construct_output_path(const char *input_path, const char *input_base,
                           const char *output_base, int preserve_structure) {
    if (!input_path || !input_base || !output_base) {
        return NULL;
    }

    // Calculate the relative path from input_base
    const char *relative_path = input_path;

    // Find where input_base ends in input_path
    size_t input_base_len = strlen(input_base);
    if (strncmp(input_path, input_base, input_base_len) == 0) {
        relative_path = input_path + input_base_len;
        // Skip leading slash if present
        while (*relative_path == '/') {
            relative_path++;
        }
    }

    size_t output_len;
    char *output_path;

    if (preserve_structure) {
        // Preserve directory structure: output_base + relative_path
        output_len = strlen(output_base) + strlen(relative_path) + 2;
        output_path = malloc(output_len);
        if (!output_path) {
            return NULL;
        }
        snprintf(output_path, output_len, "%s/%s", output_base, relative_path);
    } else {
        // Flatten: output_base + basename(input_path)
        char *input_copy = strdup(input_path);
        if (!input_copy) {
            return NULL;
        }
        char *filename = basename(input_copy);

        output_len = strlen(output_base) + strlen(filename) + 2;
        output_path = malloc(output_len);
        if (!output_path) {
            free(input_copy);
            return NULL;
        }
        snprintf(output_path, output_len, "%s/%s", output_base, filename);
        free(input_copy);
    }

    return output_path;
}

// Initialize batch statistics
void batch_stats_init(batch_stats_t *stats) {
    if (!stats) {
        return;
    }

    stats->total_files = 0;
    stats->processed_files = 0;
    stats->failed_files = 0;
    stats->skipped_files = 0;
    stats->total_input_bytes = 0;
    stats->total_output_bytes = 0;
    stats->bad_char_count = 0;
    memset(stats->bad_char_set, 0, sizeof(stats->bad_char_set)); // Initialize bad character set

    // Initialize failed file list
    stats->failed_file_list = NULL;
    stats->failed_file_count = 0;
    stats->failed_file_capacity = 0;
}

// Add a failed file to the statistics
int batch_stats_add_failed_file(batch_stats_t *stats, const char *failed_file_path) {
    if (!stats || !failed_file_path) {
        return -1;
    }

    // Resize if needed
    if (stats->failed_file_count >= stats->failed_file_capacity) {
        size_t new_capacity = (stats->failed_file_capacity == 0) ? 16 : (stats->failed_file_capacity * 2);
        char **new_list = realloc(stats->failed_file_list, new_capacity * sizeof(char*));
        if (!new_list) {
            return -1;
        }
        stats->failed_file_list = new_list;
        stats->failed_file_capacity = new_capacity;
    }

    // Duplicate the path string
    stats->failed_file_list[stats->failed_file_count] = strdup(failed_file_path);
    if (!stats->failed_file_list[stats->failed_file_count]) {
        return -1;
    }

    stats->failed_file_count++;
    return 0;
}

// Write failed files to output file
int batch_write_failed_files(const batch_stats_t *stats, const char *output_file) {
    if (!stats || !output_file) {
        return -1;
    }

    if (!stats->failed_file_list || stats->failed_file_count == 0) {
        return 0; // Nothing to write
    }

    FILE *file = fopen(output_file, "w");
    if (!file) {
        fprintf(stderr, "Error: Failed to open failed files output: %s\n", output_file);
        return -1;
    }

    for (size_t i = 0; i < stats->failed_file_count; i++) {
        fprintf(file, "%s\n", stats->failed_file_list[i]);
    }

    fclose(file);
    return 0;
}

// Free batch statistics resources
void batch_stats_free(batch_stats_t *stats) {
    if (!stats) {
        return;
    }

    // Free failed file list
    if (stats->failed_file_list) {
        for (size_t i = 0; i < stats->failed_file_count; i++) {
            free(stats->failed_file_list[i]);
        }
        free(stats->failed_file_list);
        stats->failed_file_list = NULL;
        stats->failed_file_count = 0;
        stats->failed_file_capacity = 0;
    }
}

// Print batch statistics
void batch_stats_print(const batch_stats_t *stats, int quiet) {
    if (!stats || quiet) {
        return;
    }

    printf("\n");
    printf("===== BATCH PROCESSING SUMMARY =====\n");
    printf("Total files:       %zu\n", stats->total_files);
    printf("Successfully processed: %zu (%.1f%%)\n",
           stats->processed_files,
           stats->total_files > 0 ? (100.0 * stats->processed_files / stats->total_files) : 0.0);
    printf("Failed:            %zu (%.1f%%)\n",
           stats->failed_files,
           stats->total_files > 0 ? (100.0 * stats->failed_files / stats->total_files) : 0.0);
    printf("Skipped:           %zu\n", stats->skipped_files);
    printf("\n");
    printf("Total input size:  %zu bytes\n", stats->total_input_bytes);
    printf("Total output size: %zu bytes\n", stats->total_output_bytes);

    if (stats->total_input_bytes > 0) {
        double ratio = (double)stats->total_output_bytes / (double)stats->total_input_bytes;
        printf("Average size ratio: %.2fx\n", ratio);
    }

    // Add bad character information
    printf("\n");
    printf("Bad characters:    %d configured\n", stats->bad_char_count);
    if (stats->bad_char_count > 0) {
        printf("Configured set:    ");
        int printed = 0;
        for (int i = 0; i < 256; i++) {
            if (stats->bad_char_set[i]) {
                if (printed > 0) printf(", ");
                printf("0x%02x", i);
                printed++;
            }
        }
        printf("\n");
    }

    printf("====================================\n");

    // Show failed files list if there are any
    if (stats->failed_files > 0 && stats->failed_file_list && stats->failed_file_count > 0) {
        printf("\n");
        printf("FAILED FILES (%zu):\n", stats->failed_file_count);
        for (size_t i = 0; i < stats->failed_file_count && i < 10; i++) {
            printf("  - %s\n", stats->failed_file_list[i]);
        }
        if (stats->failed_file_count > 10) {
            printf("  ... and %zu more (use --failed-files-output to save full list)\n",
                   stats->failed_file_count - 10);
        }
        printf("\n");
    }
}
