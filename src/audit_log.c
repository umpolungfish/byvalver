#include "audit_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Audit log storage
#define MAX_AUDIT_ENTRIES 10000

static audit_entry_t* g_audit_entries = NULL;
static int g_audit_count = 0;
static int g_audit_capacity = 0;
static FILE* g_audit_file = NULL;
static audit_level_t g_min_level = AUDIT_INFO;
static char g_session_id[64];

// Initialize audit logging
int audit_init(const char* log_file_path, audit_level_t min_level) {
    g_min_level = min_level;

    // Generate session ID
    snprintf(g_session_id, sizeof(g_session_id), "session_%ld", (long)time(NULL));

    if (log_file_path) {
        g_audit_file = fopen(log_file_path, "a");
        if (!g_audit_file) {
            return -1;  // Could not open audit log file
        }
    }

    // Initialize in-memory storage
    g_audit_capacity = 1000;
    g_audit_entries = calloc(g_audit_capacity, sizeof(audit_entry_t));
    if (!g_audit_entries) {
        if (g_audit_file) fclose(g_audit_file);
        return -1;
    }

    // Log initialization
    audit_log(AUDIT_INFO, AUDIT_EVENT_PROCESSING_START,
              "Audit logging initialized", "Byvalver enterprise plumbing audit system online");

    return 0;
}

// Log an audit event
void audit_log(audit_level_t level, audit_event_type_t event_type,
               const char* message, const char* details) {
    if (level < g_min_level) return;

    if (g_audit_count >= g_audit_capacity) {
        // Expand capacity
        g_audit_capacity *= 2;
        audit_entry_t* new_entries = realloc(g_audit_entries,
                                           g_audit_capacity * sizeof(audit_entry_t));
        if (!new_entries) return;  // Out of memory, skip logging
        g_audit_entries = new_entries;
    }

    audit_entry_t* entry = &g_audit_entries[g_audit_count++];
    entry->timestamp = time(NULL);
    entry->level = level;
    entry->event_type = event_type;
    entry->message = strdup(message ? message : "");
    entry->details = strdup(details ? details : "");
    entry->user_id = "system";  // TODO: Get actual user
    entry->session_id = g_session_id;

    // Write to file if available
    if (g_audit_file) {
        fprintf(g_audit_file, "[%ld] %d %d %s: %s (%s)\n",
                (long)entry->timestamp, level, event_type,
                entry->session_id, entry->message,
                entry->details ? entry->details : "");
        fflush(g_audit_file);
    }
}

// Convenience functions
void audit_processing_start(const char* input_file, size_t input_size) {
    char details[256];
    snprintf(details, sizeof(details), "{\"input_file\":\"%s\",\"input_size\":%zu}",
             input_file ? input_file : "stdin", input_size);
    audit_log(AUDIT_INFO, AUDIT_EVENT_PROCESSING_START,
              "Shellcode processing started", details);
}

void audit_processing_end(const char* output_file, size_t output_size,
                         int strategies_applied, int bad_bytes_removed) {
    char details[256];
    snprintf(details, sizeof(details),
             "{\"output_file\":\"%s\",\"output_size\":%zu,\"strategies_applied\":%d,\"bad_bytes_removed\":%d}",
             output_file ? output_file : "stdout", output_size,
             strategies_applied, bad_bytes_removed);
    audit_log(AUDIT_INFO, AUDIT_EVENT_PROCESSING_END,
              "Shellcode processing completed", details);
}

void audit_strategy_applied(const char* strategy_name, int success) {
    char details[128];
    snprintf(details, sizeof(details), "{\"strategy\":\"%s\",\"success\":%s}",
             strategy_name, success ? "true" : "false");
    audit_log(success ? AUDIT_INFO : AUDIT_WARNING, AUDIT_EVENT_STRATEGY_APPLIED,
              "Strategy applied", details);
}

void audit_bad_bytes_found(int count, const uint8_t* bytes) {
    char details[256];
    char byte_str[64] = "";
    for (int i = 0; i < count && i < 16; i++) {
        char tmp[8];
        snprintf(tmp, sizeof(tmp), "%02x ", bytes[i]);
        strncat(byte_str, tmp, sizeof(byte_str) - strlen(byte_str) - 1);
    }
    snprintf(details, sizeof(details), "{\"count\":%d,\"bytes\":\"%s\"}", count, byte_str);
    audit_log(AUDIT_INFO, AUDIT_EVENT_BAD_BYTES_FOUND, "Bad bytes detected", details);
}

void audit_integration_upload(const char* framework, const char* target, size_t size) {
    char details[128];
    snprintf(details, sizeof(details), "{\"framework\":\"%s\",\"target\":\"%s\",\"size\":%zu}",
             framework, target, size);
    audit_log(AUDIT_INFO, AUDIT_EVENT_INTEGRATION_UPLOAD,
              "Shellcode uploaded to external framework", details);
}

// Export functions (placeholders)
int audit_export_json(const char* output_path) {
    // TODO: Implement JSON export
    fprintf(stderr, "[AUDIT] JSON export not yet implemented\n");
    return -1;
}

int audit_export_csv(const char* output_path) {
    // TODO: Implement CSV export
    fprintf(stderr, "[AUDIT] CSV export not yet implemented\n");
    return -1;
}

// Cleanup
void audit_cleanup(void) {
    if (g_audit_file) {
        fclose(g_audit_file);
        g_audit_file = NULL;
    }

    for (int i = 0; i < g_audit_count; i++) {
        free((void*)g_audit_entries[i].message);
        free((void*)g_audit_entries[i].details);
    }

    free(g_audit_entries);
    g_audit_entries = NULL;
    g_audit_count = 0;
    g_audit_capacity = 0;
}

// Get statistics
void audit_get_stats(int* total_events, int* error_count, time_t* last_event_time) {
    if (total_events) *total_events = g_audit_count;
    if (error_count) {
        *error_count = 0;
        for (int i = 0; i < g_audit_count; i++) {
            if (g_audit_entries[i].level >= AUDIT_ERROR) (*error_count)++;
        }
    }
    if (last_event_time && g_audit_count > 0) {
        *last_event_time = g_audit_entries[g_audit_count - 1].timestamp;
    }
}