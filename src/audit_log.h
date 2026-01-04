#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

// Enterprise audit logging for Byvalver
// Track all plumbing operations for compliance and debugging

#include <stdint.h>
#include <stddef.h>
#include <time.h>

// Audit log levels
typedef enum {
    AUDIT_INFO,
    AUDIT_WARNING,
    AUDIT_ERROR,
    AUDIT_SECURITY
} audit_level_t;

// Audit event types
typedef enum {
    AUDIT_EVENT_PROCESSING_START,
    AUDIT_EVENT_PROCESSING_END,
    AUDIT_EVENT_STRATEGY_APPLIED,
    AUDIT_EVENT_BAD_BYTES_FOUND,
    AUDIT_EVENT_BAD_BYTES_ELIMINATED,
    AUDIT_EVENT_INTEGRATION_UPLOAD,
    AUDIT_EVENT_PLUGIN_LOADED,
    AUDIT_EVENT_ERROR_OCCURRED
} audit_event_type_t;

// Audit log entry
typedef struct {
    time_t timestamp;
    audit_level_t level;
    audit_event_type_t event_type;
    const char* message;
    const char* details;  // JSON or structured data
    const char* user_id;  // For multi-user systems
    const char* session_id;
} audit_entry_t;

// Initialize audit logging
int audit_init(const char* log_file_path, audit_level_t min_level);

// Log an audit event
void audit_log(audit_level_t level, audit_event_type_t event_type,
               const char* message, const char* details);

// Convenience functions for common events
void audit_processing_start(const char* input_file, size_t input_size);
void audit_processing_end(const char* output_file, size_t output_size,
                         int strategies_applied, int bad_bytes_removed);
void audit_strategy_applied(const char* strategy_name, int success);
void audit_bad_bytes_found(int count, const uint8_t* bytes);
void audit_integration_upload(const char* framework, const char* target, size_t size);

// Export audit log to various formats
int audit_export_json(const char* output_path);
int audit_export_csv(const char* output_path);

// Cleanup audit system
void audit_cleanup(void);

// Get audit statistics
void audit_get_stats(int* total_events, int* error_count, time_t* last_event_time);

#endif /* AUDIT_LOG_H */