/**
 * badchar_profiles.h
 *
 * Bad-Character Profile Database
 * Provides pre-configured bad-character sets for common exploit scenarios.
 *
 * Part of the byvalver v3.0+ generic bad-character elimination framework.
 */

#ifndef BADCHAR_PROFILES_H
#define BADCHAR_PROFILES_H

#include <stdint.h>
#include <stddef.h>
#include "cli.h"

/**
 * Bad-character profile structure
 * Defines a named collection of bad characters for specific exploit contexts
 */
typedef struct {
    const char *name;                  // Profile name (e.g., "http-newline")
    const char *description;           // Human-readable description
    const char *context;               // When to use this profile
    const uint8_t *bad_chars;          // Array of bad character values
    size_t bad_char_count;             // Number of bad characters
    const char *examples;              // Usage examples
    int difficulty;                    // Elimination difficulty (1-5)
} badchar_profile_t;

// Profile difficulty levels
#define DIFFICULTY_TRIVIAL    1  // Very easy (e.g., null-only)
#define DIFFICULTY_LOW        2  // Easy (e.g., null + newlines)
#define DIFFICULTY_MEDIUM     3  // Moderate (e.g., URL-safe)
#define DIFFICULTY_HIGH       4  // Hard (e.g., printable-only)
#define DIFFICULTY_EXTREME    5  // Very hard (e.g., alphanumeric-only)

// =============================================================================
// PROFILE DEFINITIONS
// =============================================================================

/**
 * Profile: null-only (default)
 * Context: Classic buffer overflows, string-based exploits
 * Difficulty: Trivial
 */
static const uint8_t PROFILE_NULL_ONLY_CHARS[] = {
    0x00  // NULL
};

/**
 * Profile: http-newline
 * Context: HTTP headers, line-based protocols (FTP, SMTP)
 * Difficulty: Low
 */
static const uint8_t PROFILE_HTTP_NEWLINE_CHARS[] = {
    0x00,  // NULL
    0x0A,  // Line Feed (LF, \n)
    0x0D   // Carriage Return (CR, \r)
};

/**
 * Profile: http-whitespace
 * Context: HTTP parameters, command injection
 * Difficulty: Low
 */
static const uint8_t PROFILE_HTTP_WHITESPACE_CHARS[] = {
    0x00,  // NULL
    0x09,  // Horizontal Tab
    0x0A,  // Line Feed
    0x0D,  // Carriage Return
    0x20   // Space
};

/**
 * Profile: url-safe
 * Context: URL parameters, GET requests
 * Difficulty: Medium
 */
static const uint8_t PROFILE_URL_SAFE_CHARS[] = {
    0x00,  // NULL
    0x20,  // Space
    0x22,  // Double quote
    0x23,  // Hash/pound (#)
    0x24,  // Dollar sign ($)
    0x25,  // Percent (%)
    0x26,  // Ampersand (&)
    0x2B,  // Plus (+)
    0x2C,  // Comma
    0x2F,  // Forward slash (/)
    0x3A,  // Colon (:)
    0x3B,  // Semicolon (;)
    0x3C,  // Less than (<)
    0x3D,  // Equal (=)
    0x3E,  // Greater than (>)
    0x3F,  // Question mark (?)
    0x40,  // At sign (@)
    0x5B,  // Left bracket ([)
    0x5D,  // Right bracket (])
    0x5C,  // Backslash (\)
    0x7B,  // Left brace ({)
    0x7D,  // Right brace (})
    0x7C   // Pipe (|)
};

/**
 * Profile: sql-injection
 * Context: SQL injection via string literals
 * Difficulty: Medium
 */
static const uint8_t PROFILE_SQL_INJECTION_CHARS[] = {
    0x00,  // NULL
    0x22,  // Double quote
    0x27,  // Single quote (')
    0x2D,  // Hyphen/dash (-- SQL comment)
    0x3B   // Semicolon (statement terminator)
};

/**
 * Profile: xml-html
 * Context: XML/HTML injection, XSS payloads
 * Difficulty: Medium
 */
static const uint8_t PROFILE_XML_HTML_CHARS[] = {
    0x00,  // NULL
    0x22,  // Double quote
    0x26,  // Ampersand (&)
    0x27,  // Single quote
    0x3C,  // Less than (<)
    0x3E   // Greater than (>)
};

/**
 * Profile: json-string
 * Context: JSON API injection, JavaScript contexts
 * Difficulty: Medium
 */
static const uint8_t PROFILE_JSON_STRING_CHARS[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  // Control chars
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x22,  // Double quote
    0x5C   // Backslash
};

/**
 * Profile: format-string
 * Context: Format string vulnerabilities
 * Difficulty: Medium-High
 */
static const uint8_t PROFILE_FORMAT_STRING_CHARS[] = {
    0x00,  // NULL
    0x20,  // Space (sometimes)
    0x25   // Percent (%) - format specifier
};

/**
 * Profile: buffer-overflow-restricted
 * Context: Stack/heap overflows with character filtering
 * Difficulty: Medium
 */
static const uint8_t PROFILE_BUFFER_OVERFLOW_CHARS[] = {
    0x00,  // NULL
    0x09,  // Tab
    0x0A,  // Line Feed
    0x0D,  // Carriage Return
    0x20   // Space
};

/**
 * Profile: printable-only
 * Context: Text-based protocols, printable character requirements
 * Difficulty: High
 */
static uint8_t PROFILE_PRINTABLE_ONLY_CHARS[161];  // Non-printable chars
static int profile_printable_initialized = 0;

static inline void init_printable_profile(void) {
    if (profile_printable_initialized) return;

    int idx = 0;
    // Control characters (0x00-0x1F)
    for (int i = 0x00; i <= 0x1F; i++) {
        PROFILE_PRINTABLE_ONLY_CHARS[idx++] = i;
    }
    // DEL (0x7F)
    PROFILE_PRINTABLE_ONLY_CHARS[idx++] = 0x7F;
    // Extended ASCII (0x80-0xFF)
    for (int i = 0x80; i <= 0xFF; i++) {
        PROFILE_PRINTABLE_ONLY_CHARS[idx++] = i;
    }

    profile_printable_initialized = 1;
}

/**
 * Profile: alphanumeric-only
 * Context: Strict input filters, alphanumeric-only requirements
 * Difficulty: Extreme
 */
static uint8_t PROFILE_ALPHANUMERIC_ONLY_CHARS[194];  // Non-alphanumeric chars
static int profile_alphanumeric_initialized = 0;

static inline void init_alphanumeric_profile(void) {
    if (profile_alphanumeric_initialized) return;

    int idx = 0;
    // Everything except 0-9, A-Z, a-z
    for (int i = 0; i < 256; i++) {
        if ((i >= 0x30 && i <= 0x39) ||  // 0-9
            (i >= 0x41 && i <= 0x5A) ||  // A-Z
            (i >= 0x61 && i <= 0x7A)) {  // a-z
            continue;  // Skip alphanumeric
        }
        PROFILE_ALPHANUMERIC_ONLY_CHARS[idx++] = i;
    }

    profile_alphanumeric_initialized = 1;
}

/**
 * Profile: command-injection
 * Context: Shell command injection, system() calls
 * Difficulty: Medium
 */
static const uint8_t PROFILE_COMMAND_INJECTION_CHARS[] = {
    0x00,  // NULL
    0x09,  // Tab
    0x0A,  // Line Feed
    0x0D,  // Carriage Return
    0x20,  // Space
    0x21,  // Exclamation (!)
    0x22,  // Double quote
    0x24,  // Dollar ($) - variable expansion
    0x26,  // Ampersand (&) - background
    0x27,  // Single quote
    0x28,  // Left paren - subshell
    0x29,  // Right paren
    0x2A,  // Asterisk (*) - glob
    0x2F,  // Slash (/)
    0x3B,  // Semicolon (;) - command separator
    0x3C,  // Less than (<) - redirect
    0x3E,  // Greater than (>) - redirect
    0x5C,  // Backslash (\) - escape
    0x60,  // Backtick (`) - command substitution
    0x7C   // Pipe (|)
};

/**
 * Profile: ldap-injection
 * Context: LDAP injection attacks
 * Difficulty: Medium
 */
static const uint8_t PROFILE_LDAP_INJECTION_CHARS[] = {
    0x00,  // NULL
    0x28,  // Left paren (
    0x29,  // Right paren )
    0x2A,  // Asterisk *
    0x5C   // Backslash
};

// =============================================================================
// PROFILE REGISTRY
// =============================================================================

static const badchar_profile_t BADCHAR_PROFILES[] = {
    {
        .name = "null-only",
        .description = "Eliminate NULL bytes only (classic denullification)",
        .context = "Most buffer overflows, string-based exploits",
        .bad_chars = PROFILE_NULL_ONLY_CHARS,
        .bad_char_count = sizeof(PROFILE_NULL_ONLY_CHARS),
        .examples = "byvalver --profile null-only input.bin output.bin",
        .difficulty = DIFFICULTY_TRIVIAL
    },
    {
        .name = "http-newline",
        .description = "Eliminate NULL, LF, and CR (line terminators)",
        .context = "HTTP headers, FTP, SMTP, line-based protocols",
        .bad_chars = PROFILE_HTTP_NEWLINE_CHARS,
        .bad_char_count = sizeof(PROFILE_HTTP_NEWLINE_CHARS),
        .examples = "byvalver --profile http-newline input.bin output.bin",
        .difficulty = DIFFICULTY_LOW
    },
    {
        .name = "http-whitespace",
        .description = "Eliminate NULL and all whitespace characters",
        .context = "HTTP parameters, command injection contexts",
        .bad_chars = PROFILE_HTTP_WHITESPACE_CHARS,
        .bad_char_count = sizeof(PROFILE_HTTP_WHITESPACE_CHARS),
        .examples = "byvalver --profile http-whitespace input.bin output.bin",
        .difficulty = DIFFICULTY_LOW
    },
    {
        .name = "url-safe",
        .description = "Eliminate URL-unsafe characters",
        .context = "URL parameters, GET requests, query strings",
        .bad_chars = PROFILE_URL_SAFE_CHARS,
        .bad_char_count = sizeof(PROFILE_URL_SAFE_CHARS),
        .examples = "byvalver --profile url-safe input.bin output.bin",
        .difficulty = DIFFICULTY_MEDIUM
    },
    {
        .name = "sql-injection",
        .description = "Eliminate SQL metacharacters",
        .context = "SQL injection via string literals",
        .bad_chars = PROFILE_SQL_INJECTION_CHARS,
        .bad_char_count = sizeof(PROFILE_SQL_INJECTION_CHARS),
        .examples = "byvalver --profile sql-injection input.bin output.bin",
        .difficulty = DIFFICULTY_MEDIUM
    },
    {
        .name = "xml-html",
        .description = "Eliminate XML/HTML special characters",
        .context = "XML/HTML injection, XSS payloads",
        .bad_chars = PROFILE_XML_HTML_CHARS,
        .bad_char_count = sizeof(PROFILE_XML_HTML_CHARS),
        .examples = "byvalver --profile xml-html input.bin output.bin",
        .difficulty = DIFFICULTY_MEDIUM
    },
    {
        .name = "json-string",
        .description = "Eliminate JSON-unsafe characters",
        .context = "JSON API injection, JavaScript contexts",
        .bad_chars = PROFILE_JSON_STRING_CHARS,
        .bad_char_count = sizeof(PROFILE_JSON_STRING_CHARS),
        .examples = "byvalver --profile json-string input.bin output.bin",
        .difficulty = DIFFICULTY_MEDIUM
    },
    {
        .name = "format-string",
        .description = "Eliminate format string specifiers",
        .context = "Format string vulnerabilities (printf, etc.)",
        .bad_chars = PROFILE_FORMAT_STRING_CHARS,
        .bad_char_count = sizeof(PROFILE_FORMAT_STRING_CHARS),
        .examples = "byvalver --profile format-string input.bin output.bin",
        .difficulty = DIFFICULTY_MEDIUM
    },
    {
        .name = "buffer-overflow",
        .description = "Common buffer overflow bad characters",
        .context = "Stack/heap overflows with character filtering",
        .bad_chars = PROFILE_BUFFER_OVERFLOW_CHARS,
        .bad_char_count = sizeof(PROFILE_BUFFER_OVERFLOW_CHARS),
        .examples = "byvalver --profile buffer-overflow input.bin output.bin",
        .difficulty = DIFFICULTY_MEDIUM
    },
    {
        .name = "command-injection",
        .description = "Eliminate shell metacharacters",
        .context = "Shell command injection, system() calls",
        .bad_chars = PROFILE_COMMAND_INJECTION_CHARS,
        .bad_char_count = sizeof(PROFILE_COMMAND_INJECTION_CHARS),
        .examples = "byvalver --profile command-injection input.bin output.bin",
        .difficulty = DIFFICULTY_MEDIUM
    },
    {
        .name = "ldap-injection",
        .description = "Eliminate LDAP special characters",
        .context = "LDAP injection attacks",
        .bad_chars = PROFILE_LDAP_INJECTION_CHARS,
        .bad_char_count = sizeof(PROFILE_LDAP_INJECTION_CHARS),
        .examples = "byvalver --profile ldap-injection input.bin output.bin",
        .difficulty = DIFFICULTY_MEDIUM
    },
    {
        .name = "printable-only",
        .description = "Allow only printable ASCII (0x20-0x7E)",
        .context = "Text-based protocols, printable character requirements",
        .bad_chars = PROFILE_PRINTABLE_ONLY_CHARS,
        .bad_char_count = 161,  // Will be initialized
        .examples = "byvalver --profile printable-only input.bin output.bin",
        .difficulty = DIFFICULTY_HIGH
    },
    {
        .name = "alphanumeric-only",
        .description = "Allow only alphanumeric chars (0-9, A-Z, a-z)",
        .context = "Strict input filters, alphanumeric-only shellcode",
        .bad_chars = PROFILE_ALPHANUMERIC_ONLY_CHARS,
        .bad_char_count = 194,  // Will be initialized
        .examples = "byvalver --profile alphanumeric-only input.bin output.bin\n"
                   "       # Warning: Extremely difficult, may require encoding",
        .difficulty = DIFFICULTY_EXTREME
    }
};

#define NUM_PROFILES (sizeof(BADCHAR_PROFILES) / sizeof(badchar_profile_t))

// =============================================================================
// PROFILE API
// =============================================================================

/**
 * Initialize dynamic profiles (printable-only, alphanumeric-only)
 */
static inline void init_badchar_profiles(void) {
    init_printable_profile();
    init_alphanumeric_profile();
}

/**
 * Find profile by name
 *
 * @param name Profile name
 * @return Pointer to profile, or NULL if not found
 */
static inline const badchar_profile_t* find_badchar_profile(const char *name) {
    if (!name) return NULL;

    init_badchar_profiles();  // Ensure dynamic profiles initialized

    for (size_t i = 0; i < NUM_PROFILES; i++) {
        if (strcmp(BADCHAR_PROFILES[i].name, name) == 0) {
            return &BADCHAR_PROFILES[i];
        }
    }

    return NULL;
}

/**
 * List all available profiles
 *
 * @param stream Output stream (stdout/stderr)
 */
static inline void list_badchar_profiles(FILE *stream) {
    init_badchar_profiles();

    fprintf(stream, "Available Bad-Character Profiles:\n\n");

    for (size_t i = 0; i < NUM_PROFILES; i++) {
        const badchar_profile_t *profile = &BADCHAR_PROFILES[i];

        fprintf(stream, "  %-20s  ", profile->name);

        // Difficulty indicator
        fprintf(stream, "[");
        for (int d = 0; d < 5; d++) {
            if (d < profile->difficulty) {
                fprintf(stream, "█");
            } else {
                fprintf(stream, "░");
            }
        }
        fprintf(stream, "]  ");

        // Character count
        fprintf(stream, "(%zu bad chars)\n", profile->bad_char_count);

        fprintf(stream, "      %s\n", profile->description);
        fprintf(stream, "      Context: %s\n\n", profile->context);
    }

    fprintf(stream, "Difficulty Legend: [█░░░░]=Trivial  [███░░]=Medium  [█████]=Extreme\n\n");
    fprintf(stream, "Usage: byvalver --profile <name> input.bin output.bin\n");
    fprintf(stream, "   or: byvalver --list-profiles  (show this list)\n");
}

/**
 * Convert profile to bad_char_config_t
 *
 * @param profile Profile to convert
 * @return Allocated config structure (caller must free)
 */
static inline bad_char_config_t* profile_to_config(const badchar_profile_t *profile) {
    if (!profile) return NULL;

    bad_char_config_t *config = (bad_char_config_t*)calloc(1, sizeof(bad_char_config_t));
    if (!config) return NULL;

    // Set bad_chars bitmap
    for (size_t i = 0; i < profile->bad_char_count; i++) {
        uint8_t bad_char = profile->bad_chars[i];
        config->bad_chars[bad_char] = 1;
        config->bad_char_list[config->bad_char_count++] = bad_char;
    }

    return config;
}

/**
 * Show profile details
 *
 * @param profile Profile to display
 * @param stream Output stream
 */
static inline void show_profile_details(const badchar_profile_t *profile, FILE *stream) {
    if (!profile) return;

    fprintf(stream, "Profile: %s\n", profile->name);
    fprintf(stream, "========%.*s\n\n", (int)strlen(profile->name), "===================");

    fprintf(stream, "Description: %s\n", profile->description);
    fprintf(stream, "Context:     %s\n", profile->context);
    fprintf(stream, "Difficulty:  ");
    for (int d = 0; d < 5; d++) {
        fprintf(stream, "%s", d < profile->difficulty ? "█" : "░");
    }
    fprintf(stream, " (%d/5)\n\n", profile->difficulty);

    fprintf(stream, "Bad Characters (%zu total):\n", profile->bad_char_count);
    fprintf(stream, "  Hex: ");
    for (size_t i = 0; i < profile->bad_char_count && i < 20; i++) {
        fprintf(stream, "0x%02X ", profile->bad_chars[i]);
    }
    if (profile->bad_char_count > 20) {
        fprintf(stream, "... (%zu more)", profile->bad_char_count - 20);
    }
    fprintf(stream, "\n\n");

    fprintf(stream, "Example Usage:\n");
    fprintf(stream, "  %s\n\n", profile->examples);
}

#endif // BADCHAR_PROFILES_H
