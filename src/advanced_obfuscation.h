#ifndef ADVANCED_OBFUSCATION_H
#define ADVANCED_OBFUSCATION_H

// Advanced obfuscation techniques for Byvalver
// Military-grade plumbing that confuses analysis tools

#include <stdint.h>
#include <stddef.h>

// Control flow flattening
typedef struct {
    int enabled;
    int max_basic_blocks;  // Maximum basic blocks per flattened section
    int use_opaque_predicates;  // Use opaque predicates for confusion
} control_flow_config_t;

int apply_control_flow_flattening(uint8_t* shellcode, size_t size, const control_flow_config_t* config);

// Opaque predicates
int insert_opaque_predicate(uint8_t* shellcode, size_t* size, size_t max_size);

// Anti-analysis features
typedef struct {
    int timing_based_detection;  // Detect debugger timing
    int environmental_checks;    // Check for analysis environment
    int anti_disassembly;        // Insert anti-disassembly sequences
} anti_analysis_config_t;

int apply_anti_analysis(uint8_t* shellcode, size_t* size, size_t max_size,
                       const anti_analysis_config_t* config);

// Polymorphic shellcode generation
int generate_polymorphic_variant(const uint8_t* original, size_t original_size,
                                uint8_t* variant, size_t* variant_size, size_t max_size);

#endif /* ADVANCED_OBFUSCATION_H */