#ifndef PROCESSING_H
#define PROCESSING_H

#include "cli.h"
#include <stddef.h>

/**
 * Process a single file with the given configuration
 * @param input_file Path to input shellcode file
 * @param output_file Path to output file
 * @param config Configuration structure
 * @param input_size_out Optional pointer to store input file size
 * @param output_size_out Optional pointer to store output file size
 * @return EXIT_SUCCESS on success, or an error code on failure
 */
int process_single_file(const char *input_file, const char *output_file,
                        byvalver_config_t *config, size_t *input_size_out,
                        size_t *output_size_out);

#endif // PROCESSING_H
