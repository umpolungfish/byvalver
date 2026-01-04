#ifndef GPU_ACCELERATION_H
#define GPU_ACCELERATION_H

// GPU acceleration for Byvalver ML inference
// High-pressure plumbing with GPU power

#include <stdint.h>
#include <stddef.h>

// Check if GPU acceleration is available
int gpu_available(void);

// Initialize GPU context
int gpu_init(void);

// Run ML inference on GPU
int gpu_ml_inference(const float* input, size_t input_size, float* output, size_t output_size);

// Parallel shellcode processing on GPU
int gpu_process_shellcodes(const uint8_t** shellcodes, size_t* sizes, int count,
                          uint8_t** outputs, size_t* output_sizes);

// Cleanup GPU resources
void gpu_cleanup(void);

// Get GPU memory info
void gpu_get_memory_info(size_t* free_mem, size_t* total_mem);

#endif /* GPU_ACCELERATION_H */