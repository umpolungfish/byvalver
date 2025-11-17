#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Create test shellcode with various instructions that would trigger SIB byte issues
    // These represent common problematic patterns:
    // 1. MOV [0x00000000], EAX - memory write with null displacement
    // 2. MOV EAX, [0x00001234] - memory read with null in displacement
    // 3. ADD [0x00100000], EBX - arithmetic on memory with null displacement
    // etc.

    unsigned char test_shellcode[] = {
        // MOV [0x00ABCDEF], EAX - memory write with null bytes (problematic)
        0xA3, 0xEF, 0xCD, 0xAB, 0x00,  // MOV [disp32], EAX (if this encoding exists)
        
        // ADD [0x00123456], EBX - memory arithmetic with null in displacement
        0x01, 0x1D, 0x56, 0x34, 0x12, 0x00,  // ADD [disp32], EBX
        
        // Some NOPs as fillers
        0x90, 0x90,
        
        // CMP [0x00008888], ECX - another potential issue
        0x39, 0x0D, 0x88, 0x88, 0x00, 0x00,  // CMP [disp32], ECX
        
        // More fillers
        0x90, 0x90, 0x90
    };
    
    FILE *f = fopen("test_comprehensive.bin", "wb");
    if (f) {
        fwrite(test_shellcode, 1, sizeof(test_shellcode), f);
        fclose(f);
        printf("Created comprehensive test shellcode with %zu bytes\n", sizeof(test_shellcode));
        
        // Count null bytes
        int null_count = 0;
        for (size_t i = 0; i < sizeof(test_shellcode); i++) {
            if (test_shellcode[i] == 0x00) null_count++;
        }
        printf("Number of null bytes in input: %d\n", null_count);
        printf("Input file: test_comprehensive.bin\n");
    } else {
        printf("Failed to create test file\n");
        return 1;
    }
    
    return 0;
}