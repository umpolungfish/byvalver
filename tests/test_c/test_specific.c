#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Create test shellcode that would specifically trigger the SIB byte issues we fixed
    // This represents instructions like ADD [0x10000000], EAX where displacement contains nulls
    // The displacement 0x10000000 has a null byte in the lower 3 bytes 
    unsigned char test_shellcode[] = {
        // MOV EAX, [0x00123456] - would have null in displacement
        0xA1, 0x56, 0x34, 0x12, 0x00,  // MOV EAX, [disp32] with null byte
        
        // ADD [0x00123456], EBX - memory operation with null in displacement
        0x01, 0x1D, 0x56, 0x34, 0x12, 0x00,  // ADD [disp32], EBX with null byte
        
        // More test data
        0x90, 0x90, 0x90, 0x90  // NOPs
    };
    
    FILE *f = fopen("test_specific.bin", "wb");
    if (f) {
        fwrite(test_shellcode, 1, sizeof(test_shellcode), f);
        fclose(f);
        printf("Created specific test shellcode with null bytes in displacements\n");
        
        // Count null bytes
        int null_count = 0;
        for (size_t i = 0; i < sizeof(test_shellcode); i++) {
            if (test_shellcode[i] == 0x00) null_count++;
        }
        printf("Number of null bytes in input: %d\n", null_count);
    } else {
        printf("Failed to create test file\n");
        return 1;
    }
    
    return 0;
}