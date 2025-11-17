#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Test shellcode that contains null bytes - represents problematic instructions
    // This is a simple test that simulates shellcode with null bytes
    unsigned char test_shellcode[] = {
        0x48, 0x65, 0x6C, 0x6C, 0x6F,  // "Hello" 
        0x00, 0x00, 0x00, 0x00,        // Null bytes that need to be eliminated
        0x57, 0x6F, 0x72, 0x6C, 0x64,  // "World"
        0x00, 0x74, 0x65, 0x73, 0x74   // More data with null
    };
    
    FILE *f = fopen("test_input.bin", "wb");
    if (f) {
        fwrite(test_shellcode, 1, sizeof(test_shellcode), f);
        fclose(f);
        printf("Created test input file with %zu bytes, including null bytes\n", sizeof(test_shellcode));
        
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