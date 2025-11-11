#include <stdio.h>
#include <string.h>

int main() {
    // Sample shellcode with NOPs that can be replaced with anti-debug checks
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  // NOP instructions (potential anti-debug insertion points)
        0xB8, 0x33, 0x22, 0x11, 0x00,  // MOV EAX, 0x00112233 (contains null)
        0x90, 0x90, 0x90, 0x90,  // More NOPs
        0x33, 0xC0,               // XOR EAX, EAX
        0x90, 0x90                // More NOPs
    };
    
    FILE *f = fopen("test_anti_debug_shellcode.bin", "wb");
    if (f) {
        fwrite(shellcode, 1, sizeof(shellcode), f);
        fclose(f);
        printf("Created test anti-debug shellcode file.\n");
    }
    return 0;
}