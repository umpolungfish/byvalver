#include <stdio.h>
#include <string.h>

// Shellcode that should trigger ADD/SUB encoding strategy
// The immediate values 0x00400000 and 0x00800000 contain null bytes
// and should be good candidates for ADD/SUB encoding
unsigned char test_addsub_shellcode[] = {
    0xB8, 0x00, 0x00, 0x40, 0x00,  // MOV EAX, 0x00400000 (contains nulls)
    0x81, 0xC3, 0x00, 0x00, 0x80, 0x00,  // ADD EBX, 0x00800000 (contains nulls)
    0x81, 0xEA, 0x00, 0x10, 0x00, 0x00   // SUB EDX, 0x00001000 (contains nulls)
};

int main() {
    printf("Test shellcode with ADD/SUB candidates created\n");
    printf("Size: %d bytes\n", sizeof(test_addsub_shellcode));
    FILE *f = fopen("test_addsub_real.bin", "wb");
    if (f) {
        fwrite(test_addsub_shellcode, 1, sizeof(test_addsub_shellcode), f);
        fclose(f);
        printf("Shellcode written to test_addsub_real.bin\n");
    }
    return 0;
}