#include <stdio.h>
#include <string.h>

// Raw shellcode bytes with specific immediate values containing null bytes
unsigned char test_shellcode[] = {
    0xB8, 0x33, 0x22, 0x11, 0x00,  // MOV EAX, 0x00112233
    0xBB, 0x66, 0x55, 0x44, 0x00,  // MOV EBX, 0x00445566
    0x83, 0xC1, 0x99,              // ADD ECX, 0x99 (this is imm8, so no nulls)
    0x81, 0xC1, 0x99, 0x88, 0x77, 0x00,  // ADD ECX, 0x00778899 (32-bit imm)
    0x83, 0xEA, 0xCC,              // SUB EDX, 0xCC
    0x81, 0xEA, 0xCC, 0xBB, 0xAA, 0x00  // SUB EDX, 0x00AABBCC
};

int main() {
    printf("Test shellcode with %d bytes created\n", sizeof(test_shellcode));
    FILE *f = fopen("test_raw.bin", "wb");
    if (f) {
        fwrite(test_shellcode, 1, sizeof(test_shellcode), f);
        fclose(f);
        printf("Shellcode written to test_raw.bin\n");
    }
    return 0;
}