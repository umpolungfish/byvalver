#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../src/utils.h"

// Expected hashes for common Windows API functions (ROR13 hash)
// These are calculated manually or from known sources
#define HASH_LOADLIBRARYA 0x0c91b000 // Example hash, actual value needs verification
#define HASH_GETPROCADDRESS 0x7c0b0100 // Example hash, actual value needs verification

int main() {
    printf("Testing ROR13 hash function:\n");

    // Test case 1: LoadLibraryA
    const char *func_name1 = "LoadLibraryA";
    uint32_t hash1 = ror13_hash(func_name1);
    printf("Hash for \"%s\": 0x%08x\n", func_name1, hash1);
    // Add assertion here if actual expected hash is known

    // Test case 2: GetProcAddress
    const char *func_name2 = "GetProcAddress";
    uint32_t hash2 = ror13_hash(func_name2);
    printf("Hash for \"%s\": 0x%08x\n", func_name2, hash2);
    // Add assertion here if actual expected hash is known

    // Test case 3: ExitProcess
    const char *func_name3 = "ExitProcess";
    uint32_t hash3 = ror13_hash(func_name3);
    printf("Hash for \"%s\": 0x%08x\n", func_name3, hash3);

    // Test case 4: Empty string
    const char *func_name4 = "";
    uint32_t hash4 = ror13_hash(func_name4);
    printf("Hash for \"%s\": 0x%08x\n", func_name4, hash4);

    // Test case 5: Short string
    const char *func_name5 = "abc";
    uint32_t hash5 = ror13_hash(func_name5);
    printf("Hash for \"%s\": 0x%08x\n", func_name5, hash5);

    return 0;
}
