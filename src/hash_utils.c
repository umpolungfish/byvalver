#include "hash_utils.h"
#include <string.h>

uint32_t ror13_hash(const char *name) {
    uint32_t hash = 0;
    while (*name) {
        hash = (hash >> 13) | (hash << (32 - 13)); // ROR 13
        hash += *name++;
    }
    return hash;
}
