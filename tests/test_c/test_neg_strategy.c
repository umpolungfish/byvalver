#include <stdio.h>
#include <stdint.h>

// Test if the NEG strategy should work for our specific case
int find_neg_equivalent(uint32_t target, uint32_t *negated_val) {
    // To get 'target' using NEG, we need to load '-target' and then apply NEG
    // So negated_val should be -target
    uint32_t negated_target = (uint32_t)(-(int32_t)target);
    
    // Check if negated_target has no null bytes
    int has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((negated_target >> (i * 8)) & 0xFF) == 0) {
            has_null = 1;
            break;
        }
    }
    
    if (!has_null) {
        *negated_val = negated_target;
        return 1; // Found a suitable negated value
    }
    
    return 0; // No suitable negated value found
}

int main() {
    uint32_t target = 0x00730071;  // Our target value
    uint32_t negated_val;
    
    printf("Target value: 0x%08X\n", target);
    
    if (find_neg_equivalent(target, &negated_val)) {
        printf("Found NEG equivalent: 0x%08X\n", negated_val);
        printf("Verification: NEG(0x%08X) = 0x%08X\n", negated_val, (uint32_t)(-(int32_t)negated_val));
        
        // Check if the negated value has null bytes
        int has_null = 0;
        for (int i = 0; i < 4; i++) {
            if (((negated_val >> (i * 8)) & 0xFF) == 0) {
                printf("Byte %d of negated value is NULL!\n", i);
                has_null = 1;
            } else {
                printf("Byte %d of negated value: 0x%02X\n", i, (negated_val >> (i * 8)) & 0xFF);
            }
        }
        
        if (!has_null) {
            printf("NEG strategy should work for this value!\n");
        }
    } else {
        printf("NEG strategy does not work for this value.\n");
    }
    
    return 0;
}