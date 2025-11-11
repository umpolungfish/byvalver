#include <stdio.h>
#include <stdint.h>

// Mock size calculation functions
size_t get_mov_eax_imm_size_mock(uint32_t imm) {
    // Mock implementation based on the actual function
    int non_zero_bytes = 0;
    for (int i = 0; i < 4; i++) if ((imm >> (i * 8)) & 0xff) non_zero_bytes++;
    
    if (non_zero_bytes <= 1) {
        if (imm == 0) return 2;
        int byte_pos = 0;
        for (int i = 0; i < 4; i++) if ((imm >> (i*8)) & 0xff) { byte_pos = i; break; }
        return 2 + 2 + (byte_pos > 0 ? 3 : 0);
    } else {
        size_t size = 2;  // XOR EAX, EAX
        for (int i = 3; i >= 0; i--) {
            if ((imm >> (i * 8)) & 0xff) size += 2;  // MOV AL, byte
            if (i > 0) size += 3;  // SHL EAX, 8
        }
        return size;
    }
}

size_t get_mov_reg_imm_size_mock(uint32_t target) {
    // For non-EAX registers, it's more complex:
    // PUSH EAX (1) + MOV EAX, imm (get_mov_eax_imm_size) + MOV reg, EAX (2) + POP EAX (1)
    return 1 + get_mov_eax_imm_size_mock(target) + 2 + 1;
}

size_t get_mov_reg_imm_neg_size_mock(uint32_t target) {
    // Check if target already has null bytes
    int target_has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((target >> (i * 8)) & 0xFF) == 0) {
            target_has_null = 1;
            break;
        }
    }
    
    if (!target_has_null) {
        // No null bytes, just use direct MOV
        return get_mov_reg_imm_size_mock(target);
    }
    
    // Try to find neg equivalent
    uint32_t negated_target = (uint32_t)(-(int32_t)target);
    
    // Check if negated_target has no null bytes
    int negated_has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((negated_target >> (i * 8)) & 0xFF) == 0) {
            negated_has_null = 1;
            break;
        }
    }
    
    if (!negated_has_null) {
        // Size for: MOV reg, negated_val + NEG reg
        // For EAX: MOV EAX, negated_val (varies) + NEG EAX (2) 
        size_t mov_size = get_mov_eax_imm_size_mock(negated_target);
        return mov_size + 2; // MOV EAX, negated_val + NEG EAX
    }
    
    // If no neg equivalent found, fall back to original strategy
    return get_mov_reg_imm_size_mock(target);
}

int main() {
    // Test with a value where the negated form is much simpler
    // Let's try: 0xFFFFFF00 (has 3 null bytes)
    // Negated: 0x00000100 (has 1 null byte)
    // Actually, let's try 0x00FFFFFF (has 1 null byte)
    // Negated: 0xFF000001 (has 1 null byte)
    
    // Better example: 0x80000000 (has 3 null bytes)
    // Negated: 0x80000000 (same!)
    
    // Even better: 0x7FFFFFFF (no null bytes)
    // Negated: 0x80000001 (has 2 null bytes)
    
    // Best example: 0xFF000000 (has 3 null bytes)
    // Negated: 0x01000000 (has 2 null bytes, but simpler to load)
    
    // Actually, let's look at what values would be simpler:
    // 0x01000000 - has 3 zero bytes, negated is 0xFF000000
    // For 0x01000000: MOV EAX, 0x01000000 is complex because it needs 1 byte for 0x01 in the top position
    // For 0xFF000000: MOV EAX, 0xFF000000 is also complex
    
    // Let's try: 0x000000FF (has 3 null bytes)
    // Negated: 0xFFFFFF01 (no null bytes)
    uint32_t target = 0x000000FF;
    
    printf("=== Test Case 1 ===\n");
    printf("Target value: 0x%08X\n", target);
    
    // Check if target has null bytes
    int target_has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((target >> (i * 8)) & 0xFF) == 0) {
            target_has_null = 1;
            printf("Target byte %d is NULL\n", i);
        }
    }
    
    printf("Target has null bytes: %s\n", target_has_null ? "Yes" : "No");
    
    // Calculate sizes
    size_t original_size = get_mov_reg_imm_size_mock(target);
    size_t neg_size = get_mov_reg_imm_neg_size_mock(target);
    
    printf("Original size: %zu bytes\n", original_size);
    printf("NEG strategy size: %zu bytes\n", neg_size);
    
    // Also calculate size of negated value
    uint32_t negated_target = (uint32_t)(-(int32_t)target);
    size_t negated_size = get_mov_eax_imm_size_mock(negated_target);
    printf("Negated value: 0x%08X\n", negated_target);
    printf("Size to load negated value: %zu bytes\n", negated_size);
    printf("Total NEG strategy size: %zu + 2 (NEG) = %zu bytes\n", negated_size, negated_size + 2);
    
    if (neg_size < original_size) {
        printf("NEG strategy is more efficient!\n");
    } else {
        printf("NEG strategy is not more efficient.\n");
    }
    
    printf("\n=== Test Case 2 ===\n");
    // Try 0x00FF0000
    target = 0x00FF0000;
    printf("Target value: 0x%08X\n", target);
    
    target_has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((target >> (i * 8)) & 0xFF) == 0) {
            target_has_null = 1;
            printf("Target byte %d is NULL\n", i);
        }
    }
    
    printf("Target has null bytes: %s\n", target_has_null ? "Yes" : "No");
    
    original_size = get_mov_reg_imm_size_mock(target);
    neg_size = get_mov_reg_imm_neg_size_mock(target);
    
    printf("Original size: %zu bytes\n", original_size);
    printf("NEG strategy size: %zu bytes\n", neg_size);
    
    negated_target = (uint32_t)(-(int32_t)target);
    negated_size = get_mov_eax_imm_size_mock(negated_target);
    printf("Negated value: 0x%08X\n", negated_target);
    printf("Size to load negated value: %zu bytes\n", negated_size);
    printf("Total NEG strategy size: %zu + 2 (NEG) = %zu bytes\n", negated_size, negated_size + 2);
    
    if (neg_size < original_size) {
        printf("NEG strategy is more efficient!\n");
    } else {
        printf("NEG strategy is not more efficient.\n");
    }
    
    printf("\n=== Test Case 3 ===\n");
    // Try 0x0000007F (smaller value)
    target = 0x0000007F;
    printf("Target value: 0x%08X\n", target);
    
    target_has_null = 0;
    for (int i = 0; i < 4; i++) {
        if (((target >> (i * 8)) & 0xFF) == 0) {
            target_has_null = 1;
            printf("Target byte %d is NULL\n", i);
        }
    }
    
    printf("Target has null bytes: %s\n", target_has_null ? "Yes" : "No");
    
    original_size = get_mov_reg_imm_size_mock(target);
    neg_size = get_mov_reg_imm_neg_size_mock(target);
    
    printf("Original size: %zu bytes\n", original_size);
    printf("NEG strategy size: %zu bytes\n", neg_size);
    
    negated_target = (uint32_t)(-(int32_t)target);
    negated_size = get_mov_eax_imm_size_mock(negated_target);
    printf("Negated value: 0x%08X\n", negated_target);
    printf("Size to load negated value: %zu bytes\n", negated_size);
    printf("Total NEG strategy size: %zu + 2 (NEG) = %zu bytes\n", negated_size, negated_size + 2);
    
    if (neg_size < original_size) {
        printf("NEG strategy is more efficient!\n");
    } else {
        printf("NEG strategy is not more efficient.\n");
    }
    
    return 0;
}