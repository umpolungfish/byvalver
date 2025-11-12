// REPLACEMENT for the byte-by-byte construction in generate_mov_eax_imm
// Replace lines ~85-105 in src/utils.c with this code:

            } else {
                // FIXED: Improved byte-by-byte construction
                // This handles all cases including values with zero bytes
                uint8_t xor_eax_eax[] = {0x31, 0xC0};  // XOR EAX, EAX
                buffer_append(b, xor_eax_eax, 2);
                
                // Find first non-zero byte from MSB
                int first_nonzero = -1;
                for (int i = 3; i >= 0; i--) {
                    if (((imm >> (i * 8)) & 0xFF) != 0) {
                        first_nonzero = i;
                        break;
                    }
                }
                
                if (first_nonzero == -1) {
                    // Value is 0x00000000, already done with XOR EAX, EAX
                    return;
                }
                
                // Load first non-zero byte into AL
                uint8_t first_byte = (imm >> (first_nonzero * 8)) & 0xFF;
                uint8_t mov_al[] = {0xB0, first_byte};  // MOV AL, imm8
                buffer_append(b, mov_al, 2);
                
                // Process remaining bytes (including zeros)
                for (int i = first_nonzero - 1; i >= 0; i--) {
                    // Shift left by 8 bits
                    uint8_t shl_eax_8[] = {0xC1, 0xE0, 0x08};  // SHL EAX, 8
                    buffer_append(b, shl_eax_8, 3);
                    
                    uint8_t byte_val = (imm >> (i * 8)) & 0xFF;
                    if (byte_val != 0) {
                        // OR in the non-zero byte using OR AL, imm8
                        uint8_t or_al[] = {0x0C, byte_val};  // OR AL, imm8
                        buffer_append(b, or_al, 2);
                    }
                    // Zero bytes don't need OR - shift already placed 0x00 in AL
                }
            }


// REPLACEMENT for find_addsub_key function
// Replace lines ~440-470 in src/utils.c with this code:

int find_addsub_key(uint32_t target, uint32_t *val1, uint32_t *val2, int *is_add) {
    // FIXED: Use deterministic approach first, then random fallback
    
    // Try systematic offsets first (much more likely to succeed)
    uint32_t offsets[] = {
        0x01010101, 0x11111111, 0x22222222, 0x33333333,
        0x44444444, 0x55555555, 0x66666666, 0x77777777,
        0x88888888, 0x99999999, 0xAAAAAAAA, 0xBBBBBBBB,
        0xCCCCCCCC, 0xDDDDDDDD, 0xEEEEEEEE, 0xFFFFFFFF,
        0x12345678, 0x87654321, 0xABCDEF01, 0xFEDCBA98,
        0x13131313, 0x24242424, 0x35353535, 0x46464646
    };
    
    for (size_t i = 0; i < sizeof(offsets)/sizeof(offsets[0]); i++) {
        // Try SUB: val1 - offset = target  =>  val1 = target + offset
        uint32_t temp_val1 = target + offsets[i];
        if (is_null_free(temp_val1) && is_null_free(offsets[i])) {
            *val1 = temp_val1;
            *val2 = offsets[i];
            *is_add = 0; // SUB
            return 1;
        }
        
        // Try ADD: val1 + offset = target  =>  val1 = target - offset
        temp_val1 = target - offsets[i];
        if (is_null_free(temp_val1) && is_null_free(offsets[i])) {
            *val1 = temp_val1;
            *val2 = offsets[i];
            *is_add = 1; // ADD
            return 1;
        }
    }

    // Fall back to random search for remaining cases
    for (int i = 0; i < 5000; i++) {  // Increased from 1000 to 5000
        uint32_t temp_val2 = rand();
        if (!is_null_free(temp_val2)) {
            continue;
        }

        // Try SUB
        uint32_t temp_val1 = target + temp_val2;
        if (is_null_free(temp_val1)) {
            *val1 = temp_val1;
            *val2 = temp_val2;
            *is_add = 0;
            return 1;
        }

        // Try ADD
        temp_val1 = target - temp_val2;
        if (is_null_free(temp_val1)) {
            *val1 = temp_val1;
            *val2 = temp_val2;
            *is_add = 1;
            return 1;
        }
    }

    return 0; // No suitable key found
}
