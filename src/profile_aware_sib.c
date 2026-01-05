#include "profile_aware_sib.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// Global statistics
sib_encoding_stats_t g_sib_stats = {0};

// Cache for SIB encoding decisions
static sib_encoding_result_t cached_encoding = {0};
static bool cache_valid = false;
static x86_reg cached_base = X86_REG_INVALID;
static x86_reg cached_dst = X86_REG_INVALID;

/**
 * @brief Check if a specific SIB byte is safe to use
 */
static bool is_sib_byte_safe(uint8_t sib_byte) {
    return is_bad_byte_free_buffer(&sib_byte, 1);
}

/**
 * @brief Check if a specific displacement value is safe
 */
static bool is_disp8_safe(int8_t disp) {
    uint8_t byte = (uint8_t)disp;
    return is_bad_byte_free_buffer(&byte, 1);
}

/**
 * @brief Check if a ModR/M byte is safe
 */
static bool is_modrm_safe(uint8_t modrm) {
    return is_bad_byte_free_buffer(&modrm, 1);
}

/**
 * @brief Select best SIB encoding for [EAX] based on bad byte profile
 */
sib_encoding_result_t select_sib_encoding_for_eax(x86_reg dst_reg) {
    sib_encoding_result_t result = {0};
    uint8_t dst_idx = get_reg_index(dst_reg);

    // Check cache
    if (cache_valid && cached_base == X86_REG_EAX && cached_dst == dst_reg) {
        return cached_encoding;
    }

    // Strategy 1: Standard SIB byte 0x20 (if safe)
    // SIB 0x20 = scale:00(1), index:100(ESP/none), base:000(EAX)
    // This encodes [EAX] with no displacement
    if (is_sib_byte_safe(0x20)) {
        result.strategy = SIB_ENCODING_STANDARD;
        result.modrm_byte = 0x04 | (dst_idx << 3);  // mod:00, reg:dst, r/m:100(SIB)
        result.sib_byte = 0x20;
        result.needs_compensation = false;
        g_sib_stats.standard_count++;

        // Cache result
        cached_encoding = result;
        cached_base = X86_REG_EAX;
        cached_dst = dst_reg;
        cache_valid = true;

        return result;
    }

    // Strategy 2: Use [EAX + disp8] with 8-bit displacement
    // Try common safe displacement values
    int8_t safe_displacements[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x0B, 0x0C, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x7F,
        -1, -2, -3, -4, -5, -7, -8, -16
    };

    for (size_t i = 0; i < sizeof(safe_displacements)/sizeof(safe_displacements[0]); i++) {
        int8_t disp = safe_displacements[i];
        uint8_t modrm = 0x40 | dst_idx;  // mod:01(disp8), reg:dst, r/m:000(EAX)

        if (is_disp8_safe(disp) && is_modrm_safe(modrm)) {
            result.strategy = SIB_ENCODING_DISP8;
            result.modrm_byte = modrm;
            result.disp8 = disp;
            result.needs_compensation = true;
            result.compensation = -disp;  // Compensate for displacement
            g_sib_stats.disp8_count++;

            // Cache result
            cached_encoding = result;
            cached_base = X86_REG_EAX;
            cached_dst = dst_reg;
            cache_valid = true;

            return result;
        }
    }

    // Strategy 3: Fallback to PUSH/POP approach
    result.strategy = SIB_ENCODING_PUSHPOP;
    result.needs_compensation = false;
    g_sib_stats.pushpop_count++;

    // Cache result
    cached_encoding = result;
    cached_base = X86_REG_EAX;
    cached_dst = dst_reg;
    cache_valid = true;

    return result;
}

/**
 * @brief Select best SIB encoding for arbitrary base register
 */
sib_encoding_result_t select_sib_encoding_for_reg(x86_reg base_reg, x86_reg dst_reg) {
    sib_encoding_result_t result = {0};
    uint8_t base_idx = get_reg_index(base_reg);
    uint8_t dst_idx = get_reg_index(dst_reg);

    // Special case: if base is EAX, use specialized function
    if (base_reg == X86_REG_EAX) {
        return select_sib_encoding_for_eax(dst_reg);
    }

    // Check cache
    if (cache_valid && cached_base == base_reg && cached_dst == dst_reg) {
        return cached_encoding;
    }

    // For other registers, first try direct ModR/M encoding (no SIB needed)
    uint8_t modrm = 0x00 | (dst_idx << 3) | base_idx;  // mod:00, reg:dst, r/m:base

    if (is_modrm_safe(modrm)) {
        result.strategy = SIB_ENCODING_STANDARD;
        result.modrm_byte = modrm;
        result.needs_compensation = false;
        g_sib_stats.standard_count++;

        // Cache result
        cached_encoding = result;
        cached_base = base_reg;
        cached_dst = dst_reg;
        cache_valid = true;

        return result;
    }

    // If direct encoding has bad byte, try [base + disp8]
    int8_t safe_displacements[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x0B, 0x0C, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x7F,
        -1, -2, -3, -4, -5, -7, -8
    };

    for (size_t i = 0; i < sizeof(safe_displacements)/sizeof(safe_displacements[0]); i++) {
        int8_t disp = safe_displacements[i];
        modrm = 0x40 | (dst_idx << 3) | base_idx;  // mod:01(disp8)

        if (is_disp8_safe(disp) && is_modrm_safe(modrm)) {
            result.strategy = SIB_ENCODING_DISP8;
            result.modrm_byte = modrm;
            result.disp8 = disp;
            result.needs_compensation = true;
            result.compensation = -disp;
            g_sib_stats.disp8_count++;

            // Cache result
            cached_encoding = result;
            cached_base = base_reg;
            cached_dst = dst_reg;
            cache_valid = true;

            return result;
        }
    }

    // Fallback
    result.strategy = SIB_ENCODING_PUSHPOP;
    result.needs_compensation = false;
    g_sib_stats.pushpop_count++;

    // Cache result
    cached_encoding = result;
    cached_base = base_reg;
    cached_dst = dst_reg;
    cache_valid = true;

    return result;
}

/**
 * @brief Generate MOV dst_reg, [base_reg] using profile-safe encoding
 */
int generate_safe_mov_reg_mem(struct buffer *b, x86_reg dst_reg, x86_reg base_reg) {
    sib_encoding_result_t enc = select_sib_encoding_for_reg(base_reg, dst_reg);

    switch (enc.strategy) {
        case SIB_ENCODING_STANDARD: {
            // Standard encoding: MOV dst, [base]
            uint8_t code[3];
            code[0] = 0x8B;  // MOV r32, r/m32
            code[1] = enc.modrm_byte;

            if ((enc.modrm_byte & 0x07) == 0x04) {
                // SIB byte follows
                code[2] = enc.sib_byte;
                buffer_append(b, code, 3);
            } else {
                buffer_append(b, code, 2);
            }
            return 0;
        }

        case SIB_ENCODING_DISP8: {
            // With displacement: first adjust base register
            if (enc.needs_compensation && base_reg != dst_reg) {
                // Only compensate if we won't clobber destination
                if (enc.compensation > 0) {
                    // ADD base_reg, compensation
                    uint8_t add_code[] = {0x83, (uint8_t)(0xC0 | get_reg_index(base_reg)), (uint8_t)enc.compensation};
                    buffer_append(b, add_code, 3);
                } else if (enc.compensation < 0) {
                    // SUB base_reg, -compensation
                    uint8_t sub_code[] = {0x83, (uint8_t)(0xE8 | get_reg_index(base_reg)), (uint8_t)(-enc.compensation)};
                    buffer_append(b, sub_code, 3);
                }
            }

            // MOV dst, [base + disp8]
            uint8_t mov_code[] = {0x8B, enc.modrm_byte, (uint8_t)enc.disp8};
            buffer_append(b, mov_code, 3);

            // Restore base register
            if (enc.needs_compensation && base_reg != dst_reg) {
                if (enc.compensation > 0) {
                    // SUB base_reg, compensation (undo the ADD)
                    uint8_t sub_code[] = {0x83, (uint8_t)(0xE8 | get_reg_index(base_reg)), (uint8_t)enc.compensation};
                    buffer_append(b, sub_code, 3);
                } else if (enc.compensation < 0) {
                    // ADD base_reg, -compensation (undo the SUB)
                    uint8_t add_code[] = {0x83, (uint8_t)(0xC0 | get_reg_index(base_reg)), (uint8_t)(-enc.compensation)};
                    buffer_append(b, add_code, 3);
                }
            }
            return 0;
        }

        case SIB_ENCODING_PUSHPOP: {
            // Fallback: use PUSH [base] / POP dst approach
            // PUSH [base_reg]
            uint8_t push_modrm = (uint8_t)(0x30 | get_reg_index(base_reg));  // /6 for PUSH
            uint8_t push_code[] = {0xFF, push_modrm};
            buffer_append(b, push_code, 2);

            // POP dst_reg
            uint8_t pop_code[] = {(uint8_t)(0x58 | get_reg_index(dst_reg))};
            buffer_append(b, pop_code, 1);
            return 0;
        }

        default:
            return -1;
    }
}

/**
 * @brief Generate MOV [base_reg], src_reg using profile-safe encoding
 */
int generate_safe_mov_mem_reg(struct buffer *b, x86_reg base_reg, x86_reg src_reg) {
    sib_encoding_result_t enc = select_sib_encoding_for_reg(base_reg, src_reg);

    switch (enc.strategy) {
        case SIB_ENCODING_STANDARD: {
            uint8_t code[3];
            code[0] = 0x89;  // MOV r/m32, r32
            code[1] = enc.modrm_byte;

            if ((enc.modrm_byte & 0x07) == 0x04) {
                code[2] = enc.sib_byte;
                buffer_append(b, code, 3);
            } else {
                buffer_append(b, code, 2);
            }
            return 0;
        }

        case SIB_ENCODING_DISP8: {
            if (enc.needs_compensation && base_reg != src_reg) {
                if (enc.compensation > 0) {
                    uint8_t add_code[] = {0x83, (uint8_t)(0xC0 | get_reg_index(base_reg)), (uint8_t)enc.compensation};
                    buffer_append(b, add_code, 3);
                } else if (enc.compensation < 0) {
                    uint8_t sub_code[] = {0x83, (uint8_t)(0xE8 | get_reg_index(base_reg)), (uint8_t)(-enc.compensation)};
                    buffer_append(b, sub_code, 3);
                }
            }

            uint8_t mov_code[] = {0x89, enc.modrm_byte, (uint8_t)enc.disp8};
            buffer_append(b, mov_code, 3);

            if (enc.needs_compensation && base_reg != src_reg) {
                if (enc.compensation > 0) {
                    uint8_t sub_code[] = {0x83, (uint8_t)(0xE8 | get_reg_index(base_reg)), (uint8_t)enc.compensation};
                    buffer_append(b, sub_code, 3);
                } else if (enc.compensation < 0) {
                    uint8_t add_code[] = {0x83, (uint8_t)(0xC0 | get_reg_index(base_reg)), (uint8_t)(-enc.compensation)};
                    buffer_append(b, add_code, 3);
                }
            }
            return 0;
        }

        case SIB_ENCODING_PUSHPOP: {
            // PUSH src_reg
            uint8_t push_code[] = {(uint8_t)(0x50 | get_reg_index(src_reg))};
            buffer_append(b, push_code, 1);

            // POP [base_reg]
            uint8_t pop_modrm = (uint8_t)(0x00 | get_reg_index(base_reg));
            uint8_t pop_code[] = {0x8F, pop_modrm};
            buffer_append(b, pop_code, 2);
            return 0;
        }

        default:
            return -1;
    }
}

/**
 * @brief Generate LEA dst_reg, [base_reg] using profile-safe encoding
 */
int generate_safe_lea_reg_mem(struct buffer *b, x86_reg dst_reg, x86_reg base_reg) {
    sib_encoding_result_t enc = select_sib_encoding_for_reg(base_reg, dst_reg);

    switch (enc.strategy) {
        case SIB_ENCODING_STANDARD: {
            uint8_t code[3];
            code[0] = 0x8D;  // LEA r32, m
            code[1] = enc.modrm_byte;

            if ((enc.modrm_byte & 0x07) == 0x04) {
                code[2] = enc.sib_byte;
                buffer_append(b, code, 3);
            } else {
                buffer_append(b, code, 2);
            }
            return 0;
        }

        case SIB_ENCODING_DISP8: {
            // LEA dst, [base + disp8], then subtract disp8 from result
            uint8_t lea_code[] = {0x8D, enc.modrm_byte, (uint8_t)enc.disp8};
            buffer_append(b, lea_code, 3);

            // Compensate: SUB dst, disp8 or ADD dst, -disp8
            if (enc.disp8 > 0) {
                uint8_t sub_code[] = {0x83, (uint8_t)(0xE8 | get_reg_index(dst_reg)), (uint8_t)enc.disp8};
                buffer_append(b, sub_code, 3);
            } else if (enc.disp8 < 0) {
                uint8_t add_code[] = {0x83, (uint8_t)(0xC0 | get_reg_index(dst_reg)), (uint8_t)(-enc.disp8)};
                buffer_append(b, add_code, 3);
            }
            return 0;
        }

        case SIB_ENCODING_PUSHPOP: {
            // LEA is just MOV for [reg] case
            // MOV dst, base
            uint8_t mov_code[] = {0x89, (uint8_t)(0xC0 | (get_reg_index(base_reg) << 3) | get_reg_index(dst_reg))};
            buffer_append(b, mov_code, 2);
            return 0;
        }

        default:
            return -1;
    }
}

/**
 * @brief Invalidate SIB encoding cache
 */
void invalidate_sib_cache(void) {
    cache_valid = false;
    cached_base = X86_REG_INVALID;
    cached_dst = X86_REG_INVALID;
    memset(&cached_encoding, 0, sizeof(cached_encoding));
}

/**
 * @brief Print SIB encoding statistics
 */
void print_sib_encoding_stats(void) {
    uint32_t total = g_sib_stats.standard_count + g_sib_stats.disp8_count + g_sib_stats.pushpop_count;

    if (total == 0) {
        printf("No SIB encoding statistics available.\n");
        return;
    }

    printf("\n=== SIB Encoding Statistics ===\n");
    printf("Standard (direct/SIB 0x20):  %u (%.1f%%)\n",
           g_sib_stats.standard_count,
           (100.0 * g_sib_stats.standard_count) / total);
    printf("Displacement-based:          %u (%.1f%%)\n",
           g_sib_stats.disp8_count,
           (100.0 * g_sib_stats.disp8_count) / total);
    printf("Push/Pop fallback:           %u (%.1f%%)\n",
           g_sib_stats.pushpop_count,
           (100.0 * g_sib_stats.pushpop_count) / total);
    printf("Total encodings:             %u\n", total);
    printf("================================\n\n");
}

/**
 * @brief Reset SIB encoding statistics
 */
void reset_sib_encoding_stats(void) {
    memset(&g_sib_stats, 0, sizeof(g_sib_stats));
}
