/*
 * Unicode String Handling Strategy
 *
 * PROBLEM: Windows APIs often require Unicode (UTF-16) strings which inherently
 * contain null bytes between ASCII characters. Direct embedding of Unicode strings
 * like L"ws2_32" would produce: 77 00 73 00 32 00 5F 00 33 00 32 00 00 00
 * containing multiple null bytes that violate shellcode null-byte constraints.
 *
 * SOLUTION: This strategy provides two complementary approaches for constructing
 * Unicode strings at runtime without embedded null bytes:
 *
 * Strategy A: Byte-by-Byte Unicode Construction (STOSW)
 *   - Use STOSW instruction to write wide characters incrementally
 *   - Pattern: mov ax, 'w'; stosw; mov ax, 's'; stosw; etc.
 *   - Ideal for short strings (DLL names, API names)
 *   - Compact and efficient for strings up to ~16 characters
 *
 * Strategy B: ASCII-to-Unicode Conversion
 *   - Store ASCII string and convert to Unicode at runtime
 *   - Use null-safe byte manipulation to set high bytes to zero
 *   - Better for longer strings where byte-by-byte is too expensive
 *   - Leverages existing null-free immediate construction
 *
 * DETECTION PATTERNS:
 *   1. Sequences of MOV AX, imm16 + STOSW (Strategy A usage)
 *   2. PUSH immediate followed by byte-level stack manipulation (Strategy B setup)
 *   3. Unicode string constants embedded in shellcode (direct replacement target)
 *   4. LoadLibraryW, GetProcAddress preparation sequences
 *
 * WINDOWS API TARGETS:
 *   - LoadLibraryW (loading DLLs by Unicode name)
 *   - CreateProcessW, CreateFileW (Unicode file operations)
 *   - GetProcAddress with Unicode DLL names
 *   - Common DLLs: ws2_32, kernel32, ntdll, user32, advapi32
 *
 * PRIORITY: 74-78 (Medium-High, Windows-specific critical functionality)
 * FREQUENCY: Common in Windows shellcode that uses Unicode APIs
 * PLATFORM: Windows-only (Unicode APIs are Windows-specific)
 *
 * Example Transformation (Strategy A - STOSW):
 *   Input:  Unicode string L"ws2_32" embedded (contains nulls)
 *   Output: sub esp, 14; mov edi, esp; mov ax, 'w'; stosw; mov ax, 's'; stosw;
 *           mov ax, '2'; stosw; mov ax, '_'; stosw; mov ax, '3'; stosw;
 *           mov ax, '2'; stosw; xor ax, ax; stosw;
 *
 * Example Transformation (Strategy B - ASCII conversion):
 *   Input:  PUSH 0x00007377 (contains nulls for "ws" prefix)
 *   Output: PUSH 0x73777777; mov byte [esp+3], 0; mov byte [esp+1], 0;
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

/*
 * Detect Unicode string construction patterns that require null-byte elimination
 *
 * This function identifies:
 * 1. MOV AX, immediate followed by STOSW (partial Unicode construction)
 * 2. PUSH operations with immediates that could be part of Unicode string setup
 * 3. SUB ESP operations that allocate space for Unicode strings (even-sized, >= 4 bytes)
 * 4. Sequences that suggest Unicode API usage preparation
 */
static int can_handle_unicode_string(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    // Detection Pattern 1: MOV AX, immediate (likely part of STOSW sequence)
    // This catches: mov ax, 'w'; stosw; mov ax, 's'; stosw; etc.
    // IMPORTANT: Only detect if instruction contains null bytes (the whole point!)
    if (insn->id == X86_INS_MOV) {
        if (insn->detail->x86.op_count == 2) {
            cs_x86_op *dst = &insn->detail->x86.operands[0];
            cs_x86_op *src = &insn->detail->x86.operands[1];

            // Check for MOV AX, immediate (16-bit register for wide character)
            if (dst->type == X86_OP_REG && src->type == X86_OP_IMM) {
                if (dst->reg == X86_REG_AX) {
                    // Only handle if instruction has null bytes
                    if (!has_null_bytes(insn)) {
                        return 0; // Already null-free, don't handle
                    }

                    // MOV AX, immediate is often used before STOSW for Unicode construction
                    uint16_t imm = (uint16_t)src->imm;

                    // Check if immediate is in printable ASCII range (typical for DLL/API names)
                    // OR if it's a null terminator (0x0000)
                    if ((imm > 0 && imm <= 0x7F && isprint((char)imm)) || imm == 0) {
                        return 1; // Likely Unicode character construction
                    }
                }
            }

            // Check for MOV EDI, ESP (setting up buffer pointer for STOSW)
            if (dst->type == X86_OP_REG && src->type == X86_OP_REG) {
                if ((dst->reg == X86_REG_EDI || dst->reg == X86_REG_RDI) &&
                    (src->reg == X86_REG_ESP || src->reg == X86_REG_RSP)) {
                    return 1; // Setting up Unicode string buffer pointer
                }
            }
        }
    }

    // Detection Pattern 2: STOSW instruction (Unicode character write)
    if (insn->id == X86_INS_STOSW) {
        return 1; // Direct Unicode string construction
    }

    // Detection Pattern 3: SUB ESP, immediate (allocating Unicode string space)
    // Unicode strings need even-sized allocation (2 bytes per character)
    if (insn->id == X86_INS_SUB) {
        if (insn->detail->x86.op_count == 2) {
            cs_x86_op *dst = &insn->detail->x86.operands[0];
            cs_x86_op *src = &insn->detail->x86.operands[1];

            if (dst->type == X86_OP_REG && src->type == X86_OP_IMM) {
                if (dst->reg == X86_REG_ESP || dst->reg == X86_REG_RSP) {
                    uint32_t alloc_size = (uint32_t)src->imm;

                    // Check if allocation is even-sized (Unicode requirement) and reasonable
                    // Typical DLL names: 6-20 chars = 12-40 bytes + null terminator = 14-42 bytes
                    if (alloc_size >= 4 && alloc_size <= 64 && (alloc_size % 2) == 0) {
                        // Check if allocation contains null bytes
                        if (has_null_bytes(insn)) {
                            return 1; // Unicode string space allocation with nulls
                        }
                    }
                }
            }
        }
    }

    // Detection Pattern 4: PUSH immediate that looks like ASCII string chunk
    // Used in Strategy B (ASCII-to-Unicode conversion)
    if (insn->id == X86_INS_PUSH) {
        if (insn->detail->x86.op_count == 1) {
            cs_x86_op *op = &insn->detail->x86.operands[0];

            if (op->type == X86_OP_IMM) {
                uint32_t imm = (uint32_t)op->imm;

                // Check if immediate looks like ASCII string chunk (4 printable bytes)
                // Common in stack-based Unicode string setup
                int printable_count = 0;
                for (int i = 0; i < 4; i++) {
                    uint8_t byte = (imm >> (i * 8)) & 0xFF;
                    if (byte != 0 && isprint(byte)) {
                        printable_count++;
                    }
                }

                // If 3-4 bytes are printable ASCII, likely part of string construction
                if (printable_count >= 3 && has_null_bytes(insn)) {
                    return 1; // ASCII string chunk with nulls (for Unicode conversion)
                }
            }
        }
    }

    return 0; // Not a Unicode string construction pattern
}

/*
 * Calculate size of null-free Unicode string construction code
 *
 * Size estimates based on transformation strategy:
 * - MOV AX, imm + STOSW: ~5 bytes per character (null-free MOV + STOSW)
 * - SUB ESP, imm: ~7-10 bytes (null-free stack allocation)
 * - PUSH imm (ASCII chunk): ~8-12 bytes (MOV reg + PUSH for null-free)
 */
static size_t get_size_unicode_string(cs_insn *insn) {
    if (!insn || !insn->detail) return insn->size;

    // MOV AX, immediate: Transform to null-free MOV + potential STOSW overhead
    if (insn->id == X86_INS_MOV) {
        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        if (dst->type == X86_OP_REG && src->type == X86_OP_IMM) {
            if (dst->reg == X86_REG_AX) {
                // MOV AX, immediate (null-free) = ~3-5 bytes
                // (MOV AL, low_byte + MOV AH, high_byte or XOR + MOV)
                return 5;
            }
        }

        // MOV EDI, ESP: Keep as-is, typically null-free
        if (dst->type == X86_OP_REG && src->type == X86_OP_REG) {
            return 2; // MOV r32, r32 encoding
        }
    }

    // STOSW: Keep as-is (single byte: 0xAB, null-free)
    if (insn->id == X86_INS_STOSW) {
        return 1; // STOSW is 0xAB (null-free)
    }

    // SUB ESP, immediate: Null-free construction
    if (insn->id == X86_INS_SUB) {
        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        if (dst->type == X86_OP_REG && src->type == X86_OP_IMM) {
            if (dst->reg == X86_REG_ESP || dst->reg == X86_REG_RSP) {
                uint32_t imm = (uint32_t)src->imm;

                if (is_null_free(imm)) {
                    return 3; // SUB ESP, imm8 or 6 for imm32 (null-free)
                } else {
                    // Transform to: PUSH reg + MOV reg, imm (null-free) + SUB ESP, reg + POP reg
                    return 10; // Conservative estimate for null-free SUB
                }
            }
        }
    }

    // PUSH immediate: Transform to MOV + PUSH
    if (insn->id == X86_INS_PUSH && insn->detail->x86.operands[0].type == X86_OP_IMM) {
        // MOV EAX, imm (null-free) + PUSH EAX
        return 8; // Conservative estimate
    }

    return insn->size; // Default: keep original size
}

/*
 * Generate null-free Unicode string construction code
 *
 * Implements transformations for:
 * 1. MOV AX, immediate -> null-free 16-bit register load
 * 2. STOSW -> keep as-is (already null-free: 0xAB)
 * 3. SUB ESP, immediate -> null-free stack allocation
 * 4. PUSH immediate -> null-free ASCII chunk push (for Unicode conversion)
 */
static void generate_unicode_string(struct buffer *b, cs_insn *insn) {
    if (!insn || !insn->detail) {
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    // Transformation 1: MOV AX, immediate (null-free 16-bit load)
    if (insn->id == X86_INS_MOV) {
        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        if (dst->type == X86_OP_REG && src->type == X86_OP_IMM) {
            if (dst->reg == X86_REG_AX) {
                uint16_t imm = (uint16_t)src->imm;
                uint8_t low_byte = imm & 0xFF;
                uint8_t high_byte = (imm >> 8) & 0xFF;

                // Strategy: Construct AX byte-by-byte to avoid null encoding

                if (low_byte == 0 && high_byte == 0) {
                    // XOR AX, AX (null-free zeroing)
                    uint8_t xor_ax[] = {0x31, 0xC0}; // XOR EAX, EAX (zeros AX too)
                    buffer_append(b, xor_ax, 2);
                } else if (low_byte != 0 && high_byte == 0) {
                    // Only low byte set: XOR AX, AX + MOV AL, low_byte
                    uint8_t xor_ax[] = {0x31, 0xC0}; // XOR EAX, EAX
                    buffer_append(b, xor_ax, 2);

                    uint8_t mov_al[] = {0xB0, low_byte}; // MOV AL, imm8
                    buffer_append(b, mov_al, 2);
                } else if (low_byte == 0 && high_byte != 0) {
                    // Only high byte set: XOR AX, AX + MOV AH, high_byte
                    uint8_t xor_ax[] = {0x31, 0xC0}; // XOR EAX, EAX
                    buffer_append(b, xor_ax, 2);

                    uint8_t mov_ah[] = {0xB4, high_byte}; // MOV AH, imm8
                    buffer_append(b, mov_ah, 2);
                } else {
                    // Both bytes set: MOV AL, low + MOV AH, high
                    uint8_t mov_al[] = {0xB0, low_byte}; // MOV AL, imm8
                    buffer_append(b, mov_al, 2);

                    uint8_t mov_ah[] = {0xB4, high_byte}; // MOV AH, imm8
                    buffer_append(b, mov_ah, 2);
                }
                return;
            }
        }

        // MOV EDI, ESP (or similar register moves) - typically null-free
        if (dst->type == X86_OP_REG && src->type == X86_OP_REG) {
            if ((dst->reg == X86_REG_EDI || dst->reg == X86_REG_RDI) &&
                (src->reg == X86_REG_ESP || src->reg == X86_REG_RSP)) {
                // Check if original encoding has nulls
                if (has_null_bytes(insn)) {
                    // Generate null-free MOV EDI, ESP
                    uint8_t mov_edi_esp[] = {0x89, 0xE7}; // MOV EDI, ESP (null-free)
                    buffer_append(b, mov_edi_esp, 2);
                    return;
                }
            }
        }
    }

    // Transformation 2: STOSW - keep as-is (0xAB is null-free)
    if (insn->id == X86_INS_STOSW) {
        uint8_t stosw[] = {0xAB}; // STOSW opcode
        buffer_append(b, stosw, 1);
        return;
    }

    // Transformation 3: SUB ESP, immediate (null-free stack allocation)
    if (insn->id == X86_INS_SUB) {
        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        if (dst->type == X86_OP_REG && src->type == X86_OP_IMM) {
            if (dst->reg == X86_REG_ESP || dst->reg == X86_REG_RSP) {
                uint32_t imm = (uint32_t)src->imm;

                if (is_null_free(imm)) {
                    // Direct encoding if null-free
                    if (imm <= 0x7F) {
                        // SUB ESP, imm8 (3 bytes: 83 EC imm8)
                        uint8_t sub_esp_imm8[] = {0x83, 0xEC, (uint8_t)imm};
                        buffer_append(b, sub_esp_imm8, 3);
                    } else {
                        // SUB ESP, imm32 (6 bytes: 81 EC imm32)
                        uint8_t sub_esp_imm32[] = {0x81, 0xEC, 0, 0, 0, 0};
                        memcpy(sub_esp_imm32 + 2, &imm, 4);
                        buffer_append(b, sub_esp_imm32, 6);
                    }
                } else {
                    // Null-containing immediate: use register-based approach
                    // PUSH EAX (save)
                    uint8_t push_eax[] = {0x50};
                    buffer_append(b, push_eax, 1);

                    // MOV EAX, imm (null-free via generate_mov_eax_imm)
                    generate_mov_eax_imm(b, imm);

                    // SUB ESP, EAX
                    uint8_t sub_esp_eax[] = {0x29, 0xC4}; // SUB ESP, EAX
                    buffer_append(b, sub_esp_eax, 2);

                    // POP EAX (restore)
                    uint8_t pop_eax[] = {0x58};
                    buffer_append(b, pop_eax, 1);
                }
                return;
            }
        }
    }

    // Transformation 4: PUSH immediate (null-free ASCII chunk for Unicode conversion)
    if (insn->id == X86_INS_PUSH) {
        cs_x86_op *op = &insn->detail->x86.operands[0];

        if (op->type == X86_OP_IMM) {
            uint32_t imm = (uint32_t)op->imm;

            if (!is_null_free(imm)) {
                // Transform to: MOV EAX, imm (null-free) + PUSH EAX
                generate_mov_eax_imm(b, imm);

                uint8_t push_eax[] = {0x50}; // PUSH EAX
                buffer_append(b, push_eax, 1);
                return;
            }
        }
    }

    // Default: copy original instruction if already null-free or unhandled
    buffer_append(b, insn->bytes, insn->size);
}

/*
 * Strategy A: Byte-by-Byte Unicode Construction Strategy (STOSW-based)
 * Priority: 93 - Very high priority for explicit Unicode/STOSW sequences
 * Must be higher than ROR13 (90) to handle MOV AX properly
 */
static strategy_t unicode_stosw_strategy = {
    .name = "Unicode STOSW Byte-by-Byte Construction",
    .can_handle = can_handle_unicode_string,
    .get_size = get_size_unicode_string,
    .generate = generate_unicode_string,
    .priority = 93  // Very high priority for direct Unicode construction
};

/*
 * Strategy B: ASCII-to-Unicode Conversion Strategy
 * Priority: 89 - High priority for ASCII chunk transformations
 *
 * Note: This uses the same handlers as Strategy A since detection is unified,
 * but with slightly lower priority to prefer STOSW when both are applicable.
 */
static strategy_t unicode_ascii_conversion_strategy = {
    .name = "Unicode ASCII-to-Unicode Conversion",
    .can_handle = can_handle_unicode_string,
    .get_size = get_size_unicode_string,
    .generate = generate_unicode_string,
    .priority = 89  // High for ASCII-based Unicode setup
};

/*
 * Registration function to add Unicode string strategies to the registry
 * This is called from init_strategies() in strategy_registry.c
 */
void register_unicode_string_strategies() {
    // Register both strategies with different priorities
    register_strategy(&unicode_stosw_strategy);
    register_strategy(&unicode_ascii_conversion_strategy);
}
