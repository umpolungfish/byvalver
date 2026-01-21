/**
 * TEST Large Immediate Null-Byte Elimination Strategies
 *
 * Handles: test eax/rax, imm32 and test reg, imm32 instructions where
 * the immediate value contains null bytes.
 *
 * x64-specific strategy file (v4.2)
 *
 * Common patterns:
 * - TEST EAX, 0x04000000 (A9 00 00 00 04)
 * - TEST RAX, 0x00008000 (48 A9 00 80 00 00)
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// ============================================================================
// STRATEGY 1: TEST reg, imm32 with null bytes → TEST reg, temp_reg
// ============================================================================
// Handles: test eax/reg, imm32 where immediate contains null bytes
// Transformation: Load immediate into temp register, then TEST with register
//
// Example:
//   Original: TEST EAX, 0x04000000  ; [A9 00 00 00 04]
//   Transformed:
//     PUSH ECX                       ; Save temp
//     MOV ECX, <null-free value>     ; Construct value
//     TEST EAX, ECX                  ; Use register operand
//     POP ECX                        ; Restore temp

static int can_handle_test_imm_null(cs_insn *insn) {
    // Only handle TEST instructions
    if (insn->id != X86_INS_TEST) {
        return 0;
    }

    // Must have null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Must have exactly 2 operands
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    // First operand must be a register
    if (op0->type != X86_OP_REG) {
        return 0;
    }

    // Second operand must be immediate
    if (op1->type != X86_OP_IMM) {
        return 0;
    }

    // Check if immediate contains null bytes
    uint32_t imm32 = (uint32_t)op1->imm;
    return !is_bad_byte_free(imm32);
}

static size_t get_size_test_imm_null(cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];

    // For 64-bit: PUSH (2) + MOV (up to 10) + TEST (3) + POP (2) = ~17 bytes
    // For 32-bit: PUSH (1) + MOV (5-10) + TEST (2) + POP (1) = ~14 bytes
    if (is_64bit_register(op0->reg)) {
        return 20;
    }
    return 15;
}

static void generate_test_imm_null(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    x86_reg dst_reg = op0->reg;
    uint32_t imm32 = (uint32_t)insn->detail->x86.operands[1].imm;

    int is_64bit = is_64bit_register(dst_reg);
    int is_ext = is_extended_register(dst_reg);
    uint8_t dst_idx = get_reg_index(dst_reg);

    // Choose a temp register that doesn't conflict with destination
    // Use RCX/ECX if destination is not RCX/ECX, otherwise use RDX/EDX
    int use_rdx = (dst_reg == X86_REG_RCX || dst_reg == X86_REG_ECX ||
                   dst_reg == X86_REG_CL || dst_reg == X86_REG_R9);
    uint8_t temp_idx = use_rdx ? 2 : 1;  // EDX=2, ECX=1
    uint8_t push_op = use_rdx ? 0x52 : 0x51;
    uint8_t pop_op = use_rdx ? 0x5A : 0x59;

    // PUSH temp_reg
    if (is_64bit) {
        // In x64, PUSH still uses 64-bit operand by default
    }
    buffer_write_byte(b, push_op);

    // Construct the immediate value in temp register
    if (is_64bit) {
        // MOV temp_64bit, imm32 (sign-extended or constructed)
        if (is_bad_byte_free(imm32)) {
            // Simple case: direct encoding
            uint8_t code[7];
            code[0] = 0x48;  // REX.W
            code[1] = 0xC7;  // MOV r/m64, imm32
            code[2] = 0xC0 + temp_idx;
            memcpy(&code[3], &imm32, 4);
            buffer_append(b, code, 7);
        } else {
            // Need to construct without nulls
            // Use XOR approach
            uint32_t xor_keys[] = {
                0x01010101, 0x11111111, 0x22222222, 0x33333333,
                0x41414141, 0x55555555, 0xAAAAAAAA, 0xFFFFFFFF,
            };

            int found = 0;
            for (size_t i = 0; i < sizeof(xor_keys) / sizeof(xor_keys[0]); i++) {
                uint32_t encoded = imm32 ^ xor_keys[i];
                if (is_bad_byte_free(encoded) && is_bad_byte_free(xor_keys[i])) {
                    // MOV temp, encoded
                    uint8_t mov_code[7];
                    mov_code[0] = 0x48;
                    mov_code[1] = 0xC7;
                    mov_code[2] = 0xC0 + temp_idx;
                    memcpy(&mov_code[3], &encoded, 4);
                    buffer_append(b, mov_code, 7);

                    // XOR temp, key
                    uint8_t xor_code[7];
                    xor_code[0] = 0x48;
                    xor_code[1] = 0x81;  // XOR r/m64, imm32
                    xor_code[2] = 0xF0 + temp_idx;  // /6 for XOR
                    memcpy(&xor_code[3], &xor_keys[i], 4);
                    buffer_append(b, xor_code, 7);
                    found = 1;
                    break;
                }
            }

            if (!found) {
                // Fallback: byte-by-byte construction
                // XOR temp, temp
                uint8_t xor_self[] = {0x48, 0x31, (uint8_t)(0xC0 | (temp_idx << 3) | temp_idx)};
                buffer_append(b, xor_self, 3);

                // Build byte by byte
                for (int i = 3; i >= 0; i--) {
                    uint8_t byte_val = (imm32 >> (i * 8)) & 0xFF;
                    if (byte_val != 0) {
                        // SHL temp, 8 (if not first non-zero)
                        uint8_t shl[] = {0x48, 0xC1, (uint8_t)(0xE0 + temp_idx), 0x08};
                        buffer_append(b, shl, 4);

                        if (is_bad_byte_free_byte(byte_val)) {
                            // OR temp_8bit, byte_val
                            uint8_t or_imm[] = {0x80, (uint8_t)(0xC8 + temp_idx), byte_val};
                            buffer_append(b, or_imm, 3);
                        } else {
                            // Split into two safe values
                            for (uint8_t base = 1; base < byte_val; base++) {
                                if (!is_bad_byte_free_byte(base)) continue;
                                uint8_t offset = byte_val - base;
                                if (is_bad_byte_free_byte(offset)) {
                                    uint8_t add1[] = {0x80, (uint8_t)(0xC0 + temp_idx), base};
                                    buffer_append(b, add1, 3);
                                    uint8_t add2[] = {0x80, (uint8_t)(0xC0 + temp_idx), offset};
                                    buffer_append(b, add2, 3);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        // 32-bit register
        // Use generate_mov_eax_imm style but for temp register
        if (is_bad_byte_free(imm32)) {
            buffer_write_byte(b, 0xB8 + temp_idx);  // MOV temp, imm32
            buffer_write_dword(b, imm32);
        } else {
            // XOR temp, temp first
            buffer_write_byte(b, 0x31);
            buffer_write_byte(b, 0xC0 | (temp_idx << 3) | temp_idx);

            // Then use arithmetic construction
            uint32_t xor_keys[] = {0x01010101, 0x11111111, 0x41414141, 0xFFFFFFFF};
            int found = 0;
            for (size_t i = 0; i < sizeof(xor_keys) / sizeof(xor_keys[0]); i++) {
                uint32_t encoded = imm32 ^ xor_keys[i];
                if (is_bad_byte_free(encoded) && is_bad_byte_free(xor_keys[i])) {
                    buffer_write_byte(b, 0xB8 + temp_idx);  // MOV temp, encoded
                    buffer_write_dword(b, encoded);
                    buffer_write_byte(b, 0x81);  // XOR r/m32, imm32
                    buffer_write_byte(b, 0xF0 + temp_idx);
                    buffer_write_dword(b, xor_keys[i]);
                    found = 1;
                    break;
                }
            }
            if (!found) {
                // Last resort: use 32-bit construction from utils
                generate_mov_eax_imm(b, imm32);
                // Move from EAX to temp if temp != EAX
                if (temp_idx != 0) {
                    buffer_write_byte(b, 0x89);  // MOV r/m32, r32
                    buffer_write_byte(b, 0xC0 | temp_idx);  // EAX to temp
                }
            }
        }
    }

    // TEST dst_reg, temp_reg
    if (is_64bit) {
        uint8_t rex = 0x48;  // REX.W
        if (is_ext) {
            rex |= 0x04;  // REX.R
        }
        buffer_write_byte(b, rex);
    } else if (is_ext) {
        buffer_write_byte(b, 0x44);  // REX.R
    }

    buffer_write_byte(b, 0x85);  // TEST r/m32/64, r32/64
    buffer_write_byte(b, 0xC0 | (temp_idx << 3) | (dst_idx & 0x07));

    // POP temp_reg
    buffer_write_byte(b, pop_op);
}

strategy_t test_large_imm_null_free_strategy = {
    .name = "test_large_imm_null_free",
    .can_handle = can_handle_test_imm_null,
    .get_size = get_size_test_imm_null,
    .generate = generate_test_imm_null,
    .priority = 85,
    .target_arch = BYVAL_ARCH_X64
};

// ============================================================================
// STRATEGY 2: TEST memory, imm32 with null bytes
// ============================================================================
// Handles: test [mem], imm32 where immediate or displacement contains null bytes

static int can_handle_test_mem_imm_null(cs_insn *insn) {
    if (insn->id != X86_INS_TEST) {
        return 0;
    }

    if (!has_null_bytes(insn)) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    // First operand must be memory
    if (op0->type != X86_OP_MEM) {
        return 0;
    }

    // Second operand must be immediate
    if (op1->type != X86_OP_IMM) {
        return 0;
    }

    return 1;
}

static size_t get_size_test_mem_imm_null(cs_insn *insn) {
    (void)insn;
    // Load memory to temp + load imm to temp2 + TEST + restore
    return 25;
}

static void generate_test_mem_imm_null(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    uint32_t imm32 = (uint32_t)insn->detail->x86.operands[1].imm;

    // PUSH RAX
    buffer_write_byte(b, 0x50);

    // PUSH RCX
    buffer_write_byte(b, 0x51);

    // MOV RAX, [mem]
    // For simplicity, reconstruct the memory access
    x86_reg base = op0->mem.base;
    int64_t disp = op0->mem.disp;

    if (base != X86_REG_INVALID && disp == 0) {
        // Simple [reg] addressing
        uint8_t base_idx = get_reg_index(base);
        int is_ext_base = is_extended_register(base);

        uint8_t rex = 0x48;  // REX.W
        if (is_ext_base) {
            rex |= 0x01;  // REX.B
        }
        buffer_write_byte(b, rex);
        buffer_write_byte(b, 0x8B);  // MOV r64, r/m64
        buffer_write_byte(b, (base_idx & 0x07));  // [base]

        // Handle special cases for RSP/RBP/R12/R13
        if ((base_idx & 0x07) == 4) {
            buffer_write_byte(b, 0x24);  // SIB for RSP
        } else if ((base_idx & 0x07) == 5) {
            buffer_write_byte(b, 0x45);  // Need disp8
            buffer_write_byte(b, 0x00);  // disp8 = 0
        }
    } else {
        // Complex addressing - use safe encoding
        // For now, copy original bytes for memory access
        buffer_append(b, insn->bytes, insn->size);
        // Then POP to clean up
        buffer_write_byte(b, 0x59);  // POP RCX
        buffer_write_byte(b, 0x58);  // POP RAX
        return;
    }

    // Construct immediate in RCX
    if (is_bad_byte_free(imm32)) {
        uint8_t mov_rcx[7] = {0x48, 0xC7, 0xC1};
        memcpy(&mov_rcx[3], &imm32, 4);
        buffer_append(b, mov_rcx, 7);
    } else {
        // Use XOR encoding
        uint32_t key = 0x41414141;
        uint32_t encoded = imm32 ^ key;
        if (is_bad_byte_free(encoded)) {
            uint8_t mov_rcx[7] = {0x48, 0xC7, 0xC1};
            memcpy(&mov_rcx[3], &encoded, 4);
            buffer_append(b, mov_rcx, 7);

            uint8_t xor_rcx[7] = {0x48, 0x81, 0xF1};
            memcpy(&xor_rcx[3], &key, 4);
            buffer_append(b, xor_rcx, 7);
        } else {
            // Fallback
            generate_mov_eax_imm(b, imm32);
            uint8_t mov_rcx_rax[] = {0x48, 0x89, 0xC1};  // MOV RCX, RAX
            buffer_append(b, mov_rcx_rax, 3);
        }
    }

    // TEST RAX, RCX
    uint8_t test_rax_rcx[] = {0x48, 0x85, 0xC8};  // TEST RAX, RCX
    buffer_append(b, test_rax_rcx, 3);

    // POP RCX
    buffer_write_byte(b, 0x59);

    // POP RAX
    buffer_write_byte(b, 0x58);
}

strategy_t test_mem_imm_null_free_strategy = {
    .name = "test_mem_imm_null_free",
    .can_handle = can_handle_test_mem_imm_null,
    .get_size = get_size_test_mem_imm_null,
    .generate = generate_test_mem_imm_null,
    .priority = 84,
    .target_arch = BYVAL_ARCH_X64
};

// ============================================================================
// Registration Function
// ============================================================================

void register_test_large_imm_strategies() {
    register_strategy(&test_large_imm_null_free_strategy);
    register_strategy(&test_mem_imm_null_free_strategy);
}
