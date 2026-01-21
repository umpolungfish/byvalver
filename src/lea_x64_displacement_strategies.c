/**
 * LEA x64 Displacement Null-Byte Elimination Strategies
 *
 * Handles: lea rbp, [rsp+0x80] and similar LEA instructions where
 * the displacement contains null bytes.
 *
 * x64-specific strategy file (v4.2)
 *
 * Common patterns:
 * - LEA RBP, [RSP+0x80] (48 8D 6C 24 80 - disp8 but patterns with disp32)
 * - LEA RAX, [RIP+0x00001000] (RIP-relative with null in displacement)
 * - LEA R12, [R13+0x00000100]
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// ============================================================================
// STRATEGY 1: LEA with Null-Byte Displacement
// ============================================================================
// Handles: lea reg, [base + disp] where disp contains null bytes
// Transformation: Use MOV + ADD to construct the address
//
// Example:
//   Original: LEA RBP, [RSP+0x100]  ; displacement may have null
//   Transformed:
//     MOV RBP, RSP                  ; Copy base
//     ADD RBP, <null-free disp>     ; Add displacement (constructed)

static int can_handle_lea_disp_null(cs_insn *insn) {
    // Only handle LEA instructions
    if (insn->id != X86_INS_LEA) {
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

    // First operand must be a 64-bit register
    if (op0->type != X86_OP_REG) {
        return 0;
    }

    if (!is_64bit_register(op0->reg)) {
        return 0;
    }

    // Second operand must be memory
    if (op1->type != X86_OP_MEM) {
        return 0;
    }

    // Check for RIP-relative (handled separately)
    if (op1->mem.base == X86_REG_RIP) {
        return 0;  // Handled by RIP-relative strategy
    }

    // Must have a displacement
    if (op1->mem.disp == 0) {
        return 0;
    }

    // Check if displacement contains null bytes
    uint32_t disp32 = (uint32_t)op1->mem.disp;
    return !is_bad_byte_free(disp32);
}

static size_t get_size_lea_disp_null(cs_insn *insn) {
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    // Base cases:
    // MOV dst, base (3 bytes with REX)
    // ADD dst, disp (constructed, up to 15 bytes)
    // If has index: additional complexity

    if (op1->mem.index != X86_REG_INVALID) {
        // Complex: MOV + LEA for scale + ADD
        return 25;
    }

    return 20;
}

static void generate_lea_disp_null(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    x86_reg dst_reg = op0->reg;
    x86_reg base = op1->mem.base;
    x86_reg index = op1->mem.index;
    int64_t disp = op1->mem.disp;
    uint8_t scale = op1->mem.scale;

    int dst_ext = is_extended_register(dst_reg);
    uint8_t dst_idx = get_reg_index(dst_reg);

    // Case 1: Simple [base + disp] without index
    if (index == X86_REG_INVALID && base != X86_REG_INVALID) {
        int base_ext = is_extended_register(base);
        uint8_t base_idx = get_reg_index(base);

        // MOV dst, base
        uint8_t rex = 0x48;  // REX.W
        if (dst_ext) rex |= 0x04;  // REX.R
        if (base_ext) rex |= 0x01;  // REX.B
        buffer_write_byte(b, rex);
        buffer_write_byte(b, 0x89);  // MOV r/m64, r64
        buffer_write_byte(b, 0xC0 | (base_idx << 3) | dst_idx);

        // ADD dst, disp (with null-free encoding)
        uint32_t disp32 = (uint32_t)disp;

        if (is_bad_byte_free(disp32)) {
            // Direct ADD dst, imm32
            rex = 0x48;
            if (dst_ext) rex |= 0x01;
            buffer_write_byte(b, rex);
            buffer_write_byte(b, 0x81);  // ADD r/m64, imm32
            buffer_write_byte(b, 0xC0 | dst_idx);  // /0 for ADD
            buffer_write_dword(b, disp32);
        } else {
            // Need to construct disp without nulls
            // Try XOR encoding
            uint32_t xor_keys[] = {0x01010101, 0x11111111, 0x41414141, 0xFFFFFFFF};
            int found = 0;

            for (size_t i = 0; i < sizeof(xor_keys) / sizeof(xor_keys[0]); i++) {
                uint32_t encoded = disp32 ^ xor_keys[i];
                if (is_bad_byte_free(encoded) && is_bad_byte_free(xor_keys[i])) {
                    // Use temp register approach
                    // PUSH RCX
                    buffer_write_byte(b, 0x51);

                    // MOV RCX, encoded
                    uint8_t mov_rex = 0x48;
                    buffer_write_byte(b, mov_rex);
                    buffer_write_byte(b, 0xC7);
                    buffer_write_byte(b, 0xC1);  // RCX
                    buffer_write_dword(b, encoded);

                    // XOR RCX, key
                    buffer_write_byte(b, 0x48);
                    buffer_write_byte(b, 0x81);
                    buffer_write_byte(b, 0xF1);  // /6 for XOR with RCX
                    buffer_write_dword(b, xor_keys[i]);

                    // ADD dst, RCX
                    rex = 0x48;
                    if (dst_ext) rex |= 0x04;
                    buffer_write_byte(b, rex);
                    buffer_write_byte(b, 0x01);  // ADD r/m64, r64
                    buffer_write_byte(b, 0xC0 | (0x01 << 3) | dst_idx);  // RCX to dst

                    // POP RCX
                    buffer_write_byte(b, 0x59);

                    found = 1;
                    break;
                }
            }

            if (!found) {
                // Fallback: byte-by-byte construction in temp
                buffer_write_byte(b, 0x51);  // PUSH RCX

                // XOR RCX, RCX
                buffer_write_byte(b, 0x48);
                buffer_write_byte(b, 0x31);
                buffer_write_byte(b, 0xC9);

                // Build displacement byte by byte
                for (int i = 3; i >= 0; i--) {
                    uint8_t byte_val = (disp32 >> (i * 8)) & 0xFF;
                    if (byte_val != 0 || i < 3) {
                        // SHL RCX, 8
                        if (i < 3) {
                            buffer_write_byte(b, 0x48);
                            buffer_write_byte(b, 0xC1);
                            buffer_write_byte(b, 0xE1);
                            buffer_write_byte(b, 0x08);
                        }

                        if (byte_val != 0) {
                            if (is_bad_byte_free_byte(byte_val)) {
                                // OR CL, byte_val
                                buffer_write_byte(b, 0x80);
                                buffer_write_byte(b, 0xC9);
                                buffer_write_byte(b, byte_val);
                            } else {
                                // ADD CL with split values
                                for (uint8_t base_val = 1; base_val < byte_val; base_val++) {
                                    if (!is_bad_byte_free_byte(base_val)) continue;
                                    uint8_t offset = byte_val - base_val;
                                    if (is_bad_byte_free_byte(offset)) {
                                        buffer_write_byte(b, 0x80);
                                        buffer_write_byte(b, 0xC1);
                                        buffer_write_byte(b, base_val);
                                        buffer_write_byte(b, 0x80);
                                        buffer_write_byte(b, 0xC1);
                                        buffer_write_byte(b, offset);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                // ADD dst, RCX
                rex = 0x48;
                if (dst_ext) rex |= 0x04;
                buffer_write_byte(b, rex);
                buffer_write_byte(b, 0x01);
                buffer_write_byte(b, 0xC0 | (0x01 << 3) | dst_idx);

                buffer_write_byte(b, 0x59);  // POP RCX
            }
        }

        return;
    }

    // Case 2: [base + index*scale + disp] - more complex
    if (index != X86_REG_INVALID && base != X86_REG_INVALID) {
        int base_ext = is_extended_register(base);
        int index_ext = is_extended_register(index);
        uint8_t base_idx = get_reg_index(base);
        uint8_t index_idx = get_reg_index(index);

        // Strategy: Calculate base + index*scale first, then add disp
        // LEA dst, [base + index*scale] (should be null-free if disp was the issue)
        // ADD dst, disp (constructed)

        // LEA dst, [base + index*scale]
        uint8_t rex = 0x48;
        if (dst_ext) rex |= 0x04;
        if (index_ext) rex |= 0x02;
        if (base_ext) rex |= 0x01;
        buffer_write_byte(b, rex);
        buffer_write_byte(b, 0x8D);  // LEA

        // ModR/M + SIB for [base + index*scale]
        uint8_t modrm = (dst_idx << 3) | 0x04;  // SIB follows
        buffer_write_byte(b, modrm);

        // SIB byte: scale | index | base
        uint8_t scale_bits = 0;
        switch (scale) {
            case 1: scale_bits = 0; break;
            case 2: scale_bits = 1; break;
            case 4: scale_bits = 2; break;
            case 8: scale_bits = 3; break;
            default: scale_bits = 0; break;
        }
        uint8_t sib = (scale_bits << 6) | ((index_idx & 0x07) << 3) | (base_idx & 0x07);
        buffer_write_byte(b, sib);

        // Handle RBP/R13 base (needs disp8)
        if ((base_idx & 0x07) == 5) {
            buffer_write_byte(b, 0x00);  // disp8 = 0
        }

        // Now ADD dst, disp
        uint32_t disp32 = (uint32_t)disp;
        if (is_bad_byte_free(disp32)) {
            rex = 0x48;
            if (dst_ext) rex |= 0x01;
            buffer_write_byte(b, rex);
            buffer_write_byte(b, 0x81);
            buffer_write_byte(b, 0xC0 | dst_idx);
            buffer_write_dword(b, disp32);
        } else {
            // Use temp register for disp construction
            buffer_write_byte(b, 0x51);  // PUSH RCX
            generate_mov_eax_imm(b, disp32);  // Construct in EAX
            // MOV RCX, RAX (zero-extend)
            buffer_write_byte(b, 0x48);
            buffer_write_byte(b, 0x89);
            buffer_write_byte(b, 0xC1);

            // ADD dst, RCX
            rex = 0x48;
            if (dst_ext) rex |= 0x04;
            buffer_write_byte(b, rex);
            buffer_write_byte(b, 0x01);
            buffer_write_byte(b, 0xC0 | (0x01 << 3) | dst_idx);

            buffer_write_byte(b, 0x59);  // POP RCX
        }

        return;
    }

    // Fallback: copy original
    buffer_append(b, insn->bytes, insn->size);
}

strategy_t lea_x64_disp_null_free_strategy = {
    .name = "lea_x64_disp_null_free",
    .can_handle = can_handle_lea_disp_null,
    .get_size = get_size_lea_disp_null,
    .generate = generate_lea_disp_null,
    .priority = 87,
    .target_arch = BYVAL_ARCH_X64
};

// ============================================================================
// STRATEGY 2: LEA RIP-Relative with Null Displacement
// ============================================================================
// Handles: lea reg, [rip + disp32] where disp32 contains null bytes
// This is tricky because RIP-relative needs precise offset calculation

static int can_handle_lea_rip_null(cs_insn *insn) {
    if (insn->id != X86_INS_LEA) {
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

    if (op0->type != X86_OP_REG || !is_64bit_register(op0->reg)) {
        return 0;
    }

    if (op1->type != X86_OP_MEM) {
        return 0;
    }

    // Check for RIP-relative
    return (op1->mem.base == X86_REG_RIP);
}

static size_t get_size_lea_rip_null(cs_insn *insn) {
    (void)insn;
    // Worst case: construct absolute address
    // MOV dst, imm64 (up to 20 bytes with construction)
    return 25;
}

static void generate_lea_rip_null(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    x86_reg dst_reg = op0->reg;
    int64_t disp = op1->mem.disp;

    // Calculate the absolute target address
    // The RIP value at time of execution would be insn->address + insn->size
    // Target = RIP + disp = (insn->address + insn->size) + disp
    uint64_t target_addr = insn->address + insn->size + disp;

    // Generate MOVABS dst, target_addr
    generate_mov_reg_imm64(b, dst_reg, target_addr);
}

strategy_t lea_rip_null_free_strategy = {
    .name = "lea_rip_null_free",
    .can_handle = can_handle_lea_rip_null,
    .get_size = get_size_lea_rip_null,
    .generate = generate_lea_rip_null,
    .priority = 86,
    .target_arch = BYVAL_ARCH_X64
};

// ============================================================================
// Registration Function
// ============================================================================

void register_lea_x64_displacement_strategies() {
    register_strategy(&lea_x64_disp_null_free_strategy);
    register_strategy(&lea_rip_null_free_strategy);
}
