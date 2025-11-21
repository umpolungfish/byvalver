#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * ADC (Add with Carry) Null-Byte Elimination Strategies
 *
 * ADC is a flag-dependent instruction that adds two operands plus the carry flag (CF).
 * Common in multi-precision arithmetic (64-bit math on 32-bit systems).
 *
 * Critical Constraint: Must preserve CF state from previous operations
 *
 * Null-byte patterns addressed:
 * 1. ModR/M null byte (e.g., ADC EAX, [EAX] -> 0x11 0x00)
 * 2. Immediate with null bytes (e.g., ADC EAX, 0x00000100 -> 0x15 0x00 0x00 0x01 0x00)
 */

// ============================================================================
// STRATEGY 1: ADC ModR/M Null-Byte Bypass
// ============================================================================
// Handles: ADC reg, [mem] and ADC [mem], reg where ModR/M byte is 0x00
// Transformation: Use temporary register to avoid null ModR/M
//
// Example:
//   Original: ADC EAX, [EAX]  ; [11 00]
//   Transformed:
//     PUSH EBX                ; Save temp register
//     MOV EBX, EAX           ; Copy address to temp
//     ADC EAX, [EBX]         ; Use non-null ModR/M
//     POP EBX                ; Restore temp register

static int can_handle_adc_modrm_null(cs_insn *insn) {
    // Only handle ADC instructions
    if (insn->id != X86_INS_ADC) {
        return 0;
    }

    // Must have null bytes in encoding
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Must have exactly 2 operands
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    // Check for patterns: reg, [mem] or [mem], reg
    int pattern1 = (op0->type == X86_OP_REG && op1->type == X86_OP_MEM);
    int pattern2 = (op0->type == X86_OP_MEM && op1->type == X86_OP_REG);

    if (!pattern1 && !pattern2) {
        return 0;
    }

    // Check if ModR/M byte would be null (0x00)
    // This happens when addressing mode is [EAX] (ModR/M = 0x00)
    cs_x86_op *mem_op = (op0->type == X86_OP_MEM) ? op0 : op1;

    // [EAX] with no displacement creates ModR/M 0x00
    if (mem_op->mem.base == X86_REG_EAX &&
        mem_op->mem.index == X86_REG_INVALID &&
        mem_op->mem.disp == 0) {
        return 1;
    }

    return 0;
}

static size_t get_size_adc_modrm_null(cs_insn *insn) {
    // PUSH EBX (1) + MOV EBX, src_reg (2) + ADC with new ModR/M (2-6) + POP EBX (1)
    // Conservative estimate: 1 + 2 + 6 + 1 = 10 bytes
    (void)insn;
    return 10;
}

static void generate_adc_modrm_null(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    // Determine which operand is register and which is memory
    x86_reg reg_operand;
    cs_x86_op *mem_op;
    int reg_is_dest;

    if (op0->type == X86_OP_REG && op1->type == X86_OP_MEM) {
        // ADC reg, [mem]
        reg_operand = op0->reg;
        mem_op = op1;
        reg_is_dest = 1;
    } else {
        // ADC [mem], reg
        reg_operand = op1->reg;
        mem_op = op0;
        reg_is_dest = 0;
    }

    // PUSH EBX - Save temporary register
    buffer_write_byte(b, 0x53); // PUSH EBX

    // MOV EBX, [mem].base - Copy the address register to temp
    if (mem_op->mem.base == X86_REG_EAX) {
        buffer_write_byte(b, 0x89); // MOV r/m32, r32
        buffer_write_byte(b, 0xC3); // ModR/M: EBX, EAX
    }

    // ADC with new addressing using EBX instead of EAX
    if (reg_is_dest) {
        // ADC reg, [EBX]
        buffer_write_byte(b, 0x13); // ADC r32, r/m32

        // Calculate ModR/M for [EBX] addressing
        uint8_t reg_code = (reg_operand - X86_REG_EAX) & 0x07;
        uint8_t modrm = (reg_code << 3) | 0x03; // [EBX] = 0x03
        buffer_write_byte(b, modrm);
    } else {
        // ADC [EBX], reg
        buffer_write_byte(b, 0x11); // ADC r/m32, r32

        uint8_t reg_code = (reg_operand - X86_REG_EAX) & 0x07;
        uint8_t modrm = (reg_code << 3) | 0x03; // [EBX] = 0x03
        buffer_write_byte(b, modrm);
    }

    // POP EBX - Restore temporary register
    buffer_write_byte(b, 0x5B); // POP EBX
}

strategy_t adc_modrm_null_bypass_strategy = {
    .name = "adc_modrm_null_bypass",
    .can_handle = can_handle_adc_modrm_null,
    .get_size = get_size_adc_modrm_null,
    .generate = generate_adc_modrm_null,
    .priority = 70
};

// ============================================================================
// STRATEGY 2: ADC Immediate Null Handling
// ============================================================================
// Handles: ADC reg, imm32 where immediate contains null bytes
// Transformation: Load immediate into temp register, then ADC with register
//
// Example:
//   Original: ADC EAX, 0x00000100  ; [15 00 00 01 00]
//   Transformed:
//     PUSH EBX                      ; Save temp
//     MOV EBX, <null-free value>    ; Construct 0x00000100 without nulls
//     ADC EAX, EBX                  ; Use register operand
//     POP EBX                       ; Restore temp

static int can_handle_adc_immediate_null(cs_insn *insn) {
    // Only handle ADC instructions
    if (insn->id != X86_INS_ADC) {
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

    // First operand must be register
    if (op0->type != X86_OP_REG) {
        return 0;
    }

    // Second operand must be immediate
    if (op1->type != X86_OP_IMM) {
        return 0;
    }

    // Check if immediate contains null bytes
    uint32_t imm = (uint32_t)op1->imm;
    return !is_null_free(imm);
}

static size_t get_size_adc_immediate_null(cs_insn *insn) {
    cs_x86_op *op1 = &insn->detail->x86.operands[1];
    uint32_t imm = (uint32_t)op1->imm;

    // PUSH EBX (1) + MOV EBX, imm32 (5) + ADC reg, EBX (2) + POP EBX (1)
    // For small immediates we might use shift-based construction
    // Conservative estimate: 15 bytes
    (void)imm;
    return 15;
}

static void generate_adc_immediate_null(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    x86_reg dst_reg = op0->reg;
    uint32_t imm = (uint32_t)op1->imm;

    // Use EBX as temporary register (avoid destination register)
    uint8_t temp_reg = 0x03; // EBX

    // PUSH EBX
    buffer_write_byte(b, 0x53);

    // Construct the immediate value in EBX using null-free techniques
    // Strategy: Use shift-based construction for power-of-2 related values
    // For 0x00000100: MOV EBX, 0x01010101; SHR EBX, 8

    // Simple approach for now: try to find a null-free equivalent
    // Check if we can use shift-based construction
    int shift_amount = 0;
    uint32_t base_val = imm;

    // Try to find shift amount that makes value null-free
    for (int i = 0; i < 32; i++) {
        uint32_t shifted = imm << i;
        if (is_null_free(shifted)) {
            base_val = shifted;
            shift_amount = i;
            break;
        }
        shifted = imm >> i;
        if (is_null_free(shifted) && shifted != 0) {
            base_val = shifted;
            shift_amount = -i;
            break;
        }
    }

    // MOV EBX, base_val (5 bytes if null-free)
    if (is_null_free(base_val)) {
        buffer_write_byte(b, 0xBB); // MOV EBX, imm32
        buffer_write_dword(b, base_val);

        // Apply shift if needed
        if (shift_amount > 0) {
            // SHL EBX, shift_amount
            if (shift_amount == 1) {
                buffer_write_byte(b, 0xD1);
                buffer_write_byte(b, 0xE3); // SHL EBX, 1
            } else {
                buffer_write_byte(b, 0xC1);
                buffer_write_byte(b, 0xE3); // SHL EBX
                buffer_write_byte(b, (uint8_t)shift_amount);
            }
        } else if (shift_amount < 0) {
            // SHR EBX, abs(shift_amount)
            int abs_shift = -shift_amount;
            if (abs_shift == 1) {
                buffer_write_byte(b, 0xD1);
                buffer_write_byte(b, 0xEB); // SHR EBX, 1
            } else {
                buffer_write_byte(b, 0xC1);
                buffer_write_byte(b, 0xEB); // SHR EBX
                buffer_write_byte(b, (uint8_t)abs_shift);
            }
        }
    } else {
        // Fallback: use byte-by-byte construction
        // XOR EBX, EBX
        buffer_write_byte(b, 0x31);
        buffer_write_byte(b, 0xDB);

        // Build value byte by byte
        for (int i = 0; i < 4; i++) {
            uint8_t byte = (imm >> (i * 8)) & 0xFF;
            if (byte != 0) {
                // SHL EBX, 8 (if not first byte)
                if (i > 0) {
                    buffer_write_byte(b, 0xC1);
                    buffer_write_byte(b, 0xE3);
                    buffer_write_byte(b, 0x08);
                }
                // OR BL, byte
                buffer_write_byte(b, 0x80);
                buffer_write_byte(b, 0xCB); // OR BL
                buffer_write_byte(b, byte);
            }
        }
    }

    // ADC dst_reg, EBX
    buffer_write_byte(b, 0x13); // ADC r32, r/m32
    uint8_t dst_code = (dst_reg - X86_REG_EAX) & 0x07;
    uint8_t modrm = 0xC0 | (dst_code << 3) | temp_reg; // reg, EBX
    buffer_write_byte(b, modrm);

    // POP EBX
    buffer_write_byte(b, 0x5B);
}

strategy_t adc_immediate_null_free_strategy = {
    .name = "adc_immediate_null_free",
    .can_handle = can_handle_adc_immediate_null,
    .get_size = get_size_adc_immediate_null,
    .generate = generate_adc_immediate_null,
    .priority = 69
};

// ============================================================================
// STRATEGY 3: ADC SIB+disp32 Null-Byte Bypass
// ============================================================================
// Handles: ADC with complex SIB addressing where disp32 contains nulls
// Example: ADC EAX, [EBX*8 + 0x1A] where disp32 = 0x0000001A (3 null bytes)
//
// Transformation:
//   Original: ADC EAX, [EBX*8 + 0x1A]  ; [13 04 DD 1A 00 00 00]
//   Transformed:
//     PUSH ECX                          ; Save temp
//     MOV ECX, EBX                     ; Copy index
//     SHL ECX, 3                       ; ECX = EBX * 8
//     PUSH EDX                          ; Save another temp
//     MOV EDX, <null-free 0x1A>        ; Construct displacement
//     ADD ECX, EDX                     ; ECX = EBX*8 + 0x1A
//     ADC EAX, [ECX]                   ; Use simple addressing
//     POP EDX
//     POP ECX

static int can_handle_adc_sib_disp32_null(cs_insn *insn) {
    if (insn->id != X86_INS_ADC) {
        return 0;
    }

    if (!has_null_bytes(insn)) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Find memory operand
    cs_x86_op *mem_op = NULL;
    if (insn->detail->x86.operands[0].type == X86_OP_MEM) {
        mem_op = &insn->detail->x86.operands[0];
    } else if (insn->detail->x86.operands[1].type == X86_OP_MEM) {
        mem_op = &insn->detail->x86.operands[1];
    } else {
        return 0;
    }

    // Check for SIB addressing with displacement containing nulls
    if (mem_op->mem.index != X86_REG_INVALID) {
        // Has index register (SIB present)
        int64_t disp = mem_op->mem.disp;
        if (disp != 0) {
            uint32_t disp_u32 = (uint32_t)disp;
            if (!is_null_free(disp_u32)) {
                return 1;  // SIB with null-containing disp32
            }
        }
    }

    return 0;
}

static size_t get_size_adc_sib_disp32_null(cs_insn *insn) {
    (void)insn;
    // PUSH ECX (1) + MOV ECX, index (2) + SHL ECX, scale (3) +
    // PUSH EDX (1) + MOV EDX, disp (5-15) + ADD ECX, EDX (2) +
    // ADC reg, [ECX] (2) + POP EDX (1) + POP ECX (1)
    // Conservative estimate: 30 bytes
    return 30;
}

static void generate_adc_sib_disp32_null(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    // Determine which operand is register and which is memory
    x86_reg reg_operand;
    cs_x86_op *mem_op;
    int reg_is_dest;

    if (op0->type == X86_OP_REG && op1->type == X86_OP_MEM) {
        // ADC reg, [mem]
        reg_operand = op0->reg;
        mem_op = op1;
        reg_is_dest = 1;
    } else {
        // ADC [mem], reg
        reg_operand = op1->reg;
        mem_op = op0;
        reg_is_dest = 0;
    }

    x86_reg index = mem_op->mem.index;
    int scale = mem_op->mem.scale;
    int64_t disp = mem_op->mem.disp;
    uint32_t disp_u32 = (uint32_t)disp;

    // PUSH ECX
    buffer_write_byte(b, 0x51);

    // MOV ECX, index
    buffer_write_byte(b, 0x89);
    uint8_t index_code = (index - X86_REG_EAX) & 0x07;
    uint8_t modrm = 0xC1 | (index_code << 3);  // MOV ECX, index
    buffer_write_byte(b, modrm);

    // SHL ECX, scale_bits (if scale > 1)
    if (scale > 1) {
        int scale_bits = 0;
        if (scale == 2) scale_bits = 1;
        else if (scale == 4) scale_bits = 2;
        else if (scale == 8) scale_bits = 3;

        if (scale_bits == 1) {
            // SHL ECX, 1
            buffer_write_byte(b, 0xD1);
            buffer_write_byte(b, 0xE1);
        } else {
            // SHL ECX, scale_bits
            buffer_write_byte(b, 0xC1);
            buffer_write_byte(b, 0xE1);
            buffer_write_byte(b, (uint8_t)scale_bits);
        }
    }

    // PUSH EDX
    buffer_write_byte(b, 0x52);

    // Construct displacement in EDX using null-free method
    // Try shift-based construction first
    int found_shift = 0;
    for (int i = 0; i < 24; i++) {
        uint32_t shifted = disp_u32 << i;
        if (is_null_free(shifted)) {
            // MOV EDX, shifted
            buffer_write_byte(b, 0xBA);  // MOV EDX, imm32
            buffer_write_dword(b, shifted);

            // SHR EDX, i
            if (i == 1) {
                buffer_write_byte(b, 0xD1);
                buffer_write_byte(b, 0xEA);  // SHR EDX, 1
            } else if (i > 1) {
                buffer_write_byte(b, 0xC1);
                buffer_write_byte(b, 0xEA);
                buffer_write_byte(b, (uint8_t)i);
            }
            found_shift = 1;
            break;
        }
    }

    if (!found_shift) {
        // Fallback: byte-by-byte construction
        // XOR EDX, EDX
        buffer_write_byte(b, 0x31);
        buffer_write_byte(b, 0xD2);

        // Build value byte by byte from MSB to LSB
        for (int i = 3; i >= 0; i--) {
            uint8_t byte = (disp_u32 >> (i * 8)) & 0xFF;
            if (byte != 0) {
                if (i < 3) {
                    // SHL EDX, 8
                    buffer_write_byte(b, 0xC1);
                    buffer_write_byte(b, 0xE2);
                    buffer_write_byte(b, 0x08);
                }
                // OR DL, byte
                buffer_write_byte(b, 0x80);
                buffer_write_byte(b, 0xCA);
                buffer_write_byte(b, byte);
            }
        }
    }

    // ADD ECX, EDX
    buffer_write_byte(b, 0x01);
    buffer_write_byte(b, 0xD1);

    // ADC with [ECX]
    if (reg_is_dest) {
        // ADC reg, [ECX]
        buffer_write_byte(b, 0x13);  // ADC r32, r/m32
        uint8_t reg_code = (reg_operand - X86_REG_EAX) & 0x07;
        modrm = 0x01 | (reg_code << 3);  // [ECX], reg
        buffer_write_byte(b, modrm);
    } else {
        // ADC [ECX], reg
        buffer_write_byte(b, 0x11);  // ADC r/m32, r32
        uint8_t reg_code = (reg_operand - X86_REG_EAX) & 0x07;
        modrm = 0x01 | (reg_code << 3);  // [ECX], reg
        buffer_write_byte(b, modrm);
    }

    // POP EDX
    buffer_write_byte(b, 0x5A);

    // POP ECX
    buffer_write_byte(b, 0x59);
}

strategy_t adc_sib_disp32_null_strategy = {
    .name = "adc_sib_disp32_null",
    .can_handle = can_handle_adc_sib_disp32_null,
    .get_size = get_size_adc_sib_disp32_null,
    .generate = generate_adc_sib_disp32_null,
    .priority = 72  // Higher than immediate strategy (69) and ModR/M (70)
};

// ============================================================================
// Registration Function
// ============================================================================

void register_adc_strategies() {
    // Register in priority order (highest first)
    register_strategy(&adc_sib_disp32_null_strategy);  // Priority 72
    register_strategy(&adc_modrm_null_bypass_strategy);  // Priority 70
    register_strategy(&adc_immediate_null_free_strategy);  // Priority 69
}
