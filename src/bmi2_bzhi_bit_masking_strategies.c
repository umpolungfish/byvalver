/*
 * bmi2_bzhi_bit_masking_strategies.c
 * Implementation of BMI2 BZHI Bit-Field Masking strategy for bad-byte elimination.
 *
 * This strategy transforms 'AND reg, mask' instructions that contain null bytes
 * (common with 32-bit immediates like 0xFF or 0xFFFF) into a BMI2-based 
 * sequence: PUSH bit_count; POP tmp; BZHI dst, src, tmp.
 */

#include "strategy.h"
#include "utils.h"
#include <capstone/capstone.h>
#include <stdint.h>

/**
 * Helper to check if a register is a 32-bit general-purpose register.
 * BZHI in this implementation targets 32-bit GPRs.
 */
static int is_gpr32_bzhi(x86_reg reg) {
    switch (reg) {
        case X86_REG_EAX:
        case X86_REG_ECX:
        case X86_REG_EDX:
        case X86_REG_EBX:
        case X86_REG_ESP:
        case X86_REG_EBP:
        case X86_REG_ESI:
        case X86_REG_EDI:
            return 1;
        default:
            return 0;
    }
}

/**
 * Maps Capstone register IDs to hardware indices (0-7).
 */
static uint8_t get_reg_idx_bzhi(x86_reg reg) {
    switch (reg) {
        case X86_REG_EAX: return 0;
        case X86_REG_ECX: return 1;
        case X86_REG_EDX: return 2;
        case X86_REG_EBX: return 3;
        case X86_REG_ESP: return 4;
        case X86_REG_EBP: return 5;
        case X86_REG_ESI: return 6;
        case X86_REG_EDI: return 7;
        default:          return 0;
    }
}

/**
 * Determines if the instruction can be handled by the BMI2 BZHI strategy.
 * Target: AND reg32, (1 << n) - 1 where the instruction contains null bytes.
 */
int can_handle_bmi2_bzhi(cs_insn *insn) {
    if (insn->id != X86_INS_AND) {
        return 0;
    }

    // Ensure we have exactly two operands (reg, imm)
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Destination must be a 32-bit GPR
    if (insn->detail->x86.operands[0].type != X86_OP_REG || 
        !is_gpr32_bzhi(insn->detail->x86.operands[0].reg)) {
        return 0;
    }

    // Source must be an immediate bitmask
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

    // Mask must be of form (1 << n) - 1, and not 0 or all 1s (which aren't masked)
    if (imm == 0 || imm == 0xFFFFFFFF) {
        return 0;
    }

    // Check if imm is a contiguous bitmask from bit 0: (imm & (imm + 1)) == 0
    if ((imm & (imm + 1)) != 0) {
        return 0;
    }

    // Only apply if the original instruction contains null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    return 1;
}

/**
 * Returns a conservative upper-bound size for the generated replacement.
 * PUSH imm8 (2) + POP reg (1) + VEX BZHI (5) = 8 bytes.
 */
size_t get_size_bmi2_bzhi(cs_insn *insn) {
    (void)insn;
    return 12;
}

/**
 * Generates the replacement byte sequence.
 * Replacement: 
 *   PUSH bit_count
 *   POP tmp_reg
 *   BZHI dst_reg, dst_reg, tmp_reg
 */
void generate_bmi2_bzhi(struct buffer *b, cs_insn *insn) {
    (void)insn;
    
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;
    
    // Calculate bit count 'n' from mask (imm = 2^n - 1)
    uint8_t bit_count = 0;
    uint32_t temp_val = imm + 1;
    while (temp_val > 1) {
        temp_val >>= 1;
        bit_count++;
    }

    // Pick a temporary register for the bit count that isn't the destination
    // We use ECX (index 1) unless the destination is ECX, in which case we use EDX (index 2).
    uint8_t tmp_idx = 1; 
    if (dst_reg == X86_REG_ECX) {
        tmp_idx = 2;
    }

    // 1. Generate: PUSH bit_count (6A [n])
    buffer_write_byte(b, 0x6A);
    buffer_write_byte(b, bit_count);

    // 2. Generate: POP tmp_reg (58 + tmp_idx)
    buffer_write_byte(b, (uint8_t)(0x58 + tmp_idx));

    // 3. Generate: BZHI dst, dst, tmp
    // BZHI is encoded with VEX: VEX.LZ.0F38.W0 F5 /r
    
    // VEX 3-byte prefix (0xC4)
    buffer_write_byte(b, 0xC4);
    
    // VEX Byte 2: R X B m-mmmm
    // R=1, X=1, B=1 (inverted bits for EAX-EDI), m-mmmm=00010 (map 0F 38)
    buffer_write_byte(b, 0xE2);
    
    // VEX Byte 3: W vvvv L pp
    // W=0, L=0, pp=00 (No prefix)
    // vvvv = inverted index of the control register (the temporary register)
    uint8_t vvvv = (~tmp_idx) & 0x0F;
    uint8_t vex3 = (uint8_t)(vvvv << 3);
    buffer_write_byte(b, vex3);
    
    // BZHI Opcode
    buffer_write_byte(b, 0xF5);
    
    // ModRM: 11 [dest] [src]
    // In our case, src is the same as dest for AND reg, mask.
    uint8_t reg_hw_idx = get_reg_idx_bzhi(dst_reg);
    uint8_t modrm = (uint8_t)(0xC0 | (reg_hw_idx << 3) | reg_hw_idx);
    buffer_write_byte(b, modrm);
}

/**
 * Strategy definition for registration.
 */
static strategy_t bmi2_bzhi_bit_masking_strategy = {
    .name = "bmi2_bzhi_bit_masking",
    .can_handle = can_handle_bmi2_bzhi,
    .get_size = get_size_bmi2_bzhi,
    .generate = generate_bmi2_bzhi,
    .priority = 85,
    .target_arch = BYVAL_ARCH_X86
};

/**
 * Registration function called by the strategy manager.
 */
void register_bmi2_bzhi_bit_masking_strategies(void) {
    register_strategy(&bmi2_bzhi_bit_masking_strategy);
}