/*
 * Small Immediate Value Encoding Optimization Strategy
 *
 * PROBLEM: Direct MOV with immediate values can contain null bytes:
 * - MOV ECX, 0x300 → B9 00 03 00 00 (contains 3 nulls)
 * - MOV DWORD PTR [EAX], 1 → C7 00 01 00 00 00 (contains 3 nulls)
 *
 * SOLUTION: Use alternative encodings like setting up values through
 * arithmetic or by constructing them byte-by-byte to avoid nulls.
 *
 * FREQUENCY: Common in shellcode for setting up flags, counters, and API parameters
 * PRIORITY: 75 (High)
 *
 * Example transformations:
 *   Original: MOV ECX, 0x300 (B9 00 03 00 00 - contains nulls)
 *   Strategy: XOR ECX,ECX; MOV CL,0x00; MOV CH,0x03 (null-free construction)
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Detection function for MOV instructions with immediate values that contain null bytes
 */
int can_handle_small_immediate_optimization(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || 
        insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Check if second operand is an immediate value
    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    cs_x86_op *src_op = &insn->detail->x86.operands[1];
    
    if (src_op->type != X86_OP_IMM) {
        return 0;
    }

    // Only work with register destinations
    if (dst_op->type != X86_OP_REG) {
        return 0;
    }
    
    // Only handle 32-bit registers
    if (dst_op->size != 4) {
        return 0;
    }

    uint32_t imm = (uint32_t)src_op->imm;
    
    // Check if immediate contains null bytes
    if (is_null_free(imm)) {
        // If immediate is already null-free, we don't need to optimize
        return 0;
    }

    // For now, focus on values that could benefit from high-byte/low-byte techniques
    // e.g. 0x00000300, 0x00000001 that have problematic encodings
    // We'll specifically look for values where high-byte method is beneficial
    
    return 1; // We can handle any MOV reg, imm that has nulls
}

/*
 * Size calculation function for small immediate optimization
 */
size_t get_size_small_immediate_optimization(cs_insn *insn) {
    // This approach varies, but often involves multiple instructions
    // XOR reg,reg (2) + MOV regLow,byte1 (2-3) + MOV regHigh,byte2 (2-3) etc = 6-8 bytes typically
    // vs original MOV reg,imm32 = 5 bytes
    (void)insn; // Unused parameter
    return 8; // Conservative estimate
}

/*
 * Generation function for null-free immediate encoding using byte-by-byte construction
 */
void generate_small_immediate_optimization(struct buffer *b, cs_insn *insn) {
    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    cs_x86_op *src_op = &insn->detail->x86.operands[1];
    
    uint32_t imm = (uint32_t)src_op->imm;
    uint8_t reg_num = dst_op->reg - X86_REG_EAX;  // 0 for EAX, 1 for ECX, etc.

    // Approach: Clear the register and then build the value byte by byte
    // This is a general approach that works for most immediate values
    
    // Clear the destination register 
    buffer_write_byte(b, 0x31);  // XOR opcode
    buffer_write_byte(b, 0xC0 + (reg_num << 3) + reg_num);  // ModR/M for XOR reg,reg

    // Now build the immediate value byte by byte
    // We'll set each byte that's non-zero using MOV instructions
    uint8_t bytes[4];
    memcpy(bytes, &imm, 4);
    
    // Set each non-zero byte
    for (int i = 0; i < 4; i++) {
        if (bytes[i] != 0) {
            // MOV [register + offset], byte_value
            // For EAX, ECX, EDX, EBX, we can access individual bytes
            // AL=0, CL=1, DL=2, BL=3; AH=4, CH=5, DH=6, BH=7
            
            if (i == 0) { // AL, CL, DL, BL
                // MOV reg8_low, imm8: B0+rb ib
                buffer_write_byte(b, 0xB0 + reg_num);  // MOV AL/CL/DL/BL, imm8
                buffer_write_byte(b, bytes[i]);
            } 
            else if (i == 1 && reg_num < 4) { // AH, CH, DH, BH
                // MOV r8_high, imm8: C6 /4 ib
                buffer_write_byte(b, 0xC6);
                buffer_write_byte(b, 0xC0 + reg_num + 4);  // ModR/M for high byte register
                buffer_write_byte(b, bytes[i]);
            }
            else { // For bytes 2 and 3, we need different approaches
                // Use shift and OR operations or direct construction
                // For now, use the general immediate construction utility
                // which should handle null bytes properly
                generate_mov_reg_imm(b, insn);
                return; // Use the general approach for complex cases
            }
        }
    }
}

// Define the strategy structure
strategy_t small_immediate_strategy = {
    .name = "Small Immediate Value Encoding Optimization",
    .can_handle = can_handle_small_immediate_optimization,
    .get_size = get_size_small_immediate_optimization,
    .generate = generate_small_immediate_optimization,
    .priority = 75  // High priority for size optimization
};