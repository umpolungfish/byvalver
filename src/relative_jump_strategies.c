/*
 * Relative CALL/JMP Displacement Null-Byte Elimination Strategy
 *
 * PROBLEM: Relative CALL and JMP instructions use displacement values that can contain null bytes:
 * - CALL 0x4480 → E8 7D 44 00 00 (contains 2 nulls in displacement)
 * - JMP 0x100 → EB FE or E9 FB 00 00 00 (depending on distance, potentially with nulls)
 *
 * SOLUTION: Use indirect call/jump through register to avoid displacement nulls.
 * - Original: CALL rel32 (E8 disp32) where disp32 contains nulls
 * - Replace: MOV EAX, target_addr; CALL EAX (no displacement nulls)
 *
 * FREQUENCY: Common in shellcode with control flow
 * PRIORITY: 85 (High)
 *
 * Example transformations:
 *   Original: CALL 0x12345 (E8 70 34 01 00 - contains nulls)
 *   Strategy: MOV EAX, 0x12345; CALL EAX (null-free)
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Detection function for relative CALL/JMP instructions with null displacement bytes
 */
int can_handle_relative_jump_displacement_null(cs_insn *insn) {
    if (insn->id != X86_INS_CALL && insn->id != X86_INS_JMP) {
        return 0;
    }
    
    // Only handle immediate operand relatives (not register indirect)
    if (insn->detail->x86.op_count != 1 || 
        insn->detail->x86.operands[0].type != X86_OP_IMM) {
        return 0;
    }
    
    // Check if immediate value contains null bytes
    uint64_t imm = (uint64_t)insn->detail->x86.operands[0].imm;
    
    // For 32-bit immediate values, check if it contains null bytes
    uint32_t imm32 = (uint32_t)imm;
    
    // Check if the immediate contains null bytes
    if (is_null_free(imm32)) {
        return 0; // No null bytes, no need to handle
    }
    
    return 1;
}

/*
 * Size calculation function for relative jump displacement null elimination
 */
size_t get_size_relative_jump_displacement_null(cs_insn *insn) {
    // We'll replace with MOV reg, imm + CALL/JMP reg
    // MOV EAX, imm32: ~6-7 bytes (using null-safe construction)
    // CALL/JMP EAX: 2 bytes
    // So approximately 8-9 bytes vs original 5 bytes (for CALL) or 5 bytes (for JMP rel32)
    
    // Use a conservative estimate based on null-safe immediate construction
    uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
    size_t mov_size = get_mov_eax_imm_size(imm);
    size_t call_or_jmp_size = 2;  // CALL reg or JMP reg is 2 bytes
    
    return mov_size + call_or_jmp_size;
}

/*
 * Generation function for null-free relative jump replacement
 */
void generate_relative_jump_displacement_null_free(struct buffer *b, cs_insn *insn) {
    // Get the target address from the immediate
    uint32_t target_addr = (uint32_t)insn->detail->x86.operands[0].imm;
    
    // Strategy: MOV EAX, target_addr; CALL/JMP EAX
    // This avoids null bytes in displacement
    
    // First, construct the target address in EAX using null-free method
    generate_mov_eax_imm(b, target_addr);
    
    // Then perform the call or jump indirectly
    if (insn->id == X86_INS_CALL) {
        // CALL EAX: FF D0
        buffer_write_byte(b, 0xFF);
        buffer_write_byte(b, 0xD0);  // ModR/M for CALL EAX
    } else if (insn->id == X86_INS_JMP) {
        // JMP EAX: FF E0
        buffer_write_byte(b, 0xFF);
        buffer_write_byte(b, 0xE0);  // ModR/M for JMP EAX
    }
}

// Define the strategy structure
strategy_t relative_jump_strategy = {
    .name = "Relative CALL/JMP Displacement Null Elimination",
    .can_handle = can_handle_relative_jump_displacement_null,
    .get_size = get_size_relative_jump_displacement_null,
    .generate = generate_relative_jump_displacement_null_free,
    .priority = 85  // High priority for control flow operations
};