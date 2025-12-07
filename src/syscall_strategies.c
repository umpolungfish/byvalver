/*
 * Windows Syscall Direct Invocation (x64) Strategy
 *
 * PROBLEM: Modern Windows x64 shellcode uses direct syscalls to bypass user-mode hooks.
 * Syscall numbers are loaded into EAX/RAX and are often small values that encode with null bytes:
 * - MOV EAX, 0x55 → B8 55 00 00 00 (contains 3 nulls)
 * - MOV RAX, 0x3A → 48 C7 C0 3A 00 00 00 (contains 3 nulls)
 *
 * SOLUTION: Detect MOV to EAX/RAX with immediate values that are likely syscall numbers
 * (small values in typical syscall range 0x00-0x1FF) and transform to null-free construction.
 *
 * FREQUENCY: Very common in modern Windows x64 shellcode
 * PRIORITY: 85 (High - critical for modern x64 shellcode)
 *
 * Example transformations:
 *   Original: MOV EAX, 0x55 (B8 55 00 00 00 - contains nulls)
 *   Strategy: XOR EAX,EAX; MOV AL,0x55 (null-free construction)
 *
 *   Original: MOV RAX, 0x3A (48 C7 C0 3A 00 00 00 - contains nulls)
 *   Strategy: XOR EAX,EAX; MOV AL,0x3A (null-free, also clears upper 32 bits in x64)
 */

#include "syscall_strategies.h"
#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Check if an immediate value looks like a syscall number
 * Windows syscall numbers are typically in the range 0x00-0x1FF
 * Linux syscall numbers can be larger but most common ones are < 0x200
 */
static int is_likely_syscall_number(uint64_t imm) {
    // Syscall numbers are typically small positive integers
    // Windows: 0x00-0x1FF (most are < 0x200)
    // Linux x64: 0x00-0x400 (most common ones < 0x200)
    return (imm <= 0x1FF);
}

/*
 * Detection function for MOV EAX/RAX with syscall number immediates
 */
int can_handle_syscall_number_mov(cs_insn *insn) {
    if (insn->id != X86_INS_MOV ||
        insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    cs_x86_op *src_op = &insn->detail->x86.operands[1];

    // Must be MOV register, immediate
    if (dst_op->type != X86_OP_REG || src_op->type != X86_OP_IMM) {
        return 0;
    }

    // Must be moving to EAX or RAX (syscall numbers are loaded here)
    if (dst_op->reg != X86_REG_EAX && dst_op->reg != X86_REG_RAX) {
        return 0;
    }

    uint64_t imm = (uint64_t)src_op->imm;

    // Check if it looks like a syscall number
    if (!is_likely_syscall_number(imm)) {
        return 0;
    }

    // Check if the immediate contains null bytes when encoded
    // For 32-bit: B8 XX XX XX XX (5 bytes)
    // For 64-bit: 48 C7 C0 XX XX XX XX (7 bytes) or B8 XX XX XX XX (5 bytes with REX prefix)
    uint32_t imm32 = (uint32_t)imm;

    if (is_null_free(imm32)) {
        // Already null-free
        return 0;
    }

    // Additional check: make sure the instruction itself has null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    return 1;
}

/*
 * Size calculation for syscall number MOV transformation
 *
 * Transformation uses:
 * - XOR EAX, EAX (2 bytes: 31 C0)
 * - MOV AL, byte (2 bytes: B0 XX)
 * Total: 4 bytes
 *
 * This is smaller than original MOV EAX, imm32 (5 bytes) and null-free
 */
size_t get_size_syscall_number_mov(cs_insn *insn) {
    (void)insn; // Unused parameter

    // XOR EAX,EAX (2) + MOV AL,byte (2) = 4 bytes
    return 4;
}

/*
 * Generate null-free syscall number loading
 *
 * Strategy: For small syscall numbers (0x00-0xFF), use:
 *   XOR EAX, EAX        ; Clear EAX (31 C0)
 *   MOV AL, syscall_num ; Load syscall number into lower byte (B0 XX)
 *
 * For larger syscall numbers (0x100-0x1FF), use:
 *   XOR EAX, EAX        ; Clear EAX (31 C0)
 *   MOV AX, syscall_num ; Load syscall number into lower word (66 B8 XX XX)
 *
 * Note: In x64 mode, XOR EAX,EAX also clears the upper 32 bits of RAX
 */
void generate_syscall_number_mov(struct buffer *b, cs_insn *insn) {
    cs_x86_op *src_op = &insn->detail->x86.operands[1];
    uint32_t syscall_num = (uint32_t)src_op->imm;

    // XOR EAX, EAX - clears EAX (and RAX upper bits in x64)
    buffer_write_byte(b, 0x31);  // XOR opcode
    buffer_write_byte(b, 0xC0);  // ModR/M for XOR EAX, EAX

    if (syscall_num <= 0xFF) {
        // Syscall number fits in a single byte
        // MOV AL, byte
        buffer_write_byte(b, 0xB0);  // MOV AL, imm8
        buffer_write_byte(b, (uint8_t)syscall_num);
    } else {
        // Syscall number requires two bytes (0x100-0x1FF range)
        // MOV AX, word
        buffer_write_byte(b, 0x66);  // Operand size override prefix
        buffer_write_byte(b, 0xB8);  // MOV AX, imm16
        buffer_write_byte(b, (uint8_t)(syscall_num & 0xFF));       // Low byte
        buffer_write_byte(b, (uint8_t)((syscall_num >> 8) & 0xFF)); // High byte
    }
}

/*
 * Strategy definition
 */
strategy_t syscall_number_mov_strategy = {
    .name = "Windows Syscall Number MOV (x64)",
    .can_handle = can_handle_syscall_number_mov,
    .get_size = get_size_syscall_number_mov,
    .generate = generate_syscall_number_mov,
    .priority = 95  // Very high priority - more efficient than ROR13 for small syscall numbers
};

/**
 * Registration function for syscall strategies
 */
void register_syscall_strategies() {
    register_strategy(&syscall_number_mov_strategy);
}
