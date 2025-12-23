/*
 * LOOP Comprehensive Variants Strategy for Bad Character Elimination
 *
 * PROBLEM: LOOP family instructions (LOOP/LOOPE/LOOPNE) use 8-bit signed
 * displacement which may contain bad characters.
 *
 * Example: LOOP offset  (E2 XX where XX is the displacement)
 * If XX contains a bad character, we need to transform it.
 *
 * SOLUTION: Replace LOOP instructions with equivalent sequences:
 *
 * 1. LOOP target:
 *    DEC ECX
 *    JNZ target
 *
 * 2. LOOPE/LOOPZ target (loop while ECX != 0 AND ZF = 1):
 *    DEC ECX
 *    JZ skip_jump   ; If ECX = 0, skip the conditional jump
 *    JE target      ; If ZF = 1, jump to target
 *    skip_jump:
 *
 * 3. LOOPNE/LOOPNZ target (loop while ECX != 0 AND ZF = 0):
 *    DEC ECX
 *    JZ skip_jump   ; If ECX = 0, skip the conditional jump
 *    JNE target     ; If ZF = 0, jump to target
 *    skip_jump:
 */

#include "loop_comprehensive_strategies.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * Check if this strategy can handle the instruction
 */
int can_handle_loop_comprehensive(cs_insn *insn) {
    if (!insn) {
        return 0;
    }

    // Check if instruction is a LOOP variant
    if (insn->id != X86_INS_LOOP &&
        insn->id != X86_INS_LOOPE &&
        insn->id != X86_INS_LOOPNE) {
        return 0;
    }

    // Check if the instruction encoding contains bad characters
    if (!is_bad_char_free_buffer(insn->bytes, insn->size)) {
        return 1;  // Has bad chars, we can handle it
    }

    return 0;  // No bad chars, no need to transform
}

/**
 * Calculate size of transformed instruction
 */
size_t get_size_loop_comprehensive(cs_insn *insn) {
    if (!insn) {
        return 0;
    }

    if (insn->id == X86_INS_LOOP) {
        // DEC ECX = 1 byte (49)
        // JNZ rel8 = 2 bytes (75 XX)
        // Total = 3 bytes
        return 3;
    } else {
        // LOOPE/LOOPNE:
        // DEC ECX = 1 byte (49)
        // JZ skip = 2 bytes (74 02)
        // JE/JNE target = 2 bytes (74/75 XX)
        // Total = 5 bytes
        return 5;
    }
}

/**
 * Generate transformed instruction sequence
 */
void generate_loop_comprehensive(struct buffer *b, cs_insn *insn) {
    if (!insn || !b) {
        return;
    }

    // Get the target displacement from the LOOP instruction
    // LOOP instructions have one operand: the target address
    if (insn->detail->x86.op_count != 1) {
        // Fallback: copy original instruction
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    cs_x86_op *op = &insn->detail->x86.operands[0];
    if (op->type != X86_OP_IMM) {
        // Fallback: copy original instruction
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    // Calculate relative displacement
    // The displacement in LOOP is relative to the instruction AFTER the LOOP
    int64_t target_addr = op->imm;
    int64_t next_insn_addr = insn->address + insn->size;
    int64_t displacement = target_addr - next_insn_addr;

    // After transformation, we need to adjust the displacement
    // because our instruction sequence is longer
    size_t transform_size = get_size_loop_comprehensive(insn);
    int64_t adjusted_disp = displacement - (transform_size - insn->size);

    // Check if displacement fits in 8-bit signed range
    if (adjusted_disp < -128 || adjusted_disp > 127) {
        // Need a 32-bit displacement - use long form jumps
        // This is more complex, for now we'll handle only 8-bit range
        // Fallback for now
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    int8_t disp8 = (int8_t)adjusted_disp;

    // Transform based on LOOP variant
    if (insn->id == X86_INS_LOOP) {
        // Simple LOOP: DEC ECX; JNZ target

        // DEC ECX (opcode: 49 in x86, 48 FF C9 in x64 for compatibility)
        // We'll use the short form for x86
        buffer_write_byte(b, 0x49);  // DEC ECX

        // JNZ rel8 (opcode: 75 XX)
        buffer_write_byte(b, 0x75);  // JNZ
        buffer_write_byte(b, (uint8_t)disp8);

    } else if (insn->id == X86_INS_LOOPE) {
        // LOOPE/LOOPZ: DEC ECX; JZ skip; JE target; skip:

        // DEC ECX
        buffer_write_byte(b, 0x49);  // DEC ECX

        // JZ skip (skip the JE if ECX = 0)
        // Skip distance = 2 bytes (length of JE instruction)
        buffer_write_byte(b, 0x74);  // JZ
        buffer_write_byte(b, 0x02);  // Skip 2 bytes

        // JE target (jump if ZF = 1)
        buffer_write_byte(b, 0x74);  // JE
        buffer_write_byte(b, (uint8_t)disp8);

    } else if (insn->id == X86_INS_LOOPNE) {
        // LOOPNE/LOOPNZ: DEC ECX; JZ skip; JNE target; skip:

        // DEC ECX
        buffer_write_byte(b, 0x49);  // DEC ECX

        // JZ skip (skip the JNE if ECX = 0)
        // Skip distance = 2 bytes (length of JNE instruction)
        buffer_write_byte(b, 0x74);  // JZ
        buffer_write_byte(b, 0x02);  // Skip 2 bytes

        // JNE target (jump if ZF = 0)
        buffer_write_byte(b, 0x75);  // JNE
        buffer_write_byte(b, (uint8_t)disp8);
    }
}

// Define the strategy structure
strategy_t loop_comprehensive_strategy = {
    .name = "LOOP Comprehensive Variants",
    .can_handle = can_handle_loop_comprehensive,
    .get_size = get_size_loop_comprehensive,
    .generate = generate_loop_comprehensive,
    .priority = 79
};
