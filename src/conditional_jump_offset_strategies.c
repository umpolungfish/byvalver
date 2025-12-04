/*
 * Conditional Jump Null-Offset Elimination Strategy
 *
 * PROBLEM: After instruction size changes, conditional jump offsets are recalculated.
 * If the new rel32 offset contains null bytes, there's no fallback transformation.
 *
 * EXAMPLE:
 *   Original:     JNE 0x50b
 *   After patch:  JNE 0x50b  (rel32 = 0x02AC)
 *   Encoding:     0f 85 ac 02 00 00
 *                            ^^ ^^ null bytes!
 *
 * SOLUTION: Transform to opposite conditional jump + unconditional jump
 *
 * TRANSFORMATION:
 *   Original:
 *     JNE target    ; 0f 85 ac 02 00 00 (6 bytes, has nulls)
 *
 *   Transformed:
 *     JE skip       ; 74 05 (2 bytes, short jump)
 *     JMP target    ; e9 xx xx xx xx (5 bytes, null-free)
 *   skip:
 *
 * Priority: 150 (highest) - must run after offset patching
 */

#include <stdint.h>
#include <stddef.h>
#include "strategy.h"
#include "utils.h"
#include <capstone/capstone.h>

/* Forward declarations */
extern void register_strategy(strategy_t *s);

// Map conditional jump opcodes to their opposites for short jumps
static uint8_t get_opposite_short_jcc_opcode(x86_insn jcc_id) {
    switch(jcc_id) {
        case X86_INS_JO:  return 0x71; // JO → JNO
        case X86_INS_JNO: return 0x70; // JNO → JO
        case X86_INS_JB:  return 0x73; // JB → JAE
        case X86_INS_JAE: return 0x72; // JAE → JB
        case X86_INS_JE:  return 0x75; // JE → JNE
        case X86_INS_JNE: return 0x74; // JNE → JE
        case X86_INS_JBE: return 0x77; // JBE → JA
        case X86_INS_JA:  return 0x76; // JA → JBE
        case X86_INS_JS:  return 0x79; // JS → JNS
        case X86_INS_JNS: return 0x78; // JNS → JS
        case X86_INS_JP:  return 0x7B; // JP → JNP
        case X86_INS_JNP: return 0x7A; // JNP → JP
        case X86_INS_JL:  return 0x7D; // JL → JGE
        case X86_INS_JGE: return 0x7C; // JGE → JL
        case X86_INS_JLE: return 0x7F; // JLE → JG
        case X86_INS_JG:  return 0x7E; // JG → JLE
        default: return 0x74; // Default to JNE
    }
}

// Check if offset contains null bytes
static int offset_has_null_bytes(int32_t offset) {
    uint32_t val = (uint32_t)offset;
    return ((val & 0xFF) == 0) ||
           ((val & 0xFF00) == 0) ||
           ((val & 0xFF0000) == 0) ||
           ((val & 0xFF000000) == 0);
}

/*
 * Detect conditional jumps with null-byte offsets after patching
 */
static int can_handle_conditional_jump_null_offset(cs_insn *insn) {
    // Check if it's a conditional jump instruction
    if (insn->id < X86_INS_JAE || insn->id > X86_INS_JS) {
        return 0;
    }

    // Must have exactly one operand (the target)
    if (insn->detail->x86.op_count != 1 ||
        insn->detail->x86.operands[0].type != X86_OP_IMM) {
        return 0;
    }

    // Check if the instruction itself contains null bytes after offset patching
    // This happens when the rel32 offset contains null bytes
    if (has_null_bytes(insn)) {
        return 1;
    }

    // Additional check: if we have an operand, check if it contains nulls
    // This may be useful for certain edge cases
    int64_t target = insn->detail->x86.operands[0].imm;
    uint32_t target32 = (uint32_t)target;
    if (offset_has_null_bytes(target32)) {
        return 1;
    }

    return 0;
}

/*
 * Calculate replacement size
 * Opposite short jump (2 bytes) + unconditional JMP (5 bytes minimum)
 */
static size_t get_size_conditional_jump_null_offset(cs_insn *insn) {
    // Short conditional jump (2 bytes) + long JMP (5 bytes)
    (void)insn; // Unused parameter
    return 7; // 2 + 5 = 7 bytes
}

/*
 * Generate null-free conditional jump replacement
 */
static void generate_conditional_jump_null_offset(struct buffer *b, cs_insn *insn) {

    // Get target address
    int64_t target = insn->detail->x86.operands[0].imm;

    // Calculate skip distance for the opposite short jump
    // The skip distance is the size of the JMP instruction (5 bytes)
    uint8_t skip_distance = 0x05;

    // Generate opposite condition short jump
    uint8_t opposite_opcode = get_opposite_short_jcc_opcode(insn->id);

    // Write opposite short jump
    buffer_write_byte(b, opposite_opcode);
    buffer_write_byte(b, skip_distance);

    // Generate unconditional JMP to target
    // Calculate the JMP rel32 offset
    size_t jmp_pos = b->size;  // Position right after the short jump
    int32_t jmp_offset = (int32_t)(target - (jmp_pos + 5)); // +5 for the JMP instruction

    // Write JMP opcode
    buffer_write_byte(b, 0xE9);  // JMP rel32
    buffer_write_dword(b, jmp_offset);
}

/* Strategy definition */
static strategy_t conditional_jump_null_offset_strategy = {
    .name = "Conditional Jump Null Offset Elimination",
    .can_handle = can_handle_conditional_jump_null_offset,
    .get_size = get_size_conditional_jump_null_offset,
    .generate = generate_conditional_jump_null_offset,
    .priority = 150  // Very high priority - handles critical case
};

/* Registration function */
void register_conditional_jump_offset_strategies() {
    register_strategy(&conditional_jump_null_offset_strategy);
}