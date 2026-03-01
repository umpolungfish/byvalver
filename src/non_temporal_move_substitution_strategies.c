/*
 * non_temporal_move_substitution_strategies.c
 * Implementation of MOVNTI substitution for bad-byte elimination.
 * Targets: MOV [mem], reg -> MOVNTI [mem], reg (89 /r -> 0F C3 /r)
 */
#include "non_temporal_move_substitution_strategies.h"
#include "strategy.h"
#include "utils.h"
#include <string.h>

/**
 * find_opcode_89_idx - Locates the primary opcode 0x89 in an instruction.
 * Skips legacy and REX prefixes.
 * Returns the index of 0x89 or -1 if not found.
 */
static int find_opcode_89_idx(cs_insn *insn) {
    int i;
    for (i = 0; i < (int)insn->size; i++) {
        uint8_t b = insn->bytes[i];
        
        /* Skip legacy prefixes: operand/address size, lock, repeat, segment overrides */
        if (b == 0x66 || b == 0x67 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65 || b == 0x36) {
            continue;
        }
        
        /* Skip REX prefix (0x40 - 0x4F) in x64 or INC/DEC in x86 (though 89 opcode doesn't follow INC/DEC) */
        if (b >= 0x40 && b <= 0x4F) {
            continue;
        }
        
        /* Check for the primary opcode 0x89 */
        if (b == 0x89) {
            return i;
        }
        
        /* If we hit anything else, it's not the MOV opcode we are looking for (e.g., 0x88, 0x8B) */
        return -1;
    }
    return -1;
}

/**
 * can_handle_nt_mov - Checks if the instruction is a standard MOV [mem], reg
 * that can be substituted with MOVNTI.
 */
static int can_handle_nt_mov(cs_insn *insn) {
    if (insn->id != X86_INS_MOV) {
        return 0;
    }

    if (insn->detail == NULL || insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *ops = insn->detail->x86.operands;

    /* Target: MOV [mem], reg (Standard MOV opcode 0x89) */
    if (ops[0].type != X86_OP_MEM || ops[1].type != X86_OP_REG) {
        return 0;
    }

    /* MOVNTI only supports 32-bit or 64-bit general-purpose registers */
    if (ops[1].size != 4 && ops[1].size != 8) {
        return 0;
    }

    /* 
     * MOVNTI does not support the LOCK prefix (0xF0). 
     * We check the instruction's prefix array provided by Capstone.
     */
    int j;
    for (j = 0; j < 4; j++) {
        if (insn->detail->x86.prefix[j] == 0xF0) {
            return 0;
        }
    }

    /* 
     * CRITICAL CONSTRAINT: generate_* must not write 0x00.
     * Since MOVNTI uses the same ModR/M and displacement as the original MOV,
     * if the original instruction contains any null bytes (in ModR/M, SIB, or Disp),
     * this strategy alone cannot eliminate them.
     */
    if (has_null_bytes(insn)) {
        return 0;
    }

    /* Locate the opcode 0x89 to ensure we are modifying the correct byte */
    if (find_opcode_89_idx(insn) == -1) {
        return 0;
    }

    return 1;
}

/**
 * get_size_nt_mov - Returns the size of the replacement instruction.
 * MOVNTI (0F C3 /r) is 1 byte longer than MOV (89 /r).
 */
static size_t get_size_nt_mov(cs_insn *insn) {
    return (size_t)insn->size + 1;
}

/**
 * generate_nt_mov - Generates the replacement MOVNTI instruction.
 */
static void generate_nt_mov(struct buffer *b, cs_insn *insn) {
    int idx = find_opcode_89_idx(insn);
    int i;

    /* Safety check, though can_handle should prevent idx == -1 */
    if (idx == -1) {
        return;
    }

    /* Write all prefixes that appeared before the opcode (Legacy/REX) */
    for (i = 0; i < idx; i++) {
        buffer_write_byte(b, insn->bytes[i]);
    }

    /* 
     * Substitute MOV (0x89) with MOVNTI (0x0F 0xC3).
     * Both 0x0F and 0xC3 are non-zero.
     */
    buffer_write_byte(b, 0x0F);
    buffer_write_byte(b, 0xC3);

    /* Write the remainder of the instruction (ModR/M, SIB, Displacement) */
    for (i = idx + 1; i < (int)insn->size; i++) {
        /* Checked for non-zero in can_handle via has_null_bytes() */
        buffer_write_byte(b, insn->bytes[i]);
    }
}

/**
 * Strategy structure definition
 */
static strategy_t nt_mov_strategy = {
    .name = "non_temporal_move_substitution",
    .can_handle = can_handle_nt_mov,
    .get_size = get_size_nt_mov,
    .generate = generate_nt_mov,
    .priority = 82,
    .target_arch = BYVAL_ARCH_X86
};

/**
 * Registry function
 */
void register_non_temporal_move_substitution_strategies(void) {
    register_strategy(&nt_mov_strategy);
}