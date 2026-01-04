#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>

// Helper function to check if MOV reg,reg encoding contains bad bytes
static int mov_reg_reg_has_bad_bytes(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    if (insn->id == X86_INS_MOV &&
        insn->detail->x86.op_count == 2 &&
        insn->detail->x86.operands[0].type == X86_OP_REG &&
        insn->detail->x86.operands[1].type == X86_OP_REG) {

        x86_reg dst = insn->detail->x86.operands[0].reg;
        x86_reg src = insn->detail->x86.operands[1].reg;

        // Calculate the ModR/M byte for MOV dst, src
        int dst_idx = get_reg_index((uint8_t)dst);
        int src_idx = get_reg_index((uint8_t)src);

        // MOV reg, reg uses opcode 0x89 (32-bit) or 0x8B (reversed)
        // ModR/M byte: 11 (mod) | src_idx (reg) | dst_idx (r/m)
        uint8_t modrm = 0xC0 | (src_idx << 3) | dst_idx;

        // Check opcode and ModR/M
        uint8_t opcode = 0x89; // MOV r/m32, r32
        if (!is_bad_byte_free_byte(opcode) || !is_bad_byte_free_byte(modrm)) {
            return 1;
        }

        // Also check reverse direction (0x8B)
        opcode = 0x8B; // MOV r32, r/m32
        uint8_t modrm_rev = 0xC0 | (dst_idx << 3) | src_idx;
        if (!is_bad_byte_free_byte(opcode) || !is_bad_byte_free_byte(modrm_rev)) {
            return 1;
        }
    }

    return 0;
}

// ============================================================================
// Strategy: MOV reg, reg with bad opcode/ModR/M → PUSH src; POP dst
// ============================================================================

static int can_handle_mov_reg_reg_bad_opcode(cs_insn *insn) {
    return mov_reg_reg_has_bad_bytes(insn);
}

static size_t get_size_mov_reg_reg_bad_opcode(cs_insn *insn) {
    (void)insn;
    // PUSH src (1 byte) + POP dst (1 byte)
    return 2;
}

static void generate_mov_reg_reg_bad_opcode(struct buffer *b, cs_insn *insn) {
    x86_reg dst = insn->detail->x86.operands[0].reg;
    x86_reg src = insn->detail->x86.operands[1].reg;

    int src_idx = get_reg_index((uint8_t)src);
    int dst_idx = get_reg_index((uint8_t)dst);

    // PUSH src
    uint8_t push_src = 0x50 + src_idx;

    // POP dst
    uint8_t pop_dst = 0x58 + dst_idx;

    // Check if PUSH/POP opcodes are safe
    if (is_bad_byte_free_byte(push_src) && is_bad_byte_free_byte(pop_dst)) {
        buffer_append(b, &push_src, 1);
        buffer_append(b, &pop_dst, 1);
    } else {
        // Fallback: Use XCHG if possible
        // XCHG EAX, reg has one-byte encoding 0x90+reg
        if (dst == X86_REG_EAX || src == X86_REG_EAX) {
            x86_reg other = (dst == X86_REG_EAX) ? src : dst;
            int other_idx = get_reg_index((uint8_t)other);
            uint8_t xchg = 0x90 + other_idx;

            if (is_bad_byte_free_byte(xchg)) {
                // XCHG EAX, other; XCHG EAX, other (double XCHG = MOV)
                buffer_append(b, &xchg, 1);
                buffer_append(b, &xchg, 1);
            } else {
                // Fallback to memory-based transfer using stack
                // SUB ESP, 4; MOV [ESP], src; MOV dst, [ESP]; ADD ESP, 4
                uint8_t sub_esp[] = {0x83, 0xEC, 0x04}; // SUB ESP, 4
                buffer_append(b, sub_esp, 3);

                // MOV [ESP], src: 89 04 24 or 89 34 24 depending on src
                uint8_t mov_mem_src[] = {0x89, 0x04 | (src_idx << 3), 0x24};
                buffer_append(b, mov_mem_src, 3);

                // MOV dst, [ESP]: 8B 04 24 or 8B 34 24 depending on dst
                uint8_t mov_dst_mem[] = {0x8B, 0x04 | (dst_idx << 3), 0x24};
                buffer_append(b, mov_dst_mem, 3);

                uint8_t add_esp[] = {0x83, 0xC4, 0x04}; // ADD ESP, 4
                buffer_append(b, add_esp, 3);
            }
        } else {
            // Use EAX as intermediary with memory
            uint8_t sub_esp[] = {0x83, 0xEC, 0x04};
            buffer_append(b, sub_esp, 3);

            uint8_t mov_mem_src[] = {0x89, 0x04 | (src_idx << 3), 0x24};
            buffer_append(b, mov_mem_src, 3);

            uint8_t mov_dst_mem[] = {0x8B, 0x04 | (dst_idx << 3), 0x24};
            buffer_append(b, mov_dst_mem, 3);

            uint8_t add_esp[] = {0x83, 0xC4, 0x04};
            buffer_append(b, add_esp, 3);
        }
    }
}

// ============================================================================
// Strategy: XCHG reg, reg with bad opcode → PUSH/POP sequence
// ============================================================================

static int can_handle_xchg_reg_reg_bad_opcode(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    if (insn->id == X86_INS_XCHG &&
        insn->detail->x86.op_count == 2 &&
        insn->detail->x86.operands[0].type == X86_OP_REG &&
        insn->detail->x86.operands[1].type == X86_OP_REG) {

        x86_reg reg1 = insn->detail->x86.operands[0].reg;
        x86_reg reg2 = insn->detail->x86.operands[1].reg;

        // XCHG EAX, reg uses one-byte opcode 0x90+reg
        if (reg1 == X86_REG_EAX || reg2 == X86_REG_EAX) {
            x86_reg other = (reg1 == X86_REG_EAX) ? reg2 : reg1;
            int other_idx = get_reg_index((uint8_t)other);
            uint8_t opcode = 0x90 + other_idx;
            if (!is_bad_byte_free_byte(opcode)) {
                return 1;
            }
        } else {
            // XCHG reg1, reg2 uses opcode 0x87 with ModR/M
            int idx1 = get_reg_index((uint8_t)reg1);
            int idx2 = get_reg_index((uint8_t)reg2);
            uint8_t opcode = 0x87;
            uint8_t modrm = 0xC0 | (idx1 << 3) | idx2;
            if (!is_bad_byte_free_byte(opcode) || !is_bad_byte_free_byte(modrm)) {
                return 1;
            }
        }
    }

    return 0;
}

static size_t get_size_xchg_reg_reg_bad_opcode(cs_insn *insn) {
    (void)insn;
    // PUSH reg1; PUSH reg2; POP reg1; POP reg2 = 4 bytes
    return 4;
}

static void generate_xchg_reg_reg_bad_opcode(struct buffer *b, cs_insn *insn) {
    x86_reg reg1 = insn->detail->x86.operands[0].reg;
    x86_reg reg2 = insn->detail->x86.operands[1].reg;

    int idx1 = get_reg_index((uint8_t)reg1);
    int idx2 = get_reg_index((uint8_t)reg2);

    // PUSH reg1
    uint8_t push_reg1 = 0x50 + idx1;
    // PUSH reg2
    uint8_t push_reg2 = 0x50 + idx2;
    // POP reg1
    uint8_t pop_reg1 = 0x58 + idx1;
    // POP reg2
    uint8_t pop_reg2 = 0x58 + idx2;

    // XCHG via stack: PUSH reg1; PUSH reg2; POP reg1; POP reg2
    buffer_append(b, &push_reg1, 1);
    buffer_append(b, &push_reg2, 1);
    buffer_append(b, &pop_reg1, 1);
    buffer_append(b, &pop_reg2, 1);
}

// ============================================================================
// Strategy Registration
// ============================================================================

void register_reg_to_reg_badbyte_strategies(void) {
    static strategy_t strategy_mov_reg_reg = {
        .name = "MOV reg, reg - Bad Opcode/ModR/M Elimination",
        .can_handle = can_handle_mov_reg_reg_bad_opcode,
        .get_size = get_size_mov_reg_reg_bad_opcode,
        .generate = generate_mov_reg_reg_bad_opcode,
        .priority = 90
    };
    register_strategy(&strategy_mov_reg_reg);

    static strategy_t strategy_xchg_reg_reg = {
        .name = "XCHG reg, reg - Bad Opcode Elimination",
        .can_handle = can_handle_xchg_reg_reg_bad_opcode,
        .get_size = get_size_xchg_reg_reg_bad_opcode,
        .generate = generate_xchg_reg_reg_bad_opcode,
        .priority = 90
    };
    register_strategy(&strategy_xchg_reg_reg);
}
