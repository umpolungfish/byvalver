/*
 * vex_xmm_gpr_bridge_substitution_strategies.c
 * 
 * Implementation of the VEX XMM GPR-to-GPR Bridge substitution strategy.
 * Replaces a standard MOV GPR, GPR with a sequence using VMOVD/VMOVQ 
 * to transfer the value through XMM0, utilizing VEX prefixes to avoid 
 * traditional opcodes and null bytes.
 */

#include "strategy.h"
#include "utils.h"
#include <capstone/capstone.h>

/**
 * Helper to extract GPR index and size for VEX encoding.
 * Returns -1 if the register is not a supported GPR.
 */
static int get_gpr_encoding_info(x86_reg reg, int *size) {
    switch (reg) {
        /* 32-bit registers */
        case X86_REG_EAX:  *size = 4; return 0;
        case X86_REG_ECX:  *size = 4; return 1;
        case X86_REG_EDX:  *size = 4; return 2;
        case X86_REG_EBX:  *size = 4; return 3;
        case X86_REG_ESP:  *size = 4; return 4;
        case X86_REG_EBP:  *size = 4; return 5;
        case X86_REG_ESI:  *size = 4; return 6;
        case X86_REG_EDI:  *size = 4; return 7;
        case X86_REG_R8D:  *size = 4; return 8;
        case X86_REG_R9D:  *size = 4; return 9;
        case X86_REG_R10D: *size = 4; return 10;
        case X86_REG_R11D: *size = 4; return 11;
        case X86_REG_R12D: *size = 4; return 12;
        case X86_REG_R13D: *size = 4; return 13;
        case X86_REG_R14D: *size = 4; return 14;
        case X86_REG_R15D: *size = 4; return 15;

        /* 64-bit registers */
        case X86_REG_RAX:  *size = 8; return 0;
        case X86_REG_RCX:  *size = 8; return 1;
        case X86_REG_RDX:  *size = 8; return 2;
        case X86_REG_RBX:  *size = 8; return 3;
        case X86_REG_RSP:  *size = 8; return 4;
        case X86_REG_RBP:  *size = 8; return 5;
        case X86_REG_RSI:  *size = 8; return 6;
        case X86_REG_RDI:  *size = 8; return 7;
        case X86_REG_R8:   *size = 8; return 8;
        case X86_REG_R9:   *size = 8; return 9;
        case X86_REG_R10:  *size = 8; return 10;
        case X86_REG_R11:  *size = 8; return 11;
        case X86_REG_R12:  *size = 8; return 12;
        case X86_REG_R13:  *size = 8; return 13;
        case X86_REG_R14:  *size = 8; return 14;
        case X86_REG_R15:  *size = 8; return 15;

        default: return -1;
    }
}

/**
 * Checks if the instruction is a MOV GPR, GPR that we can handle.
 */
int can_handle_vex_xmm_bridge(cs_insn *insn) {
    if (insn->id != X86_INS_MOV) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *ops = insn->detail->x86.operands;

    if (ops[0].type != X86_OP_REG || ops[1].type != X86_OP_REG) {
        return 0;
    }

    int size_dst, size_src;
    int idx_dst = get_gpr_encoding_info(ops[0].reg, &size_dst);
    int idx_src = get_gpr_encoding_info(ops[1].reg, &size_src);

    // Only handle 32-bit or 64-bit GPR moves of identical size
    if (idx_dst == -1 || idx_src == -1 || size_dst != size_src) {
        return 0;
    }

    // Only apply if the original instruction contains bad bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    return 1;
}

/**
 * Returns a conservative size for the two-instruction VEX sequence.
 * Each VEX instruction is 5 bytes (3-byte prefix + 1-byte opcode + 1-byte ModRM).
 */
size_t get_size_vex_xmm_bridge(cs_insn *insn) {
    (void)insn;
    return 10; 
}

/**
 * Generates the VEX sequence:
 * VMOVD/Q XMM0, GPR_SRC
 * VMOVD/Q GPR_DEST, XMM0
 */
void generate_vex_xmm_bridge(struct buffer *b, cs_insn *insn) {
    cs_x86_op *ops = insn->detail->x86.operands;
    int size_src, size_dst;
    int idx_src = get_gpr_encoding_info(ops[1].reg, &size_src);
    int idx_dst = get_gpr_encoding_info(ops[0].reg, &size_dst);

    /* 
     * Instruction 1: VMOVD/Q XMM0, GPR_SRC 
     * Opcode: 66 0F 6E /r
     */
    {
        uint8_t w = (size_src == 8) ? 1 : 0;
        uint8_t r_inv = 1; // xmm0 index 0 -> bit is inverted
        uint8_t x_inv = 1; // unused
        uint8_t b_inv = (idx_src >= 8) ? 0 : 1; // inverted B bit for GPR source
        
        // VEX 3-byte prefix: C4 [R X B m-mmmm] [W vvvv L pp]
        buffer_write_byte(b, 0xC4);
        buffer_write_byte(b, (r_inv << 7) | (x_inv << 6) | (b_inv << 5) | 0x01); // map 1
        buffer_write_byte(b, (w << 7) | (0x0F << 3) | (0 << 2) | 0x01); // vvvv=1111, L=0, pp=1 (66h)
        
        // Opcode
        buffer_write_byte(b, 0x6E);
        
        // ModRM: [mod:3 (11)] [reg:0 (xmm0)] [rm:idx_src & 7]
        buffer_write_byte(b, 0xC0 | (0 << 3) | (idx_src & 0x07));
    }

    /* 
     * Instruction 2: VMOVD/Q GPR_DST, XMM0 
     * Opcode: 66 0F 7E /r
     */
    {
        uint8_t w = (size_dst == 8) ? 1 : 0;
        uint8_t r_inv = 1; // xmm0 index 0 -> bit is inverted
        uint8_t x_inv = 1; // unused
        uint8_t b_inv = (idx_dst >= 8) ? 0 : 1; // inverted B bit for GPR destination
        
        // VEX 3-byte prefix
        buffer_write_byte(b, 0xC4);
        buffer_write_byte(b, (r_inv << 7) | (x_inv << 6) | (b_inv << 5) | 0x01);
        buffer_write_byte(b, (w << 7) | (0x0F << 3) | (0 << 2) | 0x01);
        
        // Opcode
        buffer_write_byte(b, 0x7E);
        
        // ModRM: [mod:3 (11)] [reg:0 (xmm0)] [rm:idx_dst & 7]
        buffer_write_byte(b, 0xC0 | (0 << 3) | (idx_dst & 0x07));
    }
}

strategy_t vex_xmm_gpr_bridge_substitution_strategy = {
    .name = "vex_xmm_gpr_bridge_substitution",
    .can_handle = can_handle_vex_xmm_bridge,
    .get_size = get_size_vex_xmm_bridge,
    .generate = generate_vex_xmm_bridge,
    .priority = 82,
    .target_arch = BYVAL_ARCH_X86
};

void register_vex_xmm_gpr_bridge_substitution_strategies(void) {
    register_strategy(&vex_xmm_gpr_bridge_substitution_strategy);
}