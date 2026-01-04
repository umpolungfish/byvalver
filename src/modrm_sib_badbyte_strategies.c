#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>

// Calculate ModR/M byte for a memory operation
static uint8_t calculate_modrm(int reg_field, x86_reg base, int32_t disp, int *needs_sib) {
    *needs_sib = 0;

    if (base == X86_REG_INVALID) return 0xFF; // Invalid

    int rm = get_reg_index((uint8_t)base);

    // Check if SIB is needed (ESP/R12 as base, or has index)
    if (rm == 4) {
        *needs_sib = 1;
    }

    // Determine mod field based on displacement
    int mod;
    if (disp == 0 && rm != 5) { // EBP needs at least disp8
        mod = 0;
    } else if (disp >= -128 && disp <= 127) {
        mod = 1;
    } else {
        mod = 2;
    }

    return (mod << 6) | (reg_field << 3) | rm;
}

// Calculate SIB byte
static uint8_t calculate_sib(x86_reg base, x86_reg index, int scale) {
    int base_idx = (base == X86_REG_INVALID) ? 0 : get_reg_index((uint8_t)base);
    int index_idx = (index == X86_REG_INVALID) ? 4 : get_reg_index((uint8_t)index);
    int scale_val;

    switch(scale) {
        case 1: scale_val = 0; break;
        case 2: scale_val = 1; break;
        case 4: scale_val = 2; break;
        case 8: scale_val = 3; break;
        default: scale_val = 0; break;
    }

    return (scale_val << 6) | (index_idx << 3) | base_idx;
}

// Check if ModR/M or SIB bytes would contain bad bytes
static int has_bad_modrm_sib(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    cs_x86 *x86 = &insn->detail->x86;

    // Check each operand for memory references
    for (int i = 0; i < x86->op_count; i++) {
        cs_x86_op *op = &x86->operands[i];

        if (op->type == X86_OP_MEM) {
            // Determine register field based on instruction
            int reg_field = 0;

            // For MOV instructions, check which operand is the register
            if (insn->id == X86_INS_MOV) {
                if (i == 0 && x86->operands[1].type == X86_OP_REG) {
                    reg_field = get_reg_index((uint8_t)x86->operands[1].reg);
                } else if (i == 1 && x86->operands[0].type == X86_OP_REG) {
                    reg_field = get_reg_index((uint8_t)x86->operands[0].reg);
                }
            }

            int needs_sib = 0;
            uint8_t modrm = calculate_modrm(reg_field, op->mem.base, op->mem.disp, &needs_sib);

            // Check if ModR/M byte is bad
            if (!is_bad_byte_free_byte(modrm)) {
                return 1;
            }

            // Check SIB if needed
            if (needs_sib || op->mem.index != X86_REG_INVALID) {
                uint8_t sib = calculate_sib(op->mem.base, op->mem.index, op->mem.scale);
                if (!is_bad_byte_free_byte(sib)) {
                    return 1;
                }
            }
        }
    }

    return 0;
}

// ============================================================================
// Strategy: MOV [mem], reg with bad ModR/M/SIB → LEA + MOV [reg], reg
// ============================================================================

static int can_handle_mov_mem_reg_bad_modrm(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    // MOV [mem], reg
    if (insn->id == X86_INS_MOV &&
        insn->detail->x86.op_count == 2 &&
        insn->detail->x86.operands[0].type == X86_OP_MEM &&
        insn->detail->x86.operands[1].type == X86_OP_REG) {

        return has_bad_modrm_sib(insn);
    }

    return 0;
}

static size_t get_size_mov_mem_reg_bad_modrm(cs_insn *insn) {
    (void)insn;
    // PUSH temp_reg + LEA temp_reg, [mem] + MOV [temp_reg], src_reg + POP temp_reg
    return 20;
}

static void generate_mov_mem_reg_bad_modrm(struct buffer *b, cs_insn *insn) {
    cs_x86_op *dst_mem = &insn->detail->x86.operands[0];
    cs_x86_op *src_reg = &insn->detail->x86.operands[1];

    // Use ECX as temporary register
    uint8_t push_ecx[] = {0x51};
    buffer_append(b, push_ecx, 1);

    // LEA ECX, [original_mem]
    x86_reg base = dst_mem->mem.base;
    int32_t disp = dst_mem->mem.disp;

    if (base != X86_REG_INVALID && disp == 0) {
        // LEA ECX, [base]
        uint8_t lea[] = {0x8D, 0x08 | get_reg_index((uint8_t)base)};
        buffer_append(b, lea, 2);
    } else if (base != X86_REG_INVALID) {
        // LEA ECX, [base+disp]
        if (disp >= -128 && disp <= 127) {
            uint8_t lea[] = {0x8D, 0x48 | get_reg_index((uint8_t)base), (uint8_t)disp};
            buffer_append(b, lea, 3);
        } else {
            uint8_t lea[] = {0x8D, 0x88 | get_reg_index((uint8_t)base), 0, 0, 0, 0};
            memcpy(lea + 2, &disp, 4);
            buffer_append(b, lea, 6);
        }
    }

    // MOV [ECX], src_reg
    int src_idx = get_reg_index((uint8_t)src_reg->reg);
    uint8_t mov[] = {0x89, 0x01 | (src_idx << 3)};
    buffer_append(b, mov, 2);

    // POP ECX
    uint8_t pop_ecx[] = {0x59};
    buffer_append(b, pop_ecx, 1);
}

// ============================================================================
// Strategy: MOV reg, [mem] with bad ModR/M/SIB → LEA + MOV reg, [reg]
// ============================================================================

static int can_handle_mov_reg_mem_bad_modrm(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    // MOV reg, [mem]
    if (insn->id == X86_INS_MOV &&
        insn->detail->x86.op_count == 2 &&
        insn->detail->x86.operands[0].type == X86_OP_REG &&
        insn->detail->x86.operands[1].type == X86_OP_MEM) {

        return has_bad_modrm_sib(insn);
    }

    return 0;
}

static size_t get_size_mov_reg_mem_bad_modrm(cs_insn *insn) {
    (void)insn;
    // PUSH temp_reg + LEA temp_reg, [mem] + MOV dst_reg, [temp_reg] + POP temp_reg
    return 20;
}

static void generate_mov_reg_mem_bad_modrm(struct buffer *b, cs_insn *insn) {
    cs_x86_op *dst_reg = &insn->detail->x86.operands[0];
    cs_x86_op *src_mem = &insn->detail->x86.operands[1];

    // Choose temporary register (ECX if dst is not ECX, otherwise use EDX)
    int temp_reg = (dst_reg->reg == X86_REG_ECX) ? X86_REG_EDX : X86_REG_ECX;
    uint8_t push_temp = (temp_reg == X86_REG_ECX) ? 0x51 : 0x52;
    uint8_t pop_temp = (temp_reg == X86_REG_ECX) ? 0x59 : 0x5A;

    buffer_append(b, &push_temp, 1);

    // LEA temp_reg, [original_mem]
    x86_reg base = src_mem->mem.base;
    int32_t disp = src_mem->mem.disp;
    int temp_idx = get_reg_index((uint8_t)temp_reg);

    if (base != X86_REG_INVALID && disp == 0) {
        uint8_t lea[] = {0x8D, (temp_idx << 3) | get_reg_index((uint8_t)base)};
        buffer_append(b, lea, 2);
    } else if (base != X86_REG_INVALID) {
        if (disp >= -128 && disp <= 127) {
            uint8_t lea[] = {0x8D, 0x40 | (temp_idx << 3) | get_reg_index((uint8_t)base), (uint8_t)disp};
            buffer_append(b, lea, 3);
        } else {
            uint8_t lea[] = {0x8D, 0x80 | (temp_idx << 3) | get_reg_index((uint8_t)base), 0, 0, 0, 0};
            memcpy(lea + 2, &disp, 4);
            buffer_append(b, lea, 6);
        }
    }

    // MOV dst_reg, [temp_reg]
    int dst_idx = get_reg_index((uint8_t)dst_reg->reg);
    uint8_t mov[] = {0x8B, (dst_idx << 3) | temp_idx};
    buffer_append(b, mov, 2);

    buffer_append(b, &pop_temp, 1);
}

// ============================================================================
// Strategy Registration
// ============================================================================

void register_modrm_sib_badbyte_strategies(void) {
    static strategy_t strategy_mov_mem_reg = {
        .name = "MOV [mem], reg - Bad ModR/M/SIB Elimination",
        .can_handle = can_handle_mov_mem_reg_bad_modrm,
        .get_size = get_size_mov_mem_reg_bad_modrm,
        .generate = generate_mov_mem_reg_bad_modrm,
        .priority = 88
    };
    register_strategy(&strategy_mov_mem_reg);

    static strategy_t strategy_mov_reg_mem = {
        .name = "MOV reg, [mem] - Bad ModR/M/SIB Elimination",
        .can_handle = can_handle_mov_reg_mem_bad_modrm,
        .get_size = get_size_mov_reg_mem_bad_modrm,
        .generate = generate_mov_reg_mem_bad_modrm,
        .priority = 88
    };
    register_strategy(&strategy_mov_reg_mem);
}
