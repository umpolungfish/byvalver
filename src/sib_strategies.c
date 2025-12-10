/*
 * SIB (Scale-Index-Base) Addressing Null-Byte Elimination Strategy
 *
 * PROBLEM: Instructions with SIB addressing can generate null bytes in SIB byte
 *
 * Examples:
 *   FSTP qword ptr [EAX+EAX] → DD 1C 00 (SIB byte is null)
 *   MOV EAX, [EBX+ECX*2] with specific addressing → SIB byte may contain null
 *
 * SIB BYTE BREAKDOWN:
 *   [7-6] Scale (0=1x, 1=2x, 2=4x, 3=8x)
 *   [5-3] Index register (0-7 for EAX-EDI)
 *   [2-0] Base register (0-7 for EAX-EDI)
 *   Special case: [ESP] uses [EAX+ESP] with null index (0x24)
 *
 * SOLUTIONS:
 *   1. Change register combinations to avoid null SIB
 *   2. Use displacement instead of index register
 *   3. Use temporary register for address calculation
 *
 * Priority: 65 (medium-high)
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "strategy.h"
#include "utils.h"
#include <capstone/capstone.h>

/* Forward declarations */
extern void register_strategy(strategy_t *s);

/*
 * Detect instructions with SIB bytes containing null bytes
 * This includes any memory operand that uses [base+index*scale] addressing
 * IMPORTANT: Only handle instructions that are actually supported in generate_sib_null()
 */
static int can_handle_sib_null(cs_insn *insn) {
    if (!insn || !insn->detail) {
        return 0;
    }

    // CRITICAL: Only handle instructions we actually support in the switch statement
    // Otherwise we'll fall through to default case which just copies the original with nulls!
    if (insn->id != X86_INS_MOV && insn->id != X86_INS_PUSH && insn->id != X86_INS_LEA &&
        insn->id != X86_INS_CMP && insn->id != X86_INS_ADD && insn->id != X86_INS_SUB &&
        insn->id != X86_INS_AND && insn->id != X86_INS_OR && insn->id != X86_INS_XOR) {
        return 0;  // Don't handle instructions not in our switch statement
    }

    // Check if this instruction actually has SIB addressing with potential null bytes
    cs_x86 *x86 = &insn->detail->x86;

    for (int i = 0; i < x86->op_count; i++) {
        if (x86->operands[i].type == X86_OP_MEM) {
            cs_x86_op *op = &x86->operands[i];

            // SIB addressing is used when:
            // 1. Has index register OR
            // 2. Scale factor is not 1 OR
            // 3. Base register is ESP (special case that always uses SIB)
            if (op->mem.index != X86_REG_INVALID || op->mem.base == X86_REG_ESP || op->mem.scale != 1) {
                // This instruction is using SIB addressing
                // Check if the instruction encoding contains null bytes
                if (has_null_bytes(insn)) {
                    return 1;  // SIB addressing with null bytes in instruction encoding
                }

                // Also check if just the displacement part has null bytes (even if SIB byte itself doesn't)
                // This catches cases where [EBP+disp32] or similar patterns produce nulls
                if (op->mem.disp != 0) {
                    uint64_t disp = op->mem.disp;
                    for (int j = 0; j < 8; j++) {
                        if (((disp >> (j * 8)) & 0xFF) == 0x00) {
                            return 1;  // SIB addressing with null bytes in displacement
                        }
                    }
                }
            }
            // Special case: [EBP+disp32] uses SIB byte for 32-bit displacement
            else if (op->mem.base == X86_REG_EBP && op->mem.disp != 0) {
                // Check if displacement has null bytes
                uint64_t disp = op->mem.disp;
                for (int j = 0; j < 8; j++) {
                    if (((disp >> (j * 8)) & 0xFF) == 0x00) {
                        return 1;  // [EBP+disp] with null bytes in displacement
                    }
                }
            }
        }
    }

    return 0;
}

/*
 * Calculate replacement size for SIB null elimination
 * PUSH temp_reg (1) + MOV temp_reg, base_reg (2) +
 * LEA temp_reg, [temp_reg + index_reg*scale] (3-4) +
 * original_op [temp_reg] (2-4) + POP temp_reg (1)
 */
static size_t get_size_sib_null(cs_insn *insn) {
    (void)insn;
    // Conservative estimate: PUSH (1) + MOV (2) + LEA (3-4) + OP (2-4) + POP (1) = 9-12 bytes
    return 12;
}

/*
 * Generate null-free replacement using temporary register for address calculation
 */
static void generate_sib_null(struct buffer *b, cs_insn *insn) {
    if (!insn || !insn->detail) {
        return;
    }

    cs_x86 *x86 = &insn->detail->x86;

    // Find a memory operand that uses SIB addressing
    // SIB is used when: index != INVALID OR base == ESP OR scale != 1
    cs_x86_op *mem_op = NULL;
    int mem_op_idx = -1;

    for (int i = 0; i < x86->op_count; i++) {
        if (x86->operands[i].type == X86_OP_MEM) {
            cs_x86_op *op = &x86->operands[i];
            if (op->mem.index != X86_REG_INVALID || op->mem.base == X86_REG_ESP || op->mem.scale != 1) {
                mem_op = op;
                mem_op_idx = i;
                break;
            }
        }
    }

    if (!mem_op) {
        // If no SIB addressing found, just output the original instruction
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    // Use a temporary register for address calculation
    // Prefer safer registers to minimize conflicts
    x86_reg temp_reg = X86_REG_ECX;  // Use ECX as primary choice
    if (mem_op->mem.base == X86_REG_ECX || mem_op->mem.index == X86_REG_ECX) {
        temp_reg = X86_REG_EDX;  // Use EDX if ECX is in use
        if (mem_op->mem.base == X86_REG_EDX || mem_op->mem.index == X86_REG_EDX) {
            temp_reg = X86_REG_EDI;  // Use EDI as last resort
            if (mem_op->mem.base == X86_REG_EDI || mem_op->mem.index == X86_REG_EDI) {
                // If all our preferred temp registers are in use, fall back to original
                buffer_append(b, insn->bytes, insn->size);
                return;
            }
        }
    }

    // Save temp register
    uint8_t push_temp[] = {0x50 + get_reg_index(temp_reg)};  // PUSH temp_reg
    buffer_append(b, push_temp, 1);

    // Calculate the full address in the temporary register
    // First, move the base register to temp register (or XOR to zero if no base)
    if (mem_op->mem.base != X86_REG_INVALID) {
        // MOV temp_reg, base_reg
        if (get_reg_index(temp_reg) == get_reg_index(mem_op->mem.base)) {
            // Same register, no need to move
        } else {
            uint8_t mov_code[] = {0x89, 0x00};
            mov_code[1] = 0xC0 + (get_reg_index(mem_op->mem.base) << 3) + get_reg_index(temp_reg);
            buffer_append(b, mov_code, 2);
        }
    } else {
        // XOR temp_reg, temp_reg to zero it if no base
        uint8_t xor_code[] = {0x31, 0xC0};
        xor_code[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(temp_reg);
        buffer_append(b, xor_code, 2);
    }

    // If index register exists, add it scaled appropriately
    if (mem_op->mem.index != X86_REG_INVALID) {
        // Save EAX temporarily
        uint8_t push_eax[] = {0x50};  // PUSH EAX
        buffer_append(b, push_eax, 1);

        // MOV EAX, index_reg
        uint8_t mov_eax_index[] = {0x89, 0x00};
        mov_eax_index[1] = 0xC0 + (get_reg_index(mem_op->mem.index) << 3) + get_reg_index(X86_REG_EAX);
        buffer_append(b, mov_eax_index, 2);

        // Scale EAX by multiplying (SHL by scale amount)
        uint32_t scale = mem_op->mem.scale;
        if (scale > 1) {
            uint32_t shift_amount = 0;
            // Calculate shift amount from scale (2=1, 4=2, 8=3)
            if (scale == 2) shift_amount = 1;
            else if (scale == 4) shift_amount = 2;
            else if (scale == 8) shift_amount = 3;

            for (uint32_t i = 0; i < shift_amount; i++) {
                uint8_t shl_eax[] = {0xD1, 0xE0};
                shl_eax[1] = 0xE0 + get_reg_index(X86_REG_EAX);  // SHL EAX, 1
                buffer_append(b, shl_eax, 2);
            }
        }

        // ADD temp_reg, EAX (add scaled index)
        uint8_t add_temp_eax[] = {0x01, 0x00};
        add_temp_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(temp_reg);
        buffer_append(b, add_temp_eax, 2);

        // Restore EAX
        uint8_t pop_eax[] = {0x58};  // POP EAX
        buffer_append(b, pop_eax, 1);
    }

    // Add displacement if present
    if (mem_op->mem.disp != 0) {
        uint32_t disp = (uint32_t)mem_op->mem.disp;

        // Use null-free construction for displacement
        uint8_t push_eax[] = {0x50};  // PUSH EAX to save
        buffer_append(b, push_eax, 1);

        generate_mov_eax_imm(b, disp);  // Generate disp in EAX null-free

        // ADD temp_reg, EAX
        uint8_t add_temp_eax[] = {0x01, 0x00};
        add_temp_eax[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(temp_reg);
        buffer_append(b, add_temp_eax, 2);

        uint8_t pop_eax[] = {0x58};  // POP EAX to restore
        buffer_append(b, pop_eax, 1);
    }

    // Now perform the original operation using [temp_reg] instead of SIB addressing
    // This avoids null bytes in SIB byte
    int original_op_idx = mem_op_idx;

    // Replace the SIB addressing with direct addressing using our temp register
    // Use SIB addressing to ensure no null bytes in ModR/M for addressing mode
    switch (insn->id) {
        case X86_INS_MOV: {
            if (original_op_idx == 1) {  // Memory operand is source (MOV reg, [sib_addr])
                // MOV target_reg, [temp_reg] using SIB addressing to avoid nulls
                x86_reg target_reg = x86->operands[0].reg;
                uint8_t sib_mov_code[] = {0x8B, 0x04, 0x20};
                sib_mov_code[1] = 0x04 | (get_reg_index(target_reg) << 3);  // ModR/M: mod=00, reg=target_reg, r/m=SIB
                sib_mov_code[2] = (0 << 6) | (4 << 3) | get_reg_index(temp_reg);  // SIB: scale=0, index=ESP (dummy), base=temp_reg
                buffer_append(b, sib_mov_code, 3);
            } else {  // Memory operand is destination (MOV [sib_addr], reg)
                // MOV [temp_reg], source_reg using SIB addressing to avoid nulls
                x86_reg source_reg = x86->operands[1].reg;  // Second operand is the source
                uint8_t sib_mov_code[] = {0x89, 0x04, 0x20};
                sib_mov_code[1] = 0x04 | (get_reg_index(source_reg) << 3);  // ModR/M: mod=00, reg=source_reg, r/m=SIB
                sib_mov_code[2] = (0 << 6) | (4 << 3) | get_reg_index(temp_reg);  // SIB: scale=0, index=ESP (dummy), base=temp_reg
                buffer_append(b, sib_mov_code, 3);
            }
            break;
        }
        case X86_INS_PUSH: {
            // PUSH [temp_reg] using SIB addressing to avoid nulls
            uint8_t sib_push_code[] = {0xFF, 0x34, 0x20};
            sib_push_code[1] = 0x34 | (6 << 3);  // ModR/M: mod=00, reg=110 (PUSH), r/m=SIB
            sib_push_code[2] = (0 << 6) | (4 << 3) | get_reg_index(temp_reg);  // SIB: scale=0, index=ESP (dummy), base=temp_reg
            buffer_append(b, sib_push_code, 3);
            break;
        }
        case X86_INS_LEA: {
            // LEA target_reg, [temp_reg] - load address of temp_reg using SIB addressing
            x86_reg target_reg = x86->operands[0].reg;
            uint8_t sib_lea_code[] = {0x8D, 0x04, 0x20};
            sib_lea_code[1] = 0x04 | (get_reg_index(target_reg) << 3);  // ModR/M: mod=00, reg=target_reg, r/m=SIB
            sib_lea_code[2] = (0 << 6) | (4 << 3) | get_reg_index(temp_reg);  // SIB: scale=0, index=ESP (dummy), base=temp_reg
            buffer_append(b, sib_lea_code, 3);
            break;
        }
        case X86_INS_CMP: {
            if (original_op_idx == 1) {  // Memory operand is source (CMP reg, [sib_addr])
                // CMP reg, [temp_reg] using SIB addressing
                x86_reg reg = x86->operands[0].reg;
                uint8_t sib_cmp_code[] = {0x39, 0x04, 0x20};
                sib_cmp_code[1] = 0x04 | (get_reg_index(reg) << 3);  // ModR/M: mod=00, reg=reg, r/m=SIB
                sib_cmp_code[2] = (0 << 6) | (4 << 3) | get_reg_index(temp_reg);  // SIB: scale=0, index=ESP (dummy), base=temp_reg
                buffer_append(b, sib_cmp_code, 3);
            } else {  // Memory operand is destination (CMP [sib_addr], reg)
                // CMP [temp_reg], reg using SIB addressing
                x86_reg reg = x86->operands[1].reg;  // Second operand is the reg
                uint8_t sib_cmp_code[] = {0x3B, 0x04, 0x20};
                sib_cmp_code[1] = 0x04 | (get_reg_index(reg) << 3);  // ModR/M: mod=00, reg=reg, r/m=SIB
                sib_cmp_code[2] = (0 << 6) | (4 << 3) | get_reg_index(temp_reg);  // SIB: scale=0, index=ESP (dummy), base=temp_reg
                buffer_append(b, sib_cmp_code, 3);
            }
            break;
        }
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_AND:
        case X86_INS_OR:
        case X86_INS_XOR: {
            if (original_op_idx == 1) {  // Memory operand is source (OP reg, [sib_addr])
                // OP reg, [temp_reg] using SIB addressing
                x86_reg reg = x86->operands[0].reg;
                uint8_t op_code;
                switch (insn->id) {
                    case X86_INS_ADD: op_code = 0x01; break;  // ADD r/m32, r32
                    case X86_INS_SUB: op_code = 0x29; break;  // SUB r/m32, r32
                    case X86_INS_AND: op_code = 0x21; break;  // AND r/m32, r32
                    case X86_INS_OR:  op_code = 0x09; break;  // OR r/m32, r32
                    case X86_INS_XOR: op_code = 0x31; break;  // XOR r/m32, r32
                    default: op_code = 0x01; break;  // Default to ADD
                }
                uint8_t sib_final_code[] = {op_code, 0x04, 0x20};
                sib_final_code[1] = 0x04 | (get_reg_index(reg) << 3);  // ModR/M: mod=00, reg=reg, r/m=SIB
                sib_final_code[2] = (0 << 6) | (4 << 3) | get_reg_index(temp_reg);  // SIB: scale=0, index=ESP (dummy), base=temp_reg
                buffer_append(b, sib_final_code, 3);
            } else {  // Memory operand is destination (OP [sib_addr], reg)
                // OP [temp_reg], reg using SIB addressing
                x86_reg reg = x86->operands[1].reg;  // Second operand is the reg
                uint8_t op_code;
                switch (insn->id) {
                    case X86_INS_ADD: op_code = 0x03; break;  // ADD r32, r/m32
                    case X86_INS_SUB: op_code = 0x2B; break;  // SUB r32, r/m32
                    case X86_INS_AND: op_code = 0x23; break;  // AND r32, r/m32
                    case X86_INS_OR:  op_code = 0x0B; break;  // OR r32, r/m32
                    case X86_INS_XOR: op_code = 0x33; break;  // XOR r32, r/m32
                    default: op_code = 0x03; break;  // Default to ADD
                }
                uint8_t sib_final_code[] = {op_code, 0x04, 0x20};
                sib_final_code[1] = 0x04 | (get_reg_index(reg) << 3);  // ModR/M: mod=00, reg=reg, r/m=SIB
                sib_final_code[2] = (0 << 6) | (4 << 3) | get_reg_index(temp_reg);  // SIB: scale=0, index=ESP (dummy), base=temp_reg
                buffer_append(b, sib_final_code, 3);
            }
            break;
        }
        default:
            // For other instructions, fall back to original encoding
            // This is safe since the strategy is only applied when nulls exist
            buffer_append(b, insn->bytes, insn->size);
            break;
    }

    // Restore original temp register value
    uint8_t pop_temp[] = {0x58 + get_reg_index(temp_reg)};  // POP temp_reg
    buffer_append(b, pop_temp, 1);
}

/* Strategy definition */
static strategy_t sib_null_strategy = {
    .name = "SIB Addressing Null Elimination",
    .can_handle = can_handle_sib_null,
    .get_size = get_size_sib_null,
    .generate = generate_sib_null,
    .priority = 65
};

/* Registration function */
void register_sib_strategies() {
    register_strategy(&sib_null_strategy);
}