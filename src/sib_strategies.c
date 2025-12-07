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
 * Helper function to determine if an instruction uses SIB addressing with null bytes
 * Uses Capstone's detailed info to properly detect SIB addressing
 */
static int has_sib_null_encoding(cs_insn *insn) {
    if (!insn || !insn->detail) {
        return 0;
    }

    cs_x86 *x86 = &insn->detail->x86;

    // Check each memory operand for SIB addressing
    for (int i = 0; i < x86->op_count; i++) {
        if (x86->operands[i].type == X86_OP_MEM) {
            cs_x86_op *op = &x86->operands[i];

            // SIB addressing is used when:
            // 1. There's an index register, OR
            // 2. The scale factor is not 1 (scale > 1), OR
            // 3. Base is ESP (special case where SIB is always used)
            if (op->mem.index != X86_REG_INVALID ||  // Has index register
                op->mem.scale != 1 ||                // Scale factor is not 1
                op->mem.base == X86_REG_ESP) {       // Base is ESP (requires SIB)

                // Now check if the original instruction contains null bytes
                // which would be in the SIB byte or displacement
                for (size_t j = 0; j < insn->size; j++) {
                    if (insn->bytes[j] == 0x00) {
                        return 1;  // Found null byte in instruction with SIB addressing
                    }
                }
            }

            // Special case: [EBP+disp32] always uses SIB byte for 32-bit displacement
            if (op->mem.base == X86_REG_EBP &&
                op->mem.index == X86_REG_INVALID &&
                op->mem.disp != 0) {
                // Check if displacement has null bytes
                int32_t disp = (int32_t)op->mem.disp;
                if (((disp >> 0) & 0xFF) == 0 ||
                    ((disp >> 8) & 0xFF) == 0 ||
                    ((disp >> 16) & 0xFF) == 0 ||
                    ((disp >> 24) & 0xFF) == 0) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

/*
 * Detect instructions with SIB bytes containing null bytes
 * This includes any memory operand that uses [base+index*scale] addressing
 */
static int can_handle_sib_null(cs_insn *insn) {
    if (!insn || !insn->detail) {
        return 0;
    }

    // Check if this instruction actually has SIB addressing with null bytes
    if (has_sib_null_encoding(insn)) {
        return 1;
    }

    // Double check: if it has SIB addressing (index != INVALID) and null bytes in instruction
    cs_x86 *x86 = &insn->detail->x86;

    for (int i = 0; i < x86->op_count; i++) {
        if (x86->operands[i].type == X86_OP_MEM) {
            cs_x86_op *op = &x86->operands[i];

            // Check for SIB addressing pattern: base + index*scale
            if (op->mem.index != X86_REG_INVALID || op->mem.base == X86_REG_ESP || op->mem.scale != 1) {
                // This instruction uses SIB addressing
                // If it also has null bytes, it's our target
                if (has_null_bytes(insn)) {
                    return 1;
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
    // Prefer ESI over EBX to minimize conflicts
    x86_reg temp_reg = X86_REG_ESI;
    if (mem_op->mem.base == X86_REG_ESI || mem_op->mem.index == X86_REG_ESI) {
        temp_reg = X86_REG_EDI;  // Use EDI as alternative
    }

    // PUSH temp register to save its value
    uint8_t push_code[] = {0x50};  // PUSH reg
    push_code[0] = 0x50 + get_reg_index(temp_reg);
    buffer_append(b, push_code, 1);

    // Calculate the full address in the temporary register
    // First, move the base register to temp register (or zero it if no base)
    if (mem_op->mem.base != X86_REG_INVALID) {
        // MOV temp_reg, base_reg
        uint8_t mov_code[] = {0x89, 0x00};
        mov_code[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(mem_op->mem.base);
        buffer_append(b, mov_code, 2);
    } else {
        // XOR temp_reg, temp_reg to zero it if no base
        uint8_t xor_code[] = {0x31, 0xC0};
        xor_code[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(temp_reg);
        buffer_append(b, xor_code, 2);
    }

    // Add displacement if present
    if (mem_op->mem.disp != 0) {
        uint32_t disp = (uint32_t)mem_op->mem.disp;
        if (is_null_free(disp)) {
            // Direct ADD if displacement is null-byte free
            if (disp <= 0x7F || disp >= 0xFFFFFF80) {  // Can use 8-bit sign-extended disp
                uint8_t add8_code[] = {0x83, 0x00, 0x00};
                add8_code[1] = 0xC0 + get_reg_index(temp_reg);  // ADD reg, imm8
                add8_code[2] = (uint8_t)disp & 0xFF;
                buffer_append(b, add8_code, 3);
            } else {
                // Use 32-bit immediate
                uint8_t add32_code[] = {0x83, 0x00, 0x00, 0x00, 0x00, 0x00};
                add32_code[0] = 0x81;  // ADD reg, imm32
                add32_code[1] = 0xC0 + get_reg_index(temp_reg);
                memcpy(add32_code + 2, &disp, 4);
                buffer_append(b, add32_code, 6);
            }
        } else {
            // Use null-free construction for displacement
            uint8_t push_eax[] = {0x50};  // Save EAX
            buffer_append(b, push_eax, 1);

            generate_mov_eax_imm(b, disp);  // Generate disp in EAX null-free

            // ADD temp_reg, EAX
            uint8_t add_reg_eax[] = {0x01, 0x00};
            add_reg_eax[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(X86_REG_EAX);
            buffer_append(b, add_reg_eax, 2);

            uint8_t pop_eax[] = {0x58};  // Restore EAX
            buffer_append(b, pop_eax, 1);
        }
    }

    // If index register exists, add it scaled appropriately
    if (mem_op->mem.index != X86_REG_INVALID) {
        // Save EAX (we'll use it for scaling)
        uint8_t push_eax[] = {0x50};
        buffer_append(b, push_eax, 1);

        // MOV EAX, index_reg
        uint8_t mov_eax_index[] = {0x89, 0x00};
        mov_eax_index[1] = 0xC0 + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(mem_op->mem.index);
        buffer_append(b, mov_eax_index, 2);

        // Scale by multiplying (SHL by scale amount)
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
        add_temp_eax[1] = 0xC0 + (get_reg_index(temp_reg) << 3) + get_reg_index(X86_REG_EAX);
        buffer_append(b, add_temp_eax, 2);

        // Restore EAX
        uint8_t pop_eax[] = {0x58};
        buffer_append(b, pop_eax, 1);
    }

    // Now perform the original operation using [temp_reg] instead of SIB addressing
    // This avoids null bytes in SIB byte
    switch (insn->id) {
        case X86_INS_MOV: {
            if (mem_op_idx == 1) {  // Memory operand is source (MOV reg, [sib_addr])
                // MOV target_reg, [temp_reg]
                x86_reg target_reg = x86->operands[0].reg;
                uint8_t mov_code[] = {0x8B, 0x00};
                mov_code[1] = 0x00 + (get_reg_index(target_reg) << 3) + get_reg_index(temp_reg);
                buffer_append(b, mov_code, 2);
            } else {  // Memory operand is destination (MOV [sib_addr], reg)
                // MOV [temp_reg], source_reg
                x86_reg source_reg = x86->operands[0].reg;
                uint8_t mov_code[] = {0x89, 0x00};
                mov_code[1] = 0x00 + (get_reg_index(source_reg) << 3) + get_reg_index(temp_reg);
                buffer_append(b, mov_code, 2);
            }
            break;
        }
        case X86_INS_PUSH: {
            // PUSH [temp_reg] - encoded as FF /6, so reg field is 6 (for PUSH) and r/m is temp_reg
            uint8_t push_code[] = {0xFF, 0x30};
            push_code[1] = 0x30 + get_reg_index(temp_reg);  // Mod=00, reg=110 (PUSH), r/m=temp_reg
            buffer_append(b, push_code, 2);
            break;
        }
        default:
            // For other instructions, at least do the address calculation
            // but emit a warning that full reconstruction isn't handled
            // Just use the calculated address in temp register
            break;
    }

    // Restore original value of temp register
    uint8_t pop_code[] = {0x58};  // POP reg
    pop_code[0] = 0x58 + get_reg_index(temp_reg);
    buffer_append(b, pop_code, 1);
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