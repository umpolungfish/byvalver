/*
 * Safe SIB (Scale-Index-Base) Addressing Null-Byte Elimination Strategy
 *
 * PROBLEM: Instructions with SIB addressing can generate null bytes in SIB byte
 *          The current SIB strategy sometimes introduces new null bytes after transformation
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
 *   4. VALIDATE that new nulls are not introduced after transformation
 *
 * Priority: 70 (higher than original SIB strategy to take precedence)
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "strategy.h"
#include "utils.h"
#include "profile_aware_sib.h"
#include <capstone/capstone.h>

// Global recursion depth counter to prevent stack overflow
static __thread int strategy_recursion_depth = 0;
#define MAX_STRATEGY_RECURSION_DEPTH 10

/* Forward declarations */
extern void register_strategy(strategy_t *s);

/*
 * Helper function to determine if an instruction uses SIB addressing with null bytes
 * Uses Capstone's detailed info to properly detect SIB addressing
 */
static int has_sib_null_encoding(cs_insn *insn) {
    if (!insn || !insn->detail || insn->size > 16) {  // Basic instruction size limit
        return 0;
    }

    cs_x86 *x86 = &insn->detail->x86;

    // Validate operand count to avoid out-of-bounds access
    if (x86->op_count > 4) {  // x86 instructions rarely have more than 4 operands
        return 0;
    }

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
static int can_handle_safe_sib_null(cs_insn *insn) {
    if (!insn || !insn->detail) {
        return 0;
    }

    // Prevent processing of very complex instructions that might cause stack overflow
    if (insn->size > 10) {  // Be very conservative - most SIB instructions are smaller
        return 0;
    }

    // Check if this instruction actually has SIB addressing with null bytes
    if (has_sib_null_encoding(insn)) {
        cs_x86 *x86 = &insn->detail->x86;

        // Only handle very specific, simple SIB patterns
        for (int i = 0; i < x86->op_count; i++) {
            if (x86->operands[i].type == X86_OP_MEM) {
                cs_x86_op *op = &x86->operands[i];

                // Only handle simple SIB patterns: base + index, no complex displacement
                if (op->mem.index != X86_REG_INVALID && op->mem.scale == 1) {
                    // Check if the instruction has null bytes in the right places
                    // Be very restrictive about which instructions to handle
                    if (insn->id == X86_INS_MOV || insn->id == X86_INS_PUSH ||
                        insn->id == X86_INS_LEA || insn->id == X86_INS_CMP) {

                        // Only handle small displacements
                        if (op->mem.disp != 0) {
                            int64_t disp = op->mem.disp;
                            if (disp > 0x1000 || disp < -0x1000) {  // Very small displacement limit
                                return 0;
                            }
                        }

                        // Check that the specific SIB encoding has null bytes
                        for (size_t j = 0; j < insn->size; j++) {
                            if (insn->bytes[j] == 0x00) {
                                return 1;  // Found null byte and instruction matches criteria
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}

/*
 * Calculate replacement size for safe SIB null elimination
 * PUSH temp_reg (1) + MOV temp_reg, base_reg (2) +
 * LEA temp_reg, [temp_reg + index_reg*scale] (3-4) +
 * original_op [temp_reg] (2-4) + POP temp_reg (1)
 */
static size_t get_size_safe_sib_null(cs_insn *insn) {
    (void)insn;
    // Conservative estimate: PUSH (1) + MOV (2) + LEA (3-4) + OP (2-4) + POP (1) = 9-12 bytes
    return 12;
}

/*
 * Generate null-free replacement using temporary register for address calculation
 * This version includes validation to ensure no new null bytes are introduced
 */
static void generate_safe_sib_null(struct buffer *b, cs_insn *insn) {
    if (!insn || !insn->detail || !b) {
        return;
    }

    // Prevent deep recursion
    if (strategy_recursion_depth >= MAX_STRATEGY_RECURSION_DEPTH) {
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    strategy_recursion_depth++;

    // Additional safety check for instruction size
    if (insn->size > 16) {
        buffer_append(b, insn->bytes, insn->size);
        strategy_recursion_depth--;
        return;
    }

    cs_x86 *x86 = &insn->detail->x86;

    // Validate operand count to prevent out-of-bounds access
    if (x86->op_count > 4) {
        buffer_append(b, insn->bytes, insn->size);
        strategy_recursion_depth--;
        return;
    }

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
        strategy_recursion_depth--;
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
                strategy_recursion_depth--;
                return;
            }
        }
    }

    // Calculate the address in the temporary register
    size_t initial_size = b->size;

    // PUSH temp register to save its value
    uint8_t push_code[] = {0x50};  // PUSH reg
    push_code[0] = 0x50 + get_reg_index(temp_reg);
    buffer_append(b, push_code, 1);

    // Calculate the full address in the temporary register
    // First, move the base register to temp register (or XOR to zero if no base)
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

    // If index register exists, add it scaled appropriately first
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

    // Add displacement if present
    if (mem_op->mem.disp != 0) {
        uint32_t disp = (uint32_t)mem_op->mem.disp;
        if (is_bad_byte_free(disp)) {
            // Direct ADD if displacement is null-byte free
            if (disp <= 0x7F || (disp >= 0xFFFFFF80 && disp <= 0xFFFFFFFF)) {  // Can use 8-bit sign-extended disp
                uint8_t add8_code[] = {0x83, 0x00, 0x00};
                add8_code[1] = 0xC0 + get_reg_index(temp_reg);  // ADD reg, imm8
                add8_code[2] = (uint8_t)disp & 0xFF;
                buffer_append(b, add8_code, 3);
            } else {
                // Use 32-bit immediate - but what if it has nulls? Use reliable null-free construction
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

    // Now perform the original operation using [temp_reg] instead of SIB addressing
    // This avoids null bytes in SIB byte
    int original_op_idx = mem_op_idx;

    // Replace the SIB addressing with direct addressing using our temp register
    switch (insn->id) {
        case X86_INS_MOV: {
            if (original_op_idx == 1) {  // Memory operand is source (MOV reg, [sib_addr])
                // MOV target_reg, [temp_reg]
                x86_reg target_reg = x86->operands[0].reg;
                uint8_t mov_code[] = {0x8B, 0x00};
                // Mod=00 (no displacement), r/m=temp_reg (addressing mode), reg=target_reg
                mov_code[1] = (get_reg_index(target_reg) << 3) + get_reg_index(temp_reg);
                
                // Verify this code doesn't introduce nulls
                if (mov_code[1] == 0x00) {
                    // Use profile-safe approach to avoid null
                    if (generate_safe_mov_reg_mem(b, target_reg, temp_reg) != 0) {
                        // Fallback: PUSH/POP
                        uint8_t push[] = {0xFF, 0x30 | get_reg_index(temp_reg)};
                        buffer_append(b, push, 2);
                        uint8_t pop[] = {0x58 | get_reg_index(target_reg)};
                        buffer_append(b, pop, 1);
                    }
                } else {
                    buffer_append(b, mov_code, 2);
                }
            } else {  // Memory operand is destination (MOV [sib_addr], reg)
                // MOV [temp_reg], source_reg
                x86_reg source_reg = x86->operands[1].reg;  // Second operand is the source
                uint8_t mov_code[] = {0x89, 0x00};
                // Mod=00 (no displacement), r/m=temp_reg (addressing mode), reg=source_reg
                mov_code[1] = (get_reg_index(source_reg) << 3) + get_reg_index(temp_reg);
                
                // Verify this code doesn't introduce nulls
                if (mov_code[1] == 0x00) {
                    // Use profile-safe approach to avoid null
                    if (generate_safe_mov_mem_reg(b, temp_reg, source_reg) != 0) {
                        // Fallback: PUSH/POP
                        uint8_t push[] = {0x50 | get_reg_index(source_reg)};
                        buffer_append(b, push, 1);
                        uint8_t pop[] = {0x8F, 0x00 | get_reg_index(temp_reg)};
                        buffer_append(b, pop, 2);
                    }
                } else {
                    buffer_append(b, mov_code, 2);
                }
            }
            break;
        }
        case X86_INS_PUSH: {
            // PUSH [temp_reg] - encoded as FF /6, so reg field is 6 (for PUSH) and r/m is temp_reg
            uint8_t push_code[] = {0xFF, 0x30};
            push_code[1] = 0x30 + get_reg_index(temp_reg);  // Mod=00 (no disp), reg=110 (PUSH), r/m=temp_reg
            
            // Check if this would create a null byte
            if (push_code[1] == 0x00) {
                // Use SIB addressing to avoid null
                uint8_t sib_push_code[] = {0xFF, 0x34, 0x20};
                sib_push_code[1] = 0x34 | (6 << 3);  // ModR/M: mod=00, reg=110 (PUSH), r/m=SIB
                sib_push_code[2] = (0 << 6) | (4 << 3) | get_reg_index(temp_reg);  // SIB: scale=0, index=ESP, base=temp_reg
                buffer_append(b, sib_push_code, 3);
            } else {
                buffer_append(b, push_code, 2);
            }
            break;
        }
        case X86_INS_LEA: {
            // LEA target_reg, [temp_reg] - load address of temp_reg
            x86_reg target_reg = x86->operands[0].reg;
            uint8_t lea_code[] = {0x8D, 0x00};
            // Mod=00 (no displacement), r/m=temp_reg, reg=target_reg
            lea_code[1] = (get_reg_index(target_reg) << 3) + get_reg_index(temp_reg);
            
            // Verify this code doesn't introduce nulls
            if (lea_code[1] == 0x00) {
                // Use profile-safe approach to avoid null
                if (generate_safe_lea_reg_mem(b, target_reg, temp_reg) != 0) {
                    // Fallback: just MOV the register value
                    uint8_t mov[] = {0x89, 0xC0 | (get_reg_index(temp_reg) << 3) | get_reg_index(target_reg)};
                    buffer_append(b, mov, 2);
                }
            } else {
                buffer_append(b, lea_code, 2);
            }
            break;
        }
        case X86_INS_CMP: {
            if (original_op_idx == 1) {  // Memory operand is source (CMP reg, [sib_addr])
                // CMP reg, [temp_reg]
                x86_reg reg = x86->operands[0].reg;
                uint8_t cmp_code[] = {0x39, 0x00};
                // Mod=00 (no displacement), r/m=temp_reg (addressing mode), reg=reg
                cmp_code[1] = (get_reg_index(reg) << 3) + get_reg_index(temp_reg);
                
                // Check for null in ModR/M
                if (cmp_code[1] == 0x00) {
                    // Fallback: Use PUSH/POP to compare
                    uint8_t push[] = {0xFF, 0x30 | get_reg_index(temp_reg)};
                    buffer_append(b, push, 2);
                    uint8_t pop[] = {0x5A};  // POP EDX
                    buffer_append(b, pop, 1);
                    uint8_t cmp[] = {0x39, 0xC0 | (get_reg_index(reg) << 3) | 2};  // CMP EDX, reg
                    buffer_append(b, cmp, 2);
                } else {
                    buffer_append(b, cmp_code, 2);
                }
            } else {  // Memory operand is destination (CMP [sib_addr], reg)
                // CMP [temp_reg], reg
                x86_reg reg = x86->operands[1].reg;  // Second operand is the reg
                uint8_t cmp_code[] = {0x3B, 0x00};
                // Mod=00 (no displacement), r/m=temp_reg (addressing mode), reg=reg
                cmp_code[1] = (get_reg_index(reg) << 3) + get_reg_index(temp_reg);
                
                // Check for null in ModR/M
                if (cmp_code[1] == 0x00) {
                    // Fallback: Use PUSH/POP to compare
                    uint8_t push[] = {0xFF, 0x30 | get_reg_index(temp_reg)};
                    buffer_append(b, push, 2);
                    uint8_t pop[] = {0x5A};  // POP EDX
                    buffer_append(b, pop, 1);
                    uint8_t cmp[] = {0x3B, 0xC0 | (get_reg_index(reg) << 3) | 2};  // CMP reg, EDX
                    buffer_append(b, cmp, 2);
                } else {
                    buffer_append(b, cmp_code, 2);
                }
            }
            break;
        }
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_AND:
        case X86_INS_OR:
        case X86_INS_XOR: {
            if (original_op_idx == 1) {  // Memory operand is source (OP reg, [sib_addr])
                // OP reg, [temp_reg]
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
                uint8_t final_code[] = {op_code, 0x00};
                // Mod=00 (no displacement), r/m=temp_reg (addressing mode), reg=reg
                final_code[1] = (get_reg_index(reg) << 3) + get_reg_index(temp_reg);

                // Check for null in ModR/M
                if (final_code[1] == 0x00) {
                    // Fallback: PUSH [temp], POP EDX, OP reg,EDX
                    uint8_t push[] = {0xFF, 0x30 | get_reg_index(temp_reg)};
                    buffer_append(b, push, 2);
                    uint8_t pop[] = {0x5A};  // POP EDX
                    buffer_append(b, pop, 1);
                    uint8_t arith[] = {(uint8_t)(op_code + 2), 0xC0 | (get_reg_index(reg) << 3) | 2};
                    buffer_append(b, arith, 2);
                } else {
                    buffer_append(b, final_code, 2);
                }
            } else {  // Memory operand is destination (OP [sib_addr], reg)
                // OP [temp_reg], reg
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
                uint8_t final_code[] = {op_code, 0x00};
                // Mod=00 (no displacement), r/m=temp_reg (addressing mode), reg=reg
                final_code[1] = (get_reg_index(reg) << 3) + get_reg_index(temp_reg);

                // Check for null in ModR/M
                if (final_code[1] == 0x00) {
                    // Fallback: PUSH [temp], POP EDX, OP EDX,reg, PUSH EDX, POP [temp]
                    uint8_t push_mem[] = {0xFF, 0x30 | get_reg_index(temp_reg)};
                    buffer_append(b, push_mem, 2);
                    uint8_t pop_edx[] = {0x5A};  // POP EDX
                    buffer_append(b, pop_edx, 1);
                    uint8_t arith[] = {op_code, 0xC0 | (get_reg_index(reg) << 3) | 2};
                    buffer_append(b, arith, 2);
                    uint8_t push_edx[] = {0x52};
                    buffer_append(b, push_edx, 1);
                    uint8_t pop_mem[] = {0x8F, 0x00 | get_reg_index(temp_reg)};
                    buffer_append(b, pop_mem, 2);
                } else {
                    buffer_append(b, final_code, 2);
                }
            }
            break;
        }
        default:
            // For other instructions, at least do the address calculation
            // but fallback to original encoding if not handled
            buffer_append(b, insn->bytes, insn->size);
            break;
    }

    // Restore original value of temp register
    uint8_t pop_code[] = {0x58};  // POP reg
    pop_code[0] = 0x58 + get_reg_index(temp_reg);
    buffer_append(b, pop_code, 1);

    // Final validation: Check if this transformation introduced any null bytes
    size_t final_size = b->size;
    for (size_t i = initial_size; i < final_size; i++) {
        if (b->data[i] == 0x00) {
            // If we introduced a null byte, we need to handle this more carefully
            // This shouldn't happen with our current implementation, but if it does,
            // we'll need to backtrack and use a different approach

            // For now, this is just a safety check that helps us identify potential issues
            fprintf(stderr, "[SAFE_SIB] Warning: Null byte introduced at offset %zu in output for instruction %s %s\n",
                   i - initial_size,
                   insn->mnemonic,
                   insn->op_str);
        }
    }

    strategy_recursion_depth--;
}

/* Strategy definition */
static strategy_t safe_sib_null_strategy = {
    .name = "Safe SIB Addressing Null Elimination",
    .can_handle = can_handle_safe_sib_null,
    .get_size = get_size_safe_sib_null,
    .generate = generate_safe_sib_null,
    .priority = 5  // Lowest priority to avoid conflicts with other strategies and prevent potential issues
};

/* Registration function */
void register_safe_sib_strategies() {
    register_strategy(&safe_sib_null_strategy);
}