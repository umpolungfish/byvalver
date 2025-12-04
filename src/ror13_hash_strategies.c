/*
 * ROR13 Hash-Based API Resolution Strategy
 *
 * PROBLEM: ROR13 hash algorithm is used extensively in Windows shellcode to resolve API addresses.
 * The pattern typically involves: ror reg, 0x0d; add reg, char_value
 * While the ROR instruction with 0x0d doesn't contain null bytes, other instructions in the
 * hash loop or API resolution sequence may contain nulls.
 *
 * The typical ROR13 hash loop looks like:
 * hash_loop:
 *     ror edi, 0x0d      ; ROR13 hash rotation
 *     add edi, eax       ; Add character to hash
 *     mov eax, [eax]     ; Next character
 *     test eax, eax      ; Check for null terminator
 *     jnz hash_loop      ; Continue if not null
 *
 * SOLUTION: Identify ROR13 hash patterns and provide alternatives that don't contain null bytes
 * or transform existing patterns to eliminate null bytes where they occur.
 *
 * FREQUENCY: ~90% of Windows shellcode samples
 * PRIORITY: 90 (High)
 *
 * Example transformations:
 *   Original ROR13 patterns with null-free immediate (0x0d) don't need transformation,
 *   but related instructions in the hash chain may need null-byte elimination.
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Detection function for ROR13 hash patterns that contain null bytes
 * Note: The immediate value 0x0d in ROR reg, 0x0d doesn't contain nulls,
 * but we need to look for other patterns in the hash resolution chain
 */
int can_handle_ror13_hash_null(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    // Look for ROR instructions (the core of ROR13 hash)
    if (insn->id == X86_INS_ROR) {
        // Check if it's ROR reg, imm8 - specifically ROR13 pattern
        if (insn->detail->x86.op_count == 2) {
            cs_x86_op *op1 = &insn->detail->x86.operands[0];
            cs_x86_op *op2 = &insn->detail->x86.operands[1];

            if (op1->type == X86_OP_REG && op2->type == X86_OP_IMM) {
                // Check if immediate is 13 (0x0d) - the ROR13 pattern
                if (op2->imm == 13) {
                    // ROR reg, 13 itself doesn't have nulls in immediate
                    // but the instruction might contain nulls in the opcode itself
                    // (e.g., in ModR/M byte or other components)
                    if (has_null_bytes(insn)) {
                        // If there are null bytes in the ROR instruction itself, handle it
                        return 1;
                    }
                    // For normal ROR reg, 13 with no nulls, don't handle it
                    return 0;
                }
            }
        }
    }

    // Look for MOV instructions that might contain null bytes in API name strings
    // These are often embedded in the shellcode as immediate values or memory references
    if (insn->id == X86_INS_MOV && insn->detail->x86.op_count == 2) {
        cs_x86_op *src_op = &insn->detail->x86.operands[1];

        // Check for MOV reg, imm32 where immediate contains null bytes
        if (src_op->type == X86_OP_IMM) {
            if (!is_null_free((uint32_t)src_op->imm)) {
                // This could be part of an API name string construction
                // that's part of ROR13 hash resolution
                return 1;
            }
        }
    }

    // Look for other related instructions involved in API resolution
    // that might contain null bytes in the context of hash-based resolution
    if (insn->id == X86_INS_ADD || insn->id == X86_INS_SUB || 
        insn->id == X86_INS_AND || insn->id == X86_INS_OR ||
        insn->id == X86_INS_XOR) {
        if (insn->detail->x86.op_count == 2) {
            cs_x86_op *src_op = &insn->detail->x86.operands[1];
            if (src_op->type == X86_OP_IMM) {
                uint32_t imm = (uint32_t)src_op->imm;
                if (!is_null_free(imm) && has_null_bytes(insn)) {
                    // Check if this is in context of hash-based API resolution
                    // For now, we'll be conservative and return 1 if immediate has nulls
                    return 1;
                }
            }
        }
    }

    // Look for CALL instructions that might call APIs obtained via ROR13
    if (insn->id == X86_INS_CALL && insn->detail->x86.op_count == 1) {
        cs_x86_op *op = &insn->detail->x86.operands[0];
        if (op->type == X86_OP_IMM) {
            uint32_t target = (uint32_t)op->imm;
            if (!is_null_free(target) && has_null_bytes(insn)) {
                // CALL with immediate target that has null bytes
                // This could be the result of ROR13 hash resolution
                return 1;
            } else if (op->type == X86_OP_REG) {
                // CALL reg - common in ROR13 where resolved address is in a register
                // Don't specifically handle register calls here unless other issues
                return 0;
            }
        }
    }

    return 0; // We can't specifically handle this instruction for ROR13-related nulls
}

/*
 * Size calculation function for ROR13 hash null elimination
 */
size_t get_size_ror13_hash_null(cs_insn *insn) {
    // This depends on the specific transformation needed
    // For immediate value transformations, refer to similar strategies
    (void)insn; // Unused parameter
    return 8; // Conservative estimate
}

/*
 * Generation function for null-free ROR13 hash operations
 * This is a more complex implementation that needs to handle the hash chain
 */
void generate_ror13_hash_null_free(struct buffer *b, cs_insn *insn) {
    // Store the initial size to verify no nulls are introduced
    size_t initial_size = b->size;

    // Since the core ROR13 instruction (ROR reg, 0x0d) doesn't contain nulls,
    // we're likely dealing with related instructions in the hash resolution chain

    if (insn->id == X86_INS_MOV) {
        // Handle MOV instruction with null-containing immediate
        // This could be part of API name string or API address loading
        cs_x86_op *dst_op = &insn->detail->x86.operands[0];
        cs_x86_op *src_op = &insn->detail->x86.operands[1];

        if (src_op->type == X86_OP_IMM) {
            uint32_t imm = (uint32_t)src_op->imm;

            if (!is_null_free(imm)) {
                // Use null-safe MOV generation for immediate values containing nulls
                uint8_t dst_reg = dst_op->reg;

                if (dst_reg == X86_REG_EAX) {
                    // Directly use generate_mov_eax_imm for EAX
                    generate_mov_eax_imm(b, imm);
                } else {
                    // Save original register, load via EAX, then move
                    uint8_t push_code[] = {0x50 + get_reg_index(dst_reg)}; // PUSH reg
                    buffer_append(b, push_code, 1);

                    generate_mov_eax_imm(b, imm);  // Load value to EAX (null-safe)

                    uint8_t mov_reg_eax[] = {0x89, 0xC0}; // MOV reg, EAX
                    mov_reg_eax[1] = mov_reg_eax[1] + (get_reg_index(dst_reg) << 3) + get_reg_index(X86_REG_EAX);
                    buffer_append(b, mov_reg_eax, 2);

                    uint8_t pop_code[] = {0x58 + get_reg_index(dst_reg)}; // POP reg
                    buffer_append(b, pop_code, 1);
                }
            } else {
                // No nulls in immediate, use normal MOV
                generate_mov_reg_imm(b, insn);
            }
            return;
        }
    } else if (insn->id == X86_INS_ADD || insn->id == X86_INS_SUB ||
               insn->id == X86_INS_AND || insn->id == X86_INS_OR ||
               insn->id == X86_INS_XOR) {
        // Handle arithmetic/logical instructions with null-containing immediates
        if (insn->detail->x86.op_count == 2) {
            cs_x86_op *dst_op = &insn->detail->x86.operands[0];
            cs_x86_op *src_op = &insn->detail->x86.operands[1];

            if (src_op->type == X86_OP_IMM) {
                uint32_t imm = (uint32_t)src_op->imm;

                if (!is_null_free(imm)) {
                    // Use null-safe approach: MOV reg, imm (null safe) + op reg, EAX or op reg, immediate via register
                    uint8_t dst_reg = dst_op->reg;

                    // Save the destination register
                    uint8_t push_code[] = {0x50 + get_reg_index(dst_reg)}; // PUSH dst_reg
                    buffer_append(b, push_code, 1);

                    // Load the immediate value to EAX using null-safe method
                    generate_mov_eax_imm(b, imm);

                    // Perform the operation: op dst_reg, EAX
                    uint8_t op_code = 0x01; // Default to ADD
                    switch(insn->id) {
                        case X86_INS_ADD: op_code = 0x01; break;  // ADD
                        case X86_INS_SUB: op_code = 0x29; break;  // SUB
                        case X86_INS_AND: op_code = 0x21; break;  // AND
                        case X86_INS_OR:  op_code = 0x09; break;  // OR
                        case X86_INS_XOR: op_code = 0x31; break;  // XOR
                    }

                    uint8_t op_instr[] = {op_code, 0xC0}; // op reg, EAX
                    op_instr[1] = op_instr[1] + (get_reg_index(dst_reg) << 3) + get_reg_index(X86_REG_EAX);
                    buffer_append(b, op_instr, 2);

                    // Restore the destination register
                    uint8_t pop_code[] = {0x58 + get_reg_index(dst_reg)}; // POP dst_reg
                    buffer_append(b, pop_code, 1);
                    return;
                } else {
                    // No nulls in immediate, use normal operation
                    generate_op_reg_imm(b, insn);
                    return;
                }
            }
        }
    } else if (insn->id == X86_INS_CALL) {
        // Handle CALL with immediate target that contains nulls
        cs_x86_op *op = &insn->detail->x86.operands[0];
        if (op->type == X86_OP_IMM) {
            uint32_t target = (uint32_t)op->imm;
            if (!is_null_free(target)) {
                // Transform CALL immediate to CALL register to avoid nulls in immediate
                // MOV EAX, target_address (null-free)
                generate_mov_eax_imm(b, target);
                // CALL EAX
                uint8_t call_eax[] = {0xFF, 0xD0};
                buffer_append(b, call_eax, 2);
                return;
            }
        }
    }

    // If we reach here, use the standard utilities but implement proper verification
    switch(insn->id) {
        case X86_INS_MOV:
            // Check if this instruction has nulls in its immediate or elsewhere
            if (has_null_bytes(insn)) {
                // For MOV with null bytes, use our null-safe approach for non-EAX registers too
                cs_x86_op *dst_op = &insn->detail->x86.operands[0];
                uint8_t dst_reg = dst_op->reg;

                if (dst_reg == X86_REG_EAX) {
                    generate_mov_eax_imm(b, (uint32_t)insn->detail->x86.operands[1].imm);
                } else {
                    // For other registers, save, load to EAX, move to target, restore
                    uint8_t push_code[] = {0x50 + get_reg_index(dst_reg)}; // PUSH reg
                    buffer_append(b, push_code, 1);

                    generate_mov_eax_imm(b, (uint32_t)insn->detail->x86.operands[1].imm);  // Load value to EAX (null-safe)

                    uint8_t mov_reg_eax[] = {0x89, 0xC0}; // MOV reg, EAX
                    mov_reg_eax[1] = mov_reg_eax[1] + (get_reg_index(dst_reg) << 3) + get_reg_index(X86_REG_EAX);
                    buffer_append(b, mov_reg_eax, 2);

                    uint8_t pop_code[] = {0x58 + get_reg_index(dst_reg)}; // POP reg
                    buffer_append(b, pop_code, 1);
                }
            } else {
                generate_mov_reg_imm(b, insn);
            }
            break;
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_AND:
        case X86_INS_OR:
        case X86_INS_XOR:
            // Check if this instruction has nulls in its immediate
            if (has_null_bytes(insn)) {
                // Use null-safe approach for arithmetic with null-containing immediates
                cs_x86_op *dst_op = &insn->detail->x86.operands[0];
                uint8_t dst_reg = dst_op->reg;
                uint32_t imm = (uint32_t)insn->detail->x86.operands[1].imm;

                // Save the destination register
                uint8_t push_code[] = {0x50 + get_reg_index(dst_reg)}; // PUSH dst_reg
                buffer_append(b, push_code, 1);

                // Load the immediate value to EAX using null-safe method
                generate_mov_eax_imm(b, imm);

                // Perform the operation: op dst_reg, EAX
                uint8_t op_code = 0x01; // Default to ADD
                switch(insn->id) {
                    case X86_INS_ADD: op_code = 0x01; break;  // ADD
                    case X86_INS_SUB: op_code = 0x29; break;  // SUB
                    case X86_INS_AND: op_code = 0x21; break;  // AND
                    case X86_INS_OR:  op_code = 0x09; break;  // OR
                    case X86_INS_XOR: op_code = 0x31; break;  // XOR
                }

                uint8_t op_instr[] = {op_code, 0xC0}; // op reg, EAX
                op_instr[1] = op_instr[1] + (get_reg_index(dst_reg) << 3) + get_reg_index(X86_REG_EAX);
                buffer_append(b, op_instr, 2);

                // Restore the destination register
                uint8_t pop_code[] = {0x58 + get_reg_index(dst_reg)}; // POP dst_reg
                buffer_append(b, pop_code, 1);
            } else {
                generate_op_reg_imm(b, insn);
            }
            break;
        case X86_INS_ROR:
            // For ROR with immediate 13, the immediate itself is safe (0x0d)
            // So just output normally if it's not the problematic case
            buffer_append(b, insn->bytes, insn->size);
            break;
        default:
            // For other instruction types, just append original bytes
            // Though this could still contain nulls, the detection should ensure
            // this strategy is only called when needed
            buffer_append(b, insn->bytes, insn->size);
            break;
    }

    // Verify that no null bytes were introduced by this strategy
    for (size_t i = initial_size; i < b->size; i++) {
        if (b->data[i] == 0x00) {
            fprintf(stderr, "ERROR: ROR13 strategy introduced null at offset %zu (relative offset %zu) in instruction: %s %s\n",
                   i, i - initial_size, insn->mnemonic, insn->op_str);
        }
    }
}

// Define the strategy structure
strategy_t ror13_hash_strategy = {
    .name = "ROR13 Hash-Based API Resolution Null Elimination",
    .can_handle = can_handle_ror13_hash_null,
    .get_size = get_size_ror13_hash_null,
    .generate = generate_ror13_hash_null_free,
    .priority = 90  // High priority for ROR13 hash strategy
};