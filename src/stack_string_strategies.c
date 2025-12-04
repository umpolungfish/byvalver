/*
 * Stack-Based String Construction Strategy
 *
 * PROBLEM: Direct string embedding can introduce null bytes.
 * Windows shellcode often uses stack-based string construction to embed strings
 * without null bytes. The technique involves pushing string chunks onto the stack
 * in reverse order and then referencing them.
 *
 * The typical pattern:
 * push 0x6c6c6548    ; "lleH" (reverse of "Hell")
 * push 0x6f77206f    ; "owo " (reverse of "o wo")
 * push 0x646c726f    ; "dlro" (reverse of "orld")
 *
 * However, if the immediate values contain null bytes (like when the string 
 * contains null-adjacent characters), we need alternative approaches.
 *
 * SOLUTION: Identify stack-based string construction patterns that contain null bytes
 * and provide alternatives that don't contain null bytes in the immediate values
 * or instruction encodings.
 *
 * FREQUENCY: Common in position-independent shellcode for embedding API names, strings
 * PRIORITY: 85 (High)
 *
 * Example transformations:
 *   Original: push 0x00646c72 (contains null byte)
 *   Transformed: Use alternative construction via register manipulation
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Detection function for stack-based string construction with null bytes
 * This looks for PUSH instructions with immediate values containing null bytes
 * which are common in stack-based string construction.
 */
int can_handle_stack_string_null(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    // Look for PUSH instructions with immediate values
    if (insn->id == X86_INS_PUSH) {
        if (insn->detail->x86.op_count == 1) {
            cs_x86_op *op = &insn->detail->x86.operands[0];

            // Check for immediate operand
            if (op->type == X86_OP_IMM) {
                uint32_t imm = (uint32_t)op->imm;
                
                // Check if immediate contains null bytes
                if (!is_null_free(imm)) {
                    // This could be part of a stack-based string construction
                    // where an immediate value contains null bytes
                    return 1;
                }
            }
        }
    }

    // Also consider MOV operations to stack locations that might be part of
    // string construction sequences
    if (insn->id == X86_INS_MOV) {
        cs_x86_op *dst_op = &insn->detail->x86.operands[0];
        cs_x86_op *src_op = &insn->detail->x86.operands[1];

        // Check for MOV to a stack location with immediate containing nulls
        if (dst_op->type == X86_OP_MEM && src_op->type == X86_OP_IMM) {
            // Check if destination is stack-relative
            if (dst_op->mem.base == X86_REG_ESP || dst_op->mem.base == X86_REG_EBP) {
                uint32_t imm = (uint32_t)src_op->imm;
                if (!is_null_free(imm)) {
                    return 1;
                }
            }
        }
    }

    // Check for CALL instructions that might reference strings on the stack
    if (insn->id == X86_INS_CALL) {
        cs_x86_op *op = &insn->detail->x86.operands[0];
        if (op->type == X86_OP_IMM) {
            uint32_t target = (uint32_t)op->imm;
            if (!is_null_free(target) && has_null_bytes(insn)) {
                // CALL with immediate that has null bytes
                return 1;
            }
        }
    }

    return 0; // Not a stack-based string construction with nulls
}

/*
 * Size calculation function for stack string null elimination
 */
size_t get_size_stack_string_null(cs_insn *insn) {
    // This depends on the specific transformation needed
    // For PUSH immediate with nulls, we might use: MOV reg, imm (null-free) + PUSH reg
    if (insn->id == X86_INS_PUSH && insn->detail->x86.operands[0].type == X86_OP_IMM) {
        // If we transform PUSH imm to MOV reg, imm + PUSH reg:
        // MOV EAX, imm (null-free) = ~5 bytes + PUSH EAX = 1 byte = ~6 bytes
        return 8; // Conservative estimate
    }
    
    if (insn->id == X86_INS_MOV && 
        insn->detail->x86.operands[0].type == X86_OP_MEM &&
        insn->detail->x86.operands[1].type == X86_OP_IMM) {
        // Transformation will depend on the specific encoding needed
        return 10; // Conservative estimate
    }

    return 5; // Default size
}

/*
 * Generation function for null-free stack-based string operations
 */
void generate_stack_string_null_free(struct buffer *b, cs_insn *insn) {
    if (insn->id == X86_INS_PUSH) {
        cs_x86_op *op = &insn->detail->x86.operands[0];
        if (op->type == X86_OP_IMM) {
            uint32_t imm = (uint32_t)op->imm;

            // Transform PUSH immediate with nulls to MOV reg, immediate + PUSH reg
            // MOV EAX, imm (using null-free construction)
            generate_mov_eax_imm(b, imm);

            // PUSH EAX
            uint8_t push_eax[] = {0x50};
            buffer_append(b, push_eax, 1);
            
            return;
        }
    }

    if (insn->id == X86_INS_MOV) {
        cs_x86_op *dst_op = &insn->detail->x86.operands[0];
        cs_x86_op *src_op = &insn->detail->x86.operands[1];

        if (dst_op->type == X86_OP_MEM && src_op->type == X86_OP_IMM) {
            if (dst_op->mem.base == X86_REG_ESP || dst_op->mem.base == X86_REG_EBP) {
                uint32_t imm = (uint32_t)src_op->imm;

                // For MOV [ESP+disp], immediate, where immediate has nulls
                // Use: MOV EAX, immediate (null-free) + MOV [ESP+disp], EAX
                generate_mov_eax_imm(b, imm);

                // Now generate MOV [ESP+disp], EAX
                if (dst_op->mem.disp == 0) {
                    // MOV [ESP], EAX
                    if (dst_op->mem.base == X86_REG_ESP) {
                        uint8_t mov_esp_eax[] = {0x89, 0x04, 0x24}; // MOV [ESP], EAX using SIB byte to avoid null
                        buffer_append(b, mov_esp_eax, 3);
                    }
                } else {
                    // MOV [ESP+disp32], EAX
                    if (dst_op->mem.base == X86_REG_ESP) {
                        uint8_t mov_esp_disp_eax[] = {0x89, 0x84, 0x24, 0, 0, 0, 0}; // MOV [ESP+disp32], EAX
                        memcpy(mov_esp_disp_eax + 3, &dst_op->mem.disp, 4);
                        buffer_append(b, mov_esp_disp_eax, 7);
                    }
                }
                
                return;
            }
        }
    }

    if (insn->id == X86_INS_CALL) {
        cs_x86_op *op = &insn->detail->x86.operands[0];
        if (op->type == X86_OP_IMM) {
            uint32_t target = (uint32_t)op->imm;
            if (!is_null_free(target)) {
                // Transform CALL immediate to CALL register to avoid nulls in immediate
                generate_mov_eax_imm(b, target);
                // CALL EAX
                uint8_t call_eax[] = {0xFF, 0xD0};
                buffer_append(b, call_eax, 2);
                return;
            }
        }
    }

    // Fallback to default handling if we don't have a specific transformation
    buffer_append(b, insn->bytes, insn->size);
}

// Define the strategy structure
strategy_t enhanced_stack_string_strategy = {
    .name = "Enhanced Stack-Based String Construction Null Elimination",
    .can_handle = can_handle_stack_string_null,
    .get_size = get_size_stack_string_null,
    .generate = generate_stack_string_null_free,
    .priority = 85  // High priority for stack string strategy
};