/*
 * MOVZX/MOVSX Null-Byte Elimination Strategy for BYVALVER
 *
 * This strategy handles MOVZX (Move with Zero-Extend) and MOVSX (Move with
 * Sign-Extend) instructions that produce null bytes due to ModR/M encoding
 * or displacement values.
 *
 * Example transformations:
 *   Original: movzx eax, byte [eax]  (0F B6 00 - contains null)
 *   Transformed:
 *     push ecx                        ; 51
 *     mov ecx, eax                    ; 89 C1
 *     movzx eax, byte [ecx]           ; 0F B6 01 (null-free!)
 *     pop ecx                         ; 59
 *
 * This pattern is critical for Windows shellcode that reads PE export table
 * ordinals during API resolution.
 */

#include "strategy.h"
#include "utils.h"
#include "core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>
#include <inttypes.h>

/*
 * Helper: Select a safe temporary register that doesn't conflict with the
 * destination or source registers
 */
static x86_reg get_safe_temp_register(cs_insn *insn) {
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    x86_reg temp_reg = X86_REG_ECX;  // Default to ECX

    // Cascade through alternatives if there's a conflict
    if (dst_reg == X86_REG_ECX) {
        temp_reg = X86_REG_EDX;
    }
    if (dst_reg == X86_REG_EDX) {
        temp_reg = X86_REG_EBX;
    }
    if (dst_reg == X86_REG_EBX) {
        temp_reg = X86_REG_ESI;
    }

    // Also check if memory operand uses this register
    if (insn->detail->x86.operands[1].type == X86_OP_MEM) {
        x86_reg base_reg = insn->detail->x86.operands[1].mem.base;
        x86_reg index_reg = insn->detail->x86.operands[1].mem.index;

        // If temp_reg conflicts with base or index, try next option
        if (temp_reg == base_reg || temp_reg == index_reg) {
            if (temp_reg == X86_REG_ECX) temp_reg = X86_REG_EDX;
            else if (temp_reg == X86_REG_EDX) temp_reg = X86_REG_EBX;
            else if (temp_reg == X86_REG_EBX) temp_reg = X86_REG_ESI;
            else temp_reg = X86_REG_EDI;
        }
    }

    return temp_reg;
}

/*
 * Helper: Check if the memory operand uses the destination register
 * (which would require register substitution)
 */
static int mem_operand_uses_dst_reg(cs_insn *insn) {
    if (insn->detail->x86.operands[1].type != X86_OP_MEM) {
        return 0;
    }

    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    x86_reg base_reg = insn->detail->x86.operands[1].mem.base;
    x86_reg index_reg = insn->detail->x86.operands[1].mem.index;

    return (base_reg == dst_reg || index_reg == dst_reg);
}

/*
 * Helper: Emit PUSH instruction for a register
 */
static void emit_push_reg(struct buffer *b, x86_reg reg) {
    uint8_t push_code = 0x50 + get_reg_index(reg);
    buffer_append(b, &push_code, 1);
}

/*
 * Helper: Emit POP instruction for a register
 */
static void emit_pop_reg(struct buffer *b, x86_reg reg) {
    uint8_t pop_code = 0x58 + get_reg_index(reg);
    buffer_append(b, &pop_code, 1);
}

/*
 * Helper: Emit MOV reg, reg instruction
 */
static void emit_mov_reg_reg(struct buffer *b, x86_reg dst, x86_reg src) {
    uint8_t mov_code[] = {0x89, 0xC0};
    mov_code[1] = 0xC0 + (get_reg_index(src) << 3) + get_reg_index(dst);
    buffer_append(b, mov_code, 2);
}

/*
 * Helper: Emit MOVZX/MOVSX with modified base register
 */
static void emit_movzx_with_temp_reg(struct buffer *b, cs_insn *insn, x86_reg temp_reg) {
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    uint8_t dst_idx = get_reg_index(dst_reg);
    uint8_t temp_idx = get_reg_index(temp_reg);

    // Determine if it's MOVZX or MOVSX
    uint8_t opcode_byte2;
    if (insn->id == X86_INS_MOVZX) {
        opcode_byte2 = 0xB6;  // MOVZX byte
        // Check if it's word extension
        if (insn->detail->x86.operands[1].size == 2) {
            opcode_byte2 = 0xB7;  // MOVZX word
        }
    } else {  // MOVSX
        opcode_byte2 = 0xBE;  // MOVSX byte
        // Check if it's word extension
        if (insn->detail->x86.operands[1].size == 2) {
            opcode_byte2 = 0xBF;  // MOVSX word
        }
    }

    // Build the MOVZX/MOVSX instruction with temp_reg as base
    // Format: 0F [B6/B7/BE/BF] ModR/M
    uint8_t movzx_code[3];
    movzx_code[0] = 0x0F;
    movzx_code[1] = opcode_byte2;

    // ModR/M byte: mod=00 (no displacement), reg=dst_reg, r/m=temp_reg
    // This creates [temp_reg] addressing which is null-free
    movzx_code[2] = 0x00 + (dst_idx << 3) + temp_idx;

    buffer_append(b, movzx_code, 3);
}

/*
 * Detection: Can this strategy handle the instruction?
 */
int movzx_null_elimination_can_handle(cs_insn *insn) {
    // Only handle MOVZX and MOVSX instructions
    if (insn->id != X86_INS_MOVZX && insn->id != X86_INS_MOVSX) {
        return 0;
    }

    // Must contain null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Must have exactly 2 operands
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    // First operand must be a register
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }

    // Second operand must be memory or register
    if (insn->detail->x86.operands[1].type != X86_OP_MEM &&
        insn->detail->x86.operands[1].type != X86_OP_REG) {
        return 0;
    }

    return 1;
}

/*
 * Size calculation: How many bytes will the transformed code take?
 */
size_t movzx_null_elimination_get_size(cs_insn *insn) {
    size_t size = 0;

    // PUSH temp_reg: 1 byte
    size += 1;

    // If memory operand uses destination register, need MOV temp_reg, dst_reg: 2 bytes
    if (mem_operand_uses_dst_reg(insn)) {
        size += 2;
    }

    // MOVZX/MOVSX with temp_reg: 3 bytes
    size += 3;

    // POP temp_reg: 1 byte
    size += 1;

    return size;  // Total: 5-7 bytes depending on register conflict
}

/*
 * Code generation: Emit the null-free replacement code
 */
void movzx_null_elimination_generate(struct buffer *b, cs_insn *insn) {
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    x86_reg temp_reg = get_safe_temp_register(insn);

    // 1. PUSH temp_reg to preserve its value
    emit_push_reg(b, temp_reg);

    // 2. If memory operand uses destination register, copy it to temp_reg first
    if (mem_operand_uses_dst_reg(insn)) {
        emit_mov_reg_reg(b, temp_reg, dst_reg);
    } else if (insn->detail->x86.operands[1].type == X86_OP_MEM) {
        // Copy base register to temp_reg if needed
        x86_reg base_reg = insn->detail->x86.operands[1].mem.base;
        if (base_reg != X86_REG_INVALID) {
            emit_mov_reg_reg(b, temp_reg, base_reg);
        }
    }

    // 3. Emit MOVZX/MOVSX using temp_reg as base (null-free encoding)
    emit_movzx_with_temp_reg(b, insn, temp_reg);

    // 4. POP temp_reg to restore its value
    emit_pop_reg(b, temp_reg);
}

/*
 * Strategy definition
 */
strategy_t movzx_null_elimination_strategy = {
    .name = "MOVZX/MOVSX Null-Byte Elimination Strategy",
    .can_handle = movzx_null_elimination_can_handle,
    .get_size = movzx_null_elimination_get_size,
    .generate = movzx_null_elimination_generate,
    .priority = 75  // High priority - critical for Windows API resolution
};

/*
 * Registration function
 */
void register_movzx_strategies() {
    register_strategy(&movzx_null_elimination_strategy);
}
