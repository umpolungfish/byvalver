#include "strategy.h"
#include "utils.h"
#include "profile_aware_sib.h"
#include <stdio.h>
#include <string.h>

// LEA with displacement containing null bytes strategy
int can_handle_lea_disp_nulls(cs_insn *insn) {
    if (insn->id != X86_INS_LEA) {
        return 0;
    }

    // Check if it has memory operands with displacement containing nulls
    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        if (insn->detail->x86.operands[i].type == X86_OP_MEM &&
            insn->detail->x86.operands[i].mem.disp != 0) {

            uint32_t disp = (uint32_t)insn->detail->x86.operands[i].mem.disp;

            // Check if displacement has null bytes
            for (int j = 0; j < 4; j++) {
                if (((disp >> (j * 8)) & 0xFF) == 0) {
                    return 1; // Has null bytes in displacement
                }
            }
        }
    }

    return 0; // No memory operand with null bytes in displacement
}

size_t get_size_lea_disp_nulls(__attribute__((unused)) cs_insn *insn) {
    // MOV EAX, disp (typically 5-15 bytes using null-free construction) + LEA reg, [EAX] (2 bytes)
    return 15; // Conservative estimate
}

void generate_lea_disp_nulls(struct buffer *b, cs_insn *insn) {
    // Get the displacement from the memory operand
    uint32_t disp = 0;
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;

    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        if (insn->detail->x86.operands[i].type == X86_OP_MEM) {
            disp = (uint32_t)insn->detail->x86.operands[i].mem.disp;
            break;
        }
    }

    // Load the displacement into EAX using null-free construction
    generate_mov_eax_imm(b, disp);

    // Use LEA dst_reg, [EAX] to get the address (which is the value in EAX)
    // The ModR/M byte for LEA r32, [r32] is: MM RRR MMM
    // For [EAX] (MMM=000) and dst_reg (RRR), ModR/M = 00 (RRR<<3) 000
    // FIXED: Use profile-safe SIB generation
    if (generate_safe_lea_reg_mem(b, dst_reg, X86_REG_EAX) != 0) {
        // Fallback - LEA is just MOV for this case
        uint8_t mov[] = {0x89, (uint8_t)(0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(dst_reg))};
        buffer_append(b, mov, 2);
    }
}

void generate_lea_reg_mem_disp_null_orig(struct buffer *b, cs_insn *insn) {
    // Original version - keeping for reference but not used
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;
    if (dst_reg != X86_REG_EAX) {
        // For other registers, the ModR/M byte is safe (0x8D + ModR/M where ModR/M = (dst_reg_idx << 3) | 0)
        uint8_t code[] = {0x8D, 0x00}; // LEA reg, [EAX] format
        code[1] = (get_reg_index(dst_reg) << 3) | 0;  // Encode dst_reg in reg field, [EAX] in r/m field
        buffer_append(b, code, 2);
    }
}

strategy_t lea_disp_nulls_strategy = {
    .name = "lea_disp_nulls",
    .can_handle = can_handle_lea_disp_nulls,
    .get_size = get_size_lea_disp_nulls,
    .generate = generate_lea_disp_nulls,
    .priority = 8  // Reduced priority to allow more targeted strategies to take precedence
};

// ============================================================================
// LEA Null ModR/M Strategy
// ============================================================================
// Handles: LEA reg, [EAX] where ModR/M byte is 0x00
// Example: LEA EAX, [EAX] → 0x8D 0x00 (contains null!)
//
// Transformation:
//   Original: LEA EAX, [EAX]  ; 0x8D 0x00
//   Transformed:
//     PUSH EBX                 ; Save temp
//     MOV EBX, EAX            ; Copy address
//     LEA dst, [EBX]          ; Use [EBX] (ModR/M = 0x03)
//     POP EBX                 ; Restore

int can_handle_lea_null_modrm(cs_insn *insn) {
    if (insn->id != X86_INS_LEA) {
        return 0;
    }

    if (!has_null_bytes(insn)) {
        return 0;
    }

    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    if (op0->type != X86_OP_REG || op1->type != X86_OP_MEM) {
        return 0;
    }

    // Check for [EAX] pattern (ModR/M 0x00)
    if (op1->mem.base == X86_REG_EAX &&
        op1->mem.index == X86_REG_INVALID &&
        op1->mem.disp == 0) {
        return 1;
    }

    return 0;
}

size_t get_size_lea_null_modrm(cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    x86_reg dst = op0->reg;

    if (dst == X86_REG_EAX) {
        // LEA EAX, [EAX] is essentially a NOP
        // Replace with 2-byte NOP: MOV EAX, EAX
        return 2;
    } else {
        // PUSH EBX (1) + MOV EBX, EAX (2) + LEA dst, [EBX] (2) + POP EBX (1) = 6 bytes
        return 6;
    }

    (void)insn;
}

void generate_lea_null_modrm(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    x86_reg dst = op0->reg;

    if (dst == X86_REG_EAX) {
        // LEA EAX, [EAX] is a NOP (loads EAX's value into EAX)
        // Replace with 2-byte NOP: MOV EAX, EAX (0x89 0xC0)
        buffer_write_byte(b, 0x89);
        buffer_write_byte(b, 0xC0);
        return;
    }

    // PUSH EBX
    buffer_write_byte(b, 0x53);

    // MOV EBX, EAX
    buffer_write_byte(b, 0x89);
    buffer_write_byte(b, 0xC3);

    // LEA dst, [EBX]
    buffer_write_byte(b, 0x8D);  // LEA opcode
    uint8_t dst_code = (dst - X86_REG_EAX) & 0x07;
    uint8_t modrm = (dst_code << 3) | 0x03;  // mod=00, reg=dst, r/m=011 (EBX)
    buffer_write_byte(b, modrm);

    // POP EBX
    buffer_write_byte(b, 0x5B);
}

strategy_t lea_null_modrm_strategy = {
    .name = "lea_null_modrm",
    .can_handle = can_handle_lea_null_modrm,
    .get_size = get_size_lea_null_modrm,
    .generate = generate_lea_null_modrm,
    .priority = 65  // Higher than displacement strategy
};

// Register the LEA strategies
void register_lea_strategies() {
    register_strategy(&lea_null_modrm_strategy);  // Priority 65
    register_strategy(&lea_disp_nulls_strategy);  // Priority 8
}