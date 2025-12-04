#include "new_strategies.h"
#include "utils.h"
#include <string.h>
#include <stdio.h>

// Transformation strategy for MOV reg32, [reg32] instructions that contain null bytes
// Example: mov eax, [eax] (0x8B 0x00) -> transformed to null-byte-free sequence
int transform_mov_reg_mem_self_can_handle(cs_insn *insn) {
    if (!insn || insn->id != X86_INS_MOV) {
        return 0;
    }

    // Check if the instruction is MOV reg32, [reg32]
    if (insn->detail->x86.op_count == 2) {
        cs_x86_op op0 = insn->detail->x86.operands[0];
        cs_x86_op op1 = insn->detail->x86.operands[1];

        // First operand should be a register, second should be memory
        if (op0.type == X86_OP_REG &&
            op0.size == 4 &&  // 32-bit register
            op1.type == X86_OP_MEM &&
            op1.mem.base != X86_REG_INVALID &&
            op1.mem.index == X86_REG_INVALID &&  // No index register
            op1.mem.scale == 1 &&  // Scale factor of 1
            op1.mem.disp == 0 &&   // No displacement (this creates the null byte issue in ModR/M)
            op0.reg == op1.mem.base) {  // Register and memory base are the same

            // Check that this instruction actually contains null bytes (the original problem)
            for (int i = 0; i < insn->size; i++) {
                if (insn->bytes[i] == 0x00) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

size_t transform_mov_reg_mem_self_get_size(cs_insn *insn) {
    (void)insn; // Avoid unused parameter warning
    // The transformed sequence is:
    // push ecx           // 1 byte
    // lea ecx, [eax - 1] // 3 bytes (if eax, could be 2-3 depending on reg)
    // mov eax, [ecx + 1] // 3 bytes (if eax, could be 2-3 depending on reg)
    // pop ecx            // 1 byte
    // Total: ~8 bytes (may vary based on specific registers used)

    // Conservative estimate of 10 bytes to ensure enough space
    return 10;
}

void transform_mov_reg_mem_self_generate(struct buffer *b, cs_insn *insn) {
    if (!b || !insn) {
        return;
    }

    // Get the register being used
    cs_x86_op op0 = insn->detail->x86.operands[0];  // destination register
    cs_x86_op op1 = insn->detail->x86.operands[1];  // source memory

    if (op0.type != X86_OP_REG || op1.type != X86_OP_MEM) {
        return;
    }

    // Determine register numbers
    unsigned char src_reg_num = op1.mem.base - X86_REG_EAX;
    unsigned char dest_reg_num = op0.reg - X86_REG_EAX;
    unsigned char temp_reg_num = 1;  // Use ECX as temp (reg number 1)

    // If source register is ECX, use EDX as temp register instead
    if (op1.mem.base == X86_REG_ECX) {
        temp_reg_num = 2;  // Use EDX
    }

    // push temp_reg
    unsigned char temp_reg_code = temp_reg_num == 1 ? 0x51 : 0x52; // 0x51=push ecx, 0x52=push edx
    buffer_append(b, &temp_reg_code, 1);

    // lea temp_reg, [src_reg - 1]
    // ModR/M byte format: [Mod:2][Reg:3][R/M:3]
    // For [reg - 1] with 8-bit displacement: Mod=01, Reg=temp_reg_num, R/M=src_reg_num
    unsigned char lea_instr[] = {0x8D, 0x00, 0xFF};
    lea_instr[1] = 0x40 | (temp_reg_num << 3) | src_reg_num; // Mod=01 (bits 7-6), Reg=temp_reg_num (bits 5-3), R/M=src_reg_num (bits 2-0)
    buffer_append(b, lea_instr, 3);

    // mov dest_reg, [temp_reg + 1]
    // ModR/M byte format: [Mod:2][Reg:3][R/M:3]
    // For [temp_reg + 1] with 8-bit displacement: Mod=01, Reg=dest_reg_num, R/M=temp_reg_num
    unsigned char mov_instr[] = {0x8B, 0x00, 0x01};
    mov_instr[1] = 0x40 | (dest_reg_num << 3) | temp_reg_num; // Mod=01 (bits 7-6), Reg=dest_reg_num (bits 5-3), R/M=temp_reg_num (bits 2-0)
    buffer_append(b, mov_instr, 3);

    // pop temp_reg
    unsigned char pop_code = temp_reg_num == 1 ? 0x59 : 0x5A; // 0x59=pop ecx, 0x5A=pop edx
    buffer_append(b, &pop_code, 1);
}

// Define the strategy structure for MOV reg32, [reg32]
strategy_t transform_mov_reg_mem_self = {
    .name = "transform_mov_reg_mem_self",
    .priority = 5,  // Very low priority - only as fallback when other strategies can't handle
    .can_handle = transform_mov_reg_mem_self_can_handle,
    .get_size = transform_mov_reg_mem_self_get_size,
    .generate = transform_mov_reg_mem_self_generate
};

// Transformation strategy for ADD [mem], reg8 instructions that contain null bytes
// Example: add [eax], al (0x00 0x00) -> transformed to null-byte-free sequence
int transform_add_mem_reg8_can_handle(cs_insn *insn) {
    if (!insn || insn->id != X86_INS_ADD) {
        return 0;
    }

    // Check if the instruction is ADD [mem], reg8
    if (insn->detail->x86.op_count == 2) {
        cs_x86_op op0 = insn->detail->x86.operands[0];
        cs_x86_op op1 = insn->detail->x86.operands[1];

        // First operand should be memory, second should be 8-bit register
        if (op0.type == X86_OP_MEM &&
            op1.type == X86_OP_REG &&
            op1.size == 1) {        // 8-bit register

            // Check if this instruction contains null bytes (the original problem)
            for (int i = 0; i < insn->size; i++) {
                if (insn->bytes[i] == 0x00) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

size_t transform_add_mem_reg8_get_size(cs_insn *insn) {
    (void)insn; // Avoid unused parameter warning
    // The transformed sequence is approximately:
    // push temp_reg     // 1 byte
    // movzx temp_reg, [mem]  // 3-4 bytes (0x0F 0xB6)
    // add temp_reg, reg8     // 2-3 bytes
    // mov [mem], temp_reg_lo // 2-3 bytes
    // pop temp_reg    // 1 byte
    // Total: ~10-14 bytes

    // Conservative estimate of 15 bytes to ensure enough space
    return 15;
}

void transform_add_mem_reg8_generate(struct buffer *b, cs_insn *insn) {
    if (!b || !insn) {
        return;
    }

    // Get the operands
    cs_x86_op op0 = insn->detail->x86.operands[0];  // destination memory
    cs_x86_op op1 = insn->detail->x86.operands[1];  // source register (8-bit)

    if (op0.type != X86_OP_MEM || op1.type != X86_OP_REG || op1.size != 1) {
        return;
    }

    // Use a more robust approach that avoids null-byte issues in ModR/M:
    // Instead of moving through memory, we can use LEA to create a safe address
    // and use SIB byte to avoid nulls when the address is [register] without displacement

    uint8_t src_reg = op1.reg;
    uint8_t mem_base_reg = op0.mem.base;

    // If we have [reg] addressing that leads to null bytes, we use LEA approach
    // LEA EAX, [mem_base_reg] + ADD [EAX], src_reg8 (or vice versa)
    if (op0.mem.base != X86_REG_INVALID && op0.mem.index == X86_REG_INVALID &&
        op0.mem.disp == 0 && op0.mem.scale == 1) {

        // If mem_base_reg is EAX, the direct access [EAX] will generate null bytes in ModR/M
        // So we use LEA with SIB byte to avoid this
        if (mem_base_reg == X86_REG_EAX) {
            // MOV ECX, memory base register value (ECX because it's less likely to conflict)
            // But we need to be careful with temp register selection

            // Let's try a different approach: use SIB byte encoding
            // For [EAX] access, we can use SIB byte: 0x00 0x04 0x20
            // However, we need to implement a different approach to avoid issues

            // PUSH ECX (save ECX)
            uint8_t push_ecx[] = {0x51};
            buffer_append(b, push_ecx, 1);

            // MOVZX EAX, byte ptr [mem_reg] using SIB addressing to avoid nulls
            // LEA EAX, [mem_base_reg] (this may still have nulls for [EAX], use SIB)
            // Actually, let's do: MOVZX ECX, byte ptr [mem_base_reg] with SIB
            uint8_t movzx_sib[] = {0x0F, 0xB6, 0x0C, 0x20}; // MOVZX ECX, [EAX] using SIB
            buffer_append(b, movzx_sib, 4);

            // ADD CL, src_reg
            uint8_t add_instr[2];
            if (src_reg == X86_REG_AL) {
                add_instr[0] = 0x02;  // ADD CL, AL
                add_instr[1] = 0xC1;
            } else if (src_reg == X86_REG_CL) {
                add_instr[0] = 0x02;  // ADD CL, CL
                add_instr[1] = 0xC9;
            } else if (src_reg == X86_REG_DL) {
                add_instr[0] = 0x02;  // ADD CL, DL
                add_instr[1] = 0xCA;
            } else if (src_reg == X86_REG_BL) {
                add_instr[0] = 0x02;  // ADD CL, BL
                add_instr[1] = 0xCB;
            } else {
                // Handle other registers by creating proper ModR/M byte
                // reg=CL (0x01) and r/m = src_reg with mod=11 (register-to-register)
                add_instr[0] = 0x02;
                uint8_t src_reg_idx = src_reg - X86_REG_EAX;  // This only works for AL/CL/DL/BL
                if (src_reg_idx <= 3) {  // AL/CL/DL/BL
                    add_instr[1] = 0xC0 | (1 << 3) | src_reg_idx;  // 0xC0 | (CL << 3) | src_reg
                } else {  // AH/BH/CH/DH
                    add_instr[1] = 0xC0 | (1 << 3) | (src_reg_idx - 4);  // Adjust for high byte registers
                }
            }
            buffer_append(b, add_instr, 2);

            // MOV [mem_base_reg], CL using SIB to avoid nulls
            uint8_t mov_sib[] = {0x88, 0x0C, 0x20}; // MOV [EAX], CL using SIB
            buffer_append(b, mov_sib, 3);

            // POP ECX (restore ECX)
            uint8_t pop_ecx[] = {0x59};
            buffer_append(b, pop_ecx, 1);
        } else {
            // Use the original approach for non-EAX registers
            unsigned char temp_reg_num = 1;  // Use ECX as temp (reg number 1)

            // If memory register is ECX, use EDX as temp register instead
            if (op0.mem.base == X86_REG_ECX) {
                temp_reg_num = 2;  // Use EDX
            }

            // push temp_reg (ECX or EDX)
            unsigned char push_code = temp_reg_num == 1 ? 0x51 : 0x52; // 0x51=push ecx, 0x52=push edx
            buffer_append(b, &push_code, 1);

            // movzx temp_reg, byte ptr [mem_reg] - use SIB byte if mem_reg is EAX
            unsigned char movzx_instr[4];
            unsigned char mem_reg_num = op0.mem.base - X86_REG_EAX;
            if (op0.mem.base == X86_REG_EAX) {
                // Use SIB byte to avoid null: MOVZX temp_reg, [EAX] = 0x0F 0xB6 0x04 0x20 + reg_index
                movzx_instr[0] = 0x0F;
                movzx_instr[1] = 0xB6;
                movzx_instr[2] = 0x04;
                movzx_instr[3] = 0x20 + (temp_reg_num << 3); // SIB: scale=00, index=100(ESP), base=000(EAX)
                buffer_append(b, movzx_instr, 4);
            } else {
                movzx_instr[0] = 0x0F;
                movzx_instr[1] = 0xB6;
                movzx_instr[2] = (temp_reg_num << 3) | mem_reg_num; // reg=temp_reg, r/m=mem_reg
                buffer_append(b, movzx_instr, 3);
            }

            // add temp_reg, src_reg8
            unsigned char add_instr[] = {0x02, 0xC0}; // 0x02 is ADD r8, r/m8 opcode
            unsigned char src_reg_num = op1.reg - X86_REG_EAX;
            // Adjust for high 8-bit registers (AH, CH, DH, BH)
            if (op1.reg >= X86_REG_AH && op1.reg <= X86_REG_BH) {
                src_reg_num = (op1.reg - X86_REG_AH);
            }
            add_instr[1] = 0xC0 | (temp_reg_num << 3) | src_reg_num; // ModR/M: reg=temp_reg, r/m=src_reg8
            buffer_append(b, add_instr, 2);

            // mov byte ptr [mem_reg], temp_reg_low8 - use SIB if mem_reg is EAX
            unsigned char mov_instr[4];
            if (op0.mem.base == X86_REG_EAX) {
                // Use SIB byte: MOV [EAX], temp_reg = 0x88 0x04 0x20 + temp_reg_index
                mov_instr[0] = 0x88;
                mov_instr[1] = 0x04;
                mov_instr[2] = 0x20 + (temp_reg_num << 3); // SIB: scale=00, index=100(ESP), base=000(EAX)
                buffer_append(b, mov_instr, 3);
            } else {
                mov_instr[0] = 0x88;
                mov_instr[1] = (temp_reg_num << 3) | mem_reg_num; // ModR/M: reg=temp_reg, r/m=mem_reg
                buffer_append(b, mov_instr, 2);
            }

            // pop temp_reg
            unsigned char pop_code = temp_reg_num == 1 ? 0x59 : 0x5A; // 0x59=pop ecx, 0x5A=pop edx
            buffer_append(b, &pop_code, 1);
        }
    } else {
        // For more complex memory addressing, use the general approach
        // PUSH ECX
        uint8_t push_ecx[] = {0x51};
        buffer_append(b, push_ecx, 1);

        // MOVZX ECX, byte ptr [mem] - need to handle complex addressing
        // First load the effective address
        if (op0.mem.disp != 0) {
            // Load address of memory location to ECX
            generate_mov_eax_imm(b, (uint32_t)op0.mem.disp);
            // Then we need to add base/index if present
            if (op0.mem.base != X86_REG_INVALID) {
                // ADD EAX, base_reg
                uint8_t add_eax_base[] = {0x03, 0xC0};
                add_eax_base[1] = add_eax_base[1] | (op0.mem.base - X86_REG_EAX);
                buffer_append(b, add_eax_base, 2);
            }
        } else if (op0.mem.base != X86_REG_INVALID) {
            // LEA EAX, [base]
            uint8_t lea_eax_base[3];
            if (op0.mem.base == X86_REG_EAX) {
                // Use SIB byte to avoid null: LEA EAX, [EAX] = 0x8D 0x04 0x20
                lea_eax_base[0] = 0x8D;
                lea_eax_base[1] = 0x04;
                lea_eax_base[2] = 0x20;
                buffer_append(b, lea_eax_base, 3);
            } else {
                lea_eax_base[0] = 0x8D;
                uint8_t base_reg_idx = op0.mem.base - X86_REG_EAX;
                lea_eax_base[1] = (0 << 6) | (0 << 3) | base_reg_idx; // Mod=00, reg=000 (EAX), r/m=base
                buffer_append(b, lea_eax_base, 2);
            }
        }

        // MOVZX ECX, [EAX]
        uint8_t movzx_ecx_eax[] = {0x0F, 0xB6, 0x08}; // MOVZX ECX, [EAX]
        buffer_append(b, movzx_ecx_eax, 3);

        // ADD CL, src_reg
        uint8_t add_cl_src[] = {0x02, 0xC0};
        uint8_t src_reg_idx = op1.reg - X86_REG_EAX;
        if (op1.reg >= X86_REG_AH && op1.reg <= X86_REG_BH) {
            src_reg_idx = (op1.reg - X86_REG_AH);
        }
        // Correctly map 8-bit register indices:
        // AL=0, CL=1, DL=2, BL=3, AH=4, CH=5, DH=6, BH=7
        if (op1.reg == X86_REG_AL) src_reg_idx = 0;
        else if (op1.reg == X86_REG_CL) src_reg_idx = 1;
        else if (op1.reg == X86_REG_DL) src_reg_idx = 2;
        else if (op1.reg == X86_REG_BL) src_reg_idx = 3;
        else if (op1.reg == X86_REG_AH) src_reg_idx = 4;
        else if (op1.reg == X86_REG_CH) src_reg_idx = 5;
        else if (op1.reg == X86_REG_DH) src_reg_idx = 6;
        else if (op1.reg == X86_REG_BH) src_reg_idx = 7;

        add_cl_src[1] = add_cl_src[1] | src_reg_idx;
        buffer_append(b, add_cl_src, 2);

        // MOV [EAX], CL
        uint8_t mov_eax_cl[] = {0x88, 0x08};
        buffer_append(b, mov_eax_cl, 2);

        // POP ECX
        uint8_t pop_ecx[] = {0x59};
        buffer_append(b, pop_ecx, 1);
    }
}

// Define the strategy structure for ADD [mem], reg8
strategy_t transform_add_mem_reg8 = {
    .name = "transform_add_mem_reg8",
    .priority = 5,  // Very low priority - only as fallback when other strategies can't handle
    .can_handle = transform_add_mem_reg8_can_handle,
    .get_size = transform_add_mem_reg8_get_size,
    .generate = transform_add_mem_reg8_generate
};