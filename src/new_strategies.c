#include "new_strategies.h"
#include "profile_aware_sib.h"
#include "utils.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h> // For bool type

// Helper function to get the 3-bit register index from x86_reg for ModR/M and SIB bytes
static uint8_t get_capstone_reg_index(x86_reg reg) {
    switch (reg) {
        // General purpose registers
        case X86_REG_AL: case X86_REG_AX: case X86_REG_EAX: case X86_REG_RAX: return 0;
        case X86_REG_CL: case X86_REG_CX: case X86_REG_ECX: case X86_REG_RCX: return 1;
        case X86_REG_DL: case X86_REG_DX: case X86_REG_EDX: case X86_REG_RDX: return 2;
        case X86_REG_BL: case X86_REG_BX: case X86_REG_EBX: case X86_REG_RBX: return 3;
        case X86_REG_AH: case X86_REG_SP: case X86_REG_ESP: case X86_REG_RSP: return 4;
        case X86_REG_CH: case X86_REG_BP: case X86_REG_EBP: case X86_REG_RBP: return 5;
        case X86_REG_DH: case X86_REG_SI: case X86_REG_ESI: case X86_REG_RSI: return 6;
        case X86_REG_BH: case X86_REG_DI: case X86_REG_EDI: case X86_REG_RDI: return 7;
        // Extended registers (REX.B bit)
        case X86_REG_R8:  case X86_REG_R8B:  case X86_REG_R8D:  case X86_REG_R8W:  return 0; // REX.B=0
        case X86_REG_R9:  case X86_REG_R9B:  case X86_REG_R9D:  case X86_REG_R9W:  return 1; // REX.B=0
        case X86_REG_R10: case X86_REG_R10B: case X86_REG_R10D: case X86_REG_R10W: return 2; // REX.B=0
        case X86_REG_R11: case X86_REG_R11B: case X86_REG_R11D: case X86_REG_R11W: return 3; // REX.B=0
        case X86_REG_R12: case X86_REG_R12B: case X86_REG_R12D: case X86_REG_R12W: return 4; // REX.B=0
        case X86_REG_R13: case X86_REG_R13B: case X86_REG_R13D: case X86_REG_R13W: return 5; // REX.B=0
        case X86_REG_R14: case X86_REG_R14B: case X86_REG_R14D: case X86_REG_R14W: return 6; // REX.B=0
        case X86_REG_R15: case X86_REG_R15B: case X86_REG_R15D: case X86_REG_R15W: return 7; // REX.B=0
        default: return 0; // Should not happen for valid registers
    }
}

// Helper to get REX prefix for memory operand, if needed (for x64)
static uint8_t get_rex_prefix_for_mem_op(const cs_x86_op *mem_op, uint8_t reg_field) {
    uint8_t rex = 0x40; // Base REX prefix
    bool needs_rex = false;

    // REX.R (Extension of ModR/M reg field)
    if (reg_field & 0x8) { // If reg_field indicates an extended register (R8-R15)
        rex |= 0x4; // Set REX.R
        needs_rex = true;
    }

    // REX.X (Extension of SIB index field)
    if (mem_op->mem.index != X86_REG_INVALID && get_capstone_reg_index(mem_op->mem.index) >= 8) {
        rex |= 0x2; // Set REX.X
        needs_rex = true;
    }

    // REX.B (Extension of ModR/M R/M field or SIB base field)
    uint8_t base_index = get_capstone_reg_index(mem_op->mem.base);
    if (mem_op->mem.base != X86_REG_INVALID && base_index >= 8) {
        rex |= 0x1; // Set REX.B
        needs_rex = true;
    }

    return needs_rex ? rex : 0;
}


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
    unsigned char src_reg_num = get_capstone_reg_index(op1.mem.base);
    unsigned char dest_reg_num = get_capstone_reg_index(op0.reg);
    unsigned char temp_reg_num = get_capstone_reg_index(X86_REG_ECX);  // Use ECX as temp

    // If source register is ECX, use EDX as temp register instead
    if (op1.mem.base == X86_REG_ECX || op1.mem.base == X86_REG_RCX) {
        temp_reg_num = get_capstone_reg_index(X86_REG_EDX);  // Use EDX
    }

    // push temp_reg
    unsigned char push_code = 0x50 + temp_reg_num; // 0x50=push eax, 0x51=push ecx, 0x52=push edx, etc.
    buffer_append(b, &push_code, 1);

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
    mov_instr[1] = 0x40 | (dest_reg_num << 3) | temp_reg_num; // Mod=01 (bits 7-6), Reg=dest_reg_num (bits 5-3), R/M=temp_reg_num (2-0)
    buffer_append(b, mov_instr, 3);

    // pop temp_reg
    unsigned char pop_code = 0x58 + temp_reg_num; // 0x58=pop eax, 0x59=pop ecx, 0x5A=pop edx, etc.
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
                uint8_t src_reg_idx = get_capstone_reg_index(src_reg); // This only works for AL/CL/DL/BL
                add_instr[1] = 0xC0 | (get_capstone_reg_index(X86_REG_CL) << 3) | src_reg_idx;
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
            unsigned char temp_reg_num = get_capstone_reg_index(X86_REG_ECX);  // Use ECX as temp

            // If memory register is ECX, use EDX as temp register instead
            if (op0.mem.base == X86_REG_ECX || op0.mem.base == X86_REG_RCX) {
                temp_reg_num = get_capstone_reg_index(X86_REG_EDX);  // Use EDX
            }

            // push temp_reg (ECX or EDX)
            unsigned char push_code = 0x50 + temp_reg_num;
            buffer_append(b, &push_code, 1);

            // movzx temp_reg, byte ptr [mem_reg] - use SIB byte if mem_reg is EAX
            unsigned char movzx_instr[4];
            unsigned char mem_reg_num = get_capstone_reg_index(op0.mem.base);
            if (op0.mem.base == X86_REG_EAX || op0.mem.base == X86_REG_RAX) {
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
            unsigned char src_reg_num = get_capstone_reg_index(op1.reg);
            add_instr[1] = 0xC0 | (temp_reg_num << 3) | src_reg_num; // ModR/M: reg=temp_reg, r/m=src_reg8
            buffer_append(b, add_instr, 2);

            // mov byte ptr [mem_reg], temp_reg_low8 - use SIB if mem_reg is EAX
            unsigned char mov_instr[4];
            if (op0.mem.base == X86_REG_EAX || op0.mem.base == X86_REG_RAX) {
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
            unsigned char pop_code = 0x58 + temp_reg_num;
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
                add_eax_base[1] = add_eax_base[1] | get_capstone_reg_index(op0.mem.base);
                buffer_append(b, add_eax_base, 2);
            }
        } else if (op0.mem.base != X86_REG_INVALID) {
            // LEA EAX, [base]
            if (op0.mem.base == X86_REG_EAX || op0.mem.base == X86_REG_RAX) {
                // FIXED: LEA EAX, [EAX] is just a NOP for address calculation
                // Replace with simpler: NOP or just omit (EAX already has the value)
                // For safety, use: MOV EAX, EAX (0x89 0xC0) which is a NOP
                uint8_t nop_mov[] = {0x89, 0xC0}; // MOV EAX, EAX
                buffer_append(b, nop_mov, 2);
            } else {
                uint8_t lea_eax_base[2];
                lea_eax_base[0] = 0x8D;
                uint8_t base_reg_idx = get_capstone_reg_index(op0.mem.base);
                lea_eax_base[1] = (0 << 6) | (get_capstone_reg_index(X86_REG_EAX) << 3) | base_reg_idx; // Mod=00, reg=000 (EAX), r/m=base
                buffer_append(b, lea_eax_base, 2);
            }
        }

        // MOVZX ECX, [EAX]
        uint8_t movzx_ecx_eax[] = {0x0F, 0xB6, 0x08}; // MOVZX ECX, [EAX]
        buffer_append(b, movzx_ecx_eax, 3);

        // ADD CL, src_reg
        uint8_t add_cl_src[] = {0x02, 0xC0};
        uint8_t src_reg_idx = get_capstone_reg_index(op1.reg);

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

// Strategy for runtime null-termination of strings (INC byte ptr [mem])
int delayed_string_termination_can_handle(cs_insn *insn) {
    if (!insn || insn->id != X86_INS_INC || insn->detail->x86.op_count != 1) {
        return 0;
    }

    cs_x86_op op0 = insn->detail->x86.operands[0];

    // We are looking for INC byte ptr [mem] where the memory operand
    // could result in a null byte (e.g., ModR/M or SIB byte being 0x00)
    // or if the instruction itself contains a null byte and is INC.
    if (op0.type == X86_OP_MEM && op0.size == 1) { // INC byte ptr [mem]
        // Check for null bytes in the original instruction
        for (int i = 0; i < insn->size; i++) {
            if (insn->bytes[i] == 0x00) {
                return 1;
            }
        }

        // More specific check: if the ModR/M byte or SIB byte would be 0x00.
        // For INC byte ptr [reg], this typically results in 0x40/0x41 for the
        // ModR/M byte. For [EAX] (0x00) or [EAX+disp8] (0x00), it's more problematic.
        // Capstone often resolves these, but if original instruction has a null, it's a candidate.

        // Also if the current value is 0xFF, it will become 0x00 after INC.
        // This strategy specifically targets such scenarios for delayed termination.
        // This check would require dynamic analysis or more sophisticated static analysis
        // For simplicity now, we assume if it's INC byte ptr [mem] and has null it's a target.
        // Or if the byte at target address is 0xFF (not possible to know statically)
        // For now, let's prioritize instructions with explicit null bytes.
    }
    return 0;
}

// This needs to be beefed up to handle all x64 ModR/M and SIB cases robustly
size_t delayed_string_termination_get_size(cs_insn *insn) {
    (void)insn; // Avoid unused parameter warning
    // push rcx       (1 byte)
    // mov cl, [mem]  (approx 2-7 bytes, depending on addressing mode)
    // inc cl         (2 bytes)
    // mov [mem], cl  (approx 2-7 bytes, depending on addressing mode)
    // pop rcx        (1 byte)
    // Total estimated max: 1 + 7 + 2 + 7 + 1 = 18 bytes.
    return 20; // Conservative estimate
}

void delayed_string_termination_generate(struct buffer *b, cs_insn *insn) {
    if (!b || !insn) {
        return;
    }

    cs_x86_op op0 = insn->detail->x86.operands[0];
    if (op0.type != X86_OP_MEM || op0.size != 1) {
        // Fallback to original instruction if not INC byte ptr [mem]
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    const cs_x86_op *mem_op = &op0;

    // 1. PUSH RCX (51)
    buffer_write_byte(b, 0x51);

    // Get register indices for base, index.
    uint8_t base_reg_idx = (mem_op->mem.base != X86_REG_INVALID) ? get_capstone_reg_index(mem_op->mem.base) : 0;

    // --- MOV CL, byte ptr [mem_op] ---
    // Opcode 8A, Reg field for CL (0x01)
    uint8_t reg_field = get_capstone_reg_index(X86_REG_CL); // CL is register 1 (ecx)

    uint8_t rex_prefix_mov_cl = get_rex_prefix_for_mem_op(mem_op, reg_field);
    if (rex_prefix_mov_cl != 0) {
        buffer_write_byte(b, rex_prefix_mov_cl);
    }
    buffer_write_byte(b, 0x8A); // MOV r8, r/m8 opcode

    // ModR/M byte construction
    uint8_t modrm_byte_mov_cl = 0;
    modrm_byte_mov_cl |= (reg_field << 3); // Reg field (CL)

    // Handle Mod and R/M based on addressing mode
    if (mem_op->mem.base == X86_REG_INVALID && mem_op->mem.index == X86_REG_INVALID) {
        // Absolute addressing [disp32]
        modrm_byte_mov_cl |= (0 << 6); // Mod = 00
        modrm_byte_mov_cl |= 0x05; // R/M = 101 (relative addressing for disp32)
        buffer_write_byte(b, modrm_byte_mov_cl);
        buffer_append(b, (uint8_t*)&mem_op->mem.disp, 4); // disp32
    } else if (mem_op->mem.disp == 0 && mem_op->mem.index == X86_REG_INVALID) {
        // [base_reg] addressing (Mod=00)
        modrm_byte_mov_cl |= (0 << 6); // Mod = 00
        modrm_byte_mov_cl |= base_reg_idx; // R/M = base_reg
        if (base_reg_idx == get_capstone_reg_index(X86_REG_ESP) || base_reg_idx == get_capstone_reg_index(X86_REG_RSP)) { // Special case for RSP requires SIB byte
            buffer_write_byte(b, modrm_byte_mov_cl); // ModR/M byte
            buffer_write_byte(b, 0x24); // SIB byte (00_100_100)
        } else {
            buffer_write_byte(b, modrm_byte_mov_cl);
        }
    } else if (mem_op->mem.disp != 0 && mem_op->mem.index == X86_REG_INVALID) {
        // [base_reg + disp8/32] addressing
        if (mem_op->mem.disp >= -128 && mem_op->mem.disp <= 127) { // disp8
            modrm_byte_mov_cl |= (1 << 6); // Mod = 01
            modrm_byte_mov_cl |= base_reg_idx;
            if (base_reg_idx == get_capstone_reg_index(X86_REG_ESP) || base_reg_idx == get_capstone_reg_index(X86_REG_RSP)) { // Special case for RSP requires SIB byte
                buffer_write_byte(b, modrm_byte_mov_cl);
                buffer_write_byte(b, 0x24); // SIB byte
            } else {
                buffer_write_byte(b, modrm_byte_mov_cl);
            }
            buffer_write_byte(b, (uint8_t)mem_op->mem.disp); // disp8
        } else { // disp32
            modrm_byte_mov_cl |= (2 << 6); // Mod = 10
            modrm_byte_mov_cl |= base_reg_idx;
            if (base_reg_idx == get_capstone_reg_index(X86_REG_ESP) || base_reg_idx == get_capstone_reg_index(X86_REG_RSP)) { // Special case for RSP requires SIB byte
                buffer_write_byte(b, modrm_byte_mov_cl);
                buffer_write_byte(b, 0x24); // SIB byte
            } else {
                buffer_write_byte(b, modrm_byte_mov_cl);
            }
            buffer_append(b, (uint8_t*)&mem_op->mem.disp, 4); // disp32
        }
    } else { // Handle [base + index*scale + disp]
        // This requires SIB byte construction.
        // For simplicity for now, this case will fallback if not simple.
        // More robust SIB handling would go here.
        buffer_append(b, insn->bytes, insn->size);
        buffer_write_byte(b, 0x59); // pop rcx to balance stack
        return;
    }


    // 3. INC CL (FE C1)
    buffer_write_byte(b, 0xFE);
    buffer_write_byte(b, 0xC1);

    // --- MOV byte ptr [mem_op], CL ---
    // Opcode 88, Reg field for CL (0x01)
    uint8_t reg_field_mov_mem_cl = get_capstone_reg_index(X86_REG_CL); // CL is register 1

    uint8_t rex_prefix_mov_mem_cl = get_rex_prefix_for_mem_op(mem_op, reg_field_mov_mem_cl);
    if (rex_prefix_mov_mem_cl != 0) {
        buffer_write_byte(b, rex_prefix_mov_mem_cl);
    }
    buffer_write_byte(b, 0x88); // MOV r/m8, r8 opcode

    // ModR/M byte construction
    uint8_t modrm_byte_mov_mem_cl = 0;
    modrm_byte_mov_mem_cl |= (reg_field_mov_mem_cl << 3); // Reg field (CL)

    // Handle Mod and R/M based on addressing mode (same logic as MOV CL, [mem])
    if (mem_op->mem.base == X86_REG_INVALID && mem_op->mem.index == X86_REG_INVALID) {
        // Absolute addressing [disp32]
        modrm_byte_mov_mem_cl |= (0 << 6); // Mod = 00
        modrm_byte_mov_mem_cl |= 0x05; // R/M = 101 (relative addressing for disp32)
        buffer_write_byte(b, modrm_byte_mov_mem_cl);
        buffer_append(b, (uint8_t*)&mem_op->mem.disp, 4); // disp32
    } else if (mem_op->mem.disp == 0 && mem_op->mem.index == X86_REG_INVALID) {
        // [base_reg] addressing (Mod=00)
        modrm_byte_mov_mem_cl |= (0 << 6); // Mod = 00
        modrm_byte_mov_mem_cl |= base_reg_idx; // R/M = base_reg
        if (base_reg_idx == get_capstone_reg_index(X86_REG_ESP) || base_reg_idx == get_capstone_reg_index(X86_REG_RSP)) { // Special case for RSP requires SIB byte
            buffer_write_byte(b, modrm_byte_mov_mem_cl);
            buffer_write_byte(b, 0x24); // SIB byte for [RSP]
        } else {
            buffer_write_byte(b, modrm_byte_mov_mem_cl);
        }
    } else if (mem_op->mem.disp != 0 && mem_op->mem.index == X86_REG_INVALID) {
        // [base_reg + disp8/32] addressing
        if (mem_op->mem.disp >= -128 && mem_op->mem.disp <= 127) { // disp8
            modrm_byte_mov_mem_cl |= (1 << 6); // Mod = 01
            modrm_byte_mov_mem_cl |= base_reg_idx;
            if (base_reg_idx == get_capstone_reg_index(X86_REG_ESP) || base_reg_idx == get_capstone_reg_index(X86_REG_RSP)) { // Special case for RSP requires SIB byte
                buffer_write_byte(b, modrm_byte_mov_mem_cl);
                buffer_write_byte(b, 0x24); // SIB byte
            } else {
                buffer_write_byte(b, modrm_byte_mov_mem_cl);
            }
            buffer_write_byte(b, (uint8_t)mem_op->mem.disp); // disp8
        } else { // disp32
            modrm_byte_mov_mem_cl |= (2 << 6); // Mod = 10
            modrm_byte_mov_mem_cl |= base_reg_idx;
            if (base_reg_idx == get_capstone_reg_index(X86_REG_ESP) || base_reg_idx == get_capstone_reg_index(X86_REG_RSP)) { // Special case for RSP requires SIB byte
                buffer_write_byte(b, modrm_byte_mov_mem_cl);
                buffer_write_byte(b, 0x24); // SIB byte
            } else {
                buffer_write_byte(b, modrm_byte_mov_mem_cl);
            }
            buffer_append(b, (uint8_t*)&mem_op->mem.disp, 4); // disp32
        }
    } else { // Handle [base + index*scale + disp]
        // Fallback for complex SIB cases
        buffer_append(b, insn->bytes, insn->size);
        buffer_write_byte(b, 0x59); // pop rcx to balance stack
        return;
    }

    // 5. POP RCX (59)
    buffer_write_byte(b, 0x59);
}

// Define the strategy structure
strategy_t delayed_string_termination_strategy = {
    .name = "delayed_string_termination",
    .priority = 90, // High priority for this specific null-byte pattern
    .can_handle = delayed_string_termination_can_handle,
    .get_size = delayed_string_termination_get_size,
    .generate = delayed_string_termination_generate
};
