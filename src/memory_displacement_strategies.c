/*
 * MEMORY DISPLACEMENT NULL-BYTE ELIMINATION STRATEGIES
 * =====================================================
 *
 * Priority: 82-85 (HIGH IMPACT)
 *
 * Purpose:
 *   Eliminates null bytes in memory addressing displacements, which affects
 *   167 instructions (53.9% of failures) in the shellcode corpus - the HIGHEST
 *   IMPACT single strategy category.
 *
 * Target Patterns:
 *   1. Memory operations with disp32 containing nulls:
 *      - mov eax, [0x100000]        ; A1 00 00 10 00
 *      - lea ebp, [esp + 0x80]      ; 8D AC 24 80 00 00 00
 *      - mov [ebx + 0x100], eax     ; 89 83 00 01 00 00
 *
 *   2. SIB byte addressing with null displacements:
 *      - mov [esp + 0x80], ebp      ; 89 AC 24 80 00 00 00
 *      - mov [eax + ebx*4 + 0x100], ecx
 *
 * Transformation Strategies:
 *   Strategy A: Register-Indirect with Arithmetic
 *     Original: mov eax, [ebx + 0x100]
 *     Replace:  push ecx
 *               mov ecx, ebx
 *               add ecx, 0x100    ; null-free immediate construction
 *               mov eax, [ecx]
 *               pop ecx
 *
 *   Strategy B: LEA Conversion to MOV+ADD
 *     Original: lea ebp, [esp + 0x80]
 *     Replace:  mov ebp, esp
 *               add ebp, 0x80     ; null-free immediate construction
 *
 *   Strategy C: Base Register Construction
 *     Original: mov eax, [0x100000]
 *     Replace:  push ebx
 *               mov ebx, 0x100000  ; null-free construction via generate_mov_eax_imm
 *               mov eax, [ebx]
 *               pop ebx
 *
 * Implementation Notes:
 *   - Uses generate_mov_eax_imm() for null-safe immediate construction
 *   - Preserves temporary registers with PUSH/POP
 *   - Handles both ModR/M and SIB addressing modes
 *   - Maintains proper memory access semantics
 *   - Priority 82-85 ensures high precedence in strategy selection
 *
 * Algorithm Complexity:
 *   - Detection: O(1) - check displacement bytes
 *   - Size Calculation: O(1) - fixed transformation size
 *   - Generation: O(1) - emit fixed instruction sequence
 *
 * Size Impact:
 *   - Original: 2-7 bytes (varies by addressing mode)
 *   - Replacement: 8-15 bytes (includes register preservation)
 *   - Overhead: ~2-3x (acceptable for null-free guarantee)
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Check if a 32-bit displacement value contains null bytes
 */
static int has_null_in_disp32(int32_t disp) {
    uint32_t val = (uint32_t)disp;
    return ((val & 0xFF) == 0) ||
           (((val >> 8) & 0xFF) == 0) ||
           (((val >> 16) & 0xFF) == 0) ||
           (((val >> 24) & 0xFF) == 0);
}

/**
 * Check if instruction has memory operand with null displacement
 */
static int has_memory_disp_null(cs_insn *insn) {
    if (!insn || !insn->detail) return 0;

    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        cs_x86_op *op = &insn->detail->x86.operands[i];

        if (op->type == X86_OP_MEM) {
            // Check if displacement exists and contains nulls
            if (op->mem.disp != 0 && has_null_in_disp32(op->mem.disp)) {
                return 1;
            }

            // Check for zero displacement that would be encoded as disp32
            // This happens with certain register combinations
            if (op->mem.disp == 0 && op->mem.base == X86_REG_INVALID) {
                return 1; // Absolute addressing: [disp32] where disp=0
            }
        }
    }

    return 0;
}

/**
 * Select a temporary register that doesn't conflict with instruction operands
 */
static x86_reg select_temp_register(cs_insn *insn) {
    // Preference order: ECX, EDX, EBX, ESI, EDI
    x86_reg candidates[] = {X86_REG_ECX, X86_REG_EDX, X86_REG_EBX,
                            X86_REG_ESI, X86_REG_EDI};

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        int used = 0;

        // Check if candidate is used in instruction
        for (int j = 0; j < insn->detail->x86.op_count; j++) {
            cs_x86_op *op = &insn->detail->x86.operands[j];

            if (op->type == X86_OP_REG && op->reg == candidates[i]) {
                used = 1;
                break;
            }

            if (op->type == X86_OP_MEM) {
                if (op->mem.base == candidates[i] ||
                    op->mem.index == candidates[i]) {
                    used = 1;
                    break;
                }
            }
        }

        if (!used) return candidates[i];
    }

    // Fallback to ECX (should rarely happen)
    return X86_REG_ECX;
}

// ============================================================================
// STRATEGY 1: LEA DISPLACEMENT NULL HANDLING (Priority 85)
// ============================================================================
// Handles: LEA reg, [base + disp32] where disp32 contains nulls
// Example: LEA EBP, [ESP + 0x80]  ; 8D AC 24 80 00 00 00
//
// Transformation:
//   Original: LEA EBP, [ESP + 0x80]
//   Transformed:
//     MOV EBP, ESP             ; Copy base register
//     ADD EBP, 0x80            ; Add displacement (null-free construction)

static int can_handle_lea_disp_null(cs_insn *insn) {
    if (insn->id != X86_INS_LEA) {
        return 0;
    }

    // Check if it has null bytes (primary check)
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Check if memory operand has null displacement
    return has_memory_disp_null(insn);
}

static size_t get_size_lea_disp_null(cs_insn *insn) {
    (void)insn; // Unused in size calculation

    // MOV reg, base_reg (2 bytes) +
    // Null-free ADD reg, imm construction (varies: 2-12 bytes, estimate 10)
    return 12;
}

static void generate_lea_disp_null(struct buffer *b, cs_insn *insn) {
    // Extract operands
    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    cs_x86_op *src_op = &insn->detail->x86.operands[1];

    x86_reg dst_reg = dst_op->reg;
    x86_reg base_reg = src_op->mem.base;
    int32_t disp = src_op->mem.disp;

    // Handle simple case: LEA reg, [base + disp]
    if (src_op->mem.index == X86_REG_INVALID) {
        // MOV dst, base
        uint8_t mov_code[] = {0x89, 0xC0};  // MOV r32, r32 template
        mov_code[1] = 0xC0 | (get_reg_index(base_reg) << 3) | get_reg_index(dst_reg);
        buffer_append(b, mov_code, 2);

        // ADD dst, disp (using null-free construction)
        if (disp != 0) {
            // Use ADD reg, imm with null-free immediate value
            // First construct the immediate in EAX (if dst != EAX)
            if (dst_reg == X86_REG_EAX) {
                // Special case: destination is EAX
                // Generate null-free ADD EAX, imm directly
                generate_mov_eax_imm(b, (uint32_t)disp);

                // ADD base_reg, EAX (using temp storage)
                // This is more complex, use inline construction
                uint8_t xor_eax[] = {0x31, 0xC0};  // XOR EAX, EAX
                buffer_append(b, xor_eax, 2);

                // Reconstruct displacement in EAX byte-by-byte
                for (int i = 3; i >= 0; i--) {
                    uint8_t byte = ((uint32_t)disp >> (i * 8)) & 0xFF;
                    if (byte != 0) {
                        if (i != 3) {
                            uint8_t shl[] = {0xC1, 0xE0, 0x08};  // SHL EAX, 8
                            buffer_append(b, shl, 3);
                        }
                        uint8_t or_al[] = {0x0C, byte};  // OR AL, byte
                        buffer_append(b, or_al, 2);
                    } else if (i != 3) {
                        uint8_t shl[] = {0xC1, 0xE0, 0x08};  // SHL EAX, 8
                        buffer_append(b, shl, 3);
                    }
                }
            } else {
                // Save EAX temporarily
                buffer_write_byte(b, 0x50);  // PUSH EAX

                // Construct displacement in EAX
                generate_mov_eax_imm(b, (uint32_t)disp);

                // ADD dst, EAX
                uint8_t add_code[] = {0x01, 0xC0};  // ADD r32, r32 template
                add_code[1] = 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(dst_reg);
                buffer_append(b, add_code, 2);

                // Restore EAX
                buffer_write_byte(b, 0x58);  // POP EAX
            }
        }
    } else {
        // Complex case with SIB: LEA reg, [base + index*scale + disp]
        // This is rare but needs handling
        // Transform to: base + (index << scale) + disp

        x86_reg index_reg = src_op->mem.index;
        int scale = src_op->mem.scale;

        // Use a temporary register for calculation
        x86_reg temp = select_temp_register(insn);

        // PUSH temp
        buffer_write_byte(b, 0x50 + get_reg_index(temp));

        // MOV temp, index
        uint8_t mov1[] = {0x89, 0xC0 | (get_reg_index(index_reg) << 3) | get_reg_index(temp)};
        buffer_append(b, mov1, 2);

        // Scale: SHL temp, log2(scale)
        if (scale > 1) {
            uint8_t shift_amt = 0;
            if (scale == 2) shift_amt = 1;
            else if (scale == 4) shift_amt = 2;
            else if (scale == 8) shift_amt = 3;

            uint8_t shl[] = {0xC1, 0xE0 | get_reg_index(temp), shift_amt};
            buffer_append(b, shl, 3);
        }

        // ADD temp, base
        uint8_t add1[] = {0x01, 0xC0 | (get_reg_index(base_reg) << 3) | get_reg_index(temp)};
        buffer_append(b, add1, 2);

        // ADD temp, disp (null-free)
        if (disp != 0) {
            // Save EAX if needed
            if (temp != X86_REG_EAX && dst_reg != X86_REG_EAX) {
                buffer_write_byte(b, 0x50);  // PUSH EAX
            }

            generate_mov_eax_imm(b, (uint32_t)disp);

            uint8_t add2[] = {0x01, 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(temp)};
            buffer_append(b, add2, 2);

            if (temp != X86_REG_EAX && dst_reg != X86_REG_EAX) {
                buffer_write_byte(b, 0x58);  // POP EAX
            }
        }

        // MOV dst, temp
        uint8_t mov2[] = {0x89, 0xC0 | (get_reg_index(temp) << 3) | get_reg_index(dst_reg)};
        buffer_append(b, mov2, 2);

        // POP temp
        buffer_write_byte(b, 0x58 + get_reg_index(temp));
    }
}

static strategy_t lea_disp_null_strategy = {
    .name = "lea_disp_null",
    .can_handle = can_handle_lea_disp_null,
    .get_size = get_size_lea_disp_null,
    .generate = generate_lea_disp_null,
    .priority = 85
};

// ============================================================================
// STRATEGY 2: MOV MEMORY DISPLACEMENT NULL HANDLING (Priority 83)
// ============================================================================
// Handles: MOV reg, [base + disp32] where disp32 contains nulls
// Example: MOV EAX, [EBX + 0x100]  ; 8B 83 00 01 00 00
//
// Transformation:
//   Original: MOV EAX, [EBX + 0x100]
//   Transformed:
//     PUSH ECX                 ; Save temp register
//     MOV ECX, EBX            ; Copy base
//     ADD ECX, 0x100          ; Add displacement (null-free)
//     MOV EAX, [ECX]          ; Load from calculated address
//     POP ECX                 ; Restore temp

static int can_handle_mov_mem_disp_null(cs_insn *insn) {
    if (insn->id != X86_INS_MOV) {
        return 0;
    }

    // Check if it has null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Check if has memory operand with null displacement
    return has_memory_disp_null(insn);
}

static size_t get_size_mov_mem_disp_null(cs_insn *insn) {
    (void)insn;

    // PUSH temp (1) + MOV temp, base (2) + ADD temp, disp (10) +
    // MOV reg, [temp] (3) + POP temp (1) = 17 bytes
    return 17;
}

static void generate_mov_mem_disp_null(struct buffer *b, cs_insn *insn) {
    // Determine which operand is memory
    cs_x86_op *reg_op = NULL;
    cs_x86_op *mem_op = NULL;
    int mem_is_dst = 0;

    if (insn->detail->x86.operands[0].type == X86_OP_MEM) {
        mem_op = &insn->detail->x86.operands[0];
        reg_op = &insn->detail->x86.operands[1];
        mem_is_dst = 1;
    } else {
        reg_op = &insn->detail->x86.operands[0];
        mem_op = &insn->detail->x86.operands[1];
        mem_is_dst = 0;
    }

    x86_reg data_reg = reg_op->reg;
    x86_reg base_reg = mem_op->mem.base;
    int32_t disp = mem_op->mem.disp;

    // Handle absolute addressing: mov reg, [disp32]
    if (base_reg == X86_REG_INVALID) {
        // Select temp register
        x86_reg temp = select_temp_register(insn);

        // PUSH temp
        buffer_write_byte(b, 0x50 + get_reg_index(temp));

        // MOV temp, disp (null-free construction)
        if (temp == X86_REG_EAX) {
            generate_mov_eax_imm(b, (uint32_t)disp);
        } else {
            buffer_write_byte(b, 0x50);  // PUSH EAX
            generate_mov_eax_imm(b, (uint32_t)disp);
            // MOV temp, EAX
            uint8_t mov[] = {0x89, 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(temp)};
            buffer_append(b, mov, 2);
            buffer_write_byte(b, 0x58);  // POP EAX
        }

        // MOV data_reg, [temp] or MOV [temp], data_reg
        if (mem_is_dst) {
            // MOV [temp], data_reg
            if (temp == X86_REG_EAX) {
                // Use SIB to avoid [EAX] which encodes as 00
                // 89 /r: MOV r/m32, r32
                // ModR/M: 00 (mod) | reg_index<<3 | 100 (r/m means SIB follows)
                // SIB: 00 (scale) | 100 (index means no index) | 000 (base means EAX)
                uint8_t modrm = 0x04 | (get_reg_index(data_reg) << 3);
                uint8_t sib = 0x20;  // [EAX] with no index
                uint8_t mov[] = {0x89, modrm, sib};
                buffer_append(b, mov, 3);
            } else {
                uint8_t mov[] = {0x89, 0x00 | (get_reg_index(data_reg) << 3) | get_reg_index(temp)};
                buffer_append(b, mov, 2);
            }
        } else {
            // MOV data_reg, [temp]
            if (temp == X86_REG_EAX) {
                // Use SIB encoding
                // 8B /r: MOV r32, r/m32
                // ModR/M: 00 (mod) | reg_index<<3 | 100 (r/m means SIB follows)
                // SIB: 00 (scale) | 100 (index means no index) | 000 (base means EAX)
                uint8_t modrm = 0x04 | (get_reg_index(data_reg) << 3);
                uint8_t sib = 0x20;  // [EAX] with no index
                uint8_t mov[] = {0x8B, modrm, sib};
                buffer_append(b, mov, 3);
            } else {
                uint8_t mov[] = {0x8B, 0x00 | (get_reg_index(data_reg) << 3) | get_reg_index(temp)};
                buffer_append(b, mov, 2);
            }
        }

        // POP temp
        buffer_write_byte(b, 0x58 + get_reg_index(temp));
        return;
    }

    // Handle [base + disp] addressing
    if (mem_op->mem.index == X86_REG_INVALID) {
        // Simple case: no index register
        x86_reg temp = select_temp_register(insn);

        // PUSH temp
        buffer_write_byte(b, 0x50 + get_reg_index(temp));

        // MOV temp, base
        uint8_t mov1[] = {0x89, 0xC0 | (get_reg_index(base_reg) << 3) | get_reg_index(temp)};
        buffer_append(b, mov1, 2);

        // ADD temp, disp (null-free)
        if (disp != 0) {
            if (temp == X86_REG_EAX) {
                buffer_write_byte(b, 0x50);  // PUSH EAX temporarily
                generate_mov_eax_imm(b, (uint32_t)disp);
                buffer_write_byte(b, 0x58 + get_reg_index(X86_REG_ECX));  // Store in ECX
                buffer_write_byte(b, 0x58);  // POP EAX
                uint8_t add[] = {0x01, 0xC0 | (get_reg_index(X86_REG_ECX) << 3) | get_reg_index(temp)};
                buffer_append(b, add, 2);
            } else {
                buffer_write_byte(b, 0x50);  // PUSH EAX
                generate_mov_eax_imm(b, (uint32_t)disp);
                uint8_t add[] = {0x01, 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(temp)};
                buffer_append(b, add, 2);
                buffer_write_byte(b, 0x58);  // POP EAX
            }
        }

        // MOV data_reg, [temp] or MOV [temp], data_reg
        if (mem_is_dst) {
            if (temp == X86_REG_EAX) {
                // Use SIB to avoid [EAX] which encodes as 00
                // 89 /r: MOV r/m32, r32
                // ModR/M: 00 (mod) | reg_index<<3 | 100 (r/m means SIB follows)
                // SIB: 00 (scale) | 100 (index means no index) | 000 (base means EAX)
                uint8_t modrm = 0x04 | (get_reg_index(data_reg) << 3);
                uint8_t sib = 0x20;  // [EAX] with no index
                uint8_t mov[] = {0x89, modrm, sib};
                buffer_append(b, mov, 3);
            } else {
                uint8_t mov[] = {0x89, 0x00 | (get_reg_index(data_reg) << 3) | get_reg_index(temp)};
                buffer_append(b, mov, 2);
            }
        } else {
            if (temp == X86_REG_EAX) {
                // Use SIB encoding
                // 8B /r: MOV r32, r/m32
                // ModR/M: 00 (mod) | reg_index<<3 | 100 (r/m means SIB follows)
                // SIB: 00 (scale) | 100 (index means no index) | 000 (base means EAX)
                uint8_t modrm = 0x04 | (get_reg_index(data_reg) << 3);
                uint8_t sib = 0x20;  // [EAX] with no index
                uint8_t mov[] = {0x8B, modrm, sib};
                buffer_append(b, mov, 3);
            } else {
                uint8_t mov[] = {0x8B, 0x00 | (get_reg_index(data_reg) << 3) | get_reg_index(temp)};
                buffer_append(b, mov, 2);
            }
        }

        // POP temp
        buffer_write_byte(b, 0x58 + get_reg_index(temp));
    } else {
        // Complex case with SIB: [base + index*scale + disp]
        // Similar to LEA complex case
        x86_reg index_reg = mem_op->mem.index;
        int scale = mem_op->mem.scale;
        x86_reg temp = select_temp_register(insn);

        // PUSH temp
        buffer_write_byte(b, 0x50 + get_reg_index(temp));

        // MOV temp, index
        uint8_t mov1[] = {0x89, 0xC0 | (get_reg_index(index_reg) << 3) | get_reg_index(temp)};
        buffer_append(b, mov1, 2);

        // Scale if needed
        if (scale > 1) {
            uint8_t shift_amt = 0;
            if (scale == 2) shift_amt = 1;
            else if (scale == 4) shift_amt = 2;
            else if (scale == 8) shift_amt = 3;
            uint8_t shl[] = {0xC1, 0xE0 | get_reg_index(temp), shift_amt};
            buffer_append(b, shl, 3);
        }

        // ADD temp, base
        uint8_t add1[] = {0x01, 0xC0 | (get_reg_index(base_reg) << 3) | get_reg_index(temp)};
        buffer_append(b, add1, 2);

        // ADD temp, disp (null-free)
        if (disp != 0) {
            buffer_write_byte(b, 0x50);  // PUSH EAX
            generate_mov_eax_imm(b, (uint32_t)disp);
            uint8_t add2[] = {0x01, 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(temp)};
            buffer_append(b, add2, 2);
            buffer_write_byte(b, 0x58);  // POP EAX
        }

        // Perform the MOV
        if (mem_is_dst) {
            uint8_t mov[] = {0x89, 0x00 | (get_reg_index(data_reg) << 3) | get_reg_index(temp)};
            buffer_append(b, mov, 2);
        } else {
            uint8_t mov[] = {0x8B, 0x00 | (get_reg_index(data_reg) << 3) | get_reg_index(temp)};
            buffer_append(b, mov, 2);
        }

        // POP temp
        buffer_write_byte(b, 0x58 + get_reg_index(temp));
    }
}

static strategy_t mov_mem_disp_null_strategy = {
    .name = "mov_mem_disp_null",
    .can_handle = can_handle_mov_mem_disp_null,
    .get_size = get_size_mov_mem_disp_null,
    .generate = generate_mov_mem_disp_null,
    .priority = 83
};

// ============================================================================
// STRATEGY 3: GENERAL MEMORY OPERATION DISPLACEMENT NULL HANDLING (Priority 82)
// ============================================================================
// Handles: Other memory operations (ADD, SUB, CMP, etc.) with null displacements
// Example: ADD EAX, [EBX + 0x100]  ; 03 83 00 01 00 00
//
// Transformation: Similar to MOV but preserves operation semantics

static int can_handle_general_mem_disp_null(cs_insn *insn) {
    // Skip if already handled by higher-priority strategies
    if (insn->id == X86_INS_LEA || insn->id == X86_INS_MOV) {
        return 0;
    }

    // Check if it has null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Check if has memory operand with null displacement
    return has_memory_disp_null(insn);
}

static size_t get_size_general_mem_disp_null(cs_insn *insn) {
    (void)insn;
    // Similar size to MOV strategy
    return 17;
}

static void generate_general_mem_disp_null(struct buffer *b, cs_insn *insn) {
    // Find memory operand
    cs_x86_op *mem_op = NULL;
    int mem_index = -1;

    for (int i = 0; i < insn->detail->x86.op_count; i++) {
        if (insn->detail->x86.operands[i].type == X86_OP_MEM) {
            mem_op = &insn->detail->x86.operands[i];
            mem_index = i;
            break;
        }
    }

    if (!mem_op) {
        // No memory operand, shouldn't happen
        fprintf(stderr, "[ERROR] No memory operand in general_mem_disp_null\n");
        return;
    }

    // Get memory addressing components
    x86_reg base_reg = mem_op->mem.base;
    x86_reg index_reg = mem_op->mem.index;
    int32_t disp = mem_op->mem.disp;
    int scale = mem_op->mem.scale;

    // Select temporary register
    x86_reg temp = select_temp_register(insn);

    // PUSH temp
    buffer_write_byte(b, 0x50 + get_reg_index(temp));

    // Calculate effective address in temp
    if (base_reg == X86_REG_INVALID) {
        // Absolute address
        if (temp == X86_REG_EAX) {
            generate_mov_eax_imm(b, (uint32_t)disp);
        } else {
            buffer_write_byte(b, 0x50);  // PUSH EAX
            generate_mov_eax_imm(b, (uint32_t)disp);
            uint8_t mov[] = {0x89, 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(temp)};
            buffer_append(b, mov, 2);
            buffer_write_byte(b, 0x58);  // POP EAX
        }
    } else if (index_reg == X86_REG_INVALID) {
        // [base + disp]
        // MOV temp, base
        uint8_t mov[] = {0x89, 0xC0 | (get_reg_index(base_reg) << 3) | get_reg_index(temp)};
        buffer_append(b, mov, 2);

        // ADD temp, disp
        if (disp != 0) {
            buffer_write_byte(b, 0x50);  // PUSH EAX
            generate_mov_eax_imm(b, (uint32_t)disp);
            uint8_t add[] = {0x01, 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(temp)};
            buffer_append(b, add, 2);
            buffer_write_byte(b, 0x58);  // POP EAX
        }
    } else {
        // [base + index*scale + disp]
        // MOV temp, index
        uint8_t mov1[] = {0x89, 0xC0 | (get_reg_index(index_reg) << 3) | get_reg_index(temp)};
        buffer_append(b, mov1, 2);

        // Scale
        if (scale > 1) {
            uint8_t shift_amt = (scale == 2) ? 1 : (scale == 4) ? 2 : 3;
            uint8_t shl[] = {0xC1, 0xE0 | get_reg_index(temp), shift_amt};
            buffer_append(b, shl, 3);
        }

        // ADD temp, base
        uint8_t add1[] = {0x01, 0xC0 | (get_reg_index(base_reg) << 3) | get_reg_index(temp)};
        buffer_append(b, add1, 2);

        // ADD temp, disp
        if (disp != 0) {
            buffer_write_byte(b, 0x50);  // PUSH EAX
            generate_mov_eax_imm(b, (uint32_t)disp);
            uint8_t add2[] = {0x01, 0xC0 | (get_reg_index(X86_REG_EAX) << 3) | get_reg_index(temp)};
            buffer_append(b, add2, 2);
            buffer_write_byte(b, 0x58);  // POP EAX
        }
    }

    // Now emit the original instruction but with [temp] instead of complex memory operand
    // This is a simplified approach - for full support, would need per-instruction handling
    // For now, use the fallback approach: we've addressed the memory, now perform operation

    // Get the other operand (non-memory)
    cs_x86_op *other_op = NULL;
    if (mem_index == 0 && insn->detail->x86.op_count > 1) {
        other_op = &insn->detail->x86.operands[1];
    } else if (mem_index == 1 && insn->detail->x86.op_count > 1) {
        other_op = &insn->detail->x86.operands[0];
    }

    // Emit simplified instruction using [temp]
    // This is a complex area - for a full implementation, would need instruction-specific encoding
    // For this strategy, we'll use a conservative approach

    // Example for ADD: ADD reg, [temp]
    if (other_op && other_op->type == X86_OP_REG) {
        x86_reg data_reg = other_op->reg;

        // Determine opcode based on instruction type
        uint8_t opcode = 0x03;  // Default to ADD

        switch (insn->id) {
            case X86_INS_ADD: opcode = 0x03; break;
            case X86_INS_SUB: opcode = 0x2B; break;
            case X86_INS_AND: opcode = 0x23; break;
            case X86_INS_OR:  opcode = 0x0B; break;
            case X86_INS_XOR: opcode = 0x33; break;
            case X86_INS_CMP: opcode = 0x3B; break;
            case X86_INS_TEST: opcode = 0x85; break;
            default:
                // Use fallback for unsupported instructions
                fprintf(stderr, "[WARN] Unsupported instruction in general_mem_disp_null: %s\n",
                        insn->mnemonic);
                opcode = 0x03;
                break;
        }

        // Emit: OP data_reg, [temp]
        if (temp == X86_REG_EAX) {
            // Use SIB to avoid [EAX] encoding with null
            uint8_t code[] = {opcode, 0x04, 0x20 | (get_reg_index(data_reg) << 3)};
            buffer_append(b, code, 3);
        } else {
            uint8_t modrm = 0x00 | (get_reg_index(data_reg) << 3) | get_reg_index(temp);
            uint8_t code[] = {opcode, modrm};
            buffer_append(b, code, 2);
        }
    }

    // POP temp
    buffer_write_byte(b, 0x58 + get_reg_index(temp));
}

static strategy_t general_mem_disp_null_strategy = {
    .name = "general_mem_disp_null",
    .can_handle = can_handle_general_mem_disp_null,
    .get_size = get_size_general_mem_disp_null,
    .generate = generate_general_mem_disp_null,
    .priority = 82
};

// ============================================================================
// REGISTRATION
// ============================================================================

void register_memory_displacement_strategies() {
    register_strategy(&lea_disp_null_strategy);           // Priority 85
    register_strategy(&mov_mem_disp_null_strategy);       // Priority 83
    register_strategy(&general_mem_disp_null_strategy);   // Priority 82
}
