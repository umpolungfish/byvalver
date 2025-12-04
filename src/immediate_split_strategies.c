/*
 * Immediate Value Splitting Strategy
 *
 * PROBLEM: Instructions like PUSH, MOV, ADD, SUB, CMP with immediate values
 * can contain null bytes when the immediate value has 0x00 in any byte position:
 * - push 0x1ff9090       → 68 90 90 F9 01 (original encoding, contains null if part of larger context)
 * - mov eax, 0x12340000  → B8 00 00 34 12 (contains null bytes)
 * - add eax, 0x00001234  → 05 34 12 00 00 (contains null bytes)
 * - cmp eax, 0x10000000  → 3D 00 00 00 10 (contains null bytes)
 *
 * SOLUTION: Split immediate values into null-free components using either:
 * - Strategy A: Arithmetic Splitting (decompose into base + remainder)
 * - Strategy B: Bit Manipulation Assembly (shifts and OR operations)
 * Choose the optimal strategy based on value characteristics.
 *
 * FREQUENCY: Very common in shellcode for setting up parameters, counters, addresses
 * PRIORITY: 77 (High - between small_immediate_strategies at 75 and ret_strategies at 78)
 *
 * Example transformations:
 *   Original: push 0x1ff9090 (contains nulls in encoding)
 *   Strategy A (Arithmetic):
 *     push 0x1ff0000    ; Push base value (constructed null-free)
 *     mov eax, [esp]    ; Load from stack
 *     add eax, 0x9090   ; Add remainder (null-free)
 *     mov [esp], eax    ; Store back
 *
 *   Original: mov eax, 0x12340000 (B8 00 00 34 12 - contains nulls)
 *   Strategy B (Bit Manipulation):
 *     xor eax, eax      ; Clear register
 *     mov ax, 0x3412    ; Set lower word: EAX = 0x00003412
 *     shl eax, 16       ; Shift left: EAX = 0x34120000
 *     shr eax, 8        ; Shift right: EAX = 0x00341200
 *     or al, 0x34       ; Adjust: varies by target value
 */

#include "immediate_split_strategies.h"
#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Helper function: Check if an immediate value contains null bytes
 */
static int immediate_has_nulls(uint32_t imm) {
    return !is_null_free(imm);
}

/*
 * Helper function: Find arithmetic decomposition (base + offset) that avoids nulls
 * Returns 1 if successful, 0 otherwise
 */
static int find_split_arithmetic(uint32_t target, uint32_t *base, uint32_t *remainder) {
    // Strategy: Try to decompose target = base + remainder where both are null-free
    // Start by trying to zero out the problematic bytes in base

    // Approach 1: Zero out lower bytes that contain nulls
    for (int shift = 0; shift < 32; shift += 8) {
        uint32_t byte_val = (target >> shift) & 0xFF;
        if (byte_val == 0x00) {
            // Try setting this byte to 0x01 in base and adjusting remainder
            uint32_t test_base = target | (0x01 << shift);
            uint32_t test_remainder = target - test_base;

            if (is_null_free(test_base) && is_null_free(test_remainder)) {
                *base = test_base;
                *remainder = test_remainder;
                return 1;
            }
        }
    }

    // Approach 2: Try common split patterns
    // Split at word boundaries
    uint32_t low_word = target & 0xFFFF;
    uint32_t high_word = target & 0xFFFF0000;

    if (low_word != 0 && high_word != 0) {
        if (is_null_free(low_word) && is_null_free(high_word)) {
            *base = high_word;
            *remainder = low_word;
            return 1;
        }
    }

    // Approach 3: Try to find null-free values using arithmetic_equivalent
    int operation;
    if (find_arithmetic_equivalent(target, base, remainder, &operation)) {
        // Verify both are null-free
        if (is_null_free(*base) && is_null_free(*remainder)) {
            return 1;
        }
    }

    return 0; // No suitable decomposition found
}

/*
 * Helper function: Analyze value for bit manipulation strategy
 * Returns estimated instruction count for bit manipulation approach
 */
static int analyze_bit_manipulation(uint32_t target) {
    int instr_count = 1; // Start with XOR to clear register

    // Count non-zero bytes
    int non_zero_bytes = 0;
    for (int i = 0; i < 4; i++) {
        if (((target >> (i * 8)) & 0xFF) != 0) {
            non_zero_bytes++;
        }
    }

    // Estimate: 1 MOV per non-zero byte + shifts + OR operations
    instr_count += non_zero_bytes; // MOV operations
    instr_count += non_zero_bytes - 1; // SHL/SHR operations

    return instr_count;
}

/*
 * Helper function: Determine if we should use bit manipulation vs arithmetic
 * Returns 1 for bit manipulation, 0 for arithmetic
 */
static int prefer_bit_manipulation(uint32_t target) {
    uint32_t base, remainder;

    // If arithmetic decomposition fails, must use bit manipulation
    if (!find_split_arithmetic(target, &base, &remainder)) {
        return 1;
    }

    // If value is relatively small and sparse, bit manipulation may be better
    int bit_instr = analyze_bit_manipulation(target);
    int arith_instr = 6; // Conservative estimate for arithmetic approach

    return (bit_instr < arith_instr);
}

/*
 * Detection function for immediate splitting strategy
 */
int can_handle_immediate_split(cs_insn *insn) {
    if (!insn || !insn->detail) {
        return 0;
    }

    // Handle PUSH with immediate
    if (insn->id == X86_INS_PUSH) {
        if (insn->detail->x86.op_count != 1) {
            return 0;
        }

        cs_x86_op *op = &insn->detail->x86.operands[0];
        if (op->type != X86_OP_IMM) {
            return 0;
        }

        uint32_t imm = (uint32_t)op->imm;
        return immediate_has_nulls(imm);
    }

    // Handle MOV reg, imm
    if (insn->id == X86_INS_MOV) {
        if (insn->detail->x86.op_count != 2) {
            return 0;
        }

        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        // Must be register destination and immediate source
        if (dst->type != X86_OP_REG || src->type != X86_OP_IMM) {
            return 0;
        }

        // Only handle 32-bit registers
        if (dst->size != 4) {
            return 0;
        }

        uint32_t imm = (uint32_t)src->imm;
        return immediate_has_nulls(imm);
    }

    // Handle arithmetic operations (ADD, SUB, AND, OR, XOR) with immediate
    if (insn->id == X86_INS_ADD || insn->id == X86_INS_SUB ||
        insn->id == X86_INS_AND || insn->id == X86_INS_OR ||
        insn->id == X86_INS_XOR) {

        if (insn->detail->x86.op_count != 2) {
            return 0;
        }

        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        // Must be register destination and immediate source
        if (dst->type != X86_OP_REG || src->type != X86_OP_IMM) {
            return 0;
        }

        uint32_t imm = (uint32_t)src->imm;
        return immediate_has_nulls(imm);
    }

    // Handle CMP with immediate
    if (insn->id == X86_INS_CMP) {
        if (insn->detail->x86.op_count != 2) {
            return 0;
        }

        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        // Must be register destination and immediate source
        if (dst->type != X86_OP_REG || src->type != X86_OP_IMM) {
            return 0;
        }

        uint32_t imm = (uint32_t)src->imm;
        return immediate_has_nulls(imm);
    }

    return 0;
}

/*
 * Size calculation function for immediate splitting
 */
size_t get_size_immediate_split(cs_insn *insn) {
    cs_x86_op *src_op;
    uint32_t imm;

    // Extract immediate value based on instruction type
    if (insn->id == X86_INS_PUSH) {
        src_op = &insn->detail->x86.operands[0];
        imm = (uint32_t)src_op->imm;
    } else {
        src_op = &insn->detail->x86.operands[1];
        imm = (uint32_t)src_op->imm;
    }

    // Determine which strategy to use
    if (prefer_bit_manipulation(imm)) {
        // Bit manipulation: XOR (2) + MOV byte operations + SHL/OR operations
        int bit_ops = analyze_bit_manipulation(imm);
        return bit_ops * 3; // Conservative: 3 bytes per operation average
    } else {
        // Arithmetic splitting approach
        // For PUSH: PUSH base (use null-safe) + MOV EAX,[ESP] (3) + ADD EAX,remainder (6) + MOV [ESP],EAX (3)
        // For MOV: MOV reg,base (use null-safe) + ADD reg,remainder (6)
        // For arithmetic ops: MOV temp,imm_base (use null-safe) + ADD temp,imm_remainder (6) + OP reg,temp (2)

        if (insn->id == X86_INS_PUSH) {
            return 8 + 3 + 6 + 3; // ~20 bytes for PUSH
        } else if (insn->id == X86_INS_MOV) {
            return 8 + 6; // ~14 bytes for MOV
        } else if (insn->id == X86_INS_CMP) {
            return 2 + 8 + 6 + 2 + 2; // PUSH temp + construct value + CMP + POP temp
        } else {
            // Arithmetic operations (ADD, SUB, etc.)
            return 8 + 6 + 2; // ~16 bytes
        }
    }
}

/*
 * Generate null-free code using bit manipulation strategy
 */
static void generate_bit_manipulation(struct buffer *b, uint8_t reg_num, uint32_t target) {
    // Strategy: Build value using byte operations and shifts
    // XOR reg, reg to clear
    buffer_write_byte(b, 0x31); // XOR opcode
    buffer_write_byte(b, 0xC0 + (reg_num << 3) + reg_num); // ModR/M for XOR reg,reg

    // Extract bytes
    uint8_t bytes[4];
    bytes[0] = target & 0xFF;
    bytes[1] = (target >> 8) & 0xFF;
    bytes[2] = (target >> 16) & 0xFF;
    bytes[3] = (target >> 24) & 0xFF;

    // Strategy: Build from least significant non-zero byte upward
    int first_nonzero = -1;
    for (int i = 0; i < 4; i++) {
        if (bytes[i] != 0) {
            first_nonzero = i;
            break;
        }
    }

    if (first_nonzero == -1) {
        // Value is zero, already done with XOR
        return;
    }

    // Set initial byte (using low byte register if possible)
    if (first_nonzero == 0 && is_null_free_byte(bytes[0])) {
        // MOV reg_low, imm8 (AL, CL, DL, BL, etc.)
        buffer_write_byte(b, 0xB0 + reg_num);
        buffer_write_byte(b, bytes[0]);
    } else {
        // Need to use OR to set bits
        if (is_null_free_byte(bytes[first_nonzero])) {
            // OR reg, shifted_byte
            uint32_t shifted_val = (uint32_t)bytes[first_nonzero] << (first_nonzero * 8);
            if (is_null_free(shifted_val)) {
                // OR reg, imm32
                buffer_write_byte(b, 0x81); // OR r/m32, imm32
                buffer_write_byte(b, 0xC8 + reg_num); // ModR/M
                buffer_write_byte(b, (uint8_t)(shifted_val & 0xFF));
                buffer_write_byte(b, (uint8_t)((shifted_val >> 8) & 0xFF));
                buffer_write_byte(b, (uint8_t)((shifted_val >> 16) & 0xFF));
                buffer_write_byte(b, (uint8_t)((shifted_val >> 24) & 0xFF));
            }
        }
    }

    // Build remaining bytes using shifts and ORs
    for (int i = first_nonzero + 1; i < 4; i++) {
        if (bytes[i] != 0 && is_null_free_byte(bytes[i])) {
            // Shift left to make room
            uint8_t shift_amount = 8;
            // SHL reg, 8
            buffer_write_byte(b, 0xC1); // SHL r/m32, imm8
            buffer_write_byte(b, 0xE0 + reg_num); // ModR/M
            buffer_write_byte(b, shift_amount);

            // OR in the next byte
            buffer_write_byte(b, 0x80); // OR r/m8, imm8
            buffer_write_byte(b, 0xC8 + reg_num); // ModR/M for AL, CL, etc.
            buffer_write_byte(b, bytes[i]);
        }
    }
}

/*
 * Generate null-free code using arithmetic splitting strategy
 */
static void generate_arithmetic_split(struct buffer *b, uint8_t reg_num, uint32_t target) {
    uint32_t base, remainder;

    if (!find_split_arithmetic(target, &base, &remainder)) {
        // Fallback: use bit manipulation
        generate_bit_manipulation(b, reg_num, target);
        return;
    }

    // Generate: MOV reg, base (null-free construction)
    generate_mov_eax_imm(b, base);

    // If target register is not EAX, move it
    if (reg_num != 0) { // 0 = EAX
        // MOV reg, EAX (89 C0+reg)
        buffer_write_byte(b, 0x89);
        buffer_write_byte(b, 0xC0 + reg_num);
    }

    // ADD reg, remainder (null-free)
    // Use null-safe construction for remainder
    if (remainder != 0) {
        // PUSH EAX to save if we need to use it
        if (reg_num != 0) {
            buffer_write_byte(b, 0x50); // PUSH EAX
        }

        // MOV EAX, remainder (null-free)
        generate_mov_eax_imm(b, remainder);

        // ADD reg, EAX
        buffer_write_byte(b, 0x01); // ADD r/m32, r32
        buffer_write_byte(b, 0xC0 + reg_num); // ModR/M: ADD reg, EAX

        // POP EAX to restore if we saved it
        if (reg_num != 0) {
            buffer_write_byte(b, 0x58); // POP EAX
        }
    }
}

/*
 * Generation function for immediate splitting
 */
void generate_immediate_split(struct buffer *b, cs_insn *insn) {
    if (insn->id == X86_INS_PUSH) {
        // Handle PUSH with immediate
        cs_x86_op *op = &insn->detail->x86.operands[0];
        uint32_t imm = (uint32_t)op->imm;

        uint32_t base, remainder;
        if (find_split_arithmetic(imm, &base, &remainder)) {
            // Arithmetic splitting for PUSH
            // PUSH base (using null-safe construction)
            generate_push_imm32(b, base); // This should handle nulls

            // MOV EAX, [ESP] (8B 04 24 with SIB)
            buffer_write_byte(b, 0x8B); // MOV opcode
            buffer_write_byte(b, 0x04); // ModR/M: [--][--] with SIB
            buffer_write_byte(b, 0x24); // SIB: [ESP]

            // Generate remainder in EAX using null-safe construction
            // PUSH EAX
            buffer_write_byte(b, 0x50);
            generate_mov_eax_imm(b, remainder);

            // ADD [ESP+4], EAX (01 44 24 04)
            buffer_write_byte(b, 0x01); // ADD r/m32, r32
            buffer_write_byte(b, 0x44); // ModR/M: [--][--] + disp8
            buffer_write_byte(b, 0x24); // SIB: [ESP]
            buffer_write_byte(b, 0x04); // disp8: +4

            // POP EAX
            buffer_write_byte(b, 0x58);
        } else {
            // Fallback: use bit manipulation in temp register, then PUSH
            // XOR EAX, EAX
            buffer_write_byte(b, 0x31);
            buffer_write_byte(b, 0xC0);

            generate_bit_manipulation(b, 0, imm); // Build in EAX

            // PUSH EAX
            buffer_write_byte(b, 0x50);
        }

    } else if (insn->id == X86_INS_MOV) {
        // Handle MOV reg, imm
        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        uint32_t imm = (uint32_t)src->imm;
        uint8_t reg_num = dst->reg - X86_REG_EAX;

        if (prefer_bit_manipulation(imm)) {
            generate_bit_manipulation(b, reg_num, imm);
        } else {
            generate_arithmetic_split(b, reg_num, imm);
        }

    } else if (insn->id == X86_INS_CMP) {
        // Handle CMP reg, imm
        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        uint32_t imm = (uint32_t)src->imm;
        uint8_t reg_num = dst->reg - X86_REG_EAX;

        // Use a temporary register (ECX if dst is not ECX, else EDX)
        uint8_t temp_reg = (reg_num == 1) ? 2 : 1; // ECX=1, EDX=2

        // PUSH temp_reg
        buffer_write_byte(b, 0x50 + temp_reg);

        // Build immediate in temp register
        if (prefer_bit_manipulation(imm)) {
            generate_bit_manipulation(b, temp_reg, imm);
        } else {
            generate_arithmetic_split(b, temp_reg, imm);
        }

        // CMP reg, temp_reg (39 /r)
        buffer_write_byte(b, 0x39); // CMP r/m32, r32
        buffer_write_byte(b, 0xC0 + (temp_reg << 3) + reg_num); // ModR/M

        // POP temp_reg
        buffer_write_byte(b, 0x58 + temp_reg);

    } else {
        // Handle arithmetic operations (ADD, SUB, AND, OR, XOR) with immediate
        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        uint32_t imm = (uint32_t)src->imm;
        uint8_t reg_num = dst->reg - X86_REG_EAX;

        // Use a temporary register (ECX if dst is not ECX, else EDX)
        uint8_t temp_reg = (reg_num == 1) ? 2 : 1; // ECX=1, EDX=2

        // PUSH temp_reg
        buffer_write_byte(b, 0x50 + temp_reg);

        // Build immediate in temp register
        if (prefer_bit_manipulation(imm)) {
            generate_bit_manipulation(b, temp_reg, imm);
        } else {
            generate_arithmetic_split(b, temp_reg, imm);
        }

        // Perform operation: OP reg, temp_reg
        uint8_t opcode;
        switch (insn->id) {
            case X86_INS_ADD: opcode = 0x01; break; // ADD r/m32, r32
            case X86_INS_SUB: opcode = 0x29; break; // SUB r/m32, r32
            case X86_INS_AND: opcode = 0x21; break; // AND r/m32, r32
            case X86_INS_OR:  opcode = 0x09; break; // OR r/m32, r32
            case X86_INS_XOR: opcode = 0x31; break; // XOR r/m32, r32
            default: opcode = 0x01; break; // Fallback to ADD
        }

        buffer_write_byte(b, opcode);
        buffer_write_byte(b, 0xC0 + (temp_reg << 3) + reg_num); // ModR/M

        // POP temp_reg
        buffer_write_byte(b, 0x58 + temp_reg);
    }
}

/*
 * Strategy structure definition
 */
strategy_t immediate_split_strategy = {
    .name = "Immediate Value Splitting",
    .can_handle = can_handle_immediate_split,
    .get_size = get_size_immediate_split,
    .generate = generate_immediate_split,
    .priority = 77  // High priority: between small_immediate (75) and ret_strategies (78)
};

/*
 * Registration function
 */
void register_immediate_split_strategies(void) {
    register_strategy(&immediate_split_strategy);
}
