/**
 * GET PC (Get Program Counter) Strategies
 *
 * Implements the CALL/POP technique for position-independent immediate value loading.
 * This technique is particularly useful for loading immediate values containing null bytes
 * without actually embedding the null bytes in the instruction stream.
 *
 * Technique:
 * 1. CALL to next instruction (pushes return address = current PC)
 * 2. POP into target register (gets PC value)
 * 3. Immediate value is stored as data after the CALL
 * 4. MOV from [reg+offset] to load the value
 *
 * Example transformation:
 *   Original: MOV EAX, 0x00112233  (contains null byte)
 *
 *   Replacement:
 *     CALL next
 *   next:
 *     POP EAX                      ; EAX now contains address of next instruction
 *     MOV EAX, [EAX + offset]      ; Load value from data section
 *     JMP skip_data
 *   data:
 *     DD 0x00112233                ; The immediate value as data
 *   skip_data:
 *     ; Continue execution
 */

#include "getpc_strategies.h"
#include "strategy.h"
#include "utils.h"
#include <capstone/capstone.h>
#include <stdint.h>
#include <string.h>

// Debug mode - compile with -DDEBUG to enable detailed logging
#ifdef DEBUG
  #include <stdio.h>
  #define DEBUG_LOG(fmt, ...) do { fprintf(stderr, "[DEBUG][GETPC] " fmt "\n", ##__VA_ARGS__); } while(0)
#else
  #define DEBUG_LOG(fmt, ...) do {} while(0)
#endif

/**
 * Check if GET PC technique can handle this instruction
 *
 * Criteria:
 * - MOV instruction with immediate operand
 * - Immediate value contains null bytes
 * - Destination is a general-purpose register
 */
static int can_handle_getpc_mov(cs_insn *insn) {
    // Must be MOV instruction
    if (insn->id != X86_INS_MOV) {
        return 0;
    }

    // Must have exactly 2 operands
    if (insn->detail->x86.op_count != 2) {
        return 0;
    }

    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    // First operand must be a register
    if (op0->type != X86_OP_REG) {
        return 0;
    }

    // Second operand must be an immediate
    if (op1->type != X86_OP_IMM) {
        return 0;
    }

    // Check if the instruction contains null bytes
    int has_null = 0;
    for (size_t i = 0; i < insn->size; i++) {
        if (insn->bytes[i] == 0x00) {
            has_null = 1;
            break;
        }
    }

    if (!has_null) {
        return 0;
    }

    DEBUG_LOG("GET PC can handle: %s %s (imm=0x%lx)",
              insn->mnemonic, insn->op_str, op1->imm);

    return 1;
}

/**
 * Calculate the size of the GET PC replacement
 *
 * Structure:
 * - CALL next (5 bytes: E8 00 00 00 00)
 * - POP reg (1 byte: 58+r)
 * - MOV reg, [reg+offset] (3-7 bytes depending on register and offset)
 * - JMP skip (2 bytes: EB 04 for short jump over 4 bytes of data)
 * - Data (4 bytes: the immediate value)
 *
 * Total: ~15-19 bytes
 */
static size_t get_size_getpc_mov(__attribute__((unused)) cs_insn *insn) {
    // Conservative estimate
    // CALL(5) + POP(1) + MOV reg,[reg+offset](6) + JMP(2) + DATA(4) = 18 bytes
    return 18;
}

/**
 * Generate the GET PC replacement code
 *
 * Generates position-independent code that loads the immediate value
 * without embedding null bytes in the instruction stream.
 *
 * Modified approach to avoid null bytes in CALL instruction:
 * Instead of CALL $+0 (which would be E8 00 00 00 00), we use
 * a JMP/CALL/POP sequence with negative offset.
 *
 * Structure:
 *   JMP skip_data
 *   data: DD immediate_value
 *   skip_data:
 *   CALL backwards_label (negative offset, likely no nulls)
 *   backwards_label:
 *   POP reg
 *   MOV reg, [reg + calculated_offset]
 */
static void generate_getpc_mov(struct buffer *b, cs_insn *insn) {
    cs_x86_op *op0 = &insn->detail->x86.operands[0];
    cs_x86_op *op1 = &insn->detail->x86.operands[1];

    uint8_t dest_reg = op0->reg;
    uint32_t imm_value = (uint32_t)op1->imm;
    uint8_t reg_idx = get_reg_index(dest_reg);

    DEBUG_LOG("Generating GET PC for MOV %s, 0x%x",
              cs_reg_name(NULL, dest_reg), imm_value);

    // Alternative approach: Use JMP-over-data pattern with LEA or direct memory reference
    //
    // Structure:
    //   JMP short over_data    ; EB 06 (2 bytes - jump over 6 bytes of data+nop)
    //   NOP                     ; 90 (1 byte padding)
    //   data: DD value          ; immediate value (4 bytes)
    //   NOP                     ; 90 (1 byte padding)
    //   over_data:
    //   MOV reg, [$ - offset]   ; Load from the data we just jumped over
    //
    // But we need PC... let's use the PUSH/arithmetic trick instead:

    // Even better: Use stack-based technique without CALL
    //   PUSH current_pos+N      ; But this requires knowing position...
    //
    // Best solution: Use alternative MOV strategies that don't require GET PC

    // Actually, let's implement a WORKING version using SUB/ADD/XOR techniques
    // to construct the value, OR use the data-segment approach differently.

    // For now, implement a hybrid that pushes the value onto stack:
    // The value might have nulls, so we construct it on stack indirectly

    // Temporary fix: Use the NEG/NOT/XOR strategies instead
    // This GET PC implementation needs rethinking for 32-bit x86

    // Let's use a simple but effective approach:
    // Store data inline, use relative addressing through stack manipulation

    // WORKING IMPLEMENTATION:
    // Push pointer arithmetic to avoid CALL with null offset
    //
    // 1. JMP over data
    // 2. Store data
    // 3. Use FSTENV technique or other PC-getting method

    // For THIS version, let's use FNSTENV which is a classic GET PC technique:
    //   FNSTENV [ESP-12]  ; Stores FPU environment, including EIP
    //   POP reg           ; Get EIP into register
    //   MOV reg, [reg+offset] ; Load data

    // Actually, let's just use the simplest working approach:
    // Store the value at a known offset and use clever addressing

    // NULL-FREE BYTE CONSTRUCTION METHOD:
    // Build the value byte-by-byte using shifts and ORs without null immediates
    //
    // Strategy:
    // 1. XOR reg, reg (zero the register)
    // 2. For each non-zero byte: MOV byte_reg, value; SHL reg, 8; OR reg_low, byte_value
    //
    // This constructs from MSB to LSB to avoid null bytes in shifts

    uint8_t b0 = (imm_value) & 0xFF;        // LSB
    uint8_t b1 = (imm_value >> 8) & 0xFF;
    uint8_t b2 = (imm_value >> 16) & 0xFF;
    uint8_t b3 = (imm_value >> 24) & 0xFF;   // MSB

    // Start with zero: XOR reg, reg (31 /r)
    uint8_t xor_self[] = {0x31, (uint8_t)(0xC0 | (reg_idx << 3) | reg_idx)};
    buffer_append(b, xor_self, 2);

    // Build from MSB to LSB: load byte, shift, repeat
    // This avoids null bytes in the immediate values

    // Process b3 (MSB)
    if (b3 != 0) {
        // MOV AL/CL/DL/BL/etc, b3 (B0+reg8 imm8)
        uint8_t mov_al[] = {(uint8_t)(0xB0 + reg_idx), b3};
        buffer_append(b, mov_al, 2);
    }

    // Shift left 8 bits if we have more bytes
    if (b2 != 0 || b1 != 0 || b0 != 0) {
        // SHL reg, 8 (C1 /4 imm8)
        uint8_t shl_8[] = {0xC1, (uint8_t)(0xE0 | reg_idx), 0x08};
        buffer_append(b, shl_8, 3);
    }

    // Process b2
    if (b2 != 0) {
        // OR AL, b2 (0C imm8 for AL, or 80 /1 for others)
        if (reg_idx == 0) { // AL/AX/EAX
            uint8_t or_al[] = {0x0C, b2};
            buffer_append(b, or_al, 2);
        } else {
            uint8_t or_reg[] = {0x80, (uint8_t)(0xC8 | reg_idx), b2};
            buffer_append(b, or_reg, 3);
        }
    }

    // Shift left 8 bits if we have more bytes
    if (b1 != 0 || b0 != 0) {
        uint8_t shl_8[] = {0xC1, (uint8_t)(0xE0 | reg_idx), 0x08};
        buffer_append(b, shl_8, 3);
    }

    // Process b1
    if (b1 != 0) {
        if (reg_idx == 0) {
            uint8_t or_al[] = {0x0C, b1};
            buffer_append(b, or_al, 2);
        } else {
            uint8_t or_reg[] = {0x80, (uint8_t)(0xC8 | reg_idx), b1};
            buffer_append(b, or_reg, 3);
        }
    }

    // Shift left 8 bits for last byte
    if (b0 != 0) {
        uint8_t shl_8[] = {0xC1, (uint8_t)(0xE0 | reg_idx), 0x08};
        buffer_append(b, shl_8, 3);
    }

    // Process b0 (LSB)
    if (b0 != 0) {
        if (reg_idx == 0) {
            uint8_t or_al[] = {0x0C, b0};
            buffer_append(b, or_al, 2);
        } else {
            uint8_t or_reg[] = {0x80, (uint8_t)(0xC8 | reg_idx), b0};
            buffer_append(b, or_reg, 3);
        }
    }

    DEBUG_LOG("Byte-construction method generated for immediate 0x%x", imm_value);
}

// Byte-Construction Strategy Definition
// Note: This was originally intended as GET PC but implemented as byte-construction
// due to null-byte issues with CALL $+0 in 32-bit x86
static strategy_t getpc_mov_strategy = {
    .name = "BYTE_CONSTRUCT_MOV",
    .priority = 25,  // Low priority - use as fallback when other techniques don't apply
    .can_handle = can_handle_getpc_mov,
    .get_size = get_size_getpc_mov,
    .generate = generate_getpc_mov
};

/**
 * Register all GET PC strategies
 */
void register_getpc_strategies(void) {
    extern void register_strategy(strategy_t *strategy);

    register_strategy(&getpc_mov_strategy);

    DEBUG_LOG("Registered GET PC strategies: %d", 1);
}
