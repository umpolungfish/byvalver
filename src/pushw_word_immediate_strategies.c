#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// ============================================================================
// PUSHW 16-bit Immediate for Port Numbers Strategy
// ============================================================================
// Priority: 87 (High)
// Target Instructions: PUSH imm32 where value fits in 16 bits
// Null-Byte Pattern: High-order zero bytes in 32-bit immediate
// Transformation: PUSH 0x00001234 → PUSHW 0x1234
// Preserves Flags: Yes
// Example:
//   Before: 68 34 12 00 00          (PUSH 0x1234, contains nulls)
//   After:  66 68 34 12             (PUSHW 0x1234, null-free)
// ============================================================================

int can_handle_pushw_word_immediate(cs_insn *insn) {
    // Check if this is a PUSH instruction
    if (insn->id != X86_INS_PUSH) {
        return 0;
    }

    // Verify we have an immediate operand
    if (insn->detail->x86.op_count != 1) {
        return 0;
    }

    const cs_x86_op *op = &insn->detail->x86.operands[0];
    if (op->type != X86_OP_IMM) {
        return 0;
    }

    int64_t imm = op->imm;

    // Check if value fits in 16 bits (0 to 65535 or -32768 to 32767)
    if (imm < -32768 || imm > 65535) {
        return 0;
    }

    // Check if the 32-bit encoding would contain null bytes
    uint32_t imm32 = (uint32_t)imm;
    int has_nulls = 0;

    for (int i = 0; i < 4; i++) {
        if (((imm32 >> (i * 8)) & 0xFF) == 0x00) {
            has_nulls = 1;
            break;
        }
    }

    if (!has_nulls) {
        return 0; // Original is already null-free
    }

    // Check if PUSHW encoding would contain nulls
    uint16_t imm16 = (uint16_t)imm;
    if ((imm16 & 0xFF) == 0x00 || ((imm16 >> 8) & 0xFF) == 0x00) {
        return 0; // PUSHW would also have nulls
    }

    return 1; // Can handle this instruction
}

size_t get_size_pushw_word_immediate(__attribute__((unused)) cs_insn *insn) {
    // PUSHW encoding: 66 68 XX XX = 4 bytes
    return 4;
}

void generate_pushw_word_immediate(struct buffer *b, cs_insn *insn) {
    uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;
    uint16_t imm16 = (uint16_t)imm;

    // Generate PUSHW instruction
    // 0x66 = Operand-size override prefix
    buffer_write_byte(b, 0x66);

    // 0x68 = PUSH imm16 opcode
    buffer_write_byte(b, 0x68);

    // Write 16-bit immediate in little-endian
    buffer_write_byte(b, imm16 & 0xFF);         // Low byte
    buffer_write_byte(b, (imm16 >> 8) & 0xFF);  // High byte
}

strategy_t pushw_word_immediate_strategy = {
    .name = "PUSHW Word Immediate",
    .can_handle = can_handle_pushw_word_immediate,
    .get_size = get_size_pushw_word_immediate,
    .generate = generate_pushw_word_immediate,
    .priority = 87  // High priority - common in socket shellcode
};

// Register the PUSHW strategy
void register_pushw_word_immediate_strategies() {
    register_strategy(&pushw_word_immediate_strategy);
}
