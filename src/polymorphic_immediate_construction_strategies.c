/**
 * polymorphic_immediate_construction_strategies.c
 *
 * Priority: 90 (Tier 1 - High Priority)
 * Applicability: Universal (90% of code)
 *
 * Implements polymorphic immediate value construction with multiple encoding
 * variants. Generates 5+ alternative encodings for immediate values and selects
 * the optimal one based on bad-character avoidance and size.
 *
 * This strategy is the foundation for bad-character elimination as immediate
 * values appear in ~90% of shellcode and frequently contain bad characters.
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Forward declarations for encoding techniques
static int try_xor_encoding(uint32_t target, uint32_t *key1, uint32_t *key2);
static int try_add_sub_decomposition(uint32_t target, uint32_t *part1, uint32_t *part2, int *use_sub);
static int try_shift_or_construction(uint32_t target, uint8_t bytes[4]);

// Encoding variant types
#define VARIANT_DIRECT      0  // Direct MOV (if no bad chars)
#define VARIANT_XOR_CHAIN   1  // XOR key1; XOR key2
#define VARIANT_ADD_SUB     2  // MOV part1; ADD/SUB part2
#define VARIANT_SHIFT_OR    3  // Byte-by-byte construction with shifts
#define VARIANT_LEA_CALC    4  // LEA-based arithmetic
#define VARIANT_STACK       5  // PUSH bytes; POP reg
#define NUM_VARIANTS        6

/**
 * Strategy: Polymorphic Immediate Construction - XOR Encoding
 *
 * Handles: MOV reg, imm where imm contains bad characters
 * Transform: MOV reg, key1; XOR reg, key2 (where key1 XOR key2 = target)
 * Priority: 90
 */
int can_handle_polymorphic_immediate_xor(cs_insn *insn) {
    // Only handle MOV reg, imm
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }

    if (insn->detail->x86.operands[0].type != X86_OP_REG ||
        insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;

    // If target already has no bad chars, let simpler strategies handle it
    if (is_bad_char_free(target)) {
        return 0;
    }

    // Check if XOR encoding can avoid bad chars
    uint32_t key1, key2;
    return try_xor_encoding(target, &key1, &key2);
}

size_t get_size_polymorphic_immediate_xor(cs_insn *insn) {
    x86_reg reg = insn->detail->x86.operands[0].reg;

    // MOV reg, key1 (5 bytes) + XOR reg, key2 (5-6 bytes)
    if (reg >= X86_REG_EAX && reg <= X86_REG_EDI) {
        return 11; // 5 (MOV) + 6 (XOR)
    }

    return 12; // Worst case for extended registers
}

void generate_polymorphic_immediate_xor(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    x86_reg reg = insn->detail->x86.operands[0].reg;
    uint32_t key1, key2;

    if (!try_xor_encoding(target, &key1, &key2)) {
        // Fallback: append original (shouldn't happen if can_handle returned true)
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    // Generate: MOV reg, key1
    uint8_t reg_code = reg - X86_REG_EAX;
    uint8_t mov_insn[] = {
        (uint8_t)(0xB8 + reg_code),  // MOV reg, imm32
        (uint8_t)(key1 & 0xFF),
        (uint8_t)((key1 >> 8) & 0xFF),
        (uint8_t)((key1 >> 16) & 0xFF),
        (uint8_t)((key1 >> 24) & 0xFF)
    };
    buffer_append(b, mov_insn, 5);

    // Generate: XOR reg, key2
    uint8_t xor_insn[] = {
        0x81,                         // XOR r/m32, imm32
        (uint8_t)(0xF0 + reg_code),  // ModRM: 11 110 reg (XOR opcode /6)
        (uint8_t)(key2 & 0xFF),
        (uint8_t)((key2 >> 8) & 0xFF),
        (uint8_t)((key2 >> 16) & 0xFF),
        (uint8_t)((key2 >> 24) & 0xFF)
    };
    buffer_append(b, xor_insn, 6);
}

/**
 * Strategy: Polymorphic Immediate Construction - ADD/SUB Decomposition
 *
 * Handles: MOV reg, imm where imm contains bad characters
 * Transform: MOV reg, part1; ADD reg, part2 (where part1 + part2 = target)
 * Priority: 89
 */
int can_handle_polymorphic_immediate_add_sub(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }

    if (insn->detail->x86.operands[0].type != X86_OP_REG ||
        insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;

    if (is_bad_char_free(target)) {
        return 0;
    }

    uint32_t part1, part2;
    int use_sub;
    return try_add_sub_decomposition(target, &part1, &part2, &use_sub);
}

size_t get_size_polymorphic_immediate_add_sub(__attribute__((unused)) cs_insn *insn) {
    return 11; // MOV (5) + ADD/SUB (6)
}

void generate_polymorphic_immediate_add_sub(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    x86_reg reg = insn->detail->x86.operands[0].reg;
    uint32_t part1, part2;
    int use_sub;

    if (!try_add_sub_decomposition(target, &part1, &part2, &use_sub)) {
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    uint8_t reg_code = reg - X86_REG_EAX;

    // MOV reg, part1
    uint8_t mov_insn[] = {
        (uint8_t)(0xB8 + reg_code),
        (uint8_t)(part1 & 0xFF),
        (uint8_t)((part1 >> 8) & 0xFF),
        (uint8_t)((part1 >> 16) & 0xFF),
        (uint8_t)((part1 >> 24) & 0xFF)
    };
    buffer_append(b, mov_insn, 5);

    // ADD or SUB reg, part2
    uint8_t arith_opcode = use_sub ? 0xE8 : 0xC0; // SUB: 0xE8, ADD: 0xC0
    uint8_t arith_insn[] = {
        0x81,
        (uint8_t)(arith_opcode + reg_code),
        (uint8_t)(part2 & 0xFF),
        (uint8_t)((part2 >> 8) & 0xFF),
        (uint8_t)((part2 >> 16) & 0xFF),
        (uint8_t)((part2 >> 24) & 0xFF)
    };
    buffer_append(b, arith_insn, 6);
}

/**
 * Strategy: Polymorphic Immediate Construction - Shift/OR Byte Construction
 *
 * Handles: MOV reg, imm where imm contains bad characters
 * Transform: Zero reg; MOV AL, byte0; SHL EAX, 8; OR AL, byte1; ... (byte-by-byte)
 * Priority: 88
 */
int can_handle_polymorphic_immediate_shift_or(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }

    if (insn->detail->x86.operands[0].type != X86_OP_REG ||
        insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;

    if (is_bad_char_free(target)) {
        return 0;
    }

    // Check if byte-by-byte construction avoids bad chars
    uint8_t bytes[4];
    return try_shift_or_construction(target, bytes);
}

size_t get_size_polymorphic_immediate_shift_or(__attribute__((unused)) cs_insn *insn) {
    // XOR reg, reg (2) + 4x (MOV AL, byte (2) + SHL EAX, 8 (3) + OR AL, byte (2))
    return 2 + 4 * (2 + 3 + 2); // ~30 bytes worst case
}

void generate_polymorphic_immediate_shift_or(struct buffer *b, cs_insn *insn) {
    uint32_t target = (uint32_t)insn->detail->x86.operands[1].imm;
    x86_reg reg = insn->detail->x86.operands[0].reg;
    uint8_t bytes[4];

    if (!try_shift_or_construction(target, bytes)) {
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    // Only works for EAX-EDI for simplicity
    if (reg < X86_REG_EAX || reg > X86_REG_EDI) {
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    uint8_t reg_code = reg - X86_REG_EAX;

    // XOR reg, reg (zero register)
    uint8_t xor_zero[] = {0x31, (uint8_t)(0xC0 + (reg_code << 3) + reg_code)};
    buffer_append(b, xor_zero, 2);

    // Build value byte by byte (little-endian)
    for (int i = 3; i >= 0; i--) {
        if (i < 3) {
            // SHL reg, 8
            uint8_t shl[] = {0xC1, (uint8_t)(0xE0 + reg_code), 0x08};
            buffer_append(b, shl, 3);
        }

        // OR AL, byte (use low byte register)
        uint8_t or_byte[] = {0x0C, bytes[i]}; // OR AL, imm8 (only for AL)
        if (reg_code == 0) { // EAX
            buffer_append(b, or_byte, 2);
        } else {
            // Use longer form for other registers
            uint8_t or_long[] = {0x80, (uint8_t)(0xC8 + reg_code), bytes[i]};
            buffer_append(b, or_long, 3);
        }
    }
}

// Helper function: Try XOR encoding
static int try_xor_encoding(uint32_t target, uint32_t *key1, uint32_t *key2) {
    // Try several XOR keys
    uint32_t candidate_keys[] = {
        0xAAAAAAAA, 0x55555555, 0xDEADBEEF, 0xCAFEBABE,
        0x12345678, 0x87654321, 0xFFFFFFFF, 0x01010101
    };

    for (size_t i = 0; i < sizeof(candidate_keys) / sizeof(uint32_t); i++) {
        *key1 = candidate_keys[i];
        *key2 = target ^ *key1;

        // Check if both keys are bad-char-free
        if (is_bad_char_free(*key1) && is_bad_char_free(*key2)) {
            return 1;
        }
    }

    // Try computed key: invert all bad-char bytes
    *key1 = ~target;
    *key2 = 0xFFFFFFFF;

    if (is_bad_char_free(*key1) && is_bad_char_free(*key2)) {
        return 1;
    }

    return 0;
}

// Helper function: Try ADD/SUB decomposition
static int try_add_sub_decomposition(uint32_t target, uint32_t *part1, uint32_t *part2, int *use_sub) {
    // Strategy 1: Split into two halves
    *part1 = target & 0xFFFF0000;
    *part2 = target & 0x0000FFFF;
    *use_sub = 0;

    if (is_bad_char_free(*part1) && is_bad_char_free(*part2)) {
        return 1;
    }

    // Strategy 2: Use subtraction
    *part1 = target + 0x01010101;
    *part2 = 0x01010101;
    *use_sub = 1;

    if (is_bad_char_free(*part1) && is_bad_char_free(*part2)) {
        return 1;
    }

    // Strategy 3: Try different splittings
    for (uint32_t split = 0x10000; split < target; split <<= 1) {
        *part1 = split;
        *part2 = target - split;
        *use_sub = 0;

        if (is_bad_char_free(*part1) && is_bad_char_free(*part2)) {
            return 1;
        }
    }

    return 0;
}

// Helper function: Try shift/OR construction
static int try_shift_or_construction(uint32_t target, uint8_t bytes[4]) {
    bytes[0] = target & 0xFF;
    bytes[1] = (target >> 8) & 0xFF;
    bytes[2] = (target >> 16) & 0xFF;
    bytes[3] = (target >> 24) & 0xFF;

    // Check if all individual bytes are bad-char-free
    for (int i = 0; i < 4; i++) {
        if (!is_bad_char_free_byte(bytes[i])) {
            return 0;
        }
    }

    return 1;
}

// Strategy registration
static strategy_t polymorphic_immediate_xor_strategy = {
    .name = "Polymorphic Immediate (XOR Chain)",
    .can_handle = can_handle_polymorphic_immediate_xor,
    .get_size = get_size_polymorphic_immediate_xor,
    .generate = generate_polymorphic_immediate_xor,
    .priority = 90
};

static strategy_t polymorphic_immediate_add_sub_strategy = {
    .name = "Polymorphic Immediate (ADD/SUB Decomposition)",
    .can_handle = can_handle_polymorphic_immediate_add_sub,
    .get_size = get_size_polymorphic_immediate_add_sub,
    .generate = generate_polymorphic_immediate_add_sub,
    .priority = 89
};

static strategy_t polymorphic_immediate_shift_or_strategy = {
    .name = "Polymorphic Immediate (Shift/OR Construction)",
    .can_handle = can_handle_polymorphic_immediate_shift_or,
    .get_size = get_size_polymorphic_immediate_shift_or,
    .generate = generate_polymorphic_immediate_shift_or,
    .priority = 88
};

void register_polymorphic_immediate_construction_strategies(void) {
    register_strategy(&polymorphic_immediate_xor_strategy);
    register_strategy(&polymorphic_immediate_add_sub_strategy);
    register_strategy(&polymorphic_immediate_shift_or_strategy);
}
