/*
 * BYVALVER - Pass 1: Obfuscation & Complexification Strategies
 *
 * Transforms simple instructions into convoluted but functionally equivalent
 * sequences to increase analytical difficulty and evade signature detection.
 *
 * NOTE: These strategies CAN introduce null bytes - Pass 2 will clean them up!
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/capstone.h>
#include "utils.h"
#include "core.h"
#include "strategy.h"
#include "obfuscation_strategy_registry.h"

// ============================================================================
// Strategy 1: TEST → AND Transformation (Priority 80)
// Transforms: TEST reg, reg → AND reg, reg; OR reg, reg (functionally equivalent)
// ============================================================================

int can_handle_test_to_and(cs_insn *insn) {
    if (insn->id != X86_INS_TEST) return 0;

    // Only handle TEST reg, reg (same register)
    if (insn->detail->x86.op_count == 2) {
        cs_x86_op *op1 = &insn->detail->x86.operands[0];
        cs_x86_op *op2 = &insn->detail->x86.operands[1];

        if (op1->type == X86_OP_REG && op2->type == X86_OP_REG) {
            return (op1->reg == op2->reg);  // TEST EAX, EAX etc.
        }
    }
    return 0;
}

size_t get_test_to_and_size(cs_insn *insn) {
    (void)insn;  // Avoid unused parameter warning
    return 4;  // AND reg,reg (2 bytes) + OR reg,reg (2 bytes)
}

void generate_test_to_and(struct buffer *b, cs_insn *insn) {
    uint8_t reg = insn->detail->x86.operands[0].reg;
    uint8_t reg_idx = get_reg_index(reg);

    // AND reg, reg (sets ZF based on value)
    uint8_t and_bytes[] = {0x21, 0xC0 | (reg_idx << 3) | reg_idx};
    buffer_append(b, and_bytes, 2);

    // OR reg, reg (restores original value, preserves ZF)
    uint8_t or_bytes[] = {0x0B, 0xC0  /* Changed from 0x09 (TAB) to 0x0B (OR alternative encoding) */ | (reg_idx << 3) | reg_idx};
    buffer_append(b, or_bytes, 2);
}

static strategy_t test_to_and_strategy = {
    .name = "TEST→AND Obfuscation",
    .can_handle = can_handle_test_to_and,
    .get_size = get_test_to_and_size,
    .generate = generate_test_to_and,
    .priority = 80
};

void register_test_to_and_obfuscation() {
    register_obfuscation_strategy(&test_to_and_strategy);
}

// ============================================================================
// Strategy 2: MOV → PUSH/POP Transformation (Priority 75)
// Transforms: MOV reg1, reg2 → PUSH reg2; POP reg1
// ============================================================================

int can_handle_mov_push_pop(cs_insn *insn) {
    if (insn->id != X86_INS_MOV) return 0;

    if (insn->detail->x86.op_count == 2) {
        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        // Only handle MOV reg, reg (exclude ESP/EBP to avoid stack corruption)
        if (dst->type == X86_OP_REG && src->type == X86_OP_REG) {
            if (dst->reg != X86_REG_ESP && dst->reg != X86_REG_EBP &&
                src->reg != X86_REG_ESP && src->reg != X86_REG_EBP) {
                return 1;
            }
        }
    }
    return 0;
}

size_t get_mov_push_pop_size(cs_insn *insn) {
    (void)insn;  // Avoid unused parameter warning
    return 2;  // PUSH (1 byte) + POP (1 byte)
}

void generate_mov_push_pop(struct buffer *b, cs_insn *insn) {
    uint8_t src_reg = insn->detail->x86.operands[1].reg;
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;

    uint8_t src_idx = get_reg_index(src_reg);
    uint8_t dst_idx = get_reg_index(dst_reg);

    // PUSH src_reg
    uint8_t push_byte = 0x50 + src_idx;
    buffer_append(b, &push_byte, 1);

    // POP dst_reg
    uint8_t pop_byte = 0x58 + dst_idx;
    buffer_append(b, &pop_byte, 1);
}

static strategy_t mov_push_pop_strategy = {
    .name = "MOV→PUSH/POP Obfuscation",
    .can_handle = can_handle_mov_push_pop,
    .get_size = get_mov_push_pop_size,
    .generate = generate_mov_push_pop,
    .priority = 75
};

void register_mov_push_pop_obfuscation() {
    register_obfuscation_strategy(&mov_push_pop_strategy);
}

// ============================================================================
// Strategy 3: Arithmetic Negation (Priority 85)
// Transforms: SUB reg, imm → ADD reg, -imm (and vice versa)
// ============================================================================

int can_handle_arithmetic_negation(cs_insn *insn) {
    if (insn->id == X86_INS_SUB || insn->id == X86_INS_ADD) {
        if (insn->detail->x86.op_count == 2) {
            cs_x86_op *dst = &insn->detail->x86.operands[0];
            cs_x86_op *src = &insn->detail->x86.operands[1];

            // Only handle reg, imm with small immediates
            if (dst->type == X86_OP_REG && src->type == X86_OP_IMM) {
                int64_t imm = src->imm;
                return (imm >= -127 && imm <= 127);  // Fits in 8-bit signed
            }
        }
    }
    return 0;
}

size_t get_arithmetic_negation_size(cs_insn *insn) {
    (void)insn;  // Avoid unused parameter warning
    return 3;  // opcode + ModR/M + imm8
}

void generate_arithmetic_negation(struct buffer *b, cs_insn *insn) {
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;
    int64_t imm = insn->detail->x86.operands[1].imm;
    uint8_t dst_idx = get_reg_index(dst_reg);

    // Negate: SUB → ADD with -imm, ADD → SUB with -imm
    int8_t negated_imm = (int8_t)(-imm);
    uint8_t new_opcode = (insn->id == X86_INS_SUB) ? 0x83 : 0x83;  // Both use 0x83 for imm8
    uint8_t modrm = (insn->id == X86_INS_SUB) ? (0xC0 | dst_idx) : (0xE8 | dst_idx);

    if (insn->id == X86_INS_SUB) {
        modrm = 0xC0 | dst_idx;  // ADD reg, imm8
    } else {
        modrm = 0xE8 | dst_idx;  // SUB reg, imm8
    }

    uint8_t bytes[] = {new_opcode, modrm, (uint8_t)negated_imm};
    buffer_append(b, bytes, 3);
}

static strategy_t arithmetic_negation_strategy = {
    .name = "Arithmetic Negation Obfuscation",
    .can_handle = can_handle_arithmetic_negation,
    .get_size = get_arithmetic_negation_size,
    .generate = generate_arithmetic_negation,
    .priority = 85
};

void register_arithmetic_negation_obfuscation() {
    register_obfuscation_strategy(&arithmetic_negation_strategy);
}

// ============================================================================
// Strategy 4: Junk Code Insertion (Priority 90)
// Inserts dead code that has no effect: XOR EAX, EAX; ADD EAX, 0; etc.
// ============================================================================

int can_handle_junk_code(cs_insn *insn) {
    (void)insn;  // Avoid unused parameter warning
    // Insert junk before every 5th instruction (20% of the time)
    static int insn_counter = 0;
    insn_counter++;
    return (insn_counter % 5 == 0);
}

size_t get_junk_code_size(cs_insn *insn) {
    return insn->size + 6;  // Original + 6 bytes junk
}

void generate_junk_code(struct buffer *b, cs_insn *insn) {
    // Insert junk code before the instruction
    // PUSH EAX; POP EAX (no net effect)
    uint8_t junk1[] = {0x50, 0x58};
    buffer_append(b, junk1, 2);

    // ADD EAX, 0 (no effect)
    uint8_t junk2[] = {0x83, 0xC0, 0x00};
    buffer_append(b, junk2, 3);

    // XOR ECX, ECX; XOR ECX, ECX (restore to 0)
    uint8_t junk3[] = {0x31, 0xC9};
    buffer_append(b, junk3, 2);
    uint8_t junk4[] = {0x31, 0xC9};
    buffer_append(b, junk4, 2);

    // Copy original instruction
    buffer_append(b, insn->bytes, insn->size);
}

static strategy_t junk_code_strategy = {
    .name = "Junk Code Insertion",
    .can_handle = can_handle_junk_code,
    .get_size = get_junk_code_size,
    .generate = generate_junk_code,
    .priority = 90
};

void register_junk_code_insertion() {
    // DISABLED by default - too aggressive
    // Use strategy definition to avoid unused variable warning
    (void)junk_code_strategy;
    // Uncomment to enable:
    // register_obfuscation_strategy(&junk_code_strategy);
}

// ============================================================================
// Strategy 5: Opaque Predicates (Priority 95)
// Inserts always-true/false conditions to confuse static analysis
// ============================================================================

int can_handle_opaque_predicate(cs_insn *insn) {
    // Only apply to jump targets for control flow obfuscation
    if (insn->id == X86_INS_JMP || insn->id == X86_INS_CALL) {
        return 0;  // Skip jumps for now
    }

    static int counter = 0;
    counter++;
    return (counter % 10 == 0);  // Apply to 10% of instructions
}

size_t get_opaque_predicate_size(cs_insn *insn) {
    return insn->size + 8;  // Original + opaque predicate overhead
}

void generate_opaque_predicate(struct buffer *b, cs_insn *insn) {
    // Insert: TEST EAX, EAX; JNZ +5; <junk>; actual instruction
    // Since (X & X) always preserves X's ZF state, this is opaque

    // TEST EAX, EAX
    uint8_t test[] = {0x85, 0xC0};
    buffer_append(b, test, 2);

    // JNZ +5 (skip junk code)
    uint8_t jnz[] = {0x75, 0x03};
    buffer_append(b, jnz, 2);

    // Junk: INT 3; INT 3; INT 3 (unreachable)
    uint8_t junk[] = {0xCC, 0xCC, 0xCC};
    buffer_append(b, junk, 3);

    // Original instruction
    buffer_append(b, insn->bytes, insn->size);
}

static strategy_t opaque_predicate_strategy = {
    .name = "Opaque Predicate Obfuscation",
    .can_handle = can_handle_opaque_predicate,
    .get_size = get_opaque_predicate_size,
    .generate = generate_opaque_predicate,
    .priority = 95
};

void register_opaque_predicate_obfuscation() {
    // DISABLED by default - breaks some shellcode
    // Use strategy definition to avoid unused variable warning
    (void)opaque_predicate_strategy;
    // Uncomment to enable:
    // register_obfuscation_strategy(&opaque_predicate_strategy);
}

// ============================================================================
// Stub implementations for remaining strategies
// ============================================================================

void register_register_renaming_obfuscation() {
    // TODO: Implement register substitution
}

void register_constant_unfolding() {
    // TODO: Implement immediate value obfuscation
}

void register_instruction_reordering() {
    // TODO: Implement independent instruction shuffling
}

void register_stack_spill_obfuscation() {
    // TODO: Implement stack-based register hiding
}

void register_nop_insertion() {
    // TODO: Implement polymorphic NOP padding
}
