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

// ============================================================================
// Strategy: Register Renaming Obfuscation (Priority 65)
// Transforms: MOV dst, src → XCHG dst, temp; MOV temp, src; XCHG dst, temp
// ============================================================================

int can_handle_register_renaming(cs_insn *insn) {
    if (insn->id != X86_INS_MOV) return 0;

    if (insn->detail->x86.op_count == 2) {
        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        // MOV reg, reg (exclude ESP/EBP)
        if (dst->type == X86_OP_REG && src->type == X86_OP_REG) {
            return (dst->reg != X86_REG_ESP && dst->reg != X86_REG_EBP &&
                    src->reg != X86_REG_ESP && src->reg != X86_REG_EBP);
        }
    }
    return 0;
}

size_t get_register_renaming_size(cs_insn *insn) {
    (void)insn;
    // XCHG (2) + MOV (2) + XCHG (2) = 6 bytes
    return 6;
}

void generate_register_renaming(struct buffer *b, cs_insn *insn) {
    cs_x86_op *dst = &insn->detail->x86.operands[0];
    cs_x86_op *src = &insn->detail->x86.operands[1];

    uint8_t dst_idx = get_reg_index(dst->reg);
    uint8_t src_idx = get_reg_index(src->reg);

    // Use ECX as temp register (assuming it's free)
    uint8_t temp_idx = 1; // ECX

    // XCHG dst, temp
    uint8_t xchg1[] = {0x87, 0xC0 | (dst_idx << 3) | temp_idx};
    buffer_append(b, xchg1, 2);

    // MOV temp, src
    uint8_t mov[] = {0x89, 0xC0 | (src_idx << 3) | temp_idx};
    buffer_append(b, mov, 2);

    // XCHG dst, temp
    uint8_t xchg2[] = {0x87, 0xC0 | (dst_idx << 3) | temp_idx};
    buffer_append(b, xchg2, 2);
}

static strategy_t register_renaming_strategy = {
    .name = "Register Renaming Obfuscation",
    .can_handle = can_handle_register_renaming,
    .get_size = get_register_renaming_size,
    .generate = generate_register_renaming,
    .priority = 65
};

void register_register_renaming_obfuscation() {
    register_obfuscation_strategy(&register_renaming_strategy);
}

// ============================================================================
// Strategy: Constant Unfolding (Priority 70)
// Transforms: MOV reg, imm → MOV reg, imm/2; ADD/SUB reg, imm/2
// ============================================================================

int can_handle_constant_unfolding(cs_insn *insn) {
    if (insn->id != X86_INS_MOV) return 0;

    if (insn->detail->x86.op_count == 2) {
        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        // MOV reg, imm where imm > 4 (to make it worthwhile)
        if (dst->type == X86_OP_REG && src->type == X86_OP_IMM) {
            return (src->imm > 4 && src->imm < 0x10000);  // Reasonable range
        }
    }
    return 0;
}

size_t get_constant_unfolding_size(cs_insn *insn) {
    (void)insn;  // Avoid unused parameter warning
    // MOV reg, imm (5 bytes) + ADD/SUB reg, imm (6 bytes) = 11 bytes
    return 11;
}

void generate_constant_unfolding(struct buffer *b, cs_insn *insn) {
    cs_x86_op *dst = &insn->detail->x86.operands[0];
    cs_x86_op *src = &insn->detail->x86.operands[1];

    uint32_t imm = src->imm;
    uint8_t reg = dst->reg;
    uint8_t reg_idx = get_reg_index(reg);

    uint32_t half1 = imm / 2;
    uint32_t half2 = imm - half1;

    // MOV reg, half1
    uint8_t mov_bytes[] = {0xB8 | reg_idx, half1 & 0xFF, (half1 >> 8) & 0xFF, (half1 >> 16) & 0xFF, (half1 >> 24) & 0xFF};
    buffer_append(b, mov_bytes, 5);

    // ADD reg, half2
    uint8_t add_bytes[] = {0x81, 0xC0 | reg_idx, half2 & 0xFF, (half2 >> 8) & 0xFF, (half2 >> 16) & 0xFF, (half2 >> 24) & 0xFF};
    buffer_append(b, add_bytes, 6);
}

static strategy_t constant_unfolding_strategy = {
    .name = "Constant Unfolding",
    .can_handle = can_handle_constant_unfolding,
    .get_size = get_constant_unfolding_size,
    .generate = generate_constant_unfolding,
    .priority = 70
};

void register_constant_unfolding() {
    register_obfuscation_strategy(&constant_unfolding_strategy);
}

// ============================================================================
// Strategy: Instruction Reordering (Priority 60)
// For now, implement a simple NOP insertion variant
// ============================================================================

int can_handle_obfuscation_instruction_reordering(cs_insn *insn) {
    (void)insn;
    return 1; // Always applicable
}

size_t get_obfuscation_instruction_reordering_size(cs_insn *insn) {
    (void)insn;
    return insn->size + 1; // Original + NOP
}

void generate_obfuscation_instruction_reordering(struct buffer *b, cs_insn *insn) {
    // For now, just insert a NOP before the instruction
    buffer_append(b, (uint8_t[]){0x90}, 1);
    buffer_append(b, insn->bytes, insn->size);
}

static strategy_t obfuscation_instruction_reordering_strategy = {
    .name = "Obfuscation Instruction Reordering",
    .can_handle = can_handle_obfuscation_instruction_reordering,
    .get_size = get_obfuscation_instruction_reordering_size,
    .generate = generate_obfuscation_instruction_reordering,
    .priority = 60
};

void register_instruction_reordering() {
    register_obfuscation_strategy(&obfuscation_instruction_reordering_strategy);
}

// ============================================================================
// Strategy: Stack Spill Obfuscation (Priority 55)
// Transforms: ADD dst, src → PUSH dst; ADD [ESP], src; POP dst
// ============================================================================

int can_handle_stack_spill(cs_insn *insn) {
    if (insn->id != X86_INS_ADD) return 0;

    if (insn->detail->x86.op_count == 2) {
        cs_x86_op *dst = &insn->detail->x86.operands[0];
        cs_x86_op *src = &insn->detail->x86.operands[1];

        // ADD reg, reg
        if (dst->type == X86_OP_REG && src->type == X86_OP_REG) {
            return (dst->reg != X86_REG_ESP && src->reg != X86_REG_ESP);
        }
    }
    return 0;
}

size_t get_stack_spill_size(cs_insn *insn) {
    (void)insn;
    // PUSH (1) + ADD [ESP], reg (3) + POP (1) = 5 bytes
    return 5;
}

void generate_stack_spill(struct buffer *b, cs_insn *insn) {
    cs_x86_op *dst = &insn->detail->x86.operands[0];
    cs_x86_op *src = &insn->detail->x86.operands[1];

    uint8_t dst_idx = get_reg_index(dst->reg);
    uint8_t src_idx = get_reg_index(src->reg);

    // PUSH dst
    uint8_t push[] = {0x50 | dst_idx};
    buffer_append(b, push, 1);

    // ADD [ESP], src
    uint8_t add[] = {0x01, 0x04 | (src_idx << 3), 0x24};
    buffer_append(b, add, 3);

    // POP dst
    uint8_t pop[] = {0x58 | dst_idx};
    buffer_append(b, pop, 1);
}

static strategy_t stack_spill_strategy = {
    .name = "Stack Spill Obfuscation",
    .can_handle = can_handle_stack_spill,
    .get_size = get_stack_spill_size,
    .generate = generate_stack_spill,
    .priority = 55
};

void register_stack_spill_obfuscation() {
    register_obfuscation_strategy(&stack_spill_strategy);
}

// ============================================================================
// Strategy: Polymorphic NOP Insertion (Priority 10 - Low priority, applied randomly)
// Inserts random NOP equivalents after instructions to increase size and complexity
// ============================================================================

int can_handle_nop_insertion(cs_insn *insn) {
    (void)insn;  // Can be applied to any instruction
    return 1;    // Always applicable
}

size_t get_nop_insertion_size(cs_insn *insn) {
    (void)insn;
    // Original instruction size + random NOP size (1-3 bytes)
    return insn->size + (rand() % 3 + 1);
}

void generate_nop_insertion(struct buffer *b, cs_insn *insn) {
    // First, append the original instruction bytes
    buffer_append(b, insn->bytes, insn->size);

    // Then insert a random NOP equivalent
    int nop_type = rand() % 4;
    switch (nop_type) {
        case 0: // Standard NOP
            buffer_append(b, (uint8_t[]){0x90}, 1);
            break;
        case 1: // XCHG EAX, EAX
            buffer_append(b, (uint8_t[]){0x87, 0xC0}, 2);
            break;
        case 2: // LEA EAX, [EAX + 0]
            buffer_append(b, (uint8_t[]){0x8D, 0x40, 0x00}, 3);
            break;
        case 3: // MOV EAX, EAX
            buffer_append(b, (uint8_t[]){0x89, 0xC0}, 2);
            break;
    }
}

static strategy_t nop_insertion_strategy = {
    .name = "Polymorphic NOP Insertion",
    .can_handle = can_handle_nop_insertion,
    .get_size = get_nop_insertion_size,
    .generate = generate_nop_insertion,
    .priority = 10  // Low priority
};

void register_nop_insertion() {
    register_obfuscation_strategy(&nop_insertion_strategy);
}
