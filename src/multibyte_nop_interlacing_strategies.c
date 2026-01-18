/**
 * multbyte_nop_interlacing_strategies.c
 *
 * Priority: 82 (Tier 3 - Medium Value, Low-Medium Effort)
 * Applicability: Obfuscation (50% of alignment code)
 *
 * Implements multi-byte NOP instruction interlacing for enhanced obfuscation.
 * Replaces standard NOP instructions with semantic-preserving operations that
 * are harder for disassemblers and emulators to recognize as padding.
 *
 * Key techniques:
 * 1. Arithmetic NOPs - Operations that don't change register values
 * 2. Register Rotation NOPs - Stack-based register preservation
 * 3. Conditional NOPs - Appear conditional but always execute
 * 4. FPU NOPs - Floating point operations that don't affect GPRs
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**
 * Check if instruction is a NOP (standard or multi-byte)
 */
static int is_nop_instruction(cs_insn *insn) {
    if (insn->id == X86_INS_NOP) {
        return 1;
    }

    // Check for multi-byte NOPs (Intel recommended sequences)
    if (insn->size >= 3 && insn->size <= 9) {
        // Common multi-byte NOP patterns
        const uint8_t *bytes = insn->bytes;

        // nop dword [eax] (0F 1F 00)
        if (insn->size == 3 && bytes[0] == 0x0F && bytes[1] == 0x1F && bytes[2] == 0x00) {
            return 1;
        }

        // nop dword [eax + 0x00] (0F 1F 40 00)
        if (insn->size == 4 && bytes[0] == 0x0F && bytes[1] == 0x1F && bytes[2] == 0x40 && bytes[3] == 0x00) {
            return 1;
        }

        // Other multi-byte NOPs...
        if (bytes[0] == 0x0F && bytes[1] == 0x1F) {
            return 1;
        }
    }

    return 0;
}

/**
 * Technique 1: Arithmetic NOPs
 *
 * Handles: NOP instruction (any size)
 * Transform: LEA reg, [reg+0] or XOR reg, 0 (preserves register value)
 *
 * Priority: 82
 */
int can_handle_arithmetic_nops(cs_insn *insn) {
    return is_nop_instruction(insn);
}

size_t get_size_arithmetic_nops(cs_insn *insn) {
    // Return size similar to original NOP
    return insn->size;
}

void generate_arithmetic_nops(struct buffer *b, cs_insn *insn) {
    int target_size = insn->size;

    if (target_size == 1) {
        // Single byte: XCHG EAX, EAX (90) - this is actually the standard NOP!
        uint8_t xchg_eax[] = {0x90};
        buffer_append(b, xchg_eax, 1);
    } else if (target_size == 2) {
        // 2 bytes: PUSH EAX; POP EAX
        uint8_t push_pop[] = {0x50, 0x58}; // PUSH EAX, POP EAX
        buffer_append(b, push_pop, 2);
    } else if (target_size == 3) {
        // 3 bytes: LEA EAX, [EAX + 0]
        uint8_t lea_zero[] = {0x8D, 0x40, 0x00};
        buffer_append(b, lea_zero, 3);
    } else if (target_size == 4) {
        // 4 bytes: PUSH EBX; PUSH EAX; POP EAX; POP EBX (preserves both)
        uint8_t preserve_both[] = {0x53, 0x50, 0x58, 0x5B};
        buffer_append(b, preserve_both, 4);
    } else {
        // For larger sizes, repeat the pattern or use multiple LEA
        int remaining = target_size;
        while (remaining >= 3) {
            uint8_t lea_zero[] = {0x8D, 0x40, 0x00}; // LEA EAX, [EAX + 0]
            buffer_append(b, lea_zero, 3);
            remaining -= 3;
        }
        if (remaining == 2) {
            uint8_t push_pop[] = {0x50, 0x58};
            buffer_append(b, push_pop, 2);
        } else if (remaining == 1) {
            uint8_t nop = 0x90;
            buffer_append(b, &nop, 1);
        }
    }
}

/**
 * Technique 2: Register Rotation NOPs
 *
 * Handles: NOP instruction
 * Transform: Complex register preservation sequences
 *
 * Priority: 81
 */
int can_handle_register_rotation_nops(cs_insn *insn) {
    return is_nop_instruction(insn) && insn->size >= 4; // Only for multi-byte NOPs
}

size_t get_size_register_rotation_nops(cs_insn *insn) {
    // Try to match original size
    return insn->size;
}

void generate_register_rotation_nops(struct buffer *b, cs_insn *insn) {
    int target_size = insn->size;

    if (target_size >= 8) {
        // 8 bytes: Preserve all volatile registers
        uint8_t preserve_all[] = {
            0x50, 0x51, 0x52, 0x53, // PUSH EAX, ECX, EDX, EBX
            0x5B, 0x5A, 0x59, 0x58  // POP EBX, EDX, ECX, EAX
        };
        buffer_append(b, preserve_all, 8);
    } else if (target_size >= 6) {
        // 6 bytes: PUSHAD/POPAD simulation (partial)
        uint8_t partial_pushad[] = {
            0x50, 0x51, 0x52,       // PUSH EAX, ECX, EDX
            0x5A, 0x59, 0x58        // POP EDX, ECX, EAX
        };
        buffer_append(b, partial_pushad, 6);
    } else {
        // Fallback to arithmetic NOPs
        generate_arithmetic_nops(b, insn);
    }
}

/**
 * Technique 3: Conditional NOPs
 *
 * Handles: NOP instruction
 * Transform: Conditional jump that always executes as NOP
 *
 * Priority: 80
 */
int can_handle_conditional_nops(cs_insn *insn) {
    return is_nop_instruction(insn) && insn->size >= 3; // Need space for conditional sequence
}

size_t get_size_conditional_nops(cs_insn *insn) {
    return insn->size; // Try to match size
}

void generate_conditional_nops(struct buffer *b, cs_insn *insn) {
    int target_size = insn->size;

    if (target_size >= 4) {
        // 4 bytes: JZ $+2; DB 0xEB (appears conditional but always skips nothing)
        uint8_t conditional_nop[] = {0x74, 0x00, 0xEB, 0x00}; // JZ +0; JMP +0
        buffer_append(b, conditional_nop, 4);

        // Fill remaining space with NOPs
        for (int i = 4; i < target_size; i++) {
            uint8_t nop = 0x90;
            buffer_append(b, &nop, 1);
        }
    } else {
        // Fallback to arithmetic NOPs
        generate_arithmetic_nops(b, insn);
    }
}

/**
 * Technique 4: FPU NOPs
 *
 * Handles: NOP instruction
 * Transform: FPU operations that don't affect GPRs
 *
 * Priority: 79
 */
int can_handle_fpu_nops(cs_insn *insn) {
    return is_nop_instruction(insn) && insn->size >= 2; // FPU ops are at least 2 bytes
}

size_t get_size_fpu_nops(cs_insn *insn) {
    return insn->size;
}

void generate_fpu_nops(struct buffer *b, cs_insn *insn) {
    int target_size = insn->size;

    if (target_size >= 2) {
        // 2 bytes: FNOP (D9 D0)
        uint8_t fnop[] = {0xD9, 0xD0};
        buffer_append(b, fnop, 2);

        // Fill remaining with more FPU NOPs or regular NOPs
        int remaining = target_size - 2;
        while (remaining >= 2) {
            uint8_t fst_st0[] = {0xDD, 0xD0}; // FST ST(0) - store to self
            buffer_append(b, fst_st0, 2);
            remaining -= 2;
        }
        if (remaining == 1) {
            uint8_t nop = 0x90;
            buffer_append(b, &nop, 1);
        }
    } else {
        // Fallback
        generate_arithmetic_nops(b, insn);
    }
}

// Strategy registration
static strategy_t arithmetic_nops_strategy = {
    .name = "Multi-Byte NOP (Arithmetic)",
    .can_handle = can_handle_arithmetic_nops,
    .get_size = get_size_arithmetic_nops,
    .generate = generate_arithmetic_nops,
    .priority = 82,
    .target_arch = BYVAL_ARCH_X86
};

static strategy_t register_rotation_nops_strategy = {
    .name = "Multi-Byte NOP (Register Rotation)",
    .can_handle = can_handle_register_rotation_nops,
    .get_size = get_size_register_rotation_nops,
    .generate = generate_register_rotation_nops,
    .priority = 81,
    .target_arch = BYVAL_ARCH_X86
};

static strategy_t conditional_nops_strategy = {
    .name = "Multi-Byte NOP (Conditional)",
    .can_handle = can_handle_conditional_nops,
    .get_size = get_size_conditional_nops,
    .generate = generate_conditional_nops,
    .priority = 80,
    .target_arch = BYVAL_ARCH_X86
};

static strategy_t fpu_nops_strategy = {
    .name = "Multi-Byte NOP (FPU)",
    .can_handle = can_handle_fpu_nops,
    .get_size = get_size_fpu_nops,
    .generate = generate_fpu_nops,
    .priority = 79,
    .target_arch = BYVAL_ARCH_X86
};

void register_multibyte_nop_interlacing_strategies(void) {
    register_strategy(&arithmetic_nops_strategy);
    register_strategy(&register_rotation_nops_strategy);
    register_strategy(&conditional_nops_strategy);
    register_strategy(&fpu_nops_strategy);
}