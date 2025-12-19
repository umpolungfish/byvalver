/**
 * syscall_number_obfuscation_strategies.c
 *
 * Priority: 88 (Tier 1 - Linux/x64 specific)
 * Applicability: Linux syscalls (80%+ of Linux shellcode)
 *
 * Implements syscall number obfuscation to eliminate bad characters in
 * syscall number immediates. Syscall numbers frequently contain null bytes
 * when encoded as 32-bit immediates (e.g., MOV EAX, 11 -> B8 0B 00 00 00).
 *
 * This strategy specifically targets the MOV instruction immediately before
 * INT 0x80 (x86) or SYSCALL (x64) instructions.
 */

#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

/**
 * Common Linux syscall numbers for reference
 */
#define SYSCALL_READ      0
#define SYSCALL_WRITE     1
#define SYSCALL_OPEN      2
#define SYSCALL_CLOSE     3
#define SYSCALL_EXECVE    11   // x86: 11, x64: 59
#define SYSCALL_SOCKET    41   // x86: 102 (socketcall), x64: 41
#define SYSCALL_CONNECT   42   // x64 only
#define SYSCALL_EXIT      1    // x86: 1, x64: 60
#define SYSCALL_FORK      2    // x86: 2, x64: 57

// x64 syscall numbers
#define SYSCALL_X64_EXECVE   59
#define SYSCALL_X64_EXIT     60
#define SYSCALL_X64_FORK     57

/**
 * Check if instruction is loading a syscall number into EAX/RAX
 * Heuristic: MOV EAX/RAX, small_immediate (< 400 for common syscalls)
 */
static int is_syscall_number_load(cs_insn *insn) {
    if (insn->id != X86_INS_MOV || insn->detail->x86.op_count != 2) {
        return 0;
    }

    // Check if destination is EAX or RAX (syscall number register)
    if (insn->detail->x86.operands[0].type != X86_OP_REG) {
        return 0;
    }

    x86_reg dst_reg = insn->detail->x86.operands[0].reg;
    if (dst_reg != X86_REG_EAX && dst_reg != X86_REG_RAX) {
        return 0;
    }

    // Check if source is immediate
    if (insn->detail->x86.operands[1].type != X86_OP_IMM) {
        return 0;
    }

    uint64_t imm = insn->detail->x86.operands[1].imm;

    // Syscall numbers are typically < 400
    // This is a heuristic to avoid false positives
    return (imm < 400);
}

/**
 * Strategy: Syscall Number - 8-bit AL Loading
 *
 * Handles: MOV EAX, small_syscall_number (< 256)
 * Transform: XOR EAX, EAX; MOV AL, syscall_number
 *
 * Priority: 88
 */
int can_handle_syscall_number_al_load(cs_insn *insn) {
    if (!is_syscall_number_load(insn)) {
        return 0;
    }

    uint32_t syscall_num = (uint32_t)insn->detail->x86.operands[1].imm;

    // Only handle small syscall numbers that fit in AL
    if (syscall_num > 255) {
        return 0;
    }

    // Check if full 32-bit encoding has bad chars
    return !is_bad_char_free(syscall_num);
}

size_t get_size_syscall_number_al_load(__attribute__((unused)) cs_insn *insn) {
    // XOR EAX, EAX (2) + MOV AL, imm8 (2) = 4 bytes
    return 4;
}

void generate_syscall_number_al_load(struct buffer *b, cs_insn *insn) {
    uint8_t syscall_num = (uint8_t)insn->detail->x86.operands[1].imm;

    // XOR EAX, EAX (zero the register)
    uint8_t xor_eax[] = {0x31, 0xC0}; // XOR EAX, EAX
    buffer_append(b, xor_eax, 2);

    // MOV AL, imm8 (load syscall number into low byte only)
    uint8_t mov_al[] = {0xB0, syscall_num}; // MOV AL, imm8
    buffer_append(b, mov_al, 2);
}

/**
 * Strategy: Syscall Number - PUSH/POP Loading
 *
 * Handles: MOV EAX, syscall_number
 * Transform: PUSH syscall_number; POP EAX
 *
 * Priority: 87
 */
int can_handle_syscall_number_push_pop(cs_insn *insn) {
    if (!is_syscall_number_load(insn)) {
        return 0;
    }

    uint32_t syscall_num = (uint32_t)insn->detail->x86.operands[1].imm;

    // Check if original has bad chars but PUSH immediate doesn't
    if (is_bad_char_free(syscall_num)) {
        return 0;
    }

    // PUSH uses sign-extended 8-bit immediate if value fits
    if (syscall_num <= 127) {
        return 1; // PUSH imm8 is always safe for small values
    }

    return 0;
}

size_t get_size_syscall_number_push_pop(__attribute__((unused)) cs_insn *insn) {
    uint32_t syscall_num = (uint32_t)insn->detail->x86.operands[1].imm;

    if (syscall_num <= 127) {
        return 3; // PUSH imm8 (2) + POP EAX (1) = 3 bytes
    }

    return 6; // PUSH imm32 (5) + POP EAX (1) = 6 bytes
}

void generate_syscall_number_push_pop(struct buffer *b, cs_insn *insn) {
    uint32_t syscall_num = (uint32_t)insn->detail->x86.operands[1].imm;
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;

    if (syscall_num <= 127) {
        // PUSH imm8 (sign-extended to 32/64 bits)
        uint8_t push_imm8[] = {0x6A, (uint8_t)syscall_num};
        buffer_append(b, push_imm8, 2);
    } else {
        // PUSH imm32
        uint8_t push_imm32[] = {
            0x68,
            (uint8_t)(syscall_num & 0xFF),
            (uint8_t)((syscall_num >> 8) & 0xFF),
            (uint8_t)((syscall_num >> 16) & 0xFF),
            (uint8_t)((syscall_num >> 24) & 0xFF)
        };
        buffer_append(b, push_imm32, 5);
    }

    // POP into destination register
    uint8_t pop_reg;
    if (dst_reg == X86_REG_EAX) {
        pop_reg = 0x58; // POP EAX
    } else if (dst_reg == X86_REG_RAX) {
        pop_reg = 0x58; // POP RAX (same opcode, REX prefix added if needed)
    } else {
        // Fallback for unexpected register
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    uint8_t pop[] = {pop_reg};
    buffer_append(b, pop, 1);
}

/**
 * Strategy: Syscall Number - LEA Arithmetic
 *
 * Handles: MOV EAX, syscall_number
 * Transform: XOR EAX, EAX; LEA EAX, [EAX + syscall_number]
 *
 * Priority: 86
 */
int can_handle_syscall_number_lea(cs_insn *insn) {
    if (!is_syscall_number_load(insn)) {
        return 0;
    }

    uint32_t syscall_num = (uint32_t)insn->detail->x86.operands[1].imm;

    // Check if original has bad chars
    if (is_bad_char_free(syscall_num)) {
        return 0;
    }

    // LEA can use 8-bit displacement for small values
    return (syscall_num <= 127);
}

size_t get_size_syscall_number_lea(__attribute__((unused)) cs_insn *insn) {
    // XOR EAX, EAX (2) + LEA EAX, [EAX + disp8] (3) = 5 bytes
    return 5;
}

void generate_syscall_number_lea(struct buffer *b, cs_insn *insn) {
    uint8_t syscall_num = (uint8_t)insn->detail->x86.operands[1].imm;
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;

    uint8_t reg_code = (dst_reg == X86_REG_RAX) ? 0 : 0;

    // XOR EAX, EAX
    uint8_t xor_eax[] = {0x31, 0xC0};
    buffer_append(b, xor_eax, 2);

    // LEA EAX, [EAX + disp8]
    uint8_t lea[] = {
        0x8D,                         // LEA opcode
        0x40 + reg_code,              // ModRM: 01 000 000 (EAX + disp8)
        syscall_num                   // 8-bit displacement
    };
    buffer_append(b, lea, 3);
}

/**
 * Strategy: Syscall Number - INC/DEC Chain
 *
 * Handles: MOV EAX, syscall_number
 * Transform: XOR EAX, EAX; INC EAX; INC EAX; ... (for very small numbers)
 *
 * Priority: 85
 */
int can_handle_syscall_number_inc_chain(cs_insn *insn) {
    if (!is_syscall_number_load(insn)) {
        return 0;
    }

    uint32_t syscall_num = (uint32_t)insn->detail->x86.operands[1].imm;

    // Only worth it for very small numbers (< 10)
    // Otherwise the chain becomes too long
    if (syscall_num > 10) {
        return 0;
    }

    return !is_bad_char_free(syscall_num);
}

size_t get_size_syscall_number_inc_chain(cs_insn *insn) {
    uint32_t syscall_num = (uint32_t)insn->detail->x86.operands[1].imm;

    // XOR (2) + INC * syscall_num (1 byte each)
    return 2 + syscall_num;
}

void generate_syscall_number_inc_chain(struct buffer *b, cs_insn *insn) {
    uint32_t syscall_num = (uint32_t)insn->detail->x86.operands[1].imm;
    x86_reg dst_reg = insn->detail->x86.operands[0].reg;

    uint8_t reg_code = (dst_reg == X86_REG_RAX) ? 0 : 0;

    // XOR EAX, EAX
    uint8_t xor_eax[] = {0x31, 0xC0};
    buffer_append(b, xor_eax, 2);

    // INC EAX (repeat syscall_num times)
    for (uint32_t i = 0; i < syscall_num; i++) {
        uint8_t inc_eax = 0x40 + reg_code; // INC EAX
        buffer_append(b, &inc_eax, 1);
    }
}

// Strategy registration
static strategy_t syscall_number_al_load_strategy = {
    .name = "Syscall Number (AL Loading)",
    .can_handle = can_handle_syscall_number_al_load,
    .get_size = get_size_syscall_number_al_load,
    .generate = generate_syscall_number_al_load,
    .priority = 88
};

static strategy_t syscall_number_push_pop_strategy = {
    .name = "Syscall Number (PUSH/POP)",
    .can_handle = can_handle_syscall_number_push_pop,
    .get_size = get_size_syscall_number_push_pop,
    .generate = generate_syscall_number_push_pop,
    .priority = 87
};

static strategy_t syscall_number_lea_strategy = {
    .name = "Syscall Number (LEA Arithmetic)",
    .can_handle = can_handle_syscall_number_lea,
    .get_size = get_size_syscall_number_lea,
    .generate = generate_syscall_number_lea,
    .priority = 86
};

static strategy_t syscall_number_inc_chain_strategy = {
    .name = "Syscall Number (INC Chain)",
    .can_handle = can_handle_syscall_number_inc_chain,
    .get_size = get_size_syscall_number_inc_chain,
    .generate = generate_syscall_number_inc_chain,
    .priority = 85
};

void register_syscall_number_obfuscation_strategies(void) {
    register_strategy(&syscall_number_al_load_strategy);
    register_strategy(&syscall_number_push_pop_strategy);
    register_strategy(&syscall_number_lea_strategy);
    register_strategy(&syscall_number_inc_chain_strategy);
}
