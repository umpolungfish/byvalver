#include "strategy.h"
#include "utils.h"
#include "profile_aware_sib.h"
#include <stdio.h>

/**
 * Indirect CALL strategy with proper dereferencing
 *
 * Handles: CALL DWORD PTR [disp32]
 * Pattern: FF 15 XX XX YY YY (where address contains null bytes)
 *
 * This is the CORRECTED version that properly dereferences the memory location.
 * The existing call_mem_disp32_strategy was missing the dereferencing step.
 *
 * Original instruction flow:
 *   CALL DWORD PTR ds:0x00401000
 *   -> Reads the 4-byte value at address 0x00401000
 *   -> Calls the function at that address
 *
 * Replacement (null-free):
 *   MOV EAX, 0x00401000      ; Load address (null-free construction)
 *   MOV EAX, DWORD PTR [EAX] ; Dereference to get function pointer
 *   CALL EAX                 ; Call the function
 */
int can_handle_indirect_call_mem(cs_insn *insn) {
    // Must be CALL instruction
    if (insn->id != X86_INS_CALL) {
        return 0;
    }

    // Must have exactly one operand
    if (insn->detail->x86.op_count != 1) {
        return 0;
    }

    // Operand must be memory reference
    if (insn->detail->x86.operands[0].type != X86_OP_MEM) {
        return 0;
    }

    // Must be direct memory addressing: [disp32] with no base/index registers
    // This is the pattern: FF 15 [disp32]
    if (insn->detail->x86.operands[0].mem.base != X86_REG_INVALID ||
        insn->detail->x86.operands[0].mem.index != X86_REG_INVALID) {
        return 0;
    }

    // Must have null bytes in the instruction encoding
    if (!has_null_bytes(insn)) {
        return 0;
    }

    return 1;
}

size_t get_size_indirect_call_mem(cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;

    // Size calculation:
    // 1. MOV EAX, addr (null-free) - variable size
    // 2. Safe MOV EAX, [EAX] with compensation - 9 bytes max
    // 3. CALL EAX - 2 bytes (FF D0)
    return get_mov_eax_imm_size(addr) + 9 + 2;
}

void generate_indirect_call_mem(struct buffer *b, cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;

    // Step 1: Load the address into EAX (null-free construction)
    generate_mov_eax_imm(b, addr);

    // Step 2: Dereference - Load the value at [EAX] into EAX
    // FIXED: Use profile-aware SIB generation instead of hardcoded 0x20
    // The old approach used SIB byte 0x20 (SPACE) which fails for http-whitespace profile
    if (generate_safe_mov_reg_mem(b, X86_REG_EAX, X86_REG_EAX) != 0) {
        // Fallback: PUSH [EAX] / POP EAX
        uint8_t push_mem[] = {0xFF, 0x30};  // PUSH [EAX]
        buffer_append(b, push_mem, 2);
        uint8_t pop_eax[] = {0x58};  // POP EAX
        buffer_append(b, pop_eax, 1);
    }

    // Step 3: Call the function pointer now in EAX
    // CALL EAX = FF D0
    uint8_t call_eax[] = {0xFF, 0xD0};
    buffer_append(b, call_eax, 2);
}

strategy_t indirect_call_mem_strategy = {
    .name = "indirect_call_mem",
    .can_handle = can_handle_indirect_call_mem,
    .get_size = get_size_indirect_call_mem,
    .generate = generate_indirect_call_mem,
    .priority = 100  // Highest priority - critical Windows API resolution pattern
};

/**
 * Indirect JMP strategy with proper dereferencing
 *
 * Handles: JMP DWORD PTR [disp32]
 * Pattern: FF 25 XX XX YY YY (where address contains null bytes)
 *
 * Similar to CALL, but for jumps.
 *
 * Original instruction flow:
 *   JMP DWORD PTR ds:0x00401000
 *   -> Reads the 4-byte value at address 0x00401000
 *   -> Jumps to that address
 *
 * Replacement (null-free):
 *   MOV EAX, 0x00401000      ; Load address (null-free construction)
 *   MOV EAX, DWORD PTR [EAX] ; Dereference to get target address
 *   JMP EAX                  ; Jump to the target
 */
int can_handle_indirect_jmp_mem(cs_insn *insn) {
    // Must be JMP instruction
    if (insn->id != X86_INS_JMP) {
        return 0;
    }

    // Must have exactly one operand
    if (insn->detail->x86.op_count != 1) {
        return 0;
    }

    // Operand must be memory reference
    if (insn->detail->x86.operands[0].type != X86_OP_MEM) {
        return 0;
    }

    // Must be direct memory addressing: [disp32] with no base/index registers
    // This is the pattern: FF 25 [disp32]
    if (insn->detail->x86.operands[0].mem.base != X86_REG_INVALID ||
        insn->detail->x86.operands[0].mem.index != X86_REG_INVALID) {
        return 0;
    }

    // Must have null bytes in the instruction encoding
    if (!has_null_bytes(insn)) {
        return 0;
    }

    return 1;
}

size_t get_size_indirect_jmp_mem(cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;

    // Size calculation:
    // 1. MOV EAX, addr (null-free) - variable size
    // 2. Safe MOV EAX, [EAX] with compensation - 9 bytes max
    // 3. JMP EAX - 2 bytes (FF E0)
    return get_mov_eax_imm_size(addr) + 9 + 2;
}

void generate_indirect_jmp_mem(struct buffer *b, cs_insn *insn) {
    uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;

    // Step 1: Load the address into EAX (null-free construction)
    generate_mov_eax_imm(b, addr);

    // Step 2: Dereference - Load the value at [EAX] into EAX
    // FIXED: Use profile-aware SIB generation instead of hardcoded 0x20
    // The old approach used SIB byte 0x20 (SPACE) which fails for http-whitespace profile
    if (generate_safe_mov_reg_mem(b, X86_REG_EAX, X86_REG_EAX) != 0) {
        // Fallback: PUSH [EAX] / POP EAX
        uint8_t push_mem[] = {0xFF, 0x30};  // PUSH [EAX]
        buffer_append(b, push_mem, 2);
        uint8_t pop_eax[] = {0x58};  // POP EAX
        buffer_append(b, pop_eax, 1);
    }

    // Step 3: Jump to the address now in EAX
    // JMP EAX = FF E0
    uint8_t jmp_eax[] = {0xFF, 0xE0};
    buffer_append(b, jmp_eax, 2);
}

strategy_t indirect_jmp_mem_strategy = {
    .name = "indirect_jmp_mem",
    .can_handle = can_handle_indirect_jmp_mem,
    .get_size = get_size_indirect_jmp_mem,
    .generate = generate_indirect_jmp_mem,
    .priority = 100  // Highest priority - critical for indirect jump tables
};

/**
 * Register all indirect call/jmp strategies
 */
void register_indirect_call_strategies(void) {
    register_strategy(&indirect_call_mem_strategy);
    register_strategy(&indirect_jmp_mem_strategy);
}
