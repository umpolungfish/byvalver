#include "strategy.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// ============================================================================
// LOOP Instruction Strategy (E2 cb)
// Transforms: LOOP rel8 → DEC ECX + JNZ rel8
// ============================================================================

static int can_handle_loop(cs_insn *insn) {
    // LOOP instruction with null byte in displacement
    if (insn->id != X86_INS_LOOP) return 0;
    if (insn->size != 2) return 0;  // LOOP is always 2 bytes: E2 cb

    // Check if displacement byte is null
    return (insn->bytes[1] == 0x00);
}

static size_t get_size_loop(cs_insn *insn) {
    (void)insn;  // Unused parameter
    // DEC ECX (1 byte) + JNZ rel8 (2 bytes) = 3 bytes total
    return 3;
}

static void generate_loop(struct buffer *b, cs_insn *insn) {
    // Extract original displacement
    int8_t orig_disp = (int8_t)insn->bytes[1];

    // Calculate adjusted displacement
    // Original LOOP: PC + 2 + orig_disp
    // New DEC+JNZ: PC + 3 + new_disp
    // To reach same target: new_disp = orig_disp - 1
    int8_t new_disp = orig_disp - 1;

    // Emit DEC ECX (49)
    uint8_t dec_ecx = 0x49;
    buffer_append(b, &dec_ecx, 1);

    // Emit JNZ rel8 (75 XX)
    uint8_t jnz_bytes[2];
    jnz_bytes[0] = 0x75;  // JNZ opcode
    jnz_bytes[1] = (uint8_t)new_disp;
    buffer_append(b, jnz_bytes, 2);
}

static strategy_t loop_strategy = {
    .name = "loop",
    .can_handle = can_handle_loop,
    .get_size = get_size_loop,
    .generate = generate_loop,
    .priority = 80
};

// ============================================================================
// JECXZ Instruction Strategy (E3 cb)
// Transforms: JECXZ rel8 → TEST ECX, ECX + JZ rel8
// ============================================================================

static int can_handle_jecxz(cs_insn *insn) {
    // JECXZ instruction with null byte in displacement
    if (insn->id != X86_INS_JECXZ) return 0;
    if (insn->size != 2) return 0;  // JECXZ is always 2 bytes: E3 cb

    // Check if displacement byte is null
    return (insn->bytes[1] == 0x00);
}

static size_t get_size_jecxz(cs_insn *insn) {
    (void)insn;  // Unused parameter
    // TEST ECX, ECX (2 bytes) + JZ rel8 (2 bytes) = 4 bytes total
    return 4;
}

static void generate_jecxz(struct buffer *b, cs_insn *insn) {
    // Extract original displacement
    int8_t orig_disp = (int8_t)insn->bytes[1];

    // Calculate adjusted displacement
    // Original JECXZ: PC + 2 + orig_disp
    // New TEST+JZ: PC + 4 + new_disp
    // To reach same target: new_disp = orig_disp - 2
    int8_t new_disp = orig_disp - 2;

    // Emit TEST ECX, ECX (85 C9)
    uint8_t test_ecx[2];
    test_ecx[0] = 0x85;  // TEST opcode
    test_ecx[1] = 0xC9;  // ModR/M byte for ECX, ECX
    buffer_append(b, test_ecx, 2);

    // Emit JZ rel8 (74 XX)
    uint8_t jz_bytes[2];
    jz_bytes[0] = 0x74;  // JZ opcode
    jz_bytes[1] = (uint8_t)new_disp;
    buffer_append(b, jz_bytes, 2);
}

static strategy_t jecxz_strategy = {
    .name = "jecxz",
    .can_handle = can_handle_jecxz,
    .get_size = get_size_jecxz,
    .generate = generate_jecxz,
    .priority = 80
};

// ============================================================================
// LOOPE/LOOPZ Instruction Strategy (E1 cb)
// Transforms: LOOPE rel8 → DEC ECX + JNZ (skip) + JZ rel8
// ============================================================================

static int can_handle_loope(cs_insn *insn) {
    // LOOPE/LOOPZ instruction with null byte in displacement
    if (insn->id != X86_INS_LOOPE) return 0;
    if (insn->size != 2) return 0;  // LOOPE is always 2 bytes: E1 cb

    // Check if displacement byte is null
    return (insn->bytes[1] == 0x00);
}

static size_t get_size_loope(cs_insn *insn) {
    (void)insn;  // Unused parameter
    // DEC ECX (1 byte) + JNZ skip (2 bytes) + JZ rel8 (2 bytes) = 5 bytes total
    return 5;
}

static void generate_loope(struct buffer *b, cs_insn *insn) {
    // Extract original displacement
    int8_t orig_disp = (int8_t)insn->bytes[1];

    // LOOPE semantics: decrement ECX and jump if ECX != 0 AND ZF = 1
    // Transformation:
    //   DEC ECX           ; Decrement counter
    //   JNZ +2            ; If ECX = 0, skip the JZ (don't take loop)
    //   JZ target         ; If ZF = 1, take the loop

    // Calculate adjusted displacement for the JZ
    // Original LOOPE: PC + 2 + orig_disp
    // New sequence: PC + 5 + new_disp
    // To reach same target: new_disp = orig_disp - 3
    int8_t new_disp = orig_disp - 3;

    // Emit DEC ECX (49)
    uint8_t dec_ecx = 0x49;
    buffer_append(b, &dec_ecx, 1);

    // Emit JNZ +2 (75 02) - skip over the JZ if ECX = 0
    uint8_t jnz_skip[2];
    jnz_skip[0] = 0x75;  // JNZ opcode
    jnz_skip[1] = 0x02;  // Skip 2 bytes (the JZ instruction)
    buffer_append(b, jnz_skip, 2);

    // Emit JZ target (74 XX)
    uint8_t jz_bytes[2];
    jz_bytes[0] = 0x74;  // JZ opcode
    jz_bytes[1] = (uint8_t)new_disp;
    buffer_append(b, jz_bytes, 2);
}

static strategy_t loope_strategy = {
    .name = "loope",
    .can_handle = can_handle_loope,
    .get_size = get_size_loope,
    .generate = generate_loope,
    .priority = 75
};

// ============================================================================
// LOOPNE/LOOPNZ Instruction Strategy (E0 cb)
// Transforms: LOOPNE rel8 → DEC ECX + JNZ (skip) + JNZ rel8
// ============================================================================

static int can_handle_loopne(cs_insn *insn) {
    // LOOPNE/LOOPNZ instruction with null byte in displacement
    if (insn->id != X86_INS_LOOPNE) return 0;
    if (insn->size != 2) return 0;  // LOOPNE is always 2 bytes: E0 cb

    // Check if displacement byte is null
    return (insn->bytes[1] == 0x00);
}

static size_t get_size_loopne(cs_insn *insn) {
    (void)insn;  // Unused parameter
    // DEC ECX (1 byte) + JZ skip (2 bytes) + JNZ rel8 (2 bytes) = 5 bytes total
    return 5;
}

static void generate_loopne(struct buffer *b, cs_insn *insn) {
    // Extract original displacement
    int8_t orig_disp = (int8_t)insn->bytes[1];

    // LOOPNE semantics: decrement ECX and jump if ECX != 0 AND ZF = 0
    // Transformation:
    //   DEC ECX           ; Decrement counter
    //   JZ +2             ; If ECX = 0, skip the JNZ (don't take loop)
    //   JNZ target        ; If ZF = 0, take the loop

    // Calculate adjusted displacement for the JNZ
    // Original LOOPNE: PC + 2 + orig_disp
    // New sequence: PC + 5 + new_disp
    // To reach same target: new_disp = orig_disp - 3
    int8_t new_disp = orig_disp - 3;

    // Emit DEC ECX (49)
    uint8_t dec_ecx = 0x49;
    buffer_append(b, &dec_ecx, 1);

    // Emit JZ +2 (74 02) - skip over the JNZ if ECX = 0
    uint8_t jz_skip[2];
    jz_skip[0] = 0x74;  // JZ opcode
    jz_skip[1] = 0x02;  // Skip 2 bytes (the JNZ instruction)
    buffer_append(b, jz_skip, 2);

    // Emit JNZ target (75 XX)
    uint8_t jnz_bytes[2];
    jnz_bytes[0] = 0x75;  // JNZ opcode
    jnz_bytes[1] = (uint8_t)new_disp;
    buffer_append(b, jnz_bytes, 2);
}

static strategy_t loopne_strategy = {
    .name = "loopne",
    .can_handle = can_handle_loopne,
    .get_size = get_size_loopne,
    .generate = generate_loopne,
    .priority = 75
};

// ============================================================================
// Registration Function
// ============================================================================

void register_loop_strategies() {
    register_strategy(&loop_strategy);
    register_strategy(&jecxz_strategy);
    register_strategy(&loope_strategy);
    register_strategy(&loopne_strategy);
}
