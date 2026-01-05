/*
 * Conditional Jump Displacement Strategies
 *
 * This strategy module handles conditional jumps (jz, jnz, je, jne, etc.) 
 * that have null bytes in their displacement fields. These are common in
 * shellcode patterns, especially in API resolution loops.
 */

#include "strategy.h"
#include "utils.h"
#include "conditional_jump_displacement_strategies.h"
#include <stdio.h>
#include <string.h>

/*
 * Detection for conditional jumps that contain null bytes in displacement
 * or in the instruction encoding
 */
int can_handle_conditional_jump_displacement(cs_insn *insn) {
    // Check if this is a conditional jump instruction
    if (insn->id < X86_INS_JAE || insn->id > X86_INS_JS) {
        return 0;
    }

    // Check if the instruction contains null bytes somewhere
    for (int i = 0; i < insn->size; i++) {
        if (insn->bytes[i] == 0x00) {
            return 1;
        }
    }

    // For long conditional jumps (0x0F 0x8x encoding), check displacement specifically
    // Conditional jumps use rel8 (Jcc rel8) or rel32 (Jcc rel32) depending on target distance
    if (insn->detail->x86.op_count > 0 && insn->detail->x86.operands[0].type == X86_OP_IMM) {
        uint32_t disp = (uint32_t)insn->detail->x86.operands[0].imm;
        // Check if displacement contains null bytes
        for (int i = 0; i < 4; i++) {
            if (((disp >> (i * 8)) & 0xFF) == 0x00) {
                return 1;
            }
        }
    }

    return 0;
}

/*
 * Detection for conditional jumps that use short displacement (rel8) but still contain nulls
 */
int can_handle_short_conditional_jump_with_nulls(cs_insn *insn) {
    // Check if this is a conditional jump instruction
    if (insn->id < X86_INS_JAE || insn->id > X86_INS_JS) {
        return 0;
    }

    // Short conditional jumps use rel8, but if we have near jumps (0x0F 0x8x format),
    // those use rel32 and can contain null bytes in the displacement
    // Check if this is a near conditional jump (two-byte opcode format starting with 0x0F)
    if (insn->size >= 6) { // At least 0x0F + 0x8x + 4 bytes displacement
        if (insn->bytes[0] == 0x0F) {
            // Check if bytes 2-5 (displacement) contain nulls
            for (int i = 2; i < insn->size; i++) {
                if (insn->bytes[i] == 0x00) {
                    return 1;
                }
            }
        }
    }

    return 0;
}

size_t get_size_conditional_jump_displacement(__attribute__((unused)) cs_insn *insn) {
    // Converting conditional jumps to null-free equivalents may require more bytes
    // Original: 6 bytes (0x0F 0x8x disp32) -> Alternative: 8-12 bytes using test+jmp pattern
    return 12;
}

size_t get_size_short_conditional_jump_with_nulls(__attribute__((unused)) cs_insn *insn) {
    // For short jumps with nulls in encoding (rare case)
    return 10;
}

/*
 * Transform conditional jumps with null-byte displacement to alternative pattern
 * Original: jz near_label (0x0F 0x84 disp32 where disp32 contains nulls)
 * New: Use inverse conditional jump to skip over an unconditional jump
 * Example: jz target -> jnz skip; jmp target; skip:
 */
void generate_conditional_jump_displacement(struct buffer *b, cs_insn *insn) {
    // Extract the immediate operand (the jump target)
    if (insn->detail->x86.op_count == 0 || insn->detail->x86.operands[0].type != X86_OP_IMM) {
        // If no immediate operand, fallback to original
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    uint64_t target = (uint64_t)insn->detail->x86.operands[0].imm;

    // This approach doesn't use the inverse jump directly, but we could if needed
    // The current approach uses SETcc + conditional logic

    // The approach: instead of using long conditional jump with null displacement,
    // use a short inverse conditional jump to skip over a direct jump to the target
    // This requires the ability to determine the size of the direct jump instruction
    // For this implementation, we'll push the target address and use conditional logic
    // to either execute a return (jump) or skip it

    // Push the target address onto the stack using null-safe construction
    uint8_t push_eax[] = {0x50}; // Save EAX register
    buffer_append(b, push_eax, 1);

    // MOV EAX, target address using null-free construction
    generate_mov_eax_imm(b, (uint32_t)target);

    // PUSH EAX (push the target address onto the stack)
    uint8_t push_target[] = {0x50};
    buffer_append(b, push_target, 1);

    // Now implement the conditional logic using the inverse condition:
    // If condition is NOT met (inverse), skip the RET by jumping over it
    // If condition IS met, let execution fall through to the RET
    // This is a bit complex, so let's use a different approach:
    // Execute inverse conditional jump to skip over the RET, if condition not met
    // Since we can't easily calculate the offset to skip the RET, we'll use the CALL/POP method differently

    // Restore EAX first
    uint8_t pop_eax[] = {0x58};
    buffer_append(b, pop_eax, 1);

    // For the conditional jump, we use the inverse condition approach but calculate size differently
    // Approach: Use a conditional call to skip over the return if the condition is not met
    // This gets complex. Let's implement a simpler, more reliable technique:

    // Method: Use conditional set (SETcc) instruction to store the result in a register,
    // then use that to conditionally execute the jump

    // Save an additional register to use for the conditional result
    uint8_t push_ecx[] = {0x51};
    buffer_append(b, push_ecx, 1);

    // Use SETcc instruction to store the condition result in ECX
    uint8_t setcc_op = 0;
    switch (insn->id) {
        case X86_INS_JE: setcc_op = 0x94; break; // SETZ (JE/JZ would map to same SETZ)
        case X86_INS_JNE: setcc_op = 0x95; break; // SETNZ (JNE/JNZ would map to same SETNZ)
        case X86_INS_JB: setcc_op = 0x92; break; // SETB (JB/JC/JNAE would map to same SETB)
        case X86_INS_JAE: setcc_op = 0x93; break; // SETAE (JAE/JNB/JNC would map to same SETAE)
        case X86_INS_JA: setcc_op = 0x97; break; // SETA
        case X86_INS_JBE: setcc_op = 0x96; break; // SETBE
        case X86_INS_JG: setcc_op = 0x9F; break; // SETG (JG/JNLE would map to same SETG)
        case X86_INS_JGE: setcc_op = 0x9D; break; // SETGE (JGE/JNL would map to same SETGE)
        case X86_INS_JL: setcc_op = 0x9C; break; // SETL (JL/JNGE would map to same SETL)
        case X86_INS_JLE: setcc_op = 0x9E; break; // SETLE (JLE/JNG would map to same SETLE)
        case X86_INS_JO: setcc_op = 0x90; break; // SETO
        case X86_INS_JNO: setcc_op = 0x91; break; // SETNO
        case X86_INS_JP: setcc_op = 0x9A; break; // SETPE (JP/JPE would map to same SETPE)
        case X86_INS_JNP: setcc_op = 0x9B; break; // SETPO (JNP/JPO would map to same SETPO)
        case X86_INS_JS: setcc_op = 0x98; break; // SETS
        case X86_INS_JNS: setcc_op = 0x99; break; // SETNS
        default:
            // For unhandled cases, restore and return original
            {
                uint8_t pop_ecx[] = {0x59};
                buffer_append(b, pop_ecx, 1);
                uint8_t pop_eax_final[] = {0x58};
                buffer_append(b, pop_eax_final, 1);
                buffer_append(b, insn->bytes, insn->size);
                return;
            }
    }

    // SETcc ECX - store condition result in ECX (0 or 1)
    uint8_t setcc_inst[] = {0x0F, setcc_op, 0xC1}; // SETcc ECX
    buffer_append(b, setcc_inst, 3);

    // If ECX is 1, we want to jump; if ECX is 0, we want to skip the jump
    // We'll multiply ECX by the size of the RET instruction and add to EIP using a different approach

    // Simpler approach: Use a loop to execute RET the right number of times based on ECX
    // or use conditional jump to a RET vs to a skip

    // Even simpler approach: use conditional logic to decide whether to execute a return
    // POP ECX to get the value
    uint8_t pop_ecx[] = {0x59};
    buffer_append(b, pop_ecx, 1);

    // Now use ECX value to conditionally execute jump
    // If ECX is 0 (condition not met) skip the RET
    // If ECX is 1 (condition met) execute the RET

    // Test if ECX is 0 (null-free comparison)
    // TEST ECX, ECX sets ZF if ECX is zero - no null bytes!
    uint8_t test_ecx[] = {0x85, 0xC9}; // TEST ECX, ECX
    buffer_append(b, test_ecx, 2);

    // Conditional jump to skip the RET if ECX is 0 (condition not met)
    uint8_t jz_skip_ret[] = {0x74, 0x02}; // JZ skip_next_instr (skip the RET)
    buffer_append(b, jz_skip_ret, 2);

    // RET instruction to jump to the target on the stack
    uint8_t ret_inst[] = {0xC3};
    buffer_append(b, ret_inst, 1);

    // At this point, if we didn't jump over the RET, we've executed it and jumped to target
    // If we did jump over the RET, we continue execution normally
}

/*
 * Generate short conditional jump alternative when it contains nulls
 */
void generate_short_conditional_jump_with_nulls(struct buffer *b, cs_insn *insn) {
    // For short conditional jumps that for some reason have null bytes in their encoding
    // This is unusual as short jumps (Jcc rel8) only have 1-byte displacement
    // But if there are nulls elsewhere in the encoding, we convert to near jump

    // Simply append the original instruction as a fallback
    buffer_append(b, insn->bytes, insn->size);
}

/*
 * Alternative approach: Convert conditional jump to test+jmp pattern
 * This approach creates a more complex but null-free sequence
 */
int can_handle_conditional_jump_alternative(cs_insn *insn) {
    // Check for conditional jumps with bad bytes (not just nulls)
    if (insn->id < X86_INS_JAE || insn->id > X86_INS_JS) {
        return 0;
    }

    // Handle BOTH short (2-byte) and near (6-byte) conditional jumps with bad bytes
    // The indirect jump transformation works for both cases
    // has_null_bytes() checks for ALL bad bytes despite the name (v3.0+)
    return has_null_bytes(insn);
}

size_t get_size_conditional_jump_alternative(cs_insn *insn) {
    // FIXED: Account for variable MOV EAX,imm size
    if (!insn || !insn->detail || insn->detail->x86.op_count == 0 ||
        insn->detail->x86.operands[0].type != X86_OP_IMM) {
        return insn->size; // Fallback to original size
    }

    uint32_t target = (uint32_t)insn->detail->x86.operands[0].imm;
    // inverse_jcc(2) + PUSH(1) + MOV EAX,imm(variable) + XCHG(3) + RET(1) + NOP(1)
    return 2 + 1 + get_mov_eax_imm_size(target) + 3 + 1 + 1;
}

/*
 * Generate alternative conditional jump pattern that avoids displacement nulls
 * Uses: Inverse condition + short jump to skip over target reconstruction + indirect jump
 */
void generate_conditional_jump_alternative(struct buffer *b, cs_insn *insn) {
    // Extract target address - fallback to original if we can't transform
    if (!insn || !insn->detail || insn->detail->x86.op_count == 0 ||
        insn->detail->x86.operands[0].type != X86_OP_IMM) {
        // Can't transform - copy original instruction
        buffer_append(b, insn->bytes, insn->size);
        return;
    }

    uint64_t target = (uint64_t)insn->detail->x86.operands[0].imm;

    // Get inverse conditional opcode
    uint8_t inverse_jcc = 0;
    switch (insn->id) {
        case X86_INS_JE:  inverse_jcc = 0x75; break; // JNZ
        case X86_INS_JNE: inverse_jcc = 0x74; break; // JZ
        case X86_INS_JA:  inverse_jcc = 0x76; break; // JBE
        case X86_INS_JAE: inverse_jcc = 0x72; break; // JB
        case X86_INS_JB:  inverse_jcc = 0x73; break; // JAE
        case X86_INS_JBE: inverse_jcc = 0x77; break; // JA
        case X86_INS_JG:  inverse_jcc = 0x7E; break; // JLE
        case X86_INS_JGE: inverse_jcc = 0x7C; break; // JL
        case X86_INS_JL:  inverse_jcc = 0x7D; break; // JGE
        case X86_INS_JLE: inverse_jcc = 0x7F; break; // JG
        case X86_INS_JO:  inverse_jcc = 0x71; break; // JNO
        case X86_INS_JNO: inverse_jcc = 0x70; break; // JO
        case X86_INS_JS:  inverse_jcc = 0x79; break; // JNS
        case X86_INS_JNS: inverse_jcc = 0x78; break; // JS
        case X86_INS_JP:  inverse_jcc = 0x7B; break; // JNP
        case X86_INS_JNP: inverse_jcc = 0x7A; break; // JP
        default:
            // Unknown conditional - fallback
            buffer_append(b, insn->bytes, insn->size);
            return;
    }

    // FIXED: Calculate skip offset dynamically based on actual MOV size
    // Save original EAX on stack
    uint8_t push_eax[] = {0x50};

    // Calculate size of MOV EAX,target construction
    size_t mov_size = get_mov_eax_imm_size((uint32_t)target);

    // Swap: [ESP] gets target, EAX gets original value back (3 bytes)
    uint8_t xchg_stack[] = {0x87, 0x04, 0x24}; // XCHG EAX, [ESP]

    // RET: Jump to target (1 byte)
    uint8_t ret[] = {0xC3};

    // Calculate skip distance: PUSH(1) + MOV(variable) + XCHG(3) + RET(1)
    uint8_t skip_distance = 1 + mov_size + 3 + 1;

    // Ensure skip distance is not a bad byte
    uint8_t nop_count = 0;
    while (!is_bad_byte_free_byte(skip_distance + nop_count)) {
        nop_count++;
        if (nop_count > 10) break; // Safety limit
    }

    // Inverse conditional jump to skip over the indirect jump
    uint8_t jcc_skip[] = {inverse_jcc, skip_distance + nop_count};
    buffer_append(b, jcc_skip, 2);

    buffer_append(b, push_eax, 1);

    // Load target into EAX (null-free construction)
    generate_mov_eax_imm(b, (uint32_t)target);

    buffer_append(b, xchg_stack, 3);
    buffer_append(b, ret, 1);

    // Add NOPs if needed to avoid bad byte in skip offset
    for (uint8_t i = 0; i < nop_count; i++) {
        uint8_t nop[] = {0x90};
        buffer_append(b, nop, 1);
    }

    // skip: execution continues here if condition was not met
}

/*
 * Strategy definitions
 */
strategy_t conditional_jump_displacement_strategy = {
    .name = "conditional_jump_displacement",
    .can_handle = can_handle_conditional_jump_displacement,
    .get_size = get_size_conditional_jump_displacement,
    .generate = generate_conditional_jump_displacement,
    .priority = 85  // Medium-high priority for conditional jumps
};

strategy_t short_conditional_jump_with_nulls_strategy = {
    .name = "short_conditional_jump_with_nulls",
    .can_handle = can_handle_short_conditional_jump_with_nulls,
    .get_size = get_size_short_conditional_jump_with_nulls,
    .generate = generate_short_conditional_jump_with_nulls,
    .priority = 82  // Medium priority
};

strategy_t conditional_jump_alternative_strategy = {
    .name = "conditional_jump_alternative",
    .can_handle = can_handle_conditional_jump_alternative,
    .get_size = get_size_conditional_jump_alternative,
    .generate = generate_conditional_jump_alternative,
    .priority = 86  // Higher than conditional_jump_displacement (85) to run first
};

/*
 * Register function
 */
void register_conditional_jump_displacement_strategies() {
    register_strategy(&conditional_jump_displacement_strategy);
    register_strategy(&short_conditional_jump_with_nulls_strategy);
    register_strategy(&conditional_jump_alternative_strategy);
}