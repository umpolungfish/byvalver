#include "core.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef DEBUG
// C99 compliant debug macro
#ifdef DEBUG
  #define DEBUG_LOG(fmt, ...) do { fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__); } while(0)
#else
  #define DEBUG_LOG(fmt, ...) do {} while(0)
#endif
#define DEBUG_INSN(insn) fprintf(stderr, "[DEBUG] %s %s\n", insn->mnemonic, insn->op_str)
#else
#define DEBUG_LOG(fmt, ...)
#define DEBUG_INSN(insn)
#endif

void buffer_init(struct buffer *b) {
    b->data = NULL;
    b->size = 0;
    b->capacity = 0;
}

void buffer_free(struct buffer *b) {
    if (b->data) {
        free(b->data);
        b->data = NULL;
    }
    b->size = 0;
    b->capacity = 0;
}

// Helper function to free the instruction node linked list
static void free_instruction_node_list(struct instruction_node *head) {
    struct instruction_node *current = head;
    while (current != NULL) {
        struct instruction_node *next = current->next;
        free(current);
        current = next;
    }
}

void buffer_append(struct buffer *b, const uint8_t *data, size_t size) {
    if (!data || size == 0) {
        // Log when NULL is passed so we can track down the bad strategy
        if (!data && size > 0) {
            fprintf(stderr, "[ERROR] buffer_append called with NULL data but size=%zu\n", size);
        }
        return;
    }
    if (b->size + size > b->capacity) {
        size_t new_capacity = (b->capacity == 0) ? 256 : b->capacity * 2;
        // Check for potential overflow in capacity calculation
        if (new_capacity < b->capacity) {
            fprintf(stderr, "[ERROR] buffer capacity overflow!\n");
            return;
        }
        while (new_capacity < b->size + size) {
            // Check for overflow before multiplying
            if (new_capacity > SIZE_MAX / 2) {
                fprintf(stderr, "[ERROR] buffer capacity would overflow!\n");
                return;
            }
            new_capacity *= 2;
        }
        uint8_t *new_data = realloc(b->data, new_capacity);
        if (new_data == NULL) {
            fprintf(stderr, "[ERROR] realloc failed in buffer_append!\n");
            return; // Don't lose the original pointer
        }
        b->data = new_data;
        b->capacity = new_capacity;
    }
    memcpy(b->data + b->size, data, size);
    b->size += size;
}

uint8_t get_reg_index(uint8_t reg) {
    // Map x86 registers to indices 0-7 for EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI
    switch (reg) {
        case X86_REG_EAX: return 0;
        case X86_REG_ECX: return 1;
        case X86_REG_EDX: return 2;
        case X86_REG_EBX: return 3;
        case X86_REG_ESP: return 4;
        case X86_REG_EBP: return 5;
        case X86_REG_ESI: return 6;
        case X86_REG_EDI: return 7;
        default:
            fprintf(stderr, "[WARNING] Unknown register in get_reg_index: %d\n", reg);
            return 0;  // Return EAX index as default, but log the issue
    }
}

int is_relative_jump(cs_insn *insn) {
    // Check if it's a jump instruction that has an immediate operand (relative jump)
    if (insn->id == X86_INS_JMP || insn->id == X86_INS_CALL) {
        // For JMP and CALL, we need to distinguish between immediate and memory operands
        // Immediate operand means relative jump/call, memory operand means indirect
        if (insn->detail->x86.op_count > 0 &&
            insn->detail->x86.operands[0].type == X86_OP_IMM) {
            return 1; // Relative jump/call
        } else if (insn->detail->x86.op_count > 0 &&
                   insn->detail->x86.operands[0].type == X86_OP_MEM) {
            return 0; // Indirect jump/call, not relative
        }
    }

    // For conditional jumps, they are always relative
    // NOTE: JECXZ/JCXZ and LOOP family are NOT included here because they are
    // handled by loop_strategies.c via the strategy pattern (transformed to different instructions)
    switch (insn->id) {
        case X86_INS_JAE:
        case X86_INS_JA:
        case X86_INS_JBE:
        case X86_INS_JB:
        // case X86_INS_JCXZ:     // Handled by loop_strategies.c
        // case X86_INS_JECXZ:    // Handled by loop_strategies.c
        case X86_INS_JE:
        case X86_INS_JGE:
        case X86_INS_JG:
        case X86_INS_JLE:
        case X86_INS_JL:
        case X86_INS_JNE:
        case X86_INS_JNO:
        case X86_INS_JNP:
        case X86_INS_JNS:
        case X86_INS_JO:
        case X86_INS_JP:
        case X86_INS_JRCXZ:
        case X86_INS_JS:
            return 1;
        // LOOP family instructions are handled by loop_strategies.c
        // case X86_INS_LOOP:     // Handled by loop_strategies.c
        // case X86_INS_LOOPE:    // Handled by loop_strategies.c
        // case X86_INS_LOOPNE:   // Handled by loop_strategies.c
        default:
            return 0;
    }
}

// Helper function to safely handle relative jump instructions
static void process_relative_jump(struct buffer *new_shellcode,
                                   cs_insn *insn,
                                   struct instruction_node *current,
                                   struct instruction_node *head) {

    fprintf(stderr, "[JUMP] Processing: %s %s, bytes[0]=0x%02x, size=%d\n",
            insn->mnemonic, insn->op_str, insn->bytes[0], insn->size);

    // Sanity checks
    if (insn->detail->x86.op_count == 0) {
        // No operands, just copy original
        buffer_append(new_shellcode, insn->bytes, insn->size);
        return;
    }

    if (insn->detail->x86.operands[0].type != X86_OP_IMM) {
        // Not a relative jump (indirect), copy original
        buffer_append(new_shellcode, insn->bytes, insn->size);
        return;
    }

    // Find target node
    uint64_t target_addr = (uint64_t)insn->detail->x86.operands[0].imm;
    struct instruction_node *target_node = head;
    int found = 0;

    fprintf(stderr, "[JUMP] Looking for target address 0x%lx\n", target_addr);

    while (target_node != NULL) {
        if (target_node->offset == target_addr) {
            found = 1;
            fprintf(stderr, "[JUMP] Found target at offset 0x%lx\n", target_addr);
            break;
        }
        target_node = target_node->next;
    }

    if (!found) {
        fprintf(stderr, "[JUMP] Target 0x%lx NOT FOUND! Outputting original bytes.\n", target_addr);
        // Target not in our shellcode - external reference
        // Convert to absolute addressing

        if (insn->id == X86_INS_CALL) {
            // MOV EAX, target + CALL EAX
            generate_mov_eax_imm(new_shellcode, (uint32_t)target_addr);
            uint8_t call_eax[] = {0xFF, 0xD0};
            buffer_append(new_shellcode, call_eax, 2);
            return;
        } else if (insn->id == X86_INS_JMP) {
            // MOV EAX, target + JMP EAX
            generate_mov_eax_imm(new_shellcode, (uint32_t)target_addr);
            uint8_t jmp_eax[] = {0xFF, 0xE0};
            buffer_append(new_shellcode, jmp_eax, 2);
            return;
        } else {
            // Conditional jump to external target
            // Transform using opposite condition + absolute jump to avoid null bytes
            fprintf(stderr, "[JUMP] Conditional jump to external target - transforming\n");

            // Get opposite condition opcode
            uint8_t opposite_opcode;
            if (insn->bytes[0] == 0x0F) {
                // Near conditional jump (0F 8x) - convert to short (7x)
                opposite_opcode = 0x70 + ((insn->bytes[1] ^ 0x01) & 0x0F);
            } else {
                // Short conditional jump (7x) - flip condition bit
                opposite_opcode = insn->bytes[0] ^ 0x01;
            }

            // Calculate skip size
            size_t mov_size = get_mov_eax_imm_size((uint32_t)target_addr);
            uint8_t skip_size = (uint8_t)(mov_size + 2); // MOV + JMP EAX

            // Emit opposite short jump to skip over absolute jump
            uint8_t skip[] = {opposite_opcode, skip_size};
            buffer_append(new_shellcode, skip, 2);

            // Emit absolute jump
            generate_mov_eax_imm(new_shellcode, (uint32_t)target_addr);
            uint8_t jmp_eax[] = {0xFF, 0xE0};
            buffer_append(new_shellcode, jmp_eax, 2);
            return;
        }
    }

    // Calculate new relative offset
    int64_t new_rel = (int64_t)(target_node->new_offset -
                                (current->new_offset + current->new_size));

    // Handle based on instruction type
    if (insn->bytes[0] == 0xE8) {
        // CALL rel32
        uint8_t patched[5];
        patched[0] = 0xE8;
        memcpy(&patched[1], &new_rel, 4);

        // Check for null bytes in patched version
        int has_null = 0;
        for (int i = 0; i < 5; i++) {
            if (patched[i] == 0x00) {
                has_null = 1;
                break;
            }
        }

        if (has_null) {
            // Convert to absolute
            generate_mov_eax_imm(new_shellcode, target_node->new_offset);
            uint8_t call_eax[] = {0xFF, 0xD0};
            buffer_append(new_shellcode, call_eax, 2);
        } else {
            buffer_append(new_shellcode, patched, 5);
        }
        return;
    }

    if (insn->bytes[0] == 0xE9) {
        // JMP rel32
        uint8_t patched[5];
        patched[0] = 0xE9;
        memcpy(&patched[1], &new_rel, 4);

        int has_null = 0;
        for (int i = 0; i < 5; i++) {
            if (patched[i] == 0x00) {
                has_null = 1;
                break;
            }
        }

        if (has_null) {
            generate_mov_eax_imm(new_shellcode, target_node->new_offset);
            uint8_t jmp_eax[] = {0xFF, 0xE0};
            buffer_append(new_shellcode, jmp_eax, 2);
        } else {
            buffer_append(new_shellcode, patched, 5);
        }
        return;
    }

    if (insn->bytes[0] == 0xEB) {
        // JMP rel8 (short)
        int8_t new_rel8 = (int8_t)new_rel;

        if (new_rel == new_rel8 && new_rel8 != 0) {
            // Fits in 8 bits and no null
            uint8_t patched[2] = {0xEB, (uint8_t)new_rel8};
            buffer_append(new_shellcode, patched, 2);
        } else {
            // Convert to absolute
            generate_mov_eax_imm(new_shellcode, target_node->new_offset);
            uint8_t jmp_eax[] = {0xFF, 0xE0};
            buffer_append(new_shellcode, jmp_eax, 2);
        }
        return;
    }

    // Conditional jumps (0x70-0x7F range for short, 0x0F 0x80-0x8F for near)
    if ((insn->bytes[0] >= 0x70 && insn->bytes[0] <= 0x7F)) {
        // Short conditional jump
        int8_t new_rel8 = (int8_t)new_rel;

        if (new_rel == new_rel8 && new_rel8 != 0) {
            // Fits and no null
            uint8_t patched[2];
            patched[0] = insn->bytes[0];
            patched[1] = (uint8_t)new_rel8;
            buffer_append(new_shellcode, patched, 2);
        } else {
            // Need to convert to jump-over + absolute jump pattern
            // Jcc opposite, 7; MOV EAX, target; JMP EAX

            // Map to opposite condition
            uint8_t opposite = insn->bytes[0] ^ 0x01;  // Flip lowest bit
            uint8_t skip[] = {opposite, 0x07};  // Skip over the absolute jump
            buffer_append(new_shellcode, skip, 2);

            generate_mov_eax_imm(new_shellcode, target_node->new_offset);
            uint8_t jmp_eax[] = {0xFF, 0xE0};
            buffer_append(new_shellcode, jmp_eax, 2);
        }
        return;
    }

    // Debug: Check what we're processing
    if (strstr(insn->mnemonic, "jne") || strstr(insn->mnemonic, "je")) {
        fprintf(stderr, "[DEBUG] Processing conditional jump: %s, bytes[0]=0x%02x, bytes[1]=0x%02x, size=%d\n",
                insn->mnemonic, insn->bytes[0], insn->size > 1 ? insn->bytes[1] : 0, insn->size);
    }

    if (insn->bytes[0] == 0x0F && (insn->bytes[1] >= 0x80 && insn->bytes[1] <= 0x8F)) {
        // Near conditional jump (0F 8x)
        uint8_t patched[6];
        patched[0] = 0x0F;
        patched[1] = insn->bytes[1];
        memcpy(&patched[2], &new_rel, 4);

        int has_null = 0;
        for (int i = 0; i < 6; i++) {
            if (patched[i] == 0x00) {
                has_null = 1;
                break;
            }
        }

        fprintf(stderr, "[DEBUG] Near cond jump: %s, new_rel=%d, has_null=%d, target_offset=%zu\n",
                insn->mnemonic, (int32_t)new_rel, has_null, target_node->new_offset);

        if (has_null) {
            // Convert using opposite condition trick
            // Use short conditional jump to skip (avoids null bytes in displacement)
            // Calculate skip size: generate_mov_eax_imm size + JMP EAX (2 bytes)
            size_t mov_size = get_mov_eax_imm_size(target_node->new_offset);
            size_t skip_size = mov_size + 2;

            fprintf(stderr, "[DEBUG] Transformation: mov_size=%zu, skip_size=%zu\n", mov_size, skip_size);

            // Check if skip_size fits in signed byte (range -128 to +127)
            if (skip_size > 127) {
                fprintf(stderr, "[WARNING] skip_size=%zu too large for short jump! Falling back to original.\n", skip_size);
                buffer_append(new_shellcode, patched, 6);
                return;
            }

            // Convert near conditional to short conditional (0F 8x -> 7x)
            uint8_t opposite_short = 0x70 + ((insn->bytes[1] ^ 0x01) & 0x0F);
            uint8_t skip[] = {opposite_short, (uint8_t)skip_size};
            buffer_append(new_shellcode, skip, 2);

            generate_mov_eax_imm(new_shellcode, target_node->new_offset);
            uint8_t jmp_eax[] = {0xFF, 0xE0};
            buffer_append(new_shellcode, jmp_eax, 2);
        } else {
            buffer_append(new_shellcode, patched, 6);
        }
        return;
    }

    // Unknown jump type - conservative fallback
    buffer_append(new_shellcode, insn->bytes, insn->size);
}

struct buffer remove_null_bytes(const uint8_t *shellcode, size_t size) {
    csh handle;
    cs_insn *insn_array;
    size_t count;
    struct buffer new_shellcode;
    buffer_init(&new_shellcode);

    fprintf(stderr, "[remove_null_bytes] Called with shellcode=%p, size=%zu\n", (void*)shellcode, size);
    if (!shellcode) {
        fprintf(stderr, "[ERROR] shellcode pointer is NULL!\n");
        return new_shellcode;
    }
    fprintf(stderr, "[FIRST 16 BYTES] %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
            shellcode[0], shellcode[1], shellcode[2], shellcode[3],
            shellcode[4], shellcode[5], shellcode[6], shellcode[7],
            shellcode[8], shellcode[9], shellcode[10], shellcode[11],
            shellcode[12], shellcode[13], shellcode[14], shellcode[15]);

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
        fprintf(stderr, "[ERROR] cs_open failed!\n");
        return new_shellcode;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle, shellcode, size, 0, 0, &insn_array);
    fprintf(stderr, "[DISASM] Disassembled %zu instructions from %zu bytes\n", count, size);
    if (count == 0 || insn_array == NULL) {
        fprintf(stderr, "[ERROR] cs_disasm returned 0 instructions or NULL array!\n");
        fprintf(stderr, "[ERROR] Input file does not appear to contain valid x86 shellcode.\n");
        cs_close(&handle);
        return new_shellcode;
    }

    // Create linked list of instructions
    struct instruction_node *head = NULL;
    struct instruction_node *current = NULL;

    for (size_t i = 0; i < count; i++) {
        struct instruction_node *node = malloc(sizeof(struct instruction_node));
        node->insn = &insn_array[i];
        node->offset = insn_array[i].address;
        node->new_size = 0;
        node->new_offset = 0;
        node->next = NULL;

        if (head == NULL) {
            head = node;
            current = node;
        } else {
            current->next = node;
            current = node;
        }
    }

    // First pass: calculate new sizes for each instruction
    current = head;
    while (current != NULL) {
        int has_null = 0;
        for (int j = 0; j < current->insn->size; j++) {
            if (current->insn->bytes[j] == 0x00) {
                has_null = 1;
                break;
            }
        }

        // Special handling for relative jumps - they're transformed in process_relative_jump()
        // not via strategies, so we need to estimate their size here
        if (is_relative_jump(current->insn)) {
            if (has_null || current->insn->size > 2) {
                // Relative jump might need transformation
                // Conservative estimate: opposite short jump (2) + MOV EAX (5-20) + JMP EAX (2)
                // Use worst-case: 2 + 20 + 2 = 24 bytes
                current->new_size = 24;
            } else {
                // Short jump without nulls, likely stays same size
                current->new_size = current->insn->size;
            }
        } else if (has_null) {
            // Use strategy pattern to get new size
            int strategy_count;
            strategy_t** strategies = get_strategies_for_instruction(current->insn, &strategy_count);

            if (strategy_count > 0) {
                current->new_size = strategies[0]->get_size(current->insn);
            } else {
                // Fallback to original size if no strategy available
                current->new_size = current->insn->size;
            }
        } else {
            current->new_size = current->insn->size;
        }
        current = current->next;
    }

    // Second pass: calculate new offsets
    current = head;
    size_t running_offset = 0;
    while (current != NULL) {
        current->new_offset = running_offset;
        running_offset += current->new_size;
        current = current->next;
    }

    // Third pass: generate new shellcode
    current = head;
    int insn_count = 0;
    while (current != NULL) {
        insn_count++;
        int has_null = 0;
        for (int j = 0; j < current->insn->size; j++) {
            if (current->insn->bytes[j] == 0x00) {
                has_null = 1;
                break;
            }
        }
        fprintf(stderr, "[GEN] Insn #%d: %s %s (has_null=%d, size=%d)\n",
                insn_count, current->insn->mnemonic, current->insn->op_str,
                has_null, current->insn->size);

        if (is_relative_jump(current->insn)) {
            process_relative_jump(&new_shellcode, current->insn, current, head);
        } else if (has_null) {
            // Use strategy pattern if it has nulls
            int strategy_count;
            size_t before_gen = new_shellcode.size;
            strategy_t** strategies = get_strategies_for_instruction(current->insn, &strategy_count);

            if (strategy_count > 0) {
                // Use the first (highest priority) strategy to generate code
                fprintf(stderr, "[TRACE] Using strategy '%s' for: %s %s\n",
                       strategies[0]->name, current->insn->mnemonic, current->insn->op_str);
                strategies[0]->generate(&new_shellcode, current->insn);

                // Verify no nulls introduced
                for (size_t i = before_gen; i < new_shellcode.size; i++) {
                    if (new_shellcode.data[i] == 0x00) {
                        fprintf(stderr, "ERROR: Strategy '%s' introduced null at offset %zu\n",
                               strategies[0]->name, i - before_gen);
                    }
                }
            } else {
                // If no strategy can handle it, use comprehensive fallback
                fallback_general_instruction(&new_shellcode, current->insn);
            }
        } else {
            // No nulls, output original instruction
            buffer_append(&new_shellcode, current->insn->bytes, current->insn->size);
        }
        current = current->next;
    }

    // Final verification - DO THIS BEFORE CLEANUP
    DEBUG_LOG("Final verification pass", 0);
    int null_count = 0;
    for (size_t i = 0; i < new_shellcode.size; i++) {
        if (new_shellcode.data[i] == 0x00) {
            null_count++;
            fprintf(stderr, "WARNING: Null byte at offset %zu\n", i);
            
            // Try to identify which original instruction caused this null
            struct instruction_node *debug_node = head;
            size_t current_offset = 0;
            while (debug_node != NULL) {
                if (current_offset <= i && i < current_offset + debug_node->new_size) {
                    fprintf(stderr, "  Caused by instruction at original offset 0x%lx: %s %s\n",
                           debug_node->offset,
                           debug_node->insn->mnemonic,
                           debug_node->insn->op_str);
                    break;
                }
                current_offset += debug_node->new_size;
                debug_node = debug_node->next;
            }
        }
    }

    if (null_count > 0) {
        fprintf(stderr, "\nERROR: Final shellcode contains %d null bytes\n", null_count);
        fprintf(stderr, "Recompile with -DDEBUG for details\n");
    } else {
        DEBUG_LOG("SUCCESS: No null bytes in final shellcode", 0);
    }

    // Clean up only AFTER verification
    free_instruction_node_list(head);
    cs_free(insn_array, count);

    cs_close(&handle);
    return new_shellcode;
}

int verify_null_elimination(struct buffer *processed) {
    // Check if processed buffer still contains null bytes
    for (size_t i = 0; i < processed->size; i++) {
        if (processed->data[i] == 0x00) {
            return 0; // Still has nulls
        }
    }
    return 1; // Success - no nulls
}

void fallback_mov_reg_imm(struct buffer *b, cs_insn *insn) {
    // MOV reg, imm32 where imm32 contains null bytes
    // Use EAX as temporary: MOV EAX, imm32 (null-free version); MOV reg, EAX
    generate_mov_eax_imm(b, (uint32_t)insn->detail->x86.operands[1].imm);

    // Now move from EAX to the destination register
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;
    uint8_t mov_reg_eax[] = {0x89, 0xC0};
    mov_reg_eax[1] = mov_reg_eax[1] + (get_reg_index(dst_reg) << 3) + get_reg_index(X86_REG_EAX);
    buffer_append(b, mov_reg_eax, 2);
}

void fallback_arithmetic_reg_imm(struct buffer *b, cs_insn *insn) {
    // For arithmetic operations like ADD reg, imm32 where imm32 contains nulls
    uint8_t dst_reg = insn->detail->x86.operands[0].reg;

    // If the destination register is EAX, we need to use a different temporary register
    if (dst_reg == X86_REG_EAX) {
        // Use ECX as temporary instead of EAX
        // PUSH ECX (save ECX)
        uint8_t push_ecx[] = {0x51};  // PUSH ECX
        buffer_append(b, push_ecx, 1);

        // MOV ECX, imm32 (null-free version)
        generate_mov_eax_imm(b, (uint32_t)insn->detail->x86.operands[1].imm);

        // Perform the operation: op EAX, ECX
        uint8_t op_code;
        switch(insn->id) {
            case X86_INS_ADD: op_code = 0x01; break;
            case X86_INS_SUB: op_code = 0x29; break;
            case X86_INS_AND: op_code = 0x21; break;
            case X86_INS_OR:  op_code = 0x09; break;
            case X86_INS_XOR: op_code = 0x31; break;
            case X86_INS_CMP: op_code = 0x39; break;
            default: op_code = 0x01; break;  // default to ADD
        }

        uint8_t code[] = {op_code, 0xC0};
        code[1] = code[1] + (get_reg_index(X86_REG_EAX) << 3) + get_reg_index(X86_REG_ECX);
        buffer_append(b, code, 2);

        // POP ECX (restore ECX)
        uint8_t pop_ecx[] = {0x59};  // POP ECX
        buffer_append(b, pop_ecx, 1);
    } else {
        // PUSH EAX (save EAX)
        uint8_t push_eax[] = {0x50};  // PUSH EAX
        buffer_append(b, push_eax, 1);

        // MOV EAX, imm32 (null-free version)
        generate_mov_eax_imm(b, (uint32_t)insn->detail->x86.operands[1].imm);

        // Perform the operation: op reg, EAX
        uint8_t op_code;
        switch(insn->id) {
            case X86_INS_ADD: op_code = 0x01; break;
            case X86_INS_SUB: op_code = 0x29; break;
            case X86_INS_AND: op_code = 0x21; break;
            case X86_INS_OR:  op_code = 0x09; break;
            case X86_INS_XOR: op_code = 0x31; break;
            case X86_INS_CMP: op_code = 0x39; break;
            default: op_code = 0x01; break;  // default to ADD
        }

        uint8_t code[] = {op_code, 0xC0};
        code[1] = code[1] + (get_reg_index(dst_reg) << 3) + get_reg_index(X86_REG_EAX);
        buffer_append(b, code, 2);

        // POP EAX (restore EAX)
        uint8_t pop_eax[] = {0x58};  // POP EAX
        buffer_append(b, pop_eax, 1);
    }
}

void fallback_general_instruction(struct buffer *b, cs_insn *insn) {
    // A general fallback that handles various instruction types containing null bytes
    if (insn->id == X86_INS_MOV) {
        fallback_mov_reg_imm(b, insn);
    } else if (insn->id == X86_INS_ADD || insn->id == X86_INS_SUB ||
               insn->id == X86_INS_AND || insn->id == X86_INS_OR ||
               insn->id == X86_INS_XOR || insn->id == X86_INS_CMP) {
        // Check if this is a memory operation that might have null bytes in ModR/M
        int mem_operand_with_nulls = 0;
        for (int i = 0; i < insn->detail->x86.op_count; i++) {
            if (insn->detail->x86.operands[i].type == X86_OP_MEM) {
                mem_operand_with_nulls = 1;
                break;
            }
        }

        if (mem_operand_with_nulls) {
            // Handle memory operations with potential null bytes in ModR/M
            fallback_memory_operation(b, insn);
        } else {
            fallback_arithmetic_reg_imm(b, insn);
        }
    } else if (insn->id == X86_INS_NOP) {
        // Handle NOP instructions with null bytes - just do nothing (no-op)
        // NOP is just a placeholder instruction that does nothing
        // For memory-based NOPs like "nop dword ptr [eax]", do nothing
        return;
    } else if (insn->id == X86_INS_CALL &&
               insn->detail->x86.op_count == 1 &&
               insn->detail->x86.operands[0].type == X86_OP_MEM) {
        // Handle CALL [mem] with null bytes in displacement
        uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;
        generate_mov_eax_imm(b, addr);
        uint8_t call_eax[] = {0xFF, 0xD0}; // CALL EAX
        buffer_append(b, call_eax, 2);
    } else if (insn->id == X86_INS_JMP &&
               insn->detail->x86.op_count == 1 &&
               insn->detail->x86.operands[0].type == X86_OP_MEM) {
        // Handle JMP [mem] with null bytes in displacement
        uint32_t addr = (uint32_t)insn->detail->x86.operands[0].mem.disp;
        generate_mov_eax_imm(b, addr);
        uint8_t jmp_eax[] = {0xFF, 0xE0}; // JMP EAX
        buffer_append(b, jmp_eax, 2);
    } else if (insn->id == X86_INS_PUSH &&
               insn->detail->x86.op_count == 1 &&
               insn->detail->x86.operands[0].type == X86_OP_IMM) {
        // Handle PUSH imm32 with null bytes in the immediate value
        uint32_t imm = (uint32_t)insn->detail->x86.operands[0].imm;

        // Instead of PUSH imm32, use: MOV EAX, imm32 (null-free) + PUSH EAX
        generate_mov_eax_imm(b, imm);
        uint8_t push_eax[] = {0x50}; // PUSH EAX
        buffer_append(b, push_eax, 1);
    } else {
        // For other instruction types with null bytes, we need to build a more
        // comprehensive fallback system. For now, try to identify memory operands
        // with displacements that contain null bytes and handle them generically.

        // Check if this is a memory operation with a displacement containing nulls
        int handled = 0;
        for (int i = 0; i < insn->detail->x86.op_count; i++) {
            if (insn->detail->x86.operands[i].type == X86_OP_MEM &&
                insn->detail->x86.operands[i].mem.base == X86_REG_INVALID &&
                insn->detail->x86.operands[i].mem.index == X86_REG_INVALID &&
                insn->detail->x86.operands[i].mem.disp != 0) {

                uint32_t disp = (uint32_t)insn->detail->x86.operands[i].mem.disp;

                // Check if displacement has null bytes
                int has_null_in_disp = 0;
                for (int j = 0; j < 4; j++) {
                    if (((disp >> (j * 8)) & 0xFF) == 0) {
                        has_null_in_disp = 1;
                        break;
                    }
                }

                if (has_null_in_disp) {
                    // Convert the instruction to use a register-based approach
                    // First, load the displacement to EAX
                    generate_mov_eax_imm(b, disp);

                    // Then reconstruct the instruction using [EAX] addressing
                    // For now, we'll handle based on instruction type
                    if (insn->id == X86_INS_MOV && i == 0) { // Destination is memory
                        // Handle MOV [disp32], reg
                        uint8_t src_reg = insn->detail->x86.operands[1].reg;
                        uint8_t reg_index = get_reg_index(src_reg);
                        // Use SIB byte to avoid null when source register is EAX
                        if (reg_index == 0) {
                            uint8_t code[] = {0x89, 0x04, 0x20}; // MOV [EAX], EAX using SIB: [EAX] with SIB byte 0x20
                            // SIB: scale=00 (1x), index=100 (ESP/no index), base=000 (EAX) = [EAX]
                            buffer_append(b, code, 3);
                        } else {
                            uint8_t code[] = {0x89, 0x00}; // MOV [EAX], reg format
                            code[1] = (reg_index << 3) | 0;  // Encode source register
                            buffer_append(b, code, 2);
                        }
                        handled = 1;
                    } else if (insn->id == X86_INS_MOV && i == 1) { // Source is memory
                        // Handle MOV reg, [disp32]
                        uint8_t dst_reg = insn->detail->x86.operands[0].reg;
                        uint8_t reg_index = get_reg_index(dst_reg);
                        // Use SIB byte to avoid null when destination register is EAX
                        if (reg_index == 0) {
                            uint8_t code[] = {0x8B, 0x04, 0x20}; // MOV EAX, [EAX] using SIB: [EAX] with SIB byte 0x20
                            // SIB: scale=00 (1x), index=100 (ESP/no index), base=000 (EAX) = [EAX]
                            buffer_append(b, code, 3);
                        } else {
                            uint8_t code[] = {0x8B, 0x00}; // MOV reg, [EAX] format
                            code[1] = (reg_index << 3) | 0;  // Encode destination register
                            buffer_append(b, code, 2);
                        }
                        handled = 1;
                    } else if (insn->id == X86_INS_NOP) {
                        // Handle memory-based NOPs - just return, no operation needed
                        handled = 1;
                        return;
                    } else if (insn->id == X86_INS_ADD || insn->id == X86_INS_SUB || 
                               insn->id == X86_INS_AND || insn->id == X86_INS_OR || 
                               insn->id == X86_INS_XOR || insn->id == X86_INS_CMP) {
                        // Handle arithmetic operations on memory with null displacements
                        uint8_t reg = insn->detail->x86.operands[1].reg;
                        uint8_t reg_index = get_reg_index(reg);
                        uint8_t opcode;
                        
                        switch(insn->id) {
                            case X86_INS_ADD: opcode = 0x01; break; // 32-bit ADD
                            case X86_INS_SUB: opcode = 0x29; break; // 32-bit SUB
                            case X86_INS_AND: opcode = 0x21; break; // 32-bit AND
                            case X86_INS_OR:  opcode = 0x09; break; // 32-bit OR
                            case X86_INS_XOR: opcode = 0x31; break; // 32-bit XOR
                            case X86_INS_CMP: opcode = 0x39; break; // 32-bit CMP
                            default: opcode = 0x01; break; // Default to ADD
                        }
                        
                        // Use SIB byte to avoid null: [EAX] using SIB byte format
                        uint8_t code[] = {opcode, 0x00, 0x20}; // op [EAX], reg using SIB
                        code[1] = 0x04 | (reg_index << 3); // ModR/M: reg=reg_index, r/m=100 (SIB follows)
                        code[2] = 0x20; // SIB: scale=00 (1x), index=100 (no index), base=000 (EAX)
                        buffer_append(b, code, 3);
                        handled = 1;
                    }
                    // Add more cases as needed for other instruction types
                    break;
                }
            }
        }

        if (!handled) {
            // If we still can't handle it, try to process each operand that might contain nulls
            // For now, we'll warn and just copy the original (this should be rare)
            fprintf(stderr, "WARNING: Fallback could not handle: %s %s\n",
                   insn->mnemonic, insn->op_str);
            fprintf(stderr, "  This instruction may still contain null bytes\n");
            buffer_append(b, insn->bytes, insn->size);
        }
    }
}

// Fallback function to handle memory operations that may have null bytes in ModR/M
void fallback_memory_operation(struct buffer *b, cs_insn *insn) {
    // Handle memory operations like ADD [mem], reg where [mem] has null bytes in ModR/M
    if (insn->id == X86_INS_ADD || insn->id == X86_INS_SUB ||
        insn->id == X86_INS_AND || insn->id == X86_INS_OR ||
        insn->id == X86_INS_XOR || insn->id == X86_INS_CMP) {

        // For operations like: ADD [mem_location], reg
        // If mem has direct register access (like [EAX]), it creates null bytes
        // We transform to: MOV temp_reg, [mem_location] -> op temp_reg, src_reg -> MOV [mem_location], temp_reg

        // Use ECX as temporary register (avoid conflicts with EAX usage)
        uint8_t temp_reg = X86_REG_ECX;
        uint8_t dest_mem_reg = X86_REG_INVALID;
        uint8_t src_reg = X86_REG_INVALID;

        // Identify memory operand and register operand
        for (int i = 0; i < insn->detail->x86.op_count; i++) {
            if (insn->detail->x86.operands[i].type == X86_OP_MEM) {
                dest_mem_reg = insn->detail->x86.operands[i].mem.base;
            } else if (insn->detail->x86.operands[i].type == X86_OP_REG) {
                src_reg = insn->detail->x86.operands[i].reg;
            }
        }

        if (dest_mem_reg != X86_REG_INVALID && src_reg != X86_REG_INVALID) {
            // If temp register conflicts with used registers, use different approach
            if (temp_reg == dest_mem_reg || temp_reg == src_reg) {
                temp_reg = X86_REG_EDX;  // Use EDX instead
                if (temp_reg == dest_mem_reg || temp_reg == src_reg) {
                    temp_reg = X86_REG_EBX;  // Use EBX as last resort
                }
            }

            uint8_t temp_reg_idx = get_reg_index(temp_reg);
            uint8_t src_reg_idx = get_reg_index(src_reg);
            uint8_t dest_mem_idx = get_reg_index(dest_mem_reg);

            // PUSH temp_reg (save register state)
            uint8_t push_temp[] = {0x50 + temp_reg_idx};
            buffer_append(b, push_temp, 1);

            // MOV temp_reg, [mem_location] - might need SIB addressing to avoid nulls
            if (dest_mem_reg == X86_REG_EAX) {
                // Use SIB byte to avoid null: MOV temp_reg, [EAX] = 0x8B 0x04 0x20 + temp_reg_idx
                uint8_t mov_temp_eax[] = {0x8B, 0x04, 0x20 + (temp_reg_idx << 3)}; // SIB: scale=0, index=ESP(100), base=EAX(000)
                buffer_append(b, mov_temp_eax, 3);
            } else {
                uint8_t mov_temp_mem[] = {0x8B, 0x00 + (temp_reg_idx << 3) + dest_mem_idx};
                buffer_append(b, mov_temp_mem, 2);
            }

            // Perform the operation: op temp_reg, src_reg
            uint8_t op_code;
            switch(insn->id) {
                case X86_INS_ADD: op_code = 0x01; break;
                case X86_INS_SUB: op_code = 0x29; break;
                case X86_INS_AND: op_code = 0x21; break;
                case X86_INS_OR:  op_code = 0x09; break;
                case X86_INS_XOR: op_code = 0x31; break;
                case X86_INS_CMP: op_code = 0x39; break;
                default: op_code = 0x01; break;  // default to ADD
            }

            uint8_t op_instr[] = {op_code, 0xC0};
            op_instr[1] = op_instr[1] + (temp_reg_idx << 3) + src_reg_idx;
            buffer_append(b, op_instr, 2);

            // MOV [mem_location], temp_reg - might need SIB addressing to avoid nulls
            if (dest_mem_reg == X86_REG_EAX) {
                // Use SIB byte to avoid null: MOV [EAX], temp_reg = 0x89 0x04 0x20 + temp_reg_idx
                uint8_t mov_eax_temp[] = {0x89, 0x04, 0x20 + (temp_reg_idx << 3)}; // SIB: scale=0, index=ESP(100), base=EAX(000)
                buffer_append(b, mov_eax_temp, 3);
            } else {
                uint8_t mov_mem_temp[] = {0x89, 0x00 + (temp_reg_idx << 3) + dest_mem_idx};
                buffer_append(b, mov_mem_temp, 2);
            }

            // POP temp_reg (restore register state)
            uint8_t pop_temp[] = {0x58 + temp_reg_idx};
            buffer_append(b, pop_temp, 1);
        }
    } else {
        // For other memory operations, just copy original (this shouldn't happen)
        buffer_append(b, insn->bytes, insn->size);
    }
}

struct buffer adaptive_processing(const uint8_t *input, size_t size) {
    struct buffer intermediate = remove_null_bytes(input, size);

    // Verification pass: check if any nulls remain
    if (!verify_null_elimination(&intermediate)) {
        DEBUG_LOG("WARNING: Null byte found in processed shellcode", 0);
        // Re-run remove_null_bytes with extended debugging to identify problematic instructions
        csh handle;
        cs_insn *insn_array;
        size_t count;
        
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK) {
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
            count = cs_disasm(handle, input, size, 0, 0, &insn_array);
            
            if (count > 0) {
                // Analyze each instruction to identify which one caused nulls
                struct instruction_node *head = NULL;
                struct instruction_node *current = NULL;
                
                for (size_t i = 0; i < count; i++) {
                    struct instruction_node *node = malloc(sizeof(struct instruction_node));
                    node->insn = &insn_array[i];
                    node->offset = insn_array[i].address;
                    node->new_size = 0;
                    node->new_offset = 0;
                    node->next = NULL;

                    if (head == NULL) {
                        head = node;
                        current = node;
                    } else {
                        current->next = node;
                        current = node;
                    }
                }
                
                // Check for nulls in the produced shellcode against original instructions
                size_t current_offset = 0;
                current = head;
                while (current != NULL) {
                    int found_null_in_range = 0;
                    size_t range_end = current_offset + current->new_size;
                    
                    // Check if any nulls exist in this instruction's range
                    for (size_t i = current_offset; i < range_end && i < intermediate.size; i++) {
                        if (intermediate.data[i] == 0x00) {
                            found_null_in_range = 1;
                            DEBUG_LOG("Null byte at output offset %zu caused by instruction at original offset 0x%lx: %s %s",
                                     i, current->offset, current->insn->mnemonic, current->insn->op_str);
                            break;
                        }
                    }
                    
                    if (found_null_in_range) {
                        // Check if this was handled by a specific strategy that failed
                        int has_null = 0;
                        for (int j = 0; j < current->insn->size; j++) {
                            if (current->insn->bytes[j] == 0x00) {
                                has_null = 1;
                                break;
                            }
                        }
                        
                        if (has_null) {
                            DEBUG_LOG("  Original instruction had null bytes: ", 0);
                            for (int j = 0; j < current->insn->size; j++) {
                                DEBUG_LOG("    Byte %d: 0x%02x", j, current->insn->bytes[j]);
                            }
                        }
                        
                        // Find the strategy that was applied
                        int temp_strategy_count;
                        strategy_t** strategies = get_strategies_for_instruction(current->insn, &temp_strategy_count);
                        (void)strategies; // Suppress unused variable warning when not in debug mode
                        if (temp_strategy_count > 0) {
                            DEBUG_LOG("  Applied strategy: %s", strategies[0]->name);
                        } else {
                            DEBUG_LOG("  No strategy applied, used fallback", 0);
                        }
                    }
                    
                    current_offset += current->new_size;
                    current = current->next;
                }
                
                // Clean up the temporary linked list
                current = head;
                while (current != NULL) {
                    struct instruction_node *next = current->next;
                    free(current);
                    current = next;
                }
            }
            
            cs_free(insn_array, count);
            cs_close(&handle);
        }
    }

    return intermediate;
}
// ============================================================================
// BIPHASIC ARCHITECTURE IMPLEMENTATION
// Pass 1: Obfuscation & Complexification
// Pass 2: Null-Byte Elimination
// ============================================================================

#include "obfuscation_strategy_registry.h"

/*
 * Pass 1: Apply Obfuscation Transformations
 * 
 * Transforms simple instructions into complex equivalents to increase
 * analytical difficulty. This pass CAN introduce null bytes - Pass 2
 * will clean them up.
 */
struct buffer apply_obfuscation(const uint8_t *shellcode, size_t size) {
    csh handle;
    cs_insn *insn_array;
    size_t count;
    struct buffer obfuscated;
    buffer_init(&obfuscated);

    fprintf(stderr, "\n=== PASS 1: OBFUSCATION ===\n");
    fprintf(stderr, "[OBFUSC] Input size: %zu bytes\n", size);

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
        fprintf(stderr, "[ERROR] Obfuscation: cs_open failed!\n");
        return obfuscated;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    count = cs_disasm(handle, shellcode, size, 0, 0, &insn_array);

    fprintf(stderr, "[OBFUSC] Disassembled %zu instructions\n", count);

    if (count == 0) {
        cs_close(&handle);
        // If disassembly fails, return original
        buffer_append(&obfuscated, shellcode, size);
        return obfuscated;
    }

    // Process each instruction through obfuscation strategies
    for (size_t i = 0; i < count; i++) {
        cs_insn *insn = &insn_array[i];
        
        // Try to find an obfuscation strategy
        strategy_t *strategy = find_obfuscation_strategy(insn);

        if (strategy != NULL) {
            // Apply obfuscation
            fprintf(stderr, "[OBFUSC] %s %s → %s\n", 
                    insn->mnemonic, insn->op_str, strategy->name);
            strategy->generate(&obfuscated, insn);
        } else {
            // No obfuscation - copy original
            buffer_append(&obfuscated, insn->bytes, insn->size);
        }
    }

    cs_free(insn_array, count);
    cs_close(&handle);

    fprintf(stderr, "[OBFUSC] Output size: %zu bytes (%.1f%% expansion)\n",
            obfuscated.size, ((float)obfuscated.size / size - 1.0) * 100.0);
    fprintf(stderr, "=== PASS 1 COMPLETE ===\n\n");

    return obfuscated;
}

/*
 * Biphasic Processing Pipeline
 * 
 * Combines Pass 1 (Obfuscation) and Pass 2 (Null-Elimination) for
 * maximum evasion and null-byte elimination.
 */
struct buffer biphasic_process(const uint8_t *shellcode, size_t size) {
    fprintf(stderr, "\n");
    fprintf(stderr, "╔════════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║  BYVALVER BIPHASIC PROCESSING PIPELINE                ║\n");
    fprintf(stderr, "╚════════════════════════════════════════════════════════╝\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Original shellcode: %zu bytes\n", size);

    // Pass 1: Obfuscation & Complexification
    struct buffer pass1_output = apply_obfuscation(shellcode, size);
    
    if (pass1_output.size == 0) {
        fprintf(stderr, "[ERROR] Pass 1 failed, aborting biphasic processing\n");
        return pass1_output;
    }

    // Pass 2: Null-Byte Elimination
    fprintf(stderr, "=== PASS 2: NULL-BYTE ELIMINATION ===\n");
    struct buffer pass2_output = remove_null_bytes(pass1_output.data, pass1_output.size);
    
    // Free Pass 1 intermediate buffer
    buffer_free(&pass1_output);

    fprintf(stderr, "=== PASS 2 COMPLETE ===\n\n");
    fprintf(stderr, "╔════════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║  BIPHASIC PROCESSING COMPLETE                          ║\n");
    fprintf(stderr, "╚════════════════════════════════════════════════════════╝\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Input:  %zu bytes\n", size);
    fprintf(stderr, "Output: %zu bytes (%.1f%% change)\n",
            pass2_output.size, ((float)pass2_output.size / size - 1.0) * 100.0);

    return pass2_output;
}
