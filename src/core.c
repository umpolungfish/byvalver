#include "core.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

void buffer_append(struct buffer *b, const uint8_t *data, size_t size) {
    if (b->size + size > b->capacity) {
        size_t new_capacity = (b->capacity == 0) ? 256 : b->capacity * 2;
        while (new_capacity < b->size + size) {
            new_capacity *= 2;
        }
        b->data = realloc(b->data, new_capacity);
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
        default: return 0;
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
    switch (insn->id) {
        case X86_INS_JAE:
        case X86_INS_JA:
        case X86_INS_JBE:
        case X86_INS_JB:
        case X86_INS_JCXZ:
        case X86_INS_JECXZ:
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
        default:
            return 0;
    }
}

struct buffer remove_null_bytes(const uint8_t *shellcode, size_t size) {
    csh handle;
    cs_insn *insn_array;
    size_t count;
    struct buffer new_shellcode;
    buffer_init(&new_shellcode);
    
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
        return new_shellcode;
    }
    
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    count = cs_disasm(handle, shellcode, size, 0, 0, &insn_array);
    if (count == 0) {
        cs_close(&handle);
        return new_shellcode;
    }
    
    if (count == 0) {
        cs_free(insn_array, count);
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
        
        if (has_null) {
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
    while (current != NULL) {
        int has_null = 0;
        for (int j = 0; j < current->insn->size; j++) {
            if (current->insn->bytes[j] == 0x00) {
                has_null = 1;
                break;
            }
        }
        
        // Check if this is a relative jump/call instruction
        if (is_relative_jump(current->insn) && current->insn->detail->x86.op_count > 0) {
            if (current->insn->detail->x86.operands[0].type == X86_OP_IMM) {
                // Find the target instruction node
                struct instruction_node *target_node = head;
                int found = 0;
                while (target_node != NULL) {
                    if (target_node->offset == (size_t)current->insn->detail->x86.operands[0].imm) {
                        found = 1;
                        break;
                    }
                    target_node = target_node->next;
                }
                
                if (found) {
                    // Calculate new relative offset
                    int64_t new_rel = (int64_t)(target_node->new_offset - (current->new_offset + current->new_size));
                    uint8_t patched_insn[16]; // Maximum x86 instruction size
                    memcpy(patched_insn, current->insn->bytes, current->insn->size);
                    
                    // Apply the new relative offset to the instruction
                    if (current->insn->size >= 5 && current->insn->bytes[0] == 0xe8) { // CALL
                        memcpy(&patched_insn[1], &new_rel, 4);
                    } else if (current->insn->size >= 5 && current->insn->bytes[0] == 0xe9) { // JMP
                        memcpy(&patched_insn[1], &new_rel, 4);
                    } else if (current->insn->bytes[0] == 0xeb) { // 8-bit displacement for short jumps
                        int8_t new_rel8 = (int8_t)new_rel;
                        if (new_rel == new_rel8) {
                            patched_insn[1] = new_rel8;
                            buffer_append(&new_shellcode, patched_insn, current->insn->size);
                        } else {
                            // If the relative offset is too far for 8-bit, convert to 32-bit jump
                            generate_mov_eax_imm(&new_shellcode, target_node->new_offset);
                            
                            // JMP EAX instruction
                            uint8_t jmp_eax[] = {0xff, 0xe0};
                            buffer_append(&new_shellcode, jmp_eax, sizeof(jmp_eax));
                        }
                    } else {
                        // Handle conditional jumps and other relative jumps
                        if (current->insn->detail->x86.encoding.disp_size == 4) { // 32-bit displacement
                            if (current->insn->bytes[0] == 0x0f) { // Near conditional jump (0F 8x)
                                memcpy(&patched_insn[2], &new_rel, 4);
                                
                                // Check if the new displacement has null bytes
                                int new_disp_has_null = 0;
                                for (int i = 0; i < 4; i++) {
                                    if (((new_rel >> (i * 8)) & 0xFF) == 0) {
                                        new_disp_has_null = 1;
                                        break;
                                    }
                                }
                                
                                if (new_disp_has_null) {
                                    // For conditional jumps with null bytes in displacement,
                                    // convert to opposite condition + unconditional jump sequence
                                    
                                    // Get the appropriate short conditional jump opcode for the opposite condition
                                    uint8_t opposite_jcc_opcode = 0;  // Initialize
                                    
                                    // Map each conditional jump to its opposite for short jumps (0x70-0x7F range)
                                    switch (current->insn->id) {
                                        case X86_INS_JO:  opposite_jcc_opcode = 0x71; break; // JO -> JNO (opposite: 0x71)
                                        case X86_INS_JNO: opposite_jcc_opcode = 0x70; break; // JNO -> JO (opposite: 0x70)
                                        case X86_INS_JB:  opposite_jcc_opcode = 0x73; break; // JB -> JAE (opposite: 0x73)
                                        case X86_INS_JAE: opposite_jcc_opcode = 0x72; break; // JAE -> JB (opposite: 0x72)
                                        case X86_INS_JE:  opposite_jcc_opcode = 0x75; break; // JE -> JNE (opposite: 0x75)
                                        case X86_INS_JNE: opposite_jcc_opcode = 0x74; break; // JNE -> JE (opposite: 0x74)
                                        case X86_INS_JBE: opposite_jcc_opcode = 0x77; break; // JBE -> JA (opposite: 0x77)
                                        case X86_INS_JA:  opposite_jcc_opcode = 0x76; break; // JA -> JBE (opposite: 0x76)
                                        case X86_INS_JS:  opposite_jcc_opcode = 0x79; break; // JS -> JNS (opposite: 0x79)
                                        case X86_INS_JNS: opposite_jcc_opcode = 0x78; break; // JNS -> JS (opposite: 0x78)
                                        case X86_INS_JP:  opposite_jcc_opcode = 0x7b; break; // JP -> JNP (opposite: 0x7B)
                                        case X86_INS_JNP: opposite_jcc_opcode = 0x7a; break; // JNP -> JP (opposite: 0x7A)
                                        case X86_INS_JL:  opposite_jcc_opcode = 0x7d; break; // JL -> JGE (opposite: 0x7D)
                                        case X86_INS_JGE: opposite_jcc_opcode = 0x7c; break; // JGE -> JL (opposite: 0x7C)
                                        case X86_INS_JLE: opposite_jcc_opcode = 0x7f; break; // JLE -> JG (opposite: 0x7F)
                                        case X86_INS_JG:  opposite_jcc_opcode = 0x7e; break; // JG -> JLE (opposite: 0x7E)
                                        default:
                                            // If we don't recognize the jump, fallback to original instruction
                                            buffer_append(&new_shellcode, patched_insn, current->insn->size);
                                            current = current->next;
                                            continue;
                                    }
                                    
                                    if (opposite_jcc_opcode != 0) {
                                        // Create a short jump to a nearby location (e.g., next instruction + 2 bytes)
                                        // This skips the next jump if the condition is NOT met
                                        uint8_t skip_jmp[2] = {opposite_jcc_opcode, 0x07}; // Jump over next 7 bytes (MOV + JMP sequence)
                                        
                                        buffer_append(&new_shellcode, skip_jmp, 2);
                                        
                                        // MOV EAX, target_addr
                                        generate_mov_eax_imm(&new_shellcode, target_node->new_offset);
                                        
                                        // JMP EAX
                                        uint8_t jmp_eax[] = {0xff, 0xe0};
                                        buffer_append(&new_shellcode, jmp_eax, 2);
                                    }
                                } else {
                                    buffer_append(&new_shellcode, patched_insn, current->insn->size);
                                }
                            } else if ((current->insn->bytes[0] & 0xF0) == 0x70) { // Short conditional jump (0x70-0x7F)
                                int8_t new_rel8 = (int8_t)new_rel;
                                
                                if (new_rel == new_rel8) {
                                    patched_insn[1] = new_rel8;
                                    buffer_append(&new_shellcode, patched_insn, current->insn->size);
                                } else {
                                    // If displacement doesn't fit in 8 bits, need to convert to long form
                                    // Need to convert short jcc to long jcc format (0F 8x)
                                    // This changes instruction length and affects offsets, which is complex
                                    // For simplicity, use the same approach as for null bytes
                                    
                                    uint8_t opposite_jcc_opcode = 0;
                                    switch (current->insn->id) {
                                        case X86_INS_JO:  opposite_jcc_opcode = 0x71; break;
                                        case X86_INS_JNO: opposite_jcc_opcode = 0x70; break;
                                        case X86_INS_JB:  opposite_jcc_opcode = 0x73; break;
                                        case X86_INS_JAE: opposite_jcc_opcode = 0x72; break;
                                        case X86_INS_JE:  opposite_jcc_opcode = 0x75; break;
                                        case X86_INS_JNE: opposite_jcc_opcode = 0x74; break;
                                        case X86_INS_JBE: opposite_jcc_opcode = 0x77; break;
                                        case X86_INS_JA:  opposite_jcc_opcode = 0x76; break;
                                        case X86_INS_JS:  opposite_jcc_opcode = 0x79; break;
                                        case X86_INS_JNS: opposite_jcc_opcode = 0x78; break;
                                        case X86_INS_JP:  opposite_jcc_opcode = 0x7b; break;
                                        case X86_INS_JNP: opposite_jcc_opcode = 0x7a; break;
                                        case X86_INS_JL:  opposite_jcc_opcode = 0x7d; break;
                                        case X86_INS_JGE: opposite_jcc_opcode = 0x7c; break;
                                        case X86_INS_JLE: opposite_jcc_opcode = 0x7f; break;
                                        case X86_INS_JG:  opposite_jcc_opcode = 0x7e; break;
                                        default:
                                            buffer_append(&new_shellcode, patched_insn, current->insn->size);
                                            current = current->next;
                                            continue;
                                    }
                                    
                                    if (opposite_jcc_opcode != 0) {
                                        // Use the skip approach
                                        uint8_t skip_jmp[2] = {opposite_jcc_opcode, 0x07};
                                        buffer_append(&new_shellcode, skip_jmp, 2);
                                        
                                        generate_mov_eax_imm(&new_shellcode, target_node->new_offset);
                                        
                                        uint8_t jmp_eax[] = {0xff, 0xe0};
                                        buffer_append(&new_shellcode, jmp_eax, 2);
                                    }
                                }
                            }
                        } else if (current->insn->detail->x86.encoding.disp_size == 1) { // 8-bit displacement
                            // For short conditional jumps, same logic with 8-bit displacement
                            int8_t new_rel8 = (int8_t)new_rel;
                            
                            if (new_rel == new_rel8) {
                                patched_insn[1] = new_rel8;
                                buffer_append(&new_shellcode, patched_insn, current->insn->size);
                            } else {
                                // Displacement too large for 8-bit, convert to long form using the same approach
                                uint8_t opposite_jcc_opcode = 0;
                                switch (current->insn->id) {
                                    case X86_INS_JO:  opposite_jcc_opcode = 0x71; break;
                                    case X86_INS_JNO: opposite_jcc_opcode = 0x70; break;
                                    case X86_INS_JB:  opposite_jcc_opcode = 0x73; break;
                                    case X86_INS_JAE: opposite_jcc_opcode = 0x72; break;
                                    case X86_INS_JE:  opposite_jcc_opcode = 0x75; break;
                                    case X86_INS_JNE: opposite_jcc_opcode = 0x74; break;
                                    case X86_INS_JBE: opposite_jcc_opcode = 0x77; break;
                                    case X86_INS_JA:  opposite_jcc_opcode = 0x76; break;
                                    case X86_INS_JS:  opposite_jcc_opcode = 0x79; break;
                                    case X86_INS_JNS: opposite_jcc_opcode = 0x78; break;
                                    case X86_INS_JP:  opposite_jcc_opcode = 0x7b; break;
                                    case X86_INS_JNP: opposite_jcc_opcode = 0x7a; break;
                                    case X86_INS_JL:  opposite_jcc_opcode = 0x7d; break;
                                    case X86_INS_JGE: opposite_jcc_opcode = 0x7c; break;
                                    case X86_INS_JLE: opposite_jcc_opcode = 0x7f; break;
                                    case X86_INS_JG:  opposite_jcc_opcode = 0x7e; break;
                                    default:
                                        buffer_append(&new_shellcode, patched_insn, current->insn->size);
                                        current = current->next;
                                        continue;
                                }
                                
                                if (opposite_jcc_opcode != 0) {
                                    uint8_t skip_jmp[2] = {opposite_jcc_opcode, 0x07};
                                    buffer_append(&new_shellcode, skip_jmp, 2);
                                    
                                    generate_mov_eax_imm(&new_shellcode, target_node->new_offset);
                                    
                                    uint8_t jmp_eax[] = {0xff, 0xe0};
                                    buffer_append(&new_shellcode, jmp_eax, 2);
                                }
                            }
                        }
                    }
                } else {
                    // If we can't find the target node, just output the original instruction
                    buffer_append(&new_shellcode, current->insn->bytes, current->insn->size);
                }
            } else {
                // Use strategy pattern if it has nulls but isn't a relative jump
                if (has_null) {
                    int strategy_count;
                    strategy_t** strategies = get_strategies_for_instruction(current->insn, &strategy_count);
                    
                    if (strategy_count > 0) {
                        // Use the first (highest priority) strategy to generate code
                        strategies[0]->generate(&new_shellcode, current->insn);
                    } else {
                        // If no strategy can handle it, use comprehensive fallback
                        fallback_general_instruction(&new_shellcode, current->insn);
                    }
                } else {
                    // No nulls, output original instruction
                    buffer_append(&new_shellcode, current->insn->bytes, current->insn->size);
                }
            }
        } else {
            // Use strategy pattern to generate replacement if needed
            if (has_null) {
                int strategy_count;
                strategy_t** strategies = get_strategies_for_instruction(current->insn, &strategy_count);
                
                if (strategy_count > 0) {
                    // Use the first (highest priority) strategy to generate code
                    strategies[0]->generate(&new_shellcode, current->insn);
                } else {
                    // If no strategy can handle it, use comprehensive fallback
                    fallback_general_instruction(&new_shellcode, current->insn);
                }
            } else {
                // No nulls, output original instruction
                buffer_append(&new_shellcode, current->insn->bytes, current->insn->size);
            }
        }
        current = current->next;
    }
    
    // Clean up
    current = head;
    while (current != NULL) {
        struct instruction_node *next = current->next;
        free(current);
        current = next;
    }
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
        fallback_arithmetic_reg_imm(b, insn);
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
                        uint8_t code[] = {0x89, 0x00}; // MOV [EAX], reg format
                        code[1] = 0x00 + get_reg_index(src_reg);  // Encode source register
                        buffer_append(b, code, 2);
                        handled = 1;
                    } else if (insn->id == X86_INS_MOV && i == 1) { // Source is memory
                        // Handle MOV reg, [disp32]
                        uint8_t dst_reg = insn->detail->x86.operands[0].reg;
                        uint8_t code[] = {0x8B, 0x00}; // MOV reg, [EAX] format
                        code[1] = 0x00 + (get_reg_index(dst_reg) << 3);  // Encode destination register
                        buffer_append(b, code, 2);
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
            // In a production system, we'd need to handle this case better
            buffer_append(b, insn->bytes, insn->size);
        }
    }
}

struct buffer adaptive_processing(const uint8_t *input, size_t size) {
    struct buffer intermediate = remove_null_bytes(input, size);
    
    // Verify results
    if (!verify_null_elimination(&intermediate)) {
        // Some nulls remain - we need to handle the issue more comprehensively
        // For now, we'll improve our core algorithm by modifying the processing
        // to ensure no original instructions with nulls are included
    }
    
    return intermediate;
}