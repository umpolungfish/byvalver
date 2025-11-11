// Add this near the top of core.c after the existing helper functions

// Helper function to safely handle relative jump instructions
static void process_relative_jump(struct buffer *new_shellcode, 
                                   cs_insn *insn,
                                   struct instruction_node *current,
                                   struct instruction_node *head) {
    
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
    
    while (target_node != NULL) {
        if (target_node->offset == target_addr) {
            found = 1;
            break;
        }
        target_node = target_node->next;
    }
    
    if (!found) {
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
            // Conditional jump to external target - rare, but handle conservatively
            // Just output original for now
            buffer_append(new_shellcode, insn->bytes, insn->size);
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
        
        if (has_null) {
            // Convert using opposite condition trick
            uint8_t opposite = insn->bytes[1] ^ 0x01;
            uint8_t skip[] = {0x0F, opposite, 0x07, 0x00, 0x00, 0x00};  // Skip 7 bytes
            memcpy(&skip[2], &(int32_t){7}, 4);
            buffer_append(new_shellcode, skip, 6);
            
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

// Now in the main remove_null_bytes function, replace the complex jump handling
// with a simple call to this function:
//
// In the "Third pass: generate new shellcode" section:
//
//     current = head;
//     while (current != NULL) {
//         int has_null = /* check for nulls */;
//         
//         if (is_relative_jump(current->insn)) {
//             process_relative_jump(&new_shellcode, current->insn, current, head);
//         } else if (has_null) {
//             // Use strategies
//             int strategy_count;
//             strategy_t** strategies = get_strategies_for_instruction(current->insn, &strategy_count);
//             
//             if (strategy_count > 0) {
//                 strategies[0]->generate(&new_shellcode, current->insn);
//             } else {
//                 fallback_general_instruction(&new_shellcode, current->insn);
//             }
//         } else {
//             // No nulls, copy original
//             buffer_append(&new_shellcode, current->insn->bytes, current->insn->size);
//         }
//         
//         current = current->next;
//     }
