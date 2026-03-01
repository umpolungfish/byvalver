#include "strategy.h"
#include "utils.h"
#include <capstone/capstone.h>

/**
 * Helper to determine if an instruction can be safely encoded with the LOCK prefix 
 * without introducing new null bytes in the ModR/M, SIB, or displacement fields.
 */
static int is_insn_safe_to_encode(cs_insn *insn) {
    cs_x86 *x86 = &insn->detail->x86;
    
    // We only handle 32-bit memory operations (size 4)
    if (x86->operands[0].size != 4) return 0;

    // Determine the register index for the 'reg' field of ModR/M
    int reg_idx = 0;
    if (insn->id == X86_INS_INC) {
        reg_idx = 0; // INC /0
    } else if (insn->id == X86_INS_DEC) {
        reg_idx = 1; // DEC /1
    } else if (x86->op_count >= 2 && x86->operands[1].type == X86_OP_REG) {
        reg_idx = get_reg_index(x86->operands[1].reg);
    } else {
        return 0; // Other forms (like immediate) are not supported by this strategy
    }

    if (reg_idx < 0 || reg_idx > 7) return 0;

    // We only support simple [base + disp] addressing or [base] addressing
    cs_x86_op *mem_op = &x86->operands[0];
    if (mem_op->type != X86_OP_MEM || mem_op->mem.index != X86_REG_INVALID) return 0;

    int base_idx = get_reg_index(mem_op->mem.base);
    if (base_idx < 0 || base_idx > 7) return 0;

    uint8_t mod, rm;
    int32_t disp = mem_op->mem.disp;

    // Determine Mod and RM fields
    if (disp == 0 && base_idx != 5) {
        mod = 0; // [reg]
    } else if (disp >= -128 && disp <= 127) {
        mod = 1; // [reg + disp8]
    } else {
        mod = 2; // [reg + disp32]
    }

    rm = (base_idx == 4) ? 4 : (uint8_t)base_idx;

    // 1. ModR/M byte itself must not be 0x00
    uint8_t modrm = (uint8_t)((mod << 6) | (reg_idx << 3) | rm);
    if (modrm == 0x00) return 0;

    // 2. SIB byte check (if base is ESP)
    if (rm == 4) {
        // We use 0x24: scale=0, index=4(none), base=4(ESP)
        // 0x24 is not null.
    }

    // 3. Displacement check: must not contain null bytes if present
    if (mod == 1) {
        if ((disp & 0xFF) == 0x00) return 0;
    } else if (mod == 2) {
        if (!is_bad_byte_free((uint32_t)disp)) return 0;
    }

    return 1;
}

int can_handle_atomic_lock(cs_insn *insn) {
    // Only handle x86 32-bit (LOCK prefix on x64 behaves differently or requires REX)
    // We target x86 here.
    
    // Check supported instructions
    switch (insn->id) {
        case X86_INS_MOV:
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_XOR:
        case X86_INS_OR:
        case X86_INS_AND:
        case X86_INS_XCHG:
        case X86_INS_INC:
        case X86_INS_DEC:
            break;
        default:
            return 0;
    }

    // Must reference memory in the first operand (destination)
    if (insn->detail->x86.op_count < 1 || insn->detail->x86.operands[0].type != X86_OP_MEM) {
        return 0;
    }

    // For instructions other than INC/DEC, the second operand must be a register
    if (insn->id != X86_INS_INC && insn->id != X86_INS_DEC) {
        if (insn->detail->x86.op_count < 2 || insn->detail->x86.operands[1].type != X86_OP_REG) {
            return 0;
        }
    }

    // Strategy applies if the original instruction contains null bytes
    if (!has_null_bytes(insn)) {
        return 0;
    }

    // Finally, verify if the replacement is actually null-free
    return is_insn_safe_to_encode(insn);
}

size_t get_size_atomic_lock(cs_insn *insn) {
    (void)insn;
    // Conservative upper bound: 1(prefix) + 1(opcode) + 1(modrm) + 1(sib) + 4(disp) = 8
    return 15;
}

void generate_atomic_lock(struct buffer *b, cs_insn *insn) {
    (void)insn;
    cs_x86 *x86 = &insn->detail->x86;
    cs_x86_op *mem_op = &x86->operands[0];
    
    uint8_t opcode = 0;
    int reg_idx = 0;

    // Determine new opcode and the reg field index
    switch (insn->id) {
        case X86_INS_MOV:  
        case X86_INS_XCHG: 
            opcode = 0x87; 
            reg_idx = get_reg_index(x86->operands[1].reg); 
            break;
        case X86_INS_ADD:  
            opcode = 0x01; 
            reg_idx = get_reg_index(x86->operands[1].reg); 
            break;
        case X86_INS_OR:   
            opcode = 0x09; 
            reg_idx = get_reg_index(x86->operands[1].reg); 
            break;
        case X86_INS_AND:  
            opcode = 0x21; 
            reg_idx = get_reg_index(x86->operands[1].reg); 
            break;
        case X86_INS_SUB:  
            opcode = 0x29; 
            reg_idx = get_reg_index(x86->operands[1].reg); 
            break;
        case X86_INS_XOR:  
            opcode = 0x31; 
            reg_idx = get_reg_index(x86->operands[1].reg); 
            break;
        case X86_INS_INC:  
            opcode = 0xFF; 
            reg_idx = 0; 
            break;
        case X86_INS_DEC:  
            opcode = 0xFF; 
            reg_idx = 1; 
            break;
        default:
            return; // Should be caught by can_handle
    }

    // Write LOCK prefix
    buffer_write_byte(b, 0xF0);
    // Write Opcode
    buffer_write_byte(b, opcode);

    // Encode ModR/M, SIB, and Displacement
    uint8_t mod, rm;
    int32_t disp = mem_op->mem.disp;
    int base_idx = get_reg_index(mem_op->mem.base);

    if (disp == 0 && base_idx != 5) {
        mod = 0;
    } else if (disp >= -128 && disp <= 127) {
        mod = 1;
    } else {
        mod = 2;
    }

    if (base_idx == 4) {
        rm = 4; // SIB follows
    } else {
        rm = (uint8_t)base_idx;
    }

    // Write ModR/M
    buffer_write_byte(b, (uint8_t)((mod << 6) | (reg_idx << 3) | rm));

    // Write SIB if necessary
    if (rm == 4) {
        buffer_write_byte(b, 0x24); // scale=0, index=none, base=ESP
    }

    // Write Displacement
    if (mod == 1) {
        buffer_write_byte(b, (uint8_t)disp);
    } else if (mod == 2) {
        buffer_write_dword(b, (uint32_t)disp);
    }
}

static strategy_t atomic_lock_strategy = {
    .name = "atomic_lock_prefix_alignment_shift",
    .can_handle = can_handle_atomic_lock,
    .get_size = get_size_atomic_lock,
    .generate = generate_atomic_lock,
    .priority = 75,
    .target_arch = BYVAL_ARCH_X86
};

void register_atomic_lock_prefix_alignment_shift_strategies(void) {
    register_strategy(&atomic_lock_strategy);
}