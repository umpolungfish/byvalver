#ifndef ML_INSTRUCTION_MAP_H
#define ML_INSTRUCTION_MAP_H

#include <capstone/capstone.h>

// Configuration
#define TOP_N_INSTRUCTIONS 50
// Note: ONEHOT_DIM is defined in ml_strategist.h as 51 (TOP_N_INSTRUCTIONS + 1)

/**
 * Initialize the instruction mapping system.
 * Must be called once before using ml_get_instruction_onehot_index().
 */
void ml_instruction_map_init(void);

/**
 * Map x86 instruction ID to one-hot encoding index.
 *
 * @param insn_id - x86 instruction ID from capstone (X86_INS_*)
 * @return One-hot index: 0-49 for top-50 instructions, 50 for OTHER bucket
 *
 * Example:
 *   ml_get_instruction_onehot_index(X86_INS_MOV) -> 0
 *   ml_get_instruction_onehot_index(X86_INS_PUSH) -> 1
 *   ml_get_instruction_onehot_index(X86_INS_RARE) -> 50 (OTHER)
 */
int ml_get_instruction_onehot_index(unsigned int insn_id);

/**
 * Get human-readable name for one-hot index.
 *
 * @param onehot_idx - Index from 0 to 50
 * @return Instruction mnemonic string (e.g., "MOV", "PUSH", "OTHER")
 */
const char* ml_get_instruction_name_by_index(int onehot_idx);

#endif // ML_INSTRUCTION_MAP_H
