#include "strategy.h"
#include "utils.h"
#include "new_strategies.h"
#include "enhanced_mov_mem_strategies.h"
#include "enhanced_register_chaining_strategies.h"
#include "enhanced_arithmetic_strategies.h"
#include "enhanced_immediate_strategies.h"
#include "improved_mov_strategies.h"
#include "improved_arithmetic_strategies.h"
#include "remaining_null_elimination_strategies.h"
#include "ml_strategist.h"
#include "ml_strategy_registry.h"
#include "call_pop_immediate_strategies.h"
#include "peb_api_hashing_strategies.h"
#include "shift_value_construction_strategies.h"
#include "lea_arithmetic_substitution_strategies.h"
#include "stack_string_construction_strategies.h"
#include "salc_conditional_flag_strategies.h"
#include "register_swapping_immediate_strategies.h"
#include "scasb_cmpsb_strategies.h"
#include "short_conditional_jump_strategies.h"
#include "lea_complex_addressing_strategies.h"
#include "inc_dec_chain_strategies.h"
#include "lea_arithmetic_calculation_strategies.h"
#include "push_pop_immediate_strategies.h"
#include "bitwise_flag_manipulation_strategies.h"
#include "salc_zero_flag_strategies.h"
#include "xchg_immediate_construction_strategies.h"
#include "peb_api_resolution_strategies.h"
#include "conditional_jump_displacement_strategies.h"
#include "register_allocation_strategies.h"
#include "lea_displacement_optimization_strategies.h"
#include "advanced_hash_api_resolution.h"
#include "multi_stage_peb_traversal.h"
#include "stack_based_structure_construction.h"
#include "pushw_word_immediate_strategies.h"
#include "cltd_zero_extension_strategies.h"
#include "polymorphic_immediate_construction_strategies.h"
#include "setcc_jump_elimination_strategies.h"
#include "register_dependency_chain_optimization_strategies.h"
#include "syscall_number_obfuscation_strategies.h"
#include "partial_register_optimization_strategies.h"
#include "segment_register_teb_peb_strategies.h"
#include "cmov_conditional_elimination_strategies.h"
#include "bswap_endianness_transformation_strategies.h"
#include "pushf_popf_bit_manipulation_strategies.h"
#include "bit_scanning_constant_strategies.h"
#include "loop_comprehensive_strategies.h"
#include "atomic_operation_encoding_strategies.h"
#include "bcd_arithmetic_obfuscation_strategies.h"
#include "enter_leave_alternative_encoding_strategies.h"
#include "bit_counting_constant_strategies.h"
#include "simd_xmm_register_strategies.h"
#include "jecxz_jrcxz_transformation_strategies.h"
#include "modrm_sib_badbyte_strategies.h"
#include "reg_to_reg_badbyte_strategies.h"
#include "conditional_jump_opcode_badbyte_strategies.h"
#include "one_byte_opcode_sub_strategies.h"
#include "partial_immediate_badbyte_strategies.h"
#include "stack_frame_badbyte_strategies.h"
#include "string_prefix_badbyte_strategies.h"
#include "bitwise_immediate_badbyte_strategies.h"
#include "segment_prefix_badbyte_strategies.h"
#include "operand_size_prefix_badbyte_strategies.h"
// x64-specific strategies (v4.2)
#include "movabs_strategies.h"
#include "sse_memory_strategies.h"
#include "lea_x64_displacement_strategies.h"
#include "vex_encoding_byte_evasion_strategies.h"
#include "segment_register_load_pointer_construction_strategies.h"
#include "vex_prefix_encoding_remap_for_avx_instructions_strategies.h"
#include "vex_escape_badbyte_evasion_strategies.h"
#include "vex_avx512_immediate_construction_strategies.h"
#include "vex_evx_prefix_modrm_remap_strategies.h"
#include "bmi2_bzhi_bit_masking_strategies.h"
#include "bmi1_andn_logic_transformation_strategies.h"
#include "bmi2_flags_preserving_shift_transformation_strategies.h"
#include "segment_limit_constant_loading_strategies.h"
#include "vex_xmm_gpr_bridge_substitution_strategies.h"
#include "vex_evx_immediate_encoding_shift_strategies.h"
#include "vex_evex_prefix_remapping_for_avx_immediate_strategies.h"
#include "vex_escape_byte_remapping_for_simd_mov_strategies.h"
#include "shrd_double_precision_value_synthesis_strategies.h"
#include "bmi1_bextr_bitfield_extraction_strategies.h"
#include "lsl_segment_limit_constant_substitution_strategies.h"
#include "vex_evx_prefix_byte_remapping_strategies.h"
#include "vex_escape_byte_remapping_strategies.h"
#include "non_temporal_move_substitution_strategies.h"
#include "bmi2_mulx_dual_register_transformation_strategies.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h> // Added for debug prints
// #include <stdio.h> // Removed for printf

#define MAX_STRATEGIES 400

/**
 * Check if a strategy is architecture-compatible with the target architecture.
 * Allows x86 strategies to be used on x64, unless they use incompatible instructions.
 *
 * @param strategy: The strategy to check
 * @param target_arch: The target architecture we're processing for
 * @return: 1 if compatible, 0 if not
 */
static int is_strategy_arch_compatible(strategy_t *strategy, byval_arch_t target_arch) {
    // Exact match is always compatible
    if (strategy->target_arch == target_arch) {
        return 1;
    }

    // Allow x86 strategies on x64 unless they use incompatible instructions
    // These instructions were removed or have different semantics in x64 mode:
    // - SALC: Set AL from Carry (opcode D6) - removed in x64
    // - ARPL: Adjust RPL Field (opcode 63) - repurposed as MOVSXD in x64
    // - BOUND: Check Array Index Against Bounds - removed in x64
    // - BCD instructions (AAA, AAS, DAA, DAS, AAM, AAD) - removed in x64
    if (target_arch == BYVAL_ARCH_X64 && strategy->target_arch == BYVAL_ARCH_X86) {
        const char *incompatible[] = {
            "SALC", "salc",           // Set AL from Carry - removed in x64
            "ARPL", "arpl",           // Adjust RPL - repurposed as MOVSXD in x64
            "BOUND", "bound",         // Check Array Bounds - removed in x64
            "BCD", "bcd",             // BCD arithmetic prefix
            "AAA", "aaa",             // ASCII Adjust After Addition
            "AAS", "aas",             // ASCII Adjust After Subtraction
            "DAA", "daa",             // Decimal Adjust After Addition
            "DAS", "das",             // Decimal Adjust After Subtraction
            "AAM", "aam",             // ASCII Adjust After Multiplication
            "AAD", "aad",             // ASCII Adjust Before Division
            "PUSHAD", "pushad",       // Push All General-Purpose - removed in x64
            "POPAD", "popad",         // Pop All General-Purpose - removed in x64
            "PUSHA", "pusha",         // Push All - removed in x64
            "POPA", "popa",           // Pop All - removed in x64
        };

        for (size_t i = 0; i < sizeof(incompatible) / sizeof(incompatible[0]); i++) {
            if (strstr(strategy->name, incompatible[i])) {
                return 0;  // Incompatible - uses removed x64 instruction
            }
        }
        return 1;  // Compatible - x86 strategy can be used on x64
    }

    return 0;  // Not compatible
}

// Global ML strategist instance for this module
static ml_strategist_t g_ml_strategist;
static int g_ml_initialized = 0;
static int g_ml_in_progress = 0; // Recursion guard

static strategy_t* strategies[MAX_STRATEGIES];
static int strategy_count = 0;

void register_strategy(strategy_t *strategy) {
    if (strategy_count < MAX_STRATEGIES) {
        strategies[strategy_count++] = strategy;
    } else {
        fprintf(stderr, "[ERROR] Strategy registry full! Maximum of %d strategies supported.\n", MAX_STRATEGIES);
    }
}

void register_mov_strategies(); // Forward declaration
void register_arithmetic_const_generation_strategies(); // Forward declaration - Arithmetic/Bitwise constant generation
void register_arithmetic_strategies(); // Forward declaration
void register_salc_rep_stosb_strategies(); // Forward declaration - SALC + REP STOSB for null-filled buffers
void register_xor_zero_reg_strategies(); // Forward declaration - XOR reg, reg for zeroing registers
void register_memory_strategies(); // Forward declaration
void register_jump_strategies(); // Forward declaration
void register_general_strategies(); // Forward declaration
void register_anti_debug_strategies(); // Forward declaration
void register_shift_strategy(); // Forward declaration
void register_push_immediate_strategies(); // Forward declaration - PUSH immediate null elimination
void register_lea_displacement_strategies(); // Forward declaration - LEA displacement null elimination
void register_string_instruction_strategies(); // Forward declaration - String instruction null construction
void register_conditional_flag_strategies(); // Forward declaration - Conditional flag manipulation
void register_peb_api_hashing_strategies(); // Forward declaration - PEB traversal & API hashing
void register_stack_string_const_strategies(); // Forward declaration - Stack-based string/constant construction

// Additional Windows-specific null elimination strategies
void register_call_pop_immediate_strategies(); // Register CALL/POP immediate loading strategies (priority 85)
void register_shift_value_construction_strategies(); // Register shift value construction strategies (priority 78)
void register_lea_arithmetic_substitution_strategies(); // Register LEA arithmetic substitution strategies (priority 80)
void register_stack_string_construction_strategies(); // Register stack string construction strategies (priority 85)
void register_salc_conditional_flag_strategies(); // Register SALC + conditional flag strategies (priority 91)
void register_register_swapping_immediate_strategies(); // Register register swapping immediate strategies (priority 70)
void register_peb_strategies(); // Forward declaration
void register_conservative_strategies(); // Forward declaration
// void register_lea_strategies(); // Forward declaration
void register_enhanced_conservative_mov_strategy(); // Forward declaration
void register_context_preservation_strategies(); // Forward declaration
void register_sequence_preservation_strategies(); // Forward declaration
void register_advanced_transformations(); // Forward declaration
void register_scasb_cmpsb_strategies(); // Forward declaration - SCASB/CMPSB conditional operations strategy
void register_short_conditional_jump_strategies(); // Forward declaration - Short conditional jump with 8-bit displacement strategy
void register_lea_complex_addressing_strategies(); // Forward declaration - LEA with complex addressing for value construction strategy
void register_inc_dec_chain_strategies(); // Forward declaration - INC/DEC chain strategy
void register_lea_arithmetic_calculation_strategies(); // Forward declaration - LEA arithmetic calculation strategy
void register_push_pop_immediate_strategies(); // Forward declaration - PUSH-POP immediate loading strategy
void register_bitwise_flag_manipulation_strategies(); // Forward declaration - Bitwise flag manipulation strategy
void register_salc_zero_flag_strategies(); // Forward declaration - SALC zero flag strategy
void register_xchg_immediate_construction_strategies(); // Forward declaration - XCHG immediate construction strategy
void register_peb_api_resolution_strategies(); // Forward declaration - Enhanced PEB API resolution strategies (priority 97)
void register_advanced_hash_api_resolution_strategies(); // Forward declaration - Advanced hash-based API resolution strategies (priority 96)
void register_multi_stage_peb_traversal_strategies(); // Forward declaration - Multi-stage PEB traversal strategies (priority 97)
void register_stack_based_structure_construction_strategies(); // Forward declaration - Stack-based structure construction strategies (priority 94)

// x64-specific strategy forward declarations (v4.2)
void register_sbb_imm_zero_strategies(); // Forward declaration - SBB/ADC reg, 0 null elimination (priority 86)
void register_test_large_imm_strategies(); // Forward declaration - TEST with large immediate null elimination (priority 84-85)
void register_conditional_jump_displacement_strategies(); // Forward declaration - Conditional jump displacement strategies (priority 88)
void register_register_allocation_strategies(); // Forward declaration - Register allocation strategies for null avoidance (priority 78)
void register_lea_displacement_optimization_strategies(); // Forward declaration - LEA displacement optimization strategies (priority 82)
void init_advanced_transformations(); // Forward declaration
void register_getpc_strategies(); // Forward declaration
void register_movzx_strategies(); // Forward declaration
void register_ror_rol_strategies(); // Forward declaration
void register_indirect_call_strategies(); // Forward declaration
void register_loop_strategies(); // Forward declaration
void register_ret_strategies(); // Forward declaration
void register_cmp_strategies(); // Forward declaration
void register_xchg_strategies(); // Forward declaration
void register_bt_strategies(); // Forward declaration
// void register_test_strategies(); // Forward declaration - EXCLUDED FROM BUILD
void register_adc_strategies(); // Forward declaration
void register_sbb_strategies(); // Forward declaration
void register_setcc_strategies(); // Forward declaration
void register_imul_strategies(); // Forward declaration
void register_fpu_strategies(); // Forward declaration
void register_sldt_strategies(); // Forward declaration
void register_sldt_replacement_strategy(); // Forward declaration - Priority 95
void register_retf_strategies(); // Forward declaration - Priority 85
void register_arpl_strategies(); // Forward declaration - Priority 75
void register_bound_strategies(); // Forward declaration - Priority 70
void register_byte_construct_strategy(); // Forward declaration - Byte construction strategy
void register_conditional_jump_offset_strategies(); // Forward declaration - Priority 150
void register_cmp_memory_disp_null_strategy(); // Forward declaration - Priority 55
void register_sib_strategies(); // Forward declaration - SIB addressing null elimination
void register_rip_relative_strategies(); // Forward declaration - RIP-relative addressing null elimination
void register_multibyte_nop_strategies(); // Forward declaration - Multi-byte NOP null elimination
void register_small_immediate_strategies(); // Forward declaration - Small immediate value optimization
void register_relative_jump_strategies(); // Forward declaration - Relative CALL/JMP displacement handling
void register_large_immediate_strategies(); // Forward declaration - Large immediate value optimization
// void register_ror13_hash_strategies(); // Forward declaration - DISABLED - broken implementation
void register_stack_string_strategies(); // Forward declaration - Stack-based string construction
void register_syscall_strategies(); // Forward declaration - Windows syscall direct invocation (x64) - Priority 95
void register_rep_stosb_strategies(); // Forward declaration - REP STOSB memory initialization - Priority 92
void register_salc_strategies(); // Forward declaration - SALC AL zeroing optimization - Priority 91
void register_xchg_preservation_strategies(); // Forward declaration - PUSH immediate optimization - Priority 86
void register_arithmetic_decomposition_strategies(); // Forward declaration - MOV arithmetic decomposition - Priority 70
// void register_arithmetic_substitution_strategies(); // Forward declaration - Already registered by register_advanced_transformations() - DISABLED
void register_immediate_split_strategies(); // Forward declaration - Immediate value splitting - Priority 77
void register_socket_address_strategies(); // Forward declaration - Socket address null handling - Priority 77-80
void register_unicode_string_strategies(); // Forward declaration - Unicode (UTF-16) string handling - Priority 74-78
void register_memory_displacement_strategies(); // Forward declaration - Memory displacement null handling - Priority 82-85
// void register_custom_hash_strategies(); // Forward declaration - DISABLED - broken implementation
// void register_api_hashing_strategies(); // Forward declaration - DISABLED - doesn't handle memory operands
void register_register_chaining_strategies(); // Forward declaration - Register chaining strategy - Priority 60-65
void register_linux_socketcall_strategies(); // Forward declaration - Linux socketcall multiplexer pattern - Priority 72-75
void register_linux_string_push_strategies(); // Forward declaration - Linux string construction via PUSH - Priority 68-70
void register_syscall_number_strategies(); // Forward declaration - Linux syscall number encoding strategies - Priority 77-78

// NEW: Discovered Strategies (2025-12-16)
void register_pushw_word_immediate_strategies(); // Forward declaration - PUSHW 16-bit immediate for port numbers - Priority 87
void register_cltd_zero_extension_strategies(); // Forward declaration - CLTD zero extension optimization - Priority 82

// NEW: High-Priority Additional Strategies (2025-12-19)
void register_partial_register_optimization_strategies();  // Register partial register optimization strategies (priority 89)
void register_segment_register_teb_peb_strategies();  // Register segment register TEB/PEB access strategies (priority 94)
void register_cmov_conditional_elimination_strategies();  // Register CMOV conditional move elimination strategies (priority 92)
void register_advanced_string_operation_strategies();  // Register advanced string operation strategies (priority 85)
void register_atomic_operation_encoding_strategies();  // Register atomic operation encoding strategies (priority 78)
void register_fpu_stack_immediate_encoding_strategies();  // Register FPU stack immediate encoding strategies (priority 76)
void register_xlat_table_lookup_strategies();  // Register XLAT table lookup strategies (priority 72)
void register_lahf_sahf_flag_preservation_strategies();  // Register LAHF/SAHF flag preservation strategies (priority 83)

// NEW: 5 Additional Denulling Strategies (v3.5 - 2025-12-22)
void register_bswap_endianness_transformation_strategies();  // Register BSWAP endianness transformation strategies (priority 85)
void register_pushf_popf_bit_manipulation_strategies();  // Register PUSHF/POPF bit manipulation strategies (priority 81)
void register_bit_scanning_constant_strategies();  // Register BSF/BSR bit scanning strategies (priority 80)
void register_loop_comprehensive_strategies();  // Register LOOP comprehensive variants strategies (priority 79)

// NEW: 5 Additional Denulling Strategies (v3.6 - 2025-12-28)
void register_bcd_arithmetic_obfuscation_strategies();  // Register BCD arithmetic obfuscation strategies (priority 68)
void register_enter_leave_alternative_encoding_strategies();  // Register ENTER/LEAVE alternative encoding strategies (priority 74)
void register_bit_counting_constant_strategies();  // Register POPCNT/LZCNT/TZCNT bit counting strategies (priority 77)
void register_simd_xmm_register_strategies();  // Register SIMD XMM register strategies (priority 89)
void register_jecxz_jrcxz_transformation_strategies();  // Register JECXZ/JRCXZ transformation strategies (priority 85)

// NEW: 10 High-Priority General Bad-Byte Elimination Strategies (v4.0 - 2026-01-03)
void register_modrm_sib_badbyte_strategies();  // Register ModR/M and SIB bad-byte elimination strategies (priority 88)
void register_reg_to_reg_badbyte_strategies();  // Register register-to-register transfer bad-byte elimination strategies (priority 90)
void register_conditional_jump_opcode_badbyte_strategies();  // Register conditional jump opcode bad-byte elimination strategies (priority 92)
void register_one_byte_opcode_sub_strategies();  // Register one-byte opcode substitution strategies (priority 85)
void register_partial_immediate_badbyte_strategies();  // Register partial immediate bad-byte optimization strategies (priority 87)
void register_stack_frame_badbyte_strategies();  // Register stack frame pointer bad-byte elimination strategies (priority 89)
void register_string_prefix_badbyte_strategies();  // Register string instruction prefix bad-byte elimination strategies (priority 84)
void register_bitwise_immediate_badbyte_strategies();  // Register bitwise immediate bad-byte elimination strategies (priority 86)
void register_segment_prefix_badbyte_strategies();  // Register segment prefix bad-byte detection strategies (priority 81)
void register_operand_size_prefix_badbyte_strategies();  // Register operand size prefix bad-byte elimination strategies (priority 83)

// NEW: 5 Additional Denulling Strategies (v3.0)
void register_jcxz_null_safe_loop_termination_strategy(); // Priority 86 - JCXZ null-safe loop termination
void register_push_byte_immediate_stack_construction_strategy(); // Priority 82 - PUSH byte immediate stack construction
void register_arithmetic_constant_construction_sub_strategy(); // Priority 79 - Arithmetic constant construction via SUB
void register_incremental_byte_register_syscall_strategy(); // Priority 78 - Incremental byte register syscall
void register_word_inc_chain_nullfree_strategy(); // Priority 77 - Word-size INC chain null-free

// Enhanced strategies for better null-byte elimination
void register_enhanced_mov_mem_strategies(); // Enhanced MOV memory strategies
void register_enhanced_register_chaining_strategies(); // Enhanced register chaining strategies
void register_enhanced_arithmetic_strategies(); // Enhanced arithmetic strategies
void register_enhanced_immediate_strategies(); // Enhanced immediate strategies

// Improved strategies for better null-byte elimination
void register_improved_mov_strategies(); // Improved MOV strategies
void register_improved_arithmetic_strategies(); // Improved arithmetic strategies

// Remaining null elimination strategies for final cleanup
void register_remaining_null_elimination_strategies(); // Final strategies for remaining nulls

void register_new_strategies(); // Forward declaration - New strategies for specific null-byte patterns
extern strategy_t delayed_string_termination_strategy;

void register_vex_encoding_byte_evasion_strategies(); // Forward declaration - vex_encoding_byte_evasion_strategies
void register_segment_register_load_pointer_construction_strategies(); // Forward declaration - segment_register_load_pointer_construction_strategies
void register_vex_prefix_encoding_remap_for_avx_instructions_strategies(); // Forward declaration - vex_prefix_encoding_remap_for_avx_instructions
void register_vex_escape_badbyte_evasion_strategies(); // Forward declaration - vex_escape_badbyte_evasion
void register_vex_avx512_immediate_construction_strategies(); // Forward declaration - vex_avx512_immediate_construction
void register_vex_evx_prefix_modrm_remap_strategies(); // Forward declaration - vex_evx_prefix_modrm_remap
void register_bmi2_bzhi_bit_masking_strategies(); // Forward declaration - bmi2_bzhi_bit_masking
void register_bmi1_andn_logic_transformation_strategies(); // Forward declaration - bmi1_andn_logic_transformation
void register_bmi2_flags_preserving_shift_transformation_strategies(); // Forward declaration - bmi2_flags_preserving_shift_transformation
void register_segment_limit_constant_loading_strategies(); // Forward declaration - segment_limit_constant_loading_strategies
void register_vex_xmm_gpr_bridge_substitution_strategies(); // Forward declaration - vex_xmm_gpr_bridge_substitution
void register_vex_evx_immediate_encoding_shift_strategies(); // Forward declaration - vex_evx_immediate_encoding_shift
void register_vex_evex_prefix_remapping_for_avx_immediate_strategies(); // Forward declaration - vex_evex_prefix_remapping_for_avx_immediate
void register_vex_escape_byte_remapping_for_simd_mov_strategies(); // Forward declaration - vex_escape_byte_remapping_for_simd_mov
void register_shrd_double_precision_value_synthesis_strategies(); // Forward declaration - shrd_double_precision_value_synthesis
void register_bmi1_bextr_bitfield_extraction_strategies(); // Forward declaration - bmi1_bextr_bitfield_extraction
void register_lsl_segment_limit_constant_substitution_strategies(); // Forward declaration - lsl_segment_limit_constant_substitution
void register_vex_evx_prefix_byte_remapping_strategies(); // Forward declaration - vex_evx_prefix_byte_remapping
void register_vex_escape_byte_remapping_strategies(); // Forward declaration - vex_escape_byte_remapping
void register_non_temporal_move_substitution_strategies(); // Forward declaration - non_temporal_move_substitution
void register_bmi2_mulx_dual_register_transformation_strategies(); // Forward declaration - bmi2_mulx_dual_register_transformation
void init_strategies(int use_ml, byval_arch_t arch) {
    #ifdef DEBUG
    fprintf(stderr, "[DEBUG] Initializing strategies\n");
    #endif

    strategy_count = 0;

    // Initialize ML strategist if ML is enabled
    if (use_ml && !g_ml_initialized) {
        int ml_init_result = ml_strategist_init(&g_ml_strategist, "./ml_models/byvalver_ml_model.bin");
        if (ml_init_result != 0) {
            // If model file doesn't exist, initialize without loading a specific model
            ml_strategist_init(&g_ml_strategist, ""); // Empty path initializes with default weights
        }
        g_ml_initialized = 1;
        #ifdef DEBUG
        fprintf(stderr, "[DEBUG] ML Strategist initialized\n");
        #endif
    } else if (!use_ml) {
        #ifdef DEBUG
        fprintf(stderr, "[DEBUG] ML Strategist disabled by configuration\n");
        #endif
    }

    // Register strategies based on target architecture
    if (arch == BYVAL_ARCH_X86 || arch == BYVAL_ARCH_X64) {
        register_advanced_transformations();  // Register advanced transformations (highest priority)
    init_advanced_transformations();      // Initialize the can_handle functions
    register_indirect_call_strategies();  // Register indirect CALL/JMP strategies (priority 100)
    register_sldt_replacement_strategy();  // Register SLDT replacement strategy (priority 95)

    // NEW: Tier 1 High-Priority Strategies (2025-12-19)
    register_register_dependency_chain_optimization_strategies();  // Priority 91 - Multi-instruction optimization
    register_polymorphic_immediate_construction_strategies();  // Priority 88-90 - Universal immediate encoding

    // NEW: 10 High-Priority General Bad-Byte Elimination Strategies (v4.0 - 2026-01-03)
    register_conditional_jump_opcode_badbyte_strategies();  // Priority 92 - Conditional jump opcode bad-byte elimination
    register_reg_to_reg_badbyte_strategies();  // Priority 90 - Register-to-register transfer bad-byte elimination
    register_stack_frame_badbyte_strategies();  // Priority 89 - Stack frame pointer bad-byte elimination
    register_modrm_sib_badbyte_strategies();  // Priority 88 - ModR/M and SIB bad-byte elimination
    register_partial_immediate_badbyte_strategies();  // Priority 87 - Partial immediate bad-byte optimization
    register_bitwise_immediate_badbyte_strategies();  // Priority 86 - Bitwise immediate bad-byte elimination
    register_one_byte_opcode_sub_strategies();  // Priority 85 - One-byte opcode substitution
    register_string_prefix_badbyte_strategies();  // Priority 84 - String instruction prefix bad-byte elimination
    register_operand_size_prefix_badbyte_strategies();  // Priority 83 - Operand size prefix bad-byte elimination
    register_segment_prefix_badbyte_strategies();  // Priority 81 - Segment prefix bad-byte detection

    // NEW: x64-Specific High-Priority Strategies (v4.2 - 2026-01-21)
    // These strategies handle x64-specific patterns that cause null bytes
    if (arch == BYVAL_ARCH_X64) {
        register_movabs_strategies();  // Priority 89-90 - MOVABS 64-bit immediate handling
        register_sbb_imm_zero_strategies();  // Priority 86 - SBB/ADC reg, 0 handling
        register_test_large_imm_strategies();  // Priority 84-85 - TEST with large immediate
        register_sse_memory_strategies();  // Priority 88 - SSE memory operations
        register_lea_x64_displacement_strategies();  // Priority 86-87 - LEA with null displacement
    }

    register_syscall_number_obfuscation_strategies();  // Priority 85-88 - Linux syscall optimization
    register_setcc_jump_elimination_strategies();  // Priority 84-86 - Jump offset elimination

    // NEW: High-Priority Additional Strategies (2025-12-19)
    register_partial_register_optimization_strategies();  // Register partial register optimization strategies (priority 89)
    register_simd_xmm_register_strategies();  // Register SIMD XMM register strategies (priority 89)
    register_segment_register_teb_peb_strategies();  // Register segment register TEB/PEB access strategies (priority 94)
    register_cmov_conditional_elimination_strategies();  // Register CMOV conditional move elimination strategies (priority 92)
    register_advanced_string_operation_strategies();  // Register advanced string operation strategies (priority 85)
    register_jecxz_jrcxz_transformation_strategies();  // Register JECXZ/JRCXZ transformation strategies (priority 85)

    // NEW: 5 Additional Denulling Strategies (v3.5 - 2025-12-22)
    register_bswap_endianness_transformation_strategies();  // Register BSWAP endianness transformation strategies (priority 85)
    register_lahf_sahf_flag_preservation_strategies();  // Register LAHF/SAHF flag preservation strategies (priority 83)
    register_pushf_popf_bit_manipulation_strategies();  // Register PUSHF/POPF bit manipulation strategies (priority 81)
    register_bit_scanning_constant_strategies();  // Register BSF/BSR bit scanning strategies (priority 80)
    register_loop_comprehensive_strategies();  // Register LOOP comprehensive variants strategies (priority 79)
    register_atomic_operation_encoding_strategies();  // Register atomic operation encoding strategies (priority 78)
    register_bit_counting_constant_strategies();  // Register POPCNT/LZCNT/TZCNT bit counting strategies (priority 77)

    register_fpu_stack_immediate_encoding_strategies();  // Register FPU stack immediate encoding strategies (priority 76)
    register_enter_leave_alternative_encoding_strategies();  // Register ENTER/LEAVE alternative encoding strategies (priority 74)
    register_xlat_table_lookup_strategies();  // Register XLAT table lookup strategies (priority 72)
    register_bcd_arithmetic_obfuscation_strategies();  // Register BCD arithmetic obfuscation strategies (priority 68)

    // NEW: Discovered Strategies (2025-12-16)
    register_pushw_word_immediate_strategies();  // Register PUSHW 16-bit immediate strategies (priority 87)
    register_cltd_zero_extension_strategies();  // Register CLTD zero extension strategies (priority 82)

    register_push_immediate_strategies();  // Register PUSH immediate null elimination strategies (priority 75)
    register_lea_displacement_strategies();  // Register LEA displacement null elimination strategies (priority 80)
    register_sequence_preservation_strategies();  // Register sequence preservation strategies
    register_context_preservation_strategies();  // Register context preservation strategies
    register_string_instruction_strategies();  // Register string instruction null construction strategies (priority 45)
    register_lea_strategies();  // Register LEA strategies
    //     register_enhanced_conservative_mov_strategy();  // Register enhanced conservative strategy
    register_conservative_strategies();  // Register conservative strategies
    register_movzx_strategies();  // Register MOVZX/MOVSX strategies (priority 75)
    register_ret_strategies();  // Register RET immediate strategies (priority 78)
    register_socket_address_strategies(); // Register socket address null handling strategies (priority 77-80)
    register_arpl_strategies();  // Register ARPL ModR/M strategies (priority 75)
    register_ror_rol_strategies();  // Register ROR/ROL rotation strategies (priority 70)
    register_bound_strategies();  // Register BOUND ModR/M strategies (priority 70)
    register_conditional_jump_offset_strategies();  // Register conditional jump null-offset strategies (priority 150)
    register_getpc_strategies();  // Register GET PC (CALL/POP) strategies
    register_mov_strategies();  // Register all MOV strategies
    // DISABLED - NEW in 1d8cff3: register_xor_zero_reg_strategies();  // Register XOR register zeroing strategies (priority 100)
    register_arithmetic_strategies();  // Register all arithmetic strategies
    // DISABLED - NEW in 1d8cff3: register_arithmetic_const_generation_strategies();  // Register arithmetic/bitwise constant generation strategies (priority 75)
    register_adc_strategies();  // Register ADC (Add with Carry) strategies (priority 69-70)
    register_sbb_strategies();  // Register SBB (Subtract with Borrow) strategies (priority 69-70)
    register_setcc_strategies();  // Register SETcc (Conditional Set) strategies (priority 70-75)
    register_imul_strategies();  // Register IMUL (Signed Multiply) strategies (priority 71-72)
    register_fpu_strategies();  // Register x87 FPU strategies (priority 60)
    register_sldt_strategies();  // Register SLDT strategies (priority 60)
    register_xchg_strategies();  // Register XCHG strategies (priority 60)
    // DISABLED - NEW in 1d8cff3: register_xchg_immediate_loading_strategies();  // Register XCHG immediate loading strategies (priority 60)
    register_cmp_memory_disp_null_strategy();  // Register CMP memory displacement null strategies (priority 55)
    register_memory_strategies();  // Register all memory strategies
    register_cmp_strategies();  // Register CMP strategies (priority 85-88)
    // DISABLED - NEW in 1d8cff3: register_stack_string_const_strategies();  // Register stack-based string/constant construction strategies (priority 85)
    register_retf_strategies();  // Register RETF immediate strategies (priority 85)
    // register_custom_hash_strategies(); // DISABLED - broken implementation that introduces nulls instead of removing them
    register_memory_displacement_strategies(); // Register memory displacement null handling strategies (priority 82-85)
    // register_api_hashing_strategies(); // DISABLED - doesn't properly handle memory operands in CMP instructions
    // register_test_strategies(); // EXCLUDED FROM BUILD  // Register TEST strategies (priority 82)
    register_bt_strategies();  // Register BT (bit test) strategies (priority 80)
    // DISABLED - NEW in 1d8cff3: register_conditional_flag_strategies();  // Register conditional flag manipulation strategies (priority 90)
    register_jump_strategies();  // Register all jump strategies
    register_loop_strategies();  // Register all LOOP family strategies (priority 75-80)
    register_general_strategies();  // Register all general strategies
    register_sib_strategies(); // Register SIB addressing null elimination strategies (priority 65)
    register_register_chaining_strategies(); // Register register chaining strategies (priority 60-65)
    register_rip_relative_strategies(); // Register RIP-relative addressing null elimination strategies (priority 80)
    register_multibyte_nop_strategies(); // Register multi-byte NOP null elimination strategies (priority 90)
    register_immediate_split_strategies(); // Register immediate value splitting strategies (priority 77)
    register_small_immediate_strategies(); // Register small immediate value optimization strategies (priority 75)
    // register_arithmetic_substitution_strategies(); // Already registered by register_advanced_transformations() - DISABLED to avoid duplicate
    register_linux_socketcall_strategies(); // Register Linux socketcall strategies (priority 72-75)
    register_arithmetic_decomposition_strategies(); // Register MOV arithmetic decomposition strategies (priority 70)
    register_linux_string_push_strategies(); // Register Linux string push strategies (priority 68-70)
    register_syscall_number_strategies(); // Register Linux syscall number encoding strategies (priority 77-78)
    register_relative_jump_strategies(); // Register relative CALL/JMP displacement strategies (priority 85)
    register_large_immediate_strategies(); // Register large immediate value optimization strategies (priority 85)
    // register_ror13_hash_strategies(); // DISABLED - tries to handle memory operands as registers, causing errors
    register_rep_stosb_strategies(); // Register REP STOSB memory initialization strategies (priority 92) - was in 03bbf99
    register_salc_strategies(); // Register SALC AL zeroing optimization strategies (priority 91) - was in 03bbf99
    register_jcxz_null_safe_loop_termination_strategy(); // Register JCXZ null-safe loop termination strategy (priority 86)
    register_xchg_preservation_strategies(); // Register PUSH immediate optimization strategies (priority 86) - was in 03bbf99
    register_stack_string_strategies(); // Register stack-based string construction strategies (priority 85) - was in 03bbf99
    register_push_byte_immediate_stack_construction_strategy(); // Register PUSH byte immediate stack construction strategy (priority 82)
    register_arithmetic_constant_construction_sub_strategy(); // Register arithmetic constant construction via SUB strategy (priority 79)
    register_incremental_byte_register_syscall_strategy(); // Register incremental byte register syscall strategy (priority 78)
    register_word_inc_chain_nullfree_strategy(); // Register word-size INC chain null-free strategy (priority 77)
    register_salc_rep_stosb_strategies(); // Register SALC + REP STOSB strategies (priority 65)

    // Register our new Windows-specific strategies
    register_call_pop_immediate_strategies(); // Register CALL/POP immediate loading strategies (priority 85)
    register_shift_value_construction_strategies(); // Register shift value construction strategies (priority 78)
    register_lea_arithmetic_substitution_strategies(); // Register LEA arithmetic substitution strategies (priority 80)
    register_stack_string_construction_strategies(); // Register stack string construction strategies (priority 85)
    register_salc_conditional_flag_strategies(); // Register SALC + conditional flag strategies (priority 91)
    register_register_swapping_immediate_strategies(); // Register register swapping immediate strategies (priority 70)
    register_register_allocation_strategies(); // Register register allocation strategies for null avoidance (priority 78)

    // Register additional Windows-relevant denull strategies
    register_scasb_cmpsb_strategies(); // Register SCASB/CMPSB conditional operations strategies (priority 75)
    register_short_conditional_jump_strategies(); // Register short conditional jump strategies (priority 85)
    register_conditional_jump_displacement_strategies(); // Register conditional jump displacement strategies (priority 88)
    register_lea_complex_addressing_strategies(); // Register LEA complex addressing strategies (priority 80)
    register_lea_displacement_optimization_strategies(); // Register LEA displacement optimization strategies (priority 82)
    register_inc_dec_chain_strategies(); // Register INC/DEC chain strategies (priority 75)
    register_lea_arithmetic_calculation_strategies(); // Register LEA arithmetic calculation strategies (priority 78)
    register_push_pop_immediate_strategies(); // Register PUSH-POP immediate loading strategies (priority 77)
    register_bitwise_flag_manipulation_strategies(); // Register bitwise flag manipulation strategies (priority 72)
    register_salc_zero_flag_strategies(); // Register SALC zero flag strategies (priority 75)
    register_xchg_immediate_construction_strategies(); // Register XCHG immediate construction strategies (priority 70)

    register_syscall_strategies(); // Register Windows syscall direct invocation strategies (priority 95) - was in 03bbf99
    register_peb_api_resolution_strategies(); // Register enhanced PEB API resolution strategies (priority 87-89)
    register_unicode_string_strategies(); // Register Unicode (UTF-16) string handling strategies (priority 74-78)
    register_byte_construct_strategy(); // Register byte construction strategy
    // register_anti_debug_strategies();  // DISABLED - causes issues with non-NOP instructions
    register_shift_strategy();  // Register shift-based strategy
    // DISABLED - NEW in 1d8cff3: register_peb_api_hashing_strategies();  // Register PEB API hashing strategies (priority 95)
    // register_peb_strategies();  // ALSO DISABLE THIS - was causing inappropriate application to non-NOP instructions

    // Register our new advanced strategies
    register_advanced_hash_api_resolution_strategies(); // Register advanced hash-based API resolution strategies (priority 96)
    register_multi_stage_peb_traversal_strategies(); // Register multi-stage PEB traversal strategies (priority 97)
    register_stack_based_structure_construction_strategies(); // Register stack-based structure construction strategies (priority 94)

    register_new_strategies(); // Register new strategies for specific null-byte patterns

    // Register enhanced strategies for better null-byte elimination
    register_enhanced_mov_mem_strategies(); // Enhanced MOV memory strategies (high priority)
    register_enhanced_register_chaining_strategies(); // Enhanced register chaining strategies (medium priority)
    register_enhanced_arithmetic_strategies(); // Enhanced arithmetic strategies (high priority for arithmetic ops)
    register_enhanced_immediate_strategies(); // Enhanced immediate strategies (high priority for immediate ops)

    // Register improved strategies for better null-byte elimination
    register_improved_mov_strategies(); // Improved MOV strategies (high priority)
    register_improved_arithmetic_strategies(); // Improved arithmetic strategies (high priority)

    // Register final cleanup strategies for remaining nulls
    register_remaining_null_elimination_strategies(); // Final strategies for remaining nulls (highest priority)
    } // End x86/x64 architecture check

    else if (arch == BYVAL_ARCH_ARM) {
        #include "arm_strategies.h"
        register_arm_strategies();
    }

    else if (arch == BYVAL_ARCH_ARM64) {
        #include "arm64_strategies.h"
        register_arm64_strategies();
    }

    #ifdef DEBUG
    fprintf(stderr, "[DEBUG] Registered %d strategies\n", strategy_count);
    #endif
    // printf("init_strategies: Registered %d strategies.\n", strategy_count); // Removed debug print

    // Initialize ML strategy registry if ML is enabled
    if (use_ml && g_ml_initialized) {
        if (ml_strategy_registry_init(strategies, strategy_count) == 0) {
            printf("[ML] Strategy registry initialized with %d strategies\n", strategy_count);
        } else {
            fprintf(stderr, "[ML] WARNING: Failed to initialize strategy registry\n");
        }
    }
}

strategy_t** get_strategies_for_instruction(cs_insn *insn, int *count, byval_arch_t arch) {
    DEBUG_LOG("get_strategies_for_instruction called for instruction ID: 0x%x", insn->id);
    DEBUG_LOG("Instruction: %s %s", insn->mnemonic, insn->op_str);

    static strategy_t* applicable_strategies[MAX_STRATEGIES];
    int applicable_count = 0;

    for (int i = 0; i < strategy_count; i++) {
        // Filter by target architecture (using compatibility check for x86/x64)
        if (!is_strategy_arch_compatible(strategies[i], arch)) {
            continue;
        }
        DEBUG_LOG("  Trying strategy: %s", strategies[i]->name);
        if (strategies[i]->can_handle(insn)) {
            applicable_strategies[applicable_count++] = strategies[i];
            DEBUG_LOG("    Strategy %s can handle this instruction", strategies[i]->name);
        }
    }

    // Use ML-powered reprioritization if ML strategist is initialized
    // and we're not already in an ML operation (prevent recursion)
    if (g_ml_initialized && !g_ml_in_progress) {
        g_ml_in_progress = 1; // Set recursion guard

        // Use ML to reprioritize strategies
        ml_reprioritize_strategies(&g_ml_strategist, insn, applicable_strategies, &applicable_count);

        g_ml_in_progress = 0; // Clear recursion guard
    } else {
        // Sort strategies by priority (higher priority first) - traditional approach
        for (int i = 0; i < applicable_count - 1; i++) {
            for (int j = i + 1; j < applicable_count; j++) {
                if (applicable_strategies[i]->priority < applicable_strategies[j]->priority) {
                    strategy_t* temp = applicable_strategies[i];
                    applicable_strategies[i] = applicable_strategies[j];
                    applicable_strategies[j] = temp;
                }
            }
        }
    }

    DEBUG_LOG("  Found %d applicable strategies", applicable_count);
    if (applicable_count > 0) {
        DEBUG_LOG("  Using: %s (priority %d)", applicable_strategies[0]->name, applicable_strategies[0]->priority);
    }

    *count = applicable_count;
    return applicable_strategies;
}

// Utility functions
int is_mov_instruction(cs_insn *insn) {
    int result = (insn->id == X86_INS_MOV && 
            insn->detail->x86.op_count == 2 && 
            insn->detail->x86.operands[1].type == X86_OP_IMM);
    // printf("is_mov_instruction: insn->id=0x%x, op_count=%d, operand[1].type=%d, result=%d\n",
    //        insn->id, insn->detail->x86.op_count, insn->detail->x86.operands[1].type, result); // Removed debug print
    return result;
}

int is_arithmetic_instruction(cs_insn *insn) {
    return ((insn->id == X86_INS_ADD || insn->id == X86_INS_SUB || 
             insn->id == X86_INS_AND || insn->id == X86_INS_OR || 
             insn->id == X86_INS_XOR || insn->id == X86_INS_CMP) &&
            insn->detail->x86.op_count == 2 && 
            insn->detail->x86.operands[1].type == X86_OP_IMM);
}

int has_null_bytes(cs_insn *insn) {
    // Updated in v3.0: Now checks for generic bad bytes, not just null bytes
    // Function name kept for backward compatibility with 100+ strategy files
    return !is_bad_byte_free_buffer(insn->bytes, insn->size);
}

// Register the new strategies
void register_new_strategies() {
    // Re-enabled with low priority to handle specific patterns
    register_strategy(&transform_mov_reg_mem_self);
    register_strategy(&transform_add_mem_reg8);
    register_strategy(&delayed_string_termination_strategy);
}

/**
 * @brief Provide feedback to the ML strategist about strategy application
 * @param original_insn Original instruction that needed transformation
 * @param applied_strategy Strategy that was applied (can be NULL for fallback)
 * @param success Whether the strategy application was successful
 * @param new_shellcode_size Size of the resulting shellcode
 * @return 0 on success, non-zero on failure
 */
int provide_ml_feedback(cs_insn* original_insn,
                        strategy_t* applied_strategy,
                        int success,
                        size_t new_shellcode_size) {
    // Only provide ML feedback if ML is initialized and metrics are enabled
    if (!g_ml_initialized || !original_insn || g_ml_in_progress) {
        return -1;
    }

    // If no specific strategy was applied (e.g., fallback), we can still provide feedback
    // The ML model can learn from these general patterns as well
    g_ml_in_progress = 1; // Set recursion guard
    int result = ml_provide_feedback(&g_ml_strategist, original_insn, applied_strategy, success, new_shellcode_size);
    g_ml_in_progress = 0; // Clear recursion guard
    return result;
}

/**
 * @brief Cleanup the ML strategist resources
 */
void cleanup_ml_strategist() {
    if (g_ml_initialized) {
        ml_strategist_cleanup(&g_ml_strategist);
        g_ml_initialized = 0;
    }
}

/**
 * @brief Save the updated ML model to file
 * @param path Path to save the model to
 * @return 0 on success, non-zero on failure
 */
int save_ml_model(const char* path) {
    if (!g_ml_initialized || !path) {
        return -1;
    }

    return ml_strategist_save_model(&g_ml_strategist, path);
}

// Register the shift strategy (missing from shift_strategy.c)
void register_shift_strategy() {
    extern strategy_t shift_based_strategy;
    register_strategy(&shift_based_strategy);
}

// Register the RIP-relative strategy (missing from rip_relative_strategies.c)
void register_rip_relative_strategies() {
    extern strategy_t rip_relative_strategy;
    register_strategy(&rip_relative_strategy);
}

// Register the multi-byte NOP strategy (missing from multi_byte_nop_strategies.c)
void register_multibyte_nop_strategies() {
    extern strategy_t multibyte_nop_strategy;
    register_strategy(&multibyte_nop_strategy);
}

// Register the small immediate strategy (missing from small_immediate_strategies.c)
void register_small_immediate_strategies() {
    extern strategy_t small_immediate_strategy;
    register_strategy(&small_immediate_strategy);
}

// Register the relative jump strategy (missing from relative_jump_strategies.c)
void register_relative_jump_strategies() {
    extern strategy_t relative_jump_strategy;
    register_strategy(&relative_jump_strategy);
}

// Register the REP STOSB strategy (missing from rep_stosb_strategies.c)
void register_rep_stosb_strategies() {
    extern strategy_t rep_stosb_count_setup_strategy;
    register_strategy(&rep_stosb_count_setup_strategy);
}

// Register the SALC strategy (missing from salc_strategies.c)
void register_salc_strategies() {
    extern strategy_t salc_zero_al_strategy;
    register_strategy(&salc_zero_al_strategy);
}

// Register the PUSH immediate optimization strategy (missing from xchg_preservation_strategies.c)
void register_xchg_preservation_strategies() {
    extern strategy_t push_imm_preservation_strategy;
    register_strategy(&push_imm_preservation_strategy);
}

// Register the Linux string push strategy (missing from linux_string_push_strategies.c)
void register_linux_string_push_strategies() {
    extern strategy_t safe_string_push_strategy;
    extern strategy_t null_free_path_construction_strategy;
    register_strategy(&safe_string_push_strategy);
    register_strategy(&null_free_path_construction_strategy);
}

// Register the CALL/POP immediate loading strategy
void register_call_pop_immediate_strategies() {
    extern strategy_t call_pop_immediate_strategy;
    register_strategy(&call_pop_immediate_strategy);
}


// Register the shift-based value construction strategy
void register_shift_value_construction_strategies() {
    extern strategy_t shift_value_construction_strategy;
    register_strategy(&shift_value_construction_strategy);
}

// Register the LEA arithmetic substitution strategy
void register_lea_arithmetic_substitution_strategies() {
    extern strategy_t lea_arithmetic_substitution_strategy;
    register_strategy(&lea_arithmetic_substitution_strategy);
}

// Register the stack string construction strategy
void register_stack_string_construction_strategies() {
    extern strategy_t stack_string_construction_strategy;
    register_strategy(&stack_string_construction_strategy);
}


// Register the SALC conditional flag strategy
void register_salc_conditional_flag_strategies() {
    extern strategy_t salc_conditional_flag_strategy;
    register_strategy(&salc_conditional_flag_strategy);
}

// Register the register swapping immediate strategy
void register_register_swapping_immediate_strategies() {
    extern strategy_t register_swapping_immediate_strategy;
    register_strategy(&register_swapping_immediate_strategy);
}

// Register the partial register optimization strategy
void register_partial_register_optimization_strategies() {
    extern strategy_t partial_register_optimization_strategy;
    register_strategy(&partial_register_optimization_strategy);
}

// Register the segment register TEB/PEB access strategy
void register_segment_register_teb_peb_strategies() {
    extern strategy_t segment_register_teb_peb_strategy;
    register_strategy(&segment_register_teb_peb_strategy);
}

// Register the CMOV conditional move elimination strategy
void register_cmov_conditional_elimination_strategies() {
    extern strategy_t cmov_conditional_elimination_strategy;
    register_strategy(&cmov_conditional_elimination_strategy);
}

// Register the FPU stack immediate encoding strategy
void register_fpu_stack_immediate_encoding_strategies() {
    extern strategy_t fpu_stack_immediate_encoding_strategy;
    register_strategy(&fpu_stack_immediate_encoding_strategy);
}

// Register the XLAT table lookup strategy
void register_xlat_table_lookup_strategies() {
    extern strategy_t xlat_table_lookup_strategy;
    register_strategy(&xlat_table_lookup_strategy);
}

// Register the LAHF/SAHF flag preservation strategy
void register_lahf_sahf_flag_preservation_strategies() {
    extern strategy_t lahf_sahf_flag_preservation_strategy;
    register_strategy(&lahf_sahf_flag_preservation_strategy);
}

// Register the BSWAP endianness transformation strategy
void register_bswap_endianness_transformation_strategies() {
    extern strategy_t bswap_endianness_transformation_strategy;
    register_strategy(&bswap_endianness_transformation_strategy);
}

// Register the PUSHF/POPF bit manipulation strategy
void register_pushf_popf_bit_manipulation_strategies() {
    extern strategy_t pushf_popf_flag_manipulation_strategy;
    register_strategy(&pushf_popf_flag_manipulation_strategy);
}

// Register the bit scanning constant strategy
void register_bit_scanning_constant_strategies() {
    extern strategy_t bit_scanning_constant_strategy;
    register_strategy(&bit_scanning_constant_strategy);
}

// Register the LOOP comprehensive variants strategy
void register_loop_comprehensive_strategies() {
    extern strategy_t loop_comprehensive_strategy;
    register_strategy(&loop_comprehensive_strategy);
}

// Register the BCD arithmetic obfuscation strategy
void register_bcd_arithmetic_obfuscation_strategies() {
    extern strategy_t bcd_arithmetic_strategy;
    register_strategy(&bcd_arithmetic_strategy);
}

// Register the ENTER/LEAVE alternative encoding strategy
void register_enter_leave_alternative_encoding_strategies() {
    extern strategy_t enter_leave_strategy;
    register_strategy(&enter_leave_strategy);
}

// Register the POPCNT/LZCNT/TZCNT bit counting strategy
void register_bit_counting_constant_strategies() {
    extern strategy_t bit_counting_strategy;
    register_strategy(&bit_counting_strategy);
}

// Register the SIMD XMM register strategy
void register_simd_xmm_register_strategies() {
    extern strategy_t simd_xmm_strategy;
    register_strategy(&simd_xmm_strategy);
}

// Register the JECXZ/JRCXZ transformation strategy
void register_jecxz_jrcxz_transformation_strategies() {
    extern strategy_t jecxz_jrcxz_strategy;
    register_strategy(&jecxz_jrcxz_strategy);
}



