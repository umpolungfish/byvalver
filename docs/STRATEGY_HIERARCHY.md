# BYVALVER Strategy Priority Hierarchy

This document details the current priority hierarchy of all null-elimination strategies in BYVALVER.

## COMPLETE STRATEGY PRIORITY LIST (Sorted by Priority: Lowest to Highest)

### Priority 3:
- `jump_strategies` - Absolute last resort fallback (lowest priority)

### Priority 5:
- `shift_strategy` - Last resort when other strategies can't handle
- `safe_sib_strategies` - Lowest priority to avoid conflicts

### Priority 15:
- `sequence_preservation_strategies` - Optimized PUSH operations
- `context_preservation_strategies` - INC/DEC operations

### Priority 25:
- `getpc_strategies` - Fallback when other techniques don't apply

### Priority 45:
- `string_instruction_strategies` - Lower priority, more complex approach

### Priority 50:
- `salc_rep_stosb_strategies` - Medium-low priority

### Priority 55:
- `cmp_memory_disp_null_strategy` - Medium priority

### Priority 60:
- `fpu_strategies` - FPU strategies
- `xchg_strategies` - XCHG strategies

### Priority 65:
- `sib_strategies` - SIB addressing

### Priority 68:
- `linux_string_push_strategies` - Medium-high priority for path operations

### Priority 69:
- `adc_strategies` - ADC strategies (multiple instances)
- `sbb_strategies` - SBB strategies (multiple instances)

### Priority 70:
- `arithmetic_decomposition_strategies` - Sophisticated fallback
- `bound_strategies` - BOUND ModR/M strategies
- `enhanced_register_chaining_strategies` - Medium-high priority
- `linux_socketcall_strategies` - High priority for socket operations

### Priority 71-72:
- `imul_strategies` - IMUL strategies
- `bitwise_flag_manipulation_strategies` - Medium priority

### Priority 75:
- `memory_displacement_strategies` - Memory displacement strategies (range 82-85)
- `movzx_strategies` - Critical for Windows API resolution
- `small_immediate_strategies` - High priority for size optimization
- `loop_strategies` - LOOP strategies

### Priority 77:
- `socket_address_strategies` - High priority for port numbers
- `immediate_split_strategies` - High priority for immediate splitting

### Priority 78:
- `ret_strategies` - High priority (75-80 range)

### Priority 80:
- `lea_complex_addressing_strategies` - High priority
- `bt_strategies` - BT strategies
- `rip_relative_strategies` - High priority for x64 shellcode

### Priority 85:
- `relative_jump_strategies` - High priority for control flow operations
- `cmp_strategies` - CMP strategies (85-88 range)
- `retf_strategies` - RETF immediate strategies
- `large_immediate_strategies` - High priority

### Priority 86:
- `xchg_preservation_strategies` - High priority for common pattern

### Priority 90:
- `multi_byte_nop_strategies` - Critical priority for compiler-generated code

### Priority 91:
- `salc_strategies` - SALC AL zeroing optimization strategies

### Priority 92:
- `rep_stosb_strategies` - Higher than ROR13 - more efficient for memory counts

### Priority 95:
- `syscall_strategies` - Very high priority - more efficient than ROR13
- `sldt_replacement_strategy` - Highest priority - critical hardware limitation

### Priority 100:
- `indirect_call_strategies` - Highest priority - critical Windows API resolution pattern

### Priority 150:
- `conditional_jump_offset_strategies` - Very high priority - handles critical case

### Priority 160:
- `remaining_null_elimination_strategies` - Highest priority for final cleanup (higher than conditional jumps at 150)

## DISABLED STRATEGIES:
- `xor_zero_reg_strategies` (100 priority) - Disabled (NEW in 1d8cff3)
- `arithmetic_const_generation_strategies` (75 priority) - Disabled (NEW in 1d8cff3)  
- `stack_string_const_strategies` (85 priority) - Disabled (NEW in 1d8cff3)
- `conditional_flag_strategies` (90 priority) - Disabled (NEW in 1d8cff3)
- `xchg_immediate_loading_strategies` (60 priority) - Disabled (NEW in 1d8cff3)
- `peb_api_hashing_strategies` (95 priority) - Disabled (NEW in 1d8cff3)
- `peb_strategies` - Also disabled - causing inappropriate application to non-NOP instructions
- `anti_debug_strategies` - Disabled - causes issues with non-NOP instructions
- Multiple other strategies disabled due to bugs or conflicts