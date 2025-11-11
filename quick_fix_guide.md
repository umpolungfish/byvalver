# BYVALVER Quick Fix Guide

## Step-by-Step Fix Application

### Step 1: Backup Current Code
```bash
cd byvalver
git commit -am "Before critical fixes"
git tag broken-version
```

### Step 2: Replace Strategy Files
Replace these files with the fixed versions:

1. **src/mov_strategies.c** → Use `fix_mov_strategies.c`
2. **src/arithmetic_strategies.c** → Use `fix_arithmetic_strategies.c`
3. **src/general_strategies.c** → Use `fix_general_strategies.c`

### Step 3: Fix core.c
Add the `process_relative_jump()` function from `fix_core_complete.c` and update the main loop.

### Step 4: Disable Anti-Debug (Quick Fix)
In `src/strategy_registry.c`, comment out:
```c
void init_strategies() {
    strategy_count = 0;
    register_mov_strategies();
    register_arithmetic_strategies();
    register_memory_strategies();
    register_jump_strategies();
    register_general_strategies();
    // register_anti_debug_strategies();  // DISABLED - causes issues
    register_shift_strategy();
    register_peb_strategies();  // ALSO DISABLE THIS
}
```

### Step 5: Build and Test
```bash
make clean
make
./test_byvalver
```

Expected output:
```
=== Test: MOV BYTE PTR [eax], 0x0 ===
[PASS]

=== Test: CALL 0x5 ===
[PASS]

=== Test: SUB ESP, 0x100 ===
[PASS or known issue]

Total: At least 4/6 passed (up from 0/6)
```

### Step 6: Test on Real Shellcode
```bash
# Test with a simple shellcode
echo -ne '\xb8\x00\x00\x00\x00' > test_mov_eax_0.bin
./byvalver test_mov_eax_0.bin test_mov_eax_0_fixed.bin

# Verify output
xxd test_mov_eax_0_fixed.bin
# Should show something like: 31 c0 (xor eax, eax)
# NOT: c7 c0 ff ff ff ff f7 d0 (mov eax, 0xffffffff; not eax)
```

## Verification Checklist

After applying fixes, verify:

- [ ] MOV reg, imm32 is NOT confused with MOV [mem], imm
- [ ] CALL instructions don't disappear
- [ ] SUB ESP, 0x100 produces valid output (may still need work)
- [ ] No anti-debug code injected into normal shellcode
- [ ] NOP sequences remain unchanged
- [ ] Output disassembles correctly

## Common Issues After Fixes

### Issue: SUB ESP still broken
**Cause**: Arithmetic strategies only handle reg, imm - not memory operands
**Fix**: Add separate strategy for memory arithmetic operations

### Issue: Some jumps still have nulls
**Cause**: Conditional jumps need special handling
**Solution**: The fixed code handles this with opposite-condition skips

### Issue: Code size increased significantly
**Expected**: Yes, null-free code is usually larger
**If excessive**: Check that anti-debug code isn't being injected

## Rollback Plan

If fixes break more than they fix:
```bash
git reset --hard broken-version
```

Then apply fixes one file at a time and test after each.

## Success Criteria

Fixes are successful when:
1. test_byvalver shows 4+ tests passing (up from 0)
2. Real shellcode outputs disassemble correctly
3. No semantic changes (memory vs register operands)
4. No instructions silently deleted

## Next Steps After Basic Fixes

1. Add memory operand handling for arithmetic
2. Improve test coverage
3. Add validation to main.c
4. Remove dead code
5. Document remaining limitations
