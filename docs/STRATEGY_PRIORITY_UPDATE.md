# Strategy Priority Update Summary

**Date:** 2025-12-19
**Change:** Renumbered strategies 1-4 to reflect implementation priority

## Strategy Renumbering

### Previous Order → New Order

| Old # | Old Strategy | New # | New Strategy |
|-------|--------------|-------|--------------|
| 1 | SIMD Register Zeroing | 4 | SIMD Register Zeroing |
| 2 | Syscall Number Obfuscation | 1 | Syscall Number Obfuscation |
| 3 | SETcc Flag Accumulation | 2 | SETcc Flag Accumulation |
| 4 | Negative Displacement Addressing | 3 | Negative Displacement Addressing |
| 5-10 | (unchanged) | 5-10 | (unchanged) |

## Rationale

**SIMD moved from #1 to #4** because:
- x64-only (30% applicability vs 60-90% for others)
- Modern CPUs only (SSE2+ required)
- Lower priority than syscall/conditional patterns
- Better suited for Tier 4 (Specialized) implementation

**Syscall, SETcc, Negative Displacement promoted to #1-3** because:
- Higher frequency in real-world shellcode
- Broader applicability (Linux syscalls, universal conditionals, standard addressing)
- More immediate impact on bad-character elimination success rates
- Better foundation for v3.1 release

## Updated Tier Assignments

### Tier 1: High Value, Medium Effort (v3.1)
1. **Syscall Number Obfuscation** (Priority 88)
2. **SETcc Flag Accumulation** (Priority 86)
3. **Polymorphic Immediate Construction** (Priority 90) - Strategy 6

### Tier 4: Specialized (v4.0+)
4. **SIMD Register Operations** (Priority 89)
5. **Self-Modifying Code** (Priority 75) - Strategy 10

## Files Updated

- `docs/NEW_STRATEGY_PROPOSALS.md` - Complete renumbering
  - Strategy sections 1-4 reordered
  - Tier 1-4 rankings updated
  - Size/performance table reordered
  - Summary and conclusion updated

## No Breaking Changes

This is a documentation-only change. No code has been implemented yet, so there are no breaking changes or migration requirements.
