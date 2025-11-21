# Action Plan - Fix The Real Bug

## Current Situation
- byvalver builds successfully
- NO segfault on small files (progress!)
- **Real bug: Produces 0-byte output files**

## Debug Evidence
```
[DEBUG] Runtime errors when processing loop_test.bin:
- src/core.c:44: null pointer passed to memcpy (argument 1 = data)
- src/main.c:103: null pointer in fwrite (final_shellcode.data is NULL)
Original shellcode size: 47
Modified shellcode size: 0  ← THE PROBLEM
```

## Root Cause

**Some strategy's `generate()` function is calling `buffer_append(buf, NULL, size)`**

This causes:
1. Runtime error in memcpy
2. No data written to buffer
3. Final output is empty

## How To Fix (Simple)

**Step 1: Add NULL check to buffer_append**
```c
// src/core.c, line 35
void buffer_append(struct buffer *b, const uint8_t *data, size_t size) {
    if (!data || size == 0) return;  // ADD THIS LINE
    if (b->size + size > b->capacity) {
        ...
    }
    memcpy(b->data + b->size, data, size);
    b->size += size;
}
```

**Step 2: Find which strategy passes NULL**
- Run with debug and check which instruction causes the NULL
- Add debug logging in buffer_append to print caller
- Or: add assert(!data) to crash with stack trace

**Step 3: Fix that strategy**
- Once we know which strategy, fix its generate() function
- Likely one of the recent strategies (XCHG, CMP, RET, LOOP, etc.)

## User: Should I Proceed?

I can:
**A)** Add the NULL check to buffer_append and retest
**B)** Add debug logging to find the bad strategy
**C)** Both A and B
**D)** Something else you suggest

This is a much simpler fix than all my previous attempts. The code isn't fundamentally broken - just one strategy has a bug.
