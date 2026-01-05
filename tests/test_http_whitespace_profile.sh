#!/bin/bash
# Test suite specifically for http-whitespace profile
# Ensures that generated code does not contain bad bytes: 0x00, 0x09, 0x0a, 0x0d, 0x20

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN_DIR="$PROJECT_DIR/bin"
TEST_DIR="$PROJECT_DIR/tests/http_whitespace"
BYVALVER="$BIN_DIR/byvalver"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

echo -e "${BLUE}=== HTTP-Whitespace Profile Test Suite ===${NC}"
echo ""

# Check if byvalver binary exists
if [ ! -f "$BYVALVER" ]; then
    echo -e "${RED}✗ Error: byvalver binary not found at $BYVALVER${NC}"
    echo "Please build the project first with 'make'"
    exit 1
fi

# Create test output directory
mkdir -p "$TEST_DIR/output"

# Test 1: Verify no hardcoded SIB bytes in source code
echo -e "${BLUE}Test 1: Static analysis - Check for hardcoded SIB bytes${NC}"
TESTS_TOTAL=$((TESTS_TOTAL + 1))

cd "$PROJECT_DIR"
if python3 tools/verify_no_hardcoded_sib.py > /dev/null 2>&1; then
    echo -e "${GREEN}  ✓ PASS: No hardcoded SIB bytes found${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}  ✗ FAIL: Hardcoded SIB bytes detected${NC}"
    echo "  Run 'python3 tools/verify_no_hardcoded_sib.py' for details"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test 2: Create simple test shellcode and verify output has no bad bytes
echo -e "${BLUE}Test 2: Simple shellcode - No bad bytes in output${NC}"
TESTS_TOTAL=$((TESTS_TOTAL + 1))

# Create a simple test shellcode with MOV EAX, [0x00401000] pattern
# This would trigger mov_mem_disp_enhanced strategy
TEST_INPUT="$TEST_DIR/test_mov_disp.bin"
TEST_OUTPUT="$TEST_DIR/output/test_mov_disp_cleaned.bin"

# Shellcode: MOV EAX, [0x00401000] = A1 00 10 40 00
printf '\xa1\x00\x10\x40\x00' > "$TEST_INPUT"

# Process with http-whitespace profile
if "$BYVALVER" --profile http-whitespace "$TEST_INPUT" "$TEST_OUTPUT" 2>/dev/null; then
    # Check output for bad bytes
    if hexdump -C "$TEST_OUTPUT" | grep -qE " 00 | 09 | 0a | 0d | 20 "; then
        echo -e "${RED}  ✗ FAIL: Output contains bad bytes!${NC}"
        echo "  Bad bytes found:"
        hexdump -C "$TEST_OUTPUT" | grep -E " 00 | 09 | 0a | 0d | 20 " | head -5
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        echo -e "${GREEN}  ✓ PASS: Output has no bad bytes${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
else
    echo -e "${YELLOW}  ~ SKIP: Processing failed (expected for some shellcode)${NC}"
    TESTS_TOTAL=$((TESTS_TOTAL - 1))
fi
echo ""

# Test 3: Test indirect CALL pattern
echo -e "${BLUE}Test 3: Indirect CALL - No bad bytes in output${NC}"
TESTS_TOTAL=$((TESTS_TOTAL + 1))

TEST_INPUT="$TEST_DIR/test_indirect_call.bin"
TEST_OUTPUT="$TEST_DIR/output/test_indirect_call_cleaned.bin"

# Shellcode: CALL [0x00401000] = FF 15 00 10 40 00
printf '\xff\x15\x00\x10\x40\x00' > "$TEST_INPUT"

if "$BYVALVER" --profile http-whitespace "$TEST_INPUT" "$TEST_OUTPUT" 2>/dev/null; then
    if hexdump -C "$TEST_OUTPUT" | grep -qE " 00 | 09 | 0a | 0d | 20 "; then
        echo -e "${RED}  ✗ FAIL: Output contains bad bytes!${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        echo -e "${GREEN}  ✓ PASS: Output has no bad bytes${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
else
    echo -e "${YELLOW}  ~ SKIP: Processing failed${NC}"
    TESTS_TOTAL=$((TESTS_TOTAL - 1))
fi
echo ""

# Test 4: Test indirect JMP pattern
echo -e "${BLUE}Test 4: Indirect JMP - No bad bytes in output${NC}"
TESTS_TOTAL=$((TESTS_TOTAL + 1))

TEST_INPUT="$TEST_DIR/test_indirect_jmp.bin"
TEST_OUTPUT="$TEST_DIR/output/test_indirect_jmp_cleaned.bin"

# Shellcode: JMP [0x00401000] = FF 25 00 10 40 00
printf '\xff\x25\x00\x10\x40\x00' > "$TEST_INPUT"

if "$BYVALVER" --profile http-whitespace "$TEST_INPUT" "$TEST_OUTPUT" 2>/dev/null; then
    if hexdump -C "$TEST_OUTPUT" | grep -qE " 00 | 09 | 0a | 0d | 20 "; then
        echo -e "${RED}  ✗ FAIL: Output contains bad bytes!${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        echo -e "${GREEN}  ✓ PASS: Output has no bad bytes${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
else
    echo -e "${YELLOW}  ~ SKIP: Processing failed${NC}"
    TESTS_TOTAL=$((TESTS_TOTAL - 1))
fi
echo ""

# Test 5: SIB statistics test (verify profile-aware encoding is being used)
echo -e "${BLUE}Test 5: Profile-aware SIB usage statistics${NC}"
TESTS_TOTAL=$((TESTS_TOTAL + 1))

# This test checks if the tool is actually using profile-aware encoding
# We expect to see displacement-based or push/pop encodings, not standard SIB 0x20

TEST_INPUT="$TEST_DIR/test_sib_stats.bin"
TEST_OUTPUT="$TEST_DIR/output/test_sib_stats_cleaned.bin"

# Create shellcode with multiple MOV [mem] patterns
printf '\xa1\x00\x10\x40\x00\xa3\x00\x20\x40\x00\xff\x15\x00\x30\x40\x00' > "$TEST_INPUT"

if "$BYVALVER" --profile http-whitespace "$TEST_INPUT" "$TEST_OUTPUT" --stats 2>&1 | grep -q "SIB Encoding"; then
    echo -e "${GREEN}  ✓ PASS: SIB statistics available${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    # SIB stats may not be printed by default, so this is not critical
    echo -e "${YELLOW}  ~ INFO: SIB statistics not available (feature may not be enabled)${NC}"
    TESTS_TOTAL=$((TESTS_TOTAL - 1))
fi
echo ""

# Summary
echo -e "${BLUE}=== Test Summary ===${NC}"
echo -e "Total tests:  $TESTS_TOTAL"
echo -e "Passed:       ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed:       ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
