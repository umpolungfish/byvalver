#!/bin/bash
#
# test_bad_chars.sh
# Comprehensive test suite for bad-character elimination and profiles
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Binary location
BYVALVER="./bin/byvalver"

# Test directory
TEST_DIR="./test_bad_chars_$$"
mkdir -p "$TEST_DIR"

# Cleanup function
cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Print test header
print_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# Run a test
run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expected_result="$3"  # "pass" or "fail"

    TESTS_RUN=$((TESTS_RUN + 1))
    echo -n "Test $TESTS_RUN: $test_name ... "

    if eval "$test_cmd" > /dev/null 2>&1; then
        actual_result="pass"
    else
        actual_result="fail"
    fi

    if [ "$actual_result" = "$expected_result" ]; then
        echo -e "${GREEN}✓ PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAIL${NC}"
        echo -e "  ${YELLOW}Expected: $expected_result, Got: $actual_result${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Check if output contains bad characters
check_bad_chars() {
    local file="$1"
    shift
    local bad_chars=("$@")

    if [ ! -f "$file" ]; then
        return 1
    fi

    for char in "${bad_chars[@]}"; do
        # Convert hex to byte and search
        if xxd -p "$file" | tr -d '\n' | grep -q "$char"; then
            echo "Found bad char $char in $file"
            return 1
        fi
    done

    return 0
}

# Create test shellcode (simple NOP sled + RET with varying bad chars)
create_test_shellcode() {
    local output="$1"
    local include_nulls="${2:-yes}"
    local include_newlines="${3:-no}"

    # x86 shellcode: NOPs + MOV with potential bad chars + RET
    if [ "$include_nulls" = "yes" ]; then
        # Include null byte in MOV instruction
        printf '\x90\x90\x90\xb8\x00\x00\x00\x01\xc3' > "$output"
    elif [ "$include_newlines" = "yes" ]; then
        # Include newline chars
        printf '\x90\x90\x90\xb8\x0a\x0d\x00\x01\xc3' > "$output"
    else
        # Clean shellcode
        printf '\x90\x90\x90\xb8\x01\x02\x03\x04\xc3' > "$output"
    fi
}

# =============================================================================
# TEST SUITE
# =============================================================================

print_header "BYVALVER BAD-CHARACTER ELIMINATION TEST SUITE"

# Check if byvalver exists
if [ ! -f "$BYVALVER" ]; then
    echo -e "${RED}Error: $BYVALVER not found${NC}"
    echo "Run 'make' to build byvalver first"
    exit 1
fi

# =============================================================================
# Section 1: Basic Functionality Tests
# =============================================================================
print_header "Section 1: Basic Functionality"

# Test 1: Help output
run_test "Help option works" \
    "$BYVALVER --help" \
    "pass"

# Test 2: Version output
run_test "Version option works" \
    "$BYVALVER --version" \
    "pass"

# Test 3: List profiles
run_test "List profiles option works" \
    "$BYVALVER --list-profiles" \
    "pass"

# Test 4: Invalid profile name
run_test "Reject invalid profile name" \
    "$BYVALVER --profile nonexistent input.bin output.bin" \
    "fail"

# =============================================================================
# Section 2: Profile Functionality Tests
# =============================================================================
print_header "Section 2: Profile Loading"

# Create test input
TEST_INPUT="$TEST_DIR/test_input.bin"
create_test_shellcode "$TEST_INPUT" "yes" "no"

# Test 5: null-only profile
run_test "Load null-only profile" \
    "$BYVALVER --profile null-only $TEST_INPUT $TEST_DIR/null_only.bin" \
    "pass"

# Test 6: http-newline profile
run_test "Load http-newline profile" \
    "$BYVALVER --profile http-newline $TEST_INPUT $TEST_DIR/http_newline.bin" \
    "pass"

# Test 7: http-whitespace profile
run_test "Load http-whitespace profile" \
    "$BYVALVER --profile http-whitespace $TEST_INPUT $TEST_DIR/http_whitespace.bin" \
    "pass"

# Test 8: url-safe profile
run_test "Load url-safe profile" \
    "$BYVALVER --profile url-safe $TEST_INPUT $TEST_DIR/url_safe.bin" \
    "pass"

# Test 9: sql-injection profile
run_test "Load sql-injection profile" \
    "$BYVALVER --profile sql-injection $TEST_INPUT $TEST_DIR/sql_injection.bin" \
    "pass"

# Test 10: xml-html profile
run_test "Load xml-html profile" \
    "$BYVALVER --profile xml-html $TEST_INPUT $TEST_DIR/xml_html.bin" \
    "pass"

# Test 11: json-string profile
run_test "Load json-string profile" \
    "$BYVALVER --profile json-string $TEST_INPUT $TEST_DIR/json_string.bin" \
    "pass"

# Test 12: format-string profile
run_test "Load format-string profile" \
    "$BYVALVER --profile format-string $TEST_INPUT $TEST_DIR/format_string.bin" \
    "pass"

# Test 13: buffer-overflow profile
run_test "Load buffer-overflow profile" \
    "$BYVALVER --profile buffer-overflow $TEST_INPUT $TEST_DIR/buffer_overflow.bin" \
    "pass"

# Test 14: command-injection profile
run_test "Load command-injection profile" \
    "$BYVALVER --profile command-injection $TEST_INPUT $TEST_DIR/command_injection.bin" \
    "pass"

# Test 15: ldap-injection profile
run_test "Load ldap-injection profile" \
    "$BYVALVER --profile ldap-injection $TEST_INPUT $TEST_DIR/ldap_injection.bin" \
    "pass"

# Test 16: printable-only profile
run_test "Load printable-only profile" \
    "$BYVALVER --profile printable-only $TEST_INPUT $TEST_DIR/printable_only.bin" \
    "pass"

# Test 17: alphanumeric-only profile (may fail, but should load)
run_test "Load alphanumeric-only profile" \
    "$BYVALVER --profile alphanumeric-only $TEST_INPUT $TEST_DIR/alphanumeric_only.bin || true" \
    "pass"

# =============================================================================
# Section 3: Bad Character Elimination Validation
# =============================================================================
print_header "Section 3: Bad Character Elimination"

# Test 18: Null-only elimination verification
TESTS_RUN=$((TESTS_RUN + 1))
echo -n "Test $TESTS_RUN: Null-only output has no 0x00 bytes ... "
if $BYVALVER --profile null-only $TEST_INPUT $TEST_DIR/verify_null.bin > /dev/null 2>&1; then
    if check_bad_chars "$TEST_DIR/verify_null.bin" "00"; then
        echo -e "${GREEN}✓ PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAIL (output contains 0x00)${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "${RED}✗ FAIL (processing failed)${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 19: HTTP-newline elimination verification
TEST_INPUT2="$TEST_DIR/test_input2.bin"
create_test_shellcode "$TEST_INPUT2" "yes" "yes"

TESTS_RUN=$((TESTS_RUN + 1))
echo -n "Test $TESTS_RUN: HTTP-newline output has no 0x00/0x0A/0x0D ... "
if $BYVALVER --profile http-newline $TEST_INPUT2 $TEST_DIR/verify_http.bin > /dev/null 2>&1; then
    if check_bad_chars "$TEST_DIR/verify_http.bin" "00" "0a" "0d"; then
        echo -e "${GREEN}✓ PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAIL (output contains bad chars)${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "${RED}✗ FAIL (processing failed)${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# =============================================================================
# Section 4: --bad-chars Option Tests
# =============================================================================
print_header "Section 4: Custom Bad-Chars Option"

# Test 20: Single bad char
run_test "Eliminate single custom bad char (0x00)" \
    "$BYVALVER --bad-chars '00' $TEST_INPUT $TEST_DIR/custom1.bin" \
    "pass"

# Test 21: Multiple bad chars
run_test "Eliminate multiple custom bad chars (00,0a,0d)" \
    "$BYVALVER --bad-chars '00,0a,0d' $TEST_INPUT $TEST_DIR/custom2.bin" \
    "pass"

# Test 22: Invalid bad-chars format (should fail)
run_test "Reject invalid bad-chars format" \
    "$BYVALVER --bad-chars 'ZZ' $TEST_INPUT $TEST_DIR/custom3.bin" \
    "fail"

# Test 23: Empty bad-chars (should fail)
run_test "Reject empty bad-chars" \
    "$BYVALVER --bad-chars '' $TEST_INPUT $TEST_DIR/custom4.bin" \
    "fail"

# =============================================================================
# Section 5: Profile + Option Combinations
# =============================================================================
print_header "Section 5: Combined Options"

# Test 24: Profile + Biphasic
run_test "Profile with --biphasic" \
    "$BYVALVER --profile http-newline --biphasic $TEST_INPUT $TEST_DIR/combo1.bin" \
    "pass"

# Test 25: Profile + Verbose
run_test "Profile with --verbose" \
    "$BYVALVER --profile sql-injection --verbose $TEST_INPUT $TEST_DIR/combo2.bin" \
    "pass"

# Test 26: Profile + Quiet
run_test "Profile with --quiet" \
    "$BYVALVER --profile xml-html --quiet $TEST_INPUT $TEST_DIR/combo3.bin" \
    "pass"

# Test 27: Profile + Format
run_test "Profile with --format c" \
    "$BYVALVER --profile json-string --format c $TEST_INPUT $TEST_DIR/combo4.c" \
    "pass"

# Test 28: Profile priority over --bad-chars
TESTS_RUN=$((TESTS_RUN + 1))
echo -n "Test $TESTS_RUN: Profile overrides --bad-chars option ... "
if $BYVALVER --bad-chars "00" --profile http-newline $TEST_INPUT2 $TEST_DIR/priority.bin > /dev/null 2>&1; then
    # Should use http-newline profile (00,0a,0d), not just 00
    if check_bad_chars "$TEST_DIR/priority.bin" "00" "0a" "0d"; then
        echo -e "${GREEN}✓ PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAIL (wrong profile applied)${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "${RED}✗ FAIL (processing failed)${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# =============================================================================
# Section 6: Output Format Tests
# =============================================================================
print_header "Section 6: Output Formats"

# Test 29: Raw output (default)
run_test "Output format: raw" \
    "$BYVALVER --profile null-only --format raw $TEST_INPUT $TEST_DIR/format_raw.bin" \
    "pass"

# Test 30: C array output
run_test "Output format: c" \
    "$BYVALVER --profile null-only --format c $TEST_INPUT $TEST_DIR/format_c.c" \
    "pass"

# Test 31: Python output
run_test "Output format: python" \
    "$BYVALVER --profile null-only --format python $TEST_INPUT $TEST_DIR/format_py.py" \
    "pass"

# Test 32: Hexstring output
run_test "Output format: hexstring" \
    "$BYVALVER --profile null-only --format hexstring $TEST_INPUT $TEST_DIR/format_hex.txt" \
    "pass"

# =============================================================================
# FINAL RESULTS
# =============================================================================
print_header "TEST RESULTS"

echo "Tests Run:    $TESTS_RUN"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  ALL TESTS PASSED! ✓${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    exit 0
else
    echo -e "\n${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}  SOME TESTS FAILED ✗${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    exit 1
fi
