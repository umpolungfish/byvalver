#!/bin/bash

echo "Testing all .binzzz/ files..."
echo ""

total=0
success=0

for f in .binzzz/*.bin; do
    filename=$(basename "$f")
    echo "=== Testing $filename ==="

    ./bin/byvalver "$f" "/tmp/test_$filename" 2>&1 | grep -E "(Original|Modified)"

    result=$(python3 verify_nulls.py "/tmp/test_$filename" 2>&1 | grep -E "(Found|SUCCESS)")
    echo "$result"

    if echo "$result" | grep -q "SUCCESS"; then
        ((success++))
    fi
    ((total++))
    echo ""
done

echo "========================================="
echo "FINAL RESULTS: $success/$total files with 100% null elimination"
echo "========================================="
