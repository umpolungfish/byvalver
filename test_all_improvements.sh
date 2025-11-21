#!/bin/bash
# Test all shellcode files and measure improvement

count=0
success=0
improved=0
previous_failures=6  # module_2, module_4, module_5, module_6, uhmento, uhmento_buttered

echo "Testing all files in .binzz/..."
echo "========================================"

for f in .binzz/*.bin; do
    if [ -f "$f" ]; then
        count=$((count+1))
        base=$(basename "$f" .bin)
        output=".binzz/${base}_processed.bin"

        # Process the file
        ./bin/byvalver "$f" "$output" >/dev/null 2>&1

        # Check if it's null-free
        if python3 verify_nulls.py "$output" 2>&1 | grep -q "SUCCESS"; then
            success=$((success+1))
        fi
    fi
done

echo "========================================"
echo "Total files processed: $count"
echo "Files with 100% null elimination: $success"
echo "Success rate: $((success*100/count))%"
echo ""
echo "Previous success rate: 46/52 = 88.5%"
echo "New success rate: $success/$count"
echo ""
if [ $success -gt 46 ]; then
    echo "Improvement: $((success-46)) additional files now null-free!"
fi
