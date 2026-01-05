#!/bin/bash
# Script to identify and report all hardcoded SIB byte 0x20 usage
# This helps identify files that still need to be updated

echo "=== Scanning for hardcoded SIB byte 0x20 ==="
echo ""

# Find all instances
grep -rn "0x20}" src/*.c 2>/dev/null | grep -E "(0x04, 0x20|0x20})" > /tmp/sib_instances.txt

if [ ! -s /tmp/sib_instances.txt ]; then
    echo "✓ No instances of hardcoded SIB 0x20 found!"
    exit 0
fi

echo "Found $(wc -l < /tmp/sib_instances.txt) instances of potential hardcoded SIB 0x20"
echo ""

echo "=== Files affected ==="
cut -d: -f1 /tmp/sib_instances.txt | sort -u | while read file; do
    count=$(grep -c "^$file:" /tmp/sib_instances.txt)
    echo "  $file ($count instances)"
done

echo ""
echo "=== Detailed instances ==="
cat /tmp/sib_instances.txt | while IFS=: read file line content; do
    echo "$file:$line"
    echo "  $content"
    echo ""
done

echo ""
echo "=== Recommendations ==="
echo "Each instance should be reviewed and replaced with:"
echo "  1. Add: #include \"profile_aware_sib.h\""
echo "  2. Replace {0x8B, 0x04, 0x20} with generate_safe_mov_reg_mem()"
echo "  3. Replace {0x89, 0x04, 0x20} with generate_safe_mov_mem_reg()"
echo "  4. Replace {0x8D, 0x04, 0x20} with generate_safe_lea_reg_mem()"
echo "  5. Update size estimation functions (+6 bytes for compensation)"
echo ""

echo "Priority files to fix:"
cut -d: -f1 /tmp/sib_instances.txt | sort -u | head -10

rm /tmp/sib_instances.txt
