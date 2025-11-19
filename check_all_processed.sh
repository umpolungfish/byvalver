#!/bin/bash
echo "=== NULL BYTE VERIFICATION REPORT ==="
echo ""
for f in .binzzz/processed/*.bin; do
  name="${f##*/}"
  nulls=$(python3 verify_nulls.py "$f" 2>&1 | grep "Found" | grep -oE "[0-9]+ null" | cut -d' ' -f1)
  size=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null)
  if [ "$nulls" = "0" ]; then
    echo "✓ $name - $size bytes - CLEAN"
  else
    echo "✗ $name - $size bytes - $nulls null bytes"
  fi
done
