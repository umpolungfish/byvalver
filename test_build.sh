#!/bin/bash
# Test script to verify the TUI build

echo "Testing byvalver TUI build..."

# Try to compile with TUI support
echo "Building with TUI support..."
make clean 2>/dev/null
make 2>&1 | grep -E "(error|warning)" > build_output.txt
if [ -s build_output.txt ]; then
    echo "BUILD FAILED - Check for errors/warnings:"
    cat build_output.txt
    exit 1
else
    echo "✓ Build completed successfully with no errors/warnings"
fi

# Test the no-tui build
echo "Building without TUI support..."
make clean 2>/dev/null
make no-tui 2>&1 | grep -E "(error|warning)" > build_output.txt
if [ -s build_output.txt ]; then
    echo "BUILD FAILED (no-tui) - Check for errors/warnings:"
    cat build_output.txt
    exit 1
else
    echo "✓ Build completed successfully without TUI (no errors/warnings)"
fi

# Clean up
rm -f build_output.txt

echo "All builds completed successfully!"