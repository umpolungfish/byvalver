#!/bin/bash
# Test byvalver optimization on various exploit-db shellcodes

# Array of x86 shellcode files to test
files=(
    "windows_x86/51208.asm"
    "windows_x86/50722.asm"
    "linux_x86/36637.c"
    "windows_x86/49466.asm"
    "windows_x86/43768.asm"
    "windows_x86/13514.asm"
    "windows_x86/13565.asm"
)

echo "Testing byvalver optimization on null-free shellcodes from exploit-db..."
echo

for file in "${files[@]}"; do
    if [ -f "/home/mrnob0dy666/GREPO/exploitdb/shellcodes/$file" ]; then
        echo "Processing: $file"
        
        # Extract shellcode from the file
        if [[ "$file" == *.c ]]; then
            # For C files, extract payload
            python3 -c "
import re
with open('/home/mrnob0dy666/GREPO/exploitdb/shellcodes/$file', 'r') as f:
    content = f.read()
# Look for different payload patterns
import re
hex_values = re.findall(r'\\\\x[0-9a-fA-F]{2}', content)
if hex_values:
    shellcode_bytes = [int(hv[2:], 16) for hv in hex_values]
    shellcode = bytes(shellcode_bytes)
    with open('${file//\//_}.bin', 'wb') as f:
        f.write(shellcode)
    print(f'Extracted {len(shellcode)} bytes to ${file//\//_}.bin')
"
        else
            # For .asm files, look for shellcode in comments or use a different approach
            python3 -c "
import re
with open('/home/mrnob0dy666/GREPO/exploitdb/shellcodes/$file', 'r') as f:
    content = f.read()
# Look for shellcode in various formats
hex_values = re.findall(r'\\\\x[0-9a-fA-F]{2}', content)
if not hex_values:
    # Try looking for hex values without \\x prefix in code blocks
    hex_values = re.findall(r'[A-Fa-f0-9]{2}', content.replace('\\\\', ''))
if hex_values:
    # Filter out non-hex patterns
    valid_hex = []
    for hex_val in hex_values:
        try:
            int_val = int(hex_val, 16)
            valid_hex.append(int_val)
        except ValueError:
            pass
    if valid_hex:
        shellcode = bytes(valid_hex)
        with open('${file//\//_}.bin', 'wb') as f:
            f.write(shellcode)
        print(f'Extracted {len(shellcode)} bytes to ${file//\//_}.bin')
    else:
        print('No hex values found')
else:
    shellcode_bytes = [int(hv[2:], 16) for hv in hex_values]
    shellcode = bytes(shellcode_bytes)
    with open('${file//\//_}.bin', 'wb') as f:
        f.write(shellcode)
    print(f'Extracted {len(shellcode)} bytes to ${file//\//_}.bin')
"
        fi
        
        # Check if we successfully created a binary file
        bin_file="${file//\//_}.bin"
        if [ -f "$bin_file" ]; then
            # Count original null bytes
            orig_nulls=$(python3 -c "print(sum(1 for b in open('$bin_file', 'rb').read() if b == 0))")
            orig_size=$(stat -c%s "$bin_file")
            echo "  Original: $orig_size bytes, $orig_nulls null bytes"
            
            # Process with byvalver
            ./bin/byvalver "$bin_file" "processed_$bin_file" > /dev/null 2>&1
            
            if [ -f "processed_$bin_file" ]; then
                # Count processed null bytes
                proc_nulls=$(python3 -c "print(sum(1 for b in open('processed_$bin_file', 'rb').read() if b == 0))")
                proc_size=$(stat -c%s "processed_$bin_file")
                
                echo "  Processed: $proc_size bytes, $proc_nulls null bytes"
                
                # Calculate change
                size_change=$((proc_size - orig_size))
                if [ $size_change -lt 0 ]; then
                    echo "  Optimization: $((size_change * -1)) bytes smaller"
                elif [ $size_change -gt 0 ]; then
                    echo "  Size increase: $size_change bytes"
                else
                    echo "  Size unchanged"
                fi
                echo
            else
                echo "  Failed to process with byvalver"
                echo
            fi
        else
            echo "  Could not extract shellcode"
            echo
        fi
    else
        echo "File not found: /home/mrnob0dy666/GREPO/exploitdb/shellcodes/$file"
        echo
    fi
done