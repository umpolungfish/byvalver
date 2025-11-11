import re

# Read the C file
with open('/home/mrnob0dy666/GREPO/exploitdb/shellcodes/linux_x86/36637.c', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Use regex to find all hex values in the shellcode declaration
import re
# Find the part between quotes in the shellcode array
shellcode_match = re.search(r'char shellcode\[\] = "(.*?)"\s*;', content, re.DOTALL)
if shellcode_match:
    shellcode_str = shellcode_match.group(1)
    # Remove all whitespace and newlines
    shellcode_str = re.sub(r'\s+', '', shellcode_str)
    # Remove the \x prefixes
    hex_string = shellcode_str.replace('\\x', '')
    # Convert to bytes
    bytes_list = [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]
    shellcode = bytes(bytes_list)
else:
    # Fallback to regex approach
    hex_values = re.findall(r'\\x[0-9a-fA-F]{2}', content)
    shellcode_bytes = [int(hv[2:], 16) for hv in hex_values]
    shellcode = bytes(shellcode_bytes)

# Write to binary file
with open('shellcode_36637.bin', 'wb') as f:
    f.write(shellcode)

print(f"Shellcode extracted successfully to shellcode_36637.bin")
print(f"Shellcode length: {len(shellcode)} bytes")

# Check for null bytes
null_count = shellcode.count(0)
print(f"Null bytes found: {null_count}")