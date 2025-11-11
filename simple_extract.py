import re

# Read the C file
with open('shellcode_51208.c', 'r') as f:
    content = f.read()

# Extract the payload using a more specific regex that handles multi-line strings
lines = content.split('\n')
payload_lines = []

in_payload = False
for line in lines:
    line = line.strip()
    if 'unsigned char payload[] =' in line:
        in_payload = True
        # Remove 'unsigned char payload[] =' and quotes
        line = line.replace('unsigned char payload[] =', '').strip()
        if line.startswith('"') and line.endswith('";'):
            line = line[1:-2]  # Remove starting and ending quotes
            payload_lines.append(line)
        elif line.startswith('"'):
            line = line[1:]  # Remove starting quote
            payload_lines.append(line)
        continue
    
    if in_payload:
        if line.endswith('";'):
            line = line[:-2]  # Remove ending quote and semicolon
            payload_lines.append(line)
            break
        elif line.endswith('"'):
            line = line[:-1]  # Remove ending quote
            payload_lines.append(line)
            continue
        else:
            payload_lines.append(line)

# Join all payload lines and remove whitespace
full_payload = ''.join(payload_lines).replace(' ', '').replace('\t', '').replace('\n', '')

# Remove all \x prefixes
full_payload = full_payload.replace('\\x', '')

# Convert to bytes
shellcode = bytes.fromhex(full_payload)

# Write to binary file
with open('shellcode_51208.bin', 'wb') as f:
    f.write(shellcode)

print(f"Shellcode extracted successfully to shellcode_51208.bin")
print(f"Shellcode length: {len(shellcode)} bytes")

# Check for null bytes
null_count = shellcode.count(0)
print(f"Null bytes found: {null_count}")