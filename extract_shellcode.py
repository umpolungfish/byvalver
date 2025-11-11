import re

def extract_shellcode_from_c(filename):
    with open(filename, 'r') as f:
        content = f.read()

    # Find the payload line - handle multi-line strings
    payload_match = re.search(r'unsigned char payload\[\] =\s*("(?:[^"]|\\.)*")\s*;', content, re.DOTALL)
    if payload_match:
        shellcode_str = payload_match.group(1)
        # Remove quotes and split by quotes to handle multi-line strings
        # Remove newlines, quotes, and whitespace
        shellcode_str = re.sub(r'\s+', '', shellcode_str)
        # Remove quotes and handle multi-line hex strings
        # Use a different approach - split and process
        # Find all hex values between quotes
        hex_parts = re.findall(r'"((?:\\x[0-9a-fA-F]{2})*)"', content)
        if hex_parts:
            full_hex = ''.join(hex_parts)
            # Remove the \x prefixes
            full_hex = full_hex.replace('\\x', '')
            # Convert to bytes
            return bytes.fromhex(full_hex)
    
    # Alternative pattern for the second example
    code_match = re.search(r'unsigned char code\[\] =\s*("(?:[^"]|\\.)*")\s*;', content, re.DOTALL)
    if code_match:
        code_str = code_match.group(1)
        hex_parts = re.findall(r'"((?:\\x[0-9a-fA-F]{2})*)"', code_str)
        if hex_parts:
            full_hex = ''.join(hex_parts)
            full_hex = full_hex.replace('\\x', '')
            return bytes.fromhex(full_hex)
    
    # Third pattern for the other example
    shellcode_match = re.search(r'char shellcode\[\] =\s*("(?:[^"]|\\.)*")\s*;', content, re.DOTALL)
    if shellcode_match:
        shellcode_str = shellcode_match.group(1)
        hex_parts = re.findall(r'"((?:\\x[0-9a-fA-F]{2})*)"', shellcode_str)
        if hex_parts:
            full_hex = ''.join(hex_parts)
            full_hex = full_hex.replace('\\x', '')
            return bytes.fromhex(full_hex)
    
    return None

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python extract_shellcode.py <input_file> <output_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    shellcode = extract_shellcode_from_c(input_file)
    if shellcode:
        with open(output_file, 'wb') as f:
            f.write(shellcode)
        print(f"Shellcode extracted successfully to {output_file}")
        print(f"Shellcode length: {len(shellcode)} bytes")
        
        # Check for null bytes
        null_count = shellcode.count(b'\x00')
        print(f"Null bytes found: {null_count}")
    else:
        print("Could not extract shellcode from file")