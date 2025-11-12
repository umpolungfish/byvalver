#!/usr/bin/env python3
"""
Enterprise-grade shellcode extractor with multiple format support
Supports C, C++, assembly, and other source formats
"""

import re
import sys
import os
from typing import Optional, List, Dict, Any


class ShellcodeExtractor:
    """
    Advanced shellcode extractor class supporting multiple formats
    """
    
    def __init__(self):
        self.patterns = [
            # Standard C-style arrays
            r'char\s+shellcode\s*\[\s*\]\s*=\s*(("(?:[^"]|\\.)*")\s*(?:,|\s|;|\\\s*\n)*)+',
            r'unsigned\s+char\s+shellcode\s*\[\s*\]\s*=\s*(("(?:[^"]|\\.)*")\s*(?:,|\s|;|\\\s*\n)*)+',
            r'unsigned\s+char\s+payload\s*\[\s*\]\s*=\s*(("(?:[^"]|\\.)*")\s*(?:,|\s|;|\\\s*\n)*)+',
            r'unsigned\s+char\s+code\s*\[\s*\]\s*=\s*(("(?:[^"]|\\.)*")\s*(?:,|\s|;|\\\s*\n)*)+',
            
            # Alternative formats
            r'static\s+const\s+unsigned\s+char\s+shellcode\s*\[\s*\]\s*=\s*(("(?:[^"]|\\.)*")\s*(?:,|\s|;|\\\s*\n)*)+',
            r'const\s+unsigned\s+char\s+shellcode\s*\[\s*\]\s*=\s*(("(?:[^"]|\\.)*")\s*(?:,|\s|;|\\\s*\n)*)+',
            
            # Raw hex strings (possibly multi-line)
            r'"((?:\\x[0-9a-fA-F]{2}\s*)+)"',
        ]
        
        self.hex_pattern = r'\\x[0-9a-fA-F]{2}'
    
    def extract_from_c_format(self, content: str) -> Optional[bytes]:
        """
        Extract shellcode from C-style array format
        """
        content = content.replace('\n', ' ').replace('\r', ' ')  # Normalize line endings
        
        for pattern in self.patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                # Extract the matched portion and parse hex values
                matched_content = match.group(0)
                
                # Extract all quoted strings
                quotes = re.findall(r'"((?:[^"]|\\.)*)"', matched_content)
                
                full_hex_string = ""
                for quote in quotes:
                    # Remove whitespace and add to the full hex string
                    clean_quote = re.sub(r'\s', '', quote)
                    full_hex_string += clean_quote
                
                # Find all hex values in the format \x## and convert
                hex_values = re.findall(self.hex_pattern, full_hex_string)
                if hex_values:
                    try:
                        shellcode_bytes = [int(hv[2:], 16) for hv in hex_values]
                        return bytes(shellcode_bytes)
                    except ValueError:
                        continue
        
        return None
    
    def extract_from_raw_format(self, content: str) -> Optional[bytes]:
        """
        Extract shellcode from raw hex format
        """
        # Remove comments and normalize
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)  # Block comments
        content = re.sub(r'//.*', '', content)  # Line comments
        
        # Look for raw hex strings
        raw_hex_match = re.search(r'"((?:[0-9a-fA-F]{2}\s*)+)"', content)
        if raw_hex_match:
            hex_string = raw_hex_match.group(1)
            clean_hex = re.sub(r'\s', '', hex_string)
            try:
                return bytes.fromhex(clean_hex)
            except ValueError:
                pass
        
        return None
    
    def extract_from_file(self, file_path: str) -> Optional[bytes]:
        """
        Extract shellcode from a file using multiple strategies
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Try different encodings
        encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
        content = None
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue
        
        if content is None:
            raise ValueError(f"Could not read file {file_path} with any supported encoding")
        
        # Try C-style format first
        shellcode = self.extract_from_c_format(content)
        if shellcode:
            return shellcode
        
        # Try raw format second
        shellcode = self.extract_from_raw_format(content)
        if shellcode:
            return shellcode
        
        return None


def analyze_shellcode(shellcode: bytes) -> Dict[str, Any]:
    """
    Analyze shellcode properties and generate statistics
    """
    analysis = {
        'length': len(shellcode),
        'null_bytes': shellcode.count(0),
        'null_percentage': (shellcode.count(0) / len(shellcode) * 100) if len(shellcode) > 0 else 0,
        'printable_bytes': sum(1 for b in shellcode if 32 <= b <= 126),
        'high_entropy_bytes': sum(1 for b in shellcode if b > 0x7F),
        'repeated_bytes': {},
        'common_instructions': [],
        'suspicious_patterns': []
    }
    
    # Count repeated bytes (potential NOPs, padding)
    for byte in shellcode:
        analysis['repeated_bytes'][byte] = analysis['repeated_bytes'].get(byte, 0) + 1
    
    # Find most common byte
    if analysis['repeated_bytes']:
        most_common_byte = max(analysis['repeated_bytes'].items(), key=lambda x: x[1])
        analysis['most_common_byte'] = most_common_byte
    
    return analysis


def main():
    if len(sys.argv) < 3:
        print("Usage: python extract_shellcode.py <input_file> <output_file>")
        print("Example: python extract_shellcode.py shellcode.c shellcode.bin")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    extractor = ShellcodeExtractor()
    
    try:
        shellcode = extractor.extract_from_file(input_file)
        
        if shellcode is None:
            print("Error: Could not extract shellcode from file", file=sys.stderr)
            sys.exit(1)
        
        # Analyze the extracted shellcode
        analysis = analyze_shellcode(shellcode)
        
        # Write to output file
        with open(output_file, 'wb') as f:
            f.write(shellcode)
        
        print(f"Shellcode extracted successfully to {output_file}")
        print(f"Shellcode length: {analysis['length']} bytes")
        print(f"Null bytes: {analysis['null_bytes']} ({analysis['null_percentage']:.2f}%)")
        print(f"Printable bytes: {analysis['printable_bytes']}")
        print(f"High entropy bytes (>0x7F): {analysis['high_entropy_bytes']}")
        
        if analysis['null_bytes'] > 0:
            print("\nWARNING: Shellcode contains null bytes - may require processing with BYVALVER")
        
        if analysis.get('most_common_byte'):
            byte_val, count = analysis['most_common_byte']
            if count > analysis['length'] * 0.2:  # More than 20% of shellcode
                print(f"NOTICE: High frequency byte ({hex(byte_val)}) appears {count} times ({count/analysis['length']*100:.1f}%)")
        
        # Verify extraction by checking file size
        actual_size = os.path.getsize(output_file)
        if actual_size != analysis['length']:
            print(f"WARNING: Expected {analysis['length']} bytes, wrote {actual_size} bytes", file=sys.stderr)
    
    except FileNotFoundError:
        print(f"Error: File {input_file} not found", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()