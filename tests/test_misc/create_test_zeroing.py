#!/usr/bin/env python3

import subprocess
import sys
import os

def assemble_to_shellcode(asm_file, output_file):
    """Assemble an assembly file to raw shellcode"""
    try:
        # Assemble to object file
        obj_file = "temp.o"
        subprocess.run(["nasm", "-f", "bin", asm_file, "-o", output_file], check=True)
        print(f"Successfully assembled {asm_file} to {output_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error assembling file: {e}")
        return False
    except FileNotFoundError:
        print("Error: 'nasm' not found. Please install NASM assembler.")
        return False

def main():
    asm_file = "test_zeroing.asm"
    output_file = "test_zeroing.bin"
    
    if not os.path.exists(asm_file):
        print(f"Assembly file {asm_file} does not exist.")
        return 1
        
    success = assemble_to_shellcode(asm_file, output_file)
    
    if success:
        print(f"Shellcode created: {output_file}")
        # Print the file size
        size = os.path.getsize(output_file)
        print(f"File size: {size} bytes")
        return 0
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())