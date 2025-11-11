import sys

shellcode = b"\x81\xc3\x00\x00\x00\x01"

with open("shellcode.bin", "wb") as f:
    f.write(shellcode)