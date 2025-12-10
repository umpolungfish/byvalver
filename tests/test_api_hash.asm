; A simple test case to trigger the hash_based_api_resolution strategy.
; It contains a CALL instruction with a null byte in the immediate operand.
bits 64
call 0x00401000
