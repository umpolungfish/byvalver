BITS 32

_start:
    mov eax, 0x12345678
    call _get_data
    db 'hello world', 0

_get_data:
    pop eax
    ret
