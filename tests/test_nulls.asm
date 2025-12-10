.intel_syntax noprefix
.section .text
.global _start

_start:
    /* mov eax, 0x1000000  - contains nulls */
    mov eax, 0x01000000
    
    /* mov ebx, 0x00200000 - contains nulls */
    mov ebx, 0x00200000
    
    /* add ecx, 0x00000400 - contains nulls */
    add ecx, 0x00000400
    
    /* cmp edx, 0x00000005 - contains nulls */
    cmp edx, 0x00000005
    
    /* mov [0x40000000], eax - null in address */
    mov [0x40000000], eax
    
    /* Exit syscall */
    mov eax, 1      /* sys_exit */
    mov ebx, 0      /* exit status */
    int 0x80