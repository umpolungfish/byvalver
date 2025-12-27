#include <stdio.h>
#include <capstone/capstone.h>

int main() {
    printf("X86_REG_AL = %d\n", X86_REG_AL);
    printf("X86_REG_CL = %d\n", X86_REG_CL);
    printf("X86_REG_DL = %d\n", X86_REG_DL);
    printf("X86_REG_BL = %d\n", X86_REG_BL);
    printf("X86_REG_AH = %d\n", X86_REG_AH);
    printf("X86_REG_CH = %d\n", X86_REG_CH);
    printf("X86_REG_DH = %d\n", X86_REG_DH);
    printf("X86_REG_BH = %d\n", X86_REG_BH);
    printf("\nRange check: X86_REG_AL(%d) to X86_REG_BH(%d)\n", X86_REG_AL, X86_REG_BH);
    return 0;
}
