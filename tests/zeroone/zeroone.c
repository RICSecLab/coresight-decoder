#include <stdio.h>

#define IFBRANCH(buf, idx, var) \
    __asm__ volatile ( \
        "   cmp %1, #0x31;" \
        "   b.eq 1f;" /* if bit is one, branch taken */ \
        "   mov %0, #0;" \
        "   b 2f;" \
        "1: mov %0, #1;" \
        "   b 2f;" \
        "2: nop;" /* dummy */ \
        : "=r" (var) \
        : "r" (buf[idx]) \
        : )

int main(int argc, char *argv[]) {
    const char *buf = argv[1];

    volatile int a, b, c, d, e, f, g, h;

    // do not put this into loop because we want to see control flow graph
    IFBRANCH(buf, 0, a);
    IFBRANCH(buf, 1, b);
    IFBRANCH(buf, 2, c);
    IFBRANCH(buf, 3, d);
    IFBRANCH(buf, 4, e);
    IFBRANCH(buf, 5, f);
    IFBRANCH(buf, 6, g);
    IFBRANCH(buf, 7, h);

    printf("Result: %d%d%d%d%d%d%d%d\n", a, b, c, d, e, f, g, h);
}
