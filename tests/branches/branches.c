/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

// A64 instruction set, direct branches:
//     - B
//     - B.cond
//     - CBZ/CBNZ
//     - TBZ/BNZ
//     - BL
//     - ISB

void execute_b_instruction()
{
    // taken
    __asm__ volatile (
        "       nop \n" /* dummy */
        "       b end_b \n"
        "       nop \n" /* dummy */
        "end_b: nop \n"
    );
}

void execute_bcond_instruction()
{
    // taken -> taken -> taken -> not taken
    int input = 4;
    __asm__ volatile (
        "   nop \n" /* dummy */
        "1: subs %[input], %[input], #1 \n" /* decrement register */
        "   nop \n" /* dummy */
        "   bne 1b \n" /* if not zero, loop */
        "   nop \n" /* dummy */
        :
        : [input] "r" (input)
        : );
}

void execute_cbz_instruction()
{
    // taken
    int  input = 0;
    __asm__ volatile (
        "   nop \n" /* dummy */
        "   cbz %[input], 1f \n" /* if input is zero, branch */
        "   nop \n" /* dummy */
        "1: nop \n"
        :
        : [input] "r" (input)
        : );

    // not taken
    input = 1;
    __asm__ volatile (
        "   nop \n" /* dummy */
        "   cbz %[input], 1f \n" /* if input is zero, branch */
        "   nop \n" /* dummy */
        "1: nop \n"
        :
        : [input] "r" (input)
        : );
}

void execute_cbnz_instruction()
{
    // taken
    int  input = 1;
    __asm__ volatile (
        "   nop \n" /* dummy */
        "   cbnz %[input], 1f \n" /* if input is not zero, branch */
        "   nop \n" /* dummy */
        "1: nop \n"
        :
        : [input] "r" (input)
        : );

    // not taken
    input = 0;
    __asm__ volatile (
        "   nop \n" /* dummy */
        "   cbnz %[input], 1f \n" /* if input is not zero, branch */
        "   nop \n" /* dummy */
        "1: nop \n"
        :
        : [input] "r" (input)
        : );
}

void execute_tbz_instruction()
{
    // taken
    int  input = 0;
    __asm__ volatile (
        "   nop \n" /* dummy */
        "   tbz %[input], #0, 1f \n" /* if the 0th bit of input is zero, branch */
        "   nop \n" /* dummy */
        "1: nop \n"
        :
        : [input] "r" (input)
        : );

    // not taken
    input = 1;
    __asm__ volatile (
        "   nop \n" /* dummy */
        "   tbz %[input], #0, 1f \n" /* if the 0th bit of input is zero, branch */
        "   nop \n" /* dummy */
        "1: nop \n"
        :
        : [input] "r" (input)
        : );
}

void execute_tbnz_instruction()
{
    // taken
    int  input = 1;
    __asm__ volatile (
        "   nop \n" /* dummy */
        "   tbnz %[input], #0, 1f \n" /* if the 0th bit of input is not zero, branch */
        "   nop \n" /* dummy */
        "1: nop \n"
        :
        : [input] "r" (input)
        : );

    // not taken
    input = 0;
    __asm__ volatile (
        "   nop \n" /* dummy */
        "   tbnz %[input], #0, 1f \n" /* if the 0th bit of input is not zero, branch */
        "   nop \n" /* dummy */
        "1: nop \n"
        :
        : [input] "r" (input)
        : );
}

void execute_bl_instruction()
{
    __asm__ volatile (
        "           nop \n" /* dummy */
        "           mov x0, x30 \n" /* save return address */
        "           bl bl_target \n"
        "           mov x30, x0 \n" /* load return address */
        "           ret \n" /* return from this function */
        "bl_target: nop \n"
        "           ret \n"
        :
        :
        : "x0" );
}

void execute_ibs_instruction()
{
    __asm__ volatile (
        "isb \n"
        "isb \n"
    );
}



// A64 instruction set, indirect branches:
//     - RET
//     - BR
//     - BLR

void execute_ret_instruction()
{
    __asm__ volatile (
        "nop \n" /* dummy */
        "ret \n"
    );
}

void execute_br_instruction()
{
    __asm__ volatile (
        "           nop \n" /* dummy */
        "           adr x0, br_target \n"
        "           br x0 \n" /* jump br_target */
        "br_target: nop\n"
        "           nop \n" /* dummy */
        :
        :
        : "x0" );
}

void execute_blr_instruction()
{
    __asm__ volatile (
        "            nop \n" /* dummy */
        "            mov x1, x30 \n" /* save return address */
        "            adr x0, blr_target \n"
        "            blr x0 \n" /* jump blr_target */
        "            mov x30, x1 \n" /* load return address */
        "            ret \n" /* return from this function */
        "blr_target: nop \n"
        "            nop \n" /* dummy */
        "            ret \n"
        :
        :
        : "x0", "x1" );
}

int main() {
    // direct branch
    execute_b_instruction();
    execute_bcond_instruction();
    execute_cbz_instruction();
    execute_cbnz_instruction();
    execute_tbz_instruction();
    execute_tbnz_instruction();
    execute_bl_instruction();
    execute_ibs_instruction();

    // indirect branch
    execute_ret_instruction();
    execute_br_instruction();
    execute_blr_instruction();

    return 0;
}
