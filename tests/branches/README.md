# Branches

This is a test to verify that all branch instructions are decoded correctly.

According to the Arm Embedded Trace Macrocell Architecture Specification ETMv4.0 to ETMv4.6 F.1 Branch instructions, a list of branch instructions is as follows. In this test, instructions with strike-through are not supported.

* A64 instruction set, direct branches:
  * B
  * B.cond
  * CBZ/CBNZ
  * TBZ/BNZ
  * BL
  * ISB
  * ~WFI, WFE~

* A64 instruction set, indirect branches:
  * RET
  * BR
  * BLR
  * ~ERET~
  * ~ERETAA/ERETAB, RETAA/RETAB, BRAA/BRAB, BRAAZ/BRABZ, BLRAA/BLRAB, BLRAAZ/BLRABZ~

The trace results of `branches.c`, which contains all the above branch instructions, are saved as `trace1`, `trace2`, `trace3`, and `trace4`. The implementation of the decoder is verified by comparing the edge coverage calculated from these traces with the edge coverage manually created beforehand.
