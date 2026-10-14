    .set noreorder
    .set noat
    .set mips32r2
    .text
    .globl _start
    .ent _start
_start:
    mtc0  $0, $12            # Status=0: kernel mode, BEV=0 (vector @0x80000180), IE=0
    ehb
    la    $29, _stack_top
    la    $8, __bss_start
    la    $9, __bss_end
1:  sltu  $10, $8, $9
    beqz  $10, 2f
    nop
    sw    $0, 0($8)
    addiu $8, $8, 4
    b     1b
    nop
2:  jal   test_main
    nop
3:  b     3b
    nop
    .end _start
