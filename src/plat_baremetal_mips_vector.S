/*
 * plat_baremetal_mips_vector.S -- MIPS general-exception trampoline.
 *
 * libcov_vector_entry is reached from the CPU's general exception vector
 * (standard 0x80000180 when BEV=0, EBase=0x80000000; the integrator installs
 * a jump to here via plat_trap_install). It is the baremetal analogue of the
 * Linux SIGILL sigaction handler:
 *
 *   - read CP0 Cause; if ExcCode != 10 (Reserved Instruction) or the branch-
 *     delay (BD) bit is set, this trap is not ours -> chain to the integrator's
 *     handler (weak libcov_bm_vector_chain; spin if none, which never happens
 *     once the real OS handler is chained).
 *   - otherwise spill the full GPR set + EPC + Cause (+ HI/LO) into g_bm_frame,
 *     switch to a private exception stack, call the C dispatcher, reload the
 *     (possibly emulate-advanced) EPC and GPRs, and ERET.
 *
 * k0/k1 ($26/$27) are the architectural kernel-scratch registers and are free
 * to clobber in exception context; we do not preserve the interrupted code's
 * k0/k1 (MIPS convention). Register slots in the frame are 64-bit to match
 * glibc greg_t / the libcov_frame layout; 32-bit values are sign-extended.
 */
    .set noreorder
    .set noat
    .set mips32r2

    .section .bss
    .align 3
    .globl g_bm_frame
g_bm_frame:     .space 272          /* gpr[32]*8 + epc(8) + cause(4) + pad */
save_hilo:      .space 8
    .align 3
exc_stack:      .space 8192
exc_stack_top:

    .macro SAVEREG n, reg            /* big-endian: high word low addr, low word high addr */
    sra     $1, \reg, 31
    sw      $1, (\n*8)($27)          /* high 32 (sign-extension) */
    sw      \reg, (\n*8+4)($27)     /* low 32 (the register value) */
    .endm

    .macro LOADREG n, reg
    lw      \reg, (\n*8+4)($27)     /* low 32 (the register value) */
    .endm

    .text
    .globl libcov_vector_entry
    .ent libcov_vector_entry
libcov_vector_entry:
    mfc0    $26, $13                /* k0 = Cause */
    srl     $27, $26, 2
    andi    $27, $27, 0x1f          /* ExcCode */
    addiu   $27, $27, -10           /* RI == 10 ? */
    bnez    $27, libcov_vec_chain
    nop
    srl     $27, $26, 31            /* Cause.BD */
    bnez    $27, libcov_vec_chain
    nop

    /* ---- ours: spill context ---- */
    la      $27, g_bm_frame
    sw      $1, 12($27)             /* save $1 (at): low 32 at +12 (BE) */
    sra     $1, $1, 31
    sw      $1, 8($27)              /* high 32 at +8; $1 now free as scratch */
    SAVEREG 2,  $2
    SAVEREG 3,  $3
    SAVEREG 4,  $4
    SAVEREG 5,  $5
    SAVEREG 6,  $6
    SAVEREG 7,  $7
    SAVEREG 8,  $8
    SAVEREG 9,  $9
    SAVEREG 10, $10
    SAVEREG 11, $11
    SAVEREG 12, $12
    SAVEREG 13, $13
    SAVEREG 14, $14
    SAVEREG 15, $15
    SAVEREG 16, $16
    SAVEREG 17, $17
    SAVEREG 18, $18
    SAVEREG 19, $19
    SAVEREG 20, $20
    SAVEREG 21, $21
    SAVEREG 22, $22
    SAVEREG 23, $23
    SAVEREG 24, $24
    SAVEREG 25, $25
    SAVEREG 28, $28
    SAVEREG 29, $29
    SAVEREG 30, $30
    SAVEREG 31, $31
    sw      $0, 0($27)              /* gpr[0] = 0 */
    sw      $0, 4($27)
    sw      $0, 208($27)            /* gpr[26]=k0: not preserved */
    sw      $0, 212($27)
    sw      $0, 216($27)            /* gpr[27]=k1: not preserved */
    sw      $0, 220($27)

    sw      $26, 264($27)           /* frame.cause (uint32 at +264) */
    mfc0    $26, $14                /* EPC */
    sw      $0,  256($27)           /* frame.epc high 32 = 0 (BE) */
    sw      $26, 260($27)           /* frame.epc low 32 = EPC */

    la      $26, save_hilo          /* preserve HI/LO around the C call */
    mfhi    $1
    sw      $1, 0($26)
    mflo    $1
    sw      $1, 4($26)

    la      $29, exc_stack_top      /* private exception stack */
    la      $4,  g_bm_frame         /* a0 = &frame */
    la      $25, libcov_trap_dispatch
    jalr    $25
    nop

    /* ---- restore ---- */
    la      $26, save_hilo
    lw      $1, 0($26)
    mthi    $1
    lw      $1, 4($26)
    mtlo    $1

    la      $27, g_bm_frame
    lw      $26, 260($27)           /* (possibly advanced) EPC low 32 */
    mtc0    $26, $14
    ehb
    LOADREG 2,  $2
    LOADREG 3,  $3
    LOADREG 4,  $4
    LOADREG 5,  $5
    LOADREG 6,  $6
    LOADREG 7,  $7
    LOADREG 8,  $8
    LOADREG 9,  $9
    LOADREG 10, $10
    LOADREG 11, $11
    LOADREG 12, $12
    LOADREG 13, $13
    LOADREG 14, $14
    LOADREG 15, $15
    LOADREG 16, $16
    LOADREG 17, $17
    LOADREG 18, $18
    LOADREG 19, $19
    LOADREG 20, $20
    LOADREG 21, $21
    LOADREG 22, $22
    LOADREG 23, $23
    LOADREG 24, $24
    LOADREG 25, $25
    LOADREG 28, $28
    LOADREG 29, $29
    LOADREG 30, $30
    LOADREG 31, $31
    lw      $1, 12($27)             /* restore $1 (at) low 32, last */
    eret
    nop

libcov_vec_chain:
    /* Not our RI. Jump to the integrator's chain handler if one is linked
     * (the real OS exception path); otherwise spin -- a configuration error
     * that only happens if a non-RI exception reaches an uninstrumented OS. */
    la      $27, libcov_bm_vector_chain
    beqz    $27, 9f
    nop
    jr      $27
    nop
9:  b       9b
    nop
    .end libcov_vector_entry

    .weak libcov_bm_vector_chain
