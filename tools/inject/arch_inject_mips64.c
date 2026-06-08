/*
 * arch_inject_mips64.c -- MIPS64 (mips64, mips64el) backend STUB.
 *
 * Phase 6 placeholder. Planned implementation parallels arch_inject_mips.c
 * but uses the N64 ABI:
 *
 *   N64 ABI:
 *     args: $4..$11 (a0..a7); 9th+ on stack
 *     return: $2 (v0)
 *     return-PC: $31 (ra)
 *
 *   Linux MIPS64 syscall ABI:
 *     nr: $2 (v0) with the offset 5000 added (the N64 syscall numbers
 *         live in a separate range from N32/O32)
 *     args: $4..$9 (a0..a5)
 *     return: $2 (v0); error indicator in $7 (a3) like O32
 *     instruction: SYSCALL = same opcode as MIPS32
 *
 *   Endianness: identical handling to MIPS32. The backend uses native
 *   word loads/stores at runtime; the cross-compiler sets the
 *   endianness via -EL/-EB.
 *
 *   prstatus regset: same struct shape as MIPS32 but 64-bit regs.
 */

#include "arch_inject.h"

const struct inject_arch inject_arch_mips64 = {
    .name              = "mips64",
    .elf_machine       = EM_MIPS,    /* MIPS64 also reports EM_MIPS; the
                                        EI_CLASS byte (ELFCLASS64) tells
                                        them apart. The selector uses
                                        e_machine + ei_class for MIPS. */
    .supported         = 0,
    .setup_call        = NULL,
    .setup_syscall     = NULL,
    .get_retval        = NULL,
    .get_pc            = NULL,
    .set_pc            = NULL,
    .find_syscall_insn = NULL,
    .pm_shellcode      = NULL,
    .pm_build_sigframe = NULL,
};
