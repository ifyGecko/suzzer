/*
 * arch_inject_powerpc.c -- PowerPC 32-bit backend STUB.
 *
 * Phase 6 placeholder. Planned implementation:
 *
 *   PowerPC ELF ABI (32-bit System V):
 *     args: r3..r10
 *     return: r3
 *     return-PC: lr (special-purpose register, not a GPR); function's
 *                `blr` (branch to LR) returns. -> set lr = trap_pc.
 *
 *   Linux PowerPC syscall ABI:
 *     nr: r0
 *     args: r3..r8
 *     return: r3; cr0.SO (summary overflow bit of condition register 0)
 *             set on error, in which case r3 holds errno.
 *     instruction: sc = 0x44000002 (BE) / 02 00 00 44 (LE)
 *
 *   PTRACE_GETREGSET(NT_PRSTATUS): struct user_regs (PT_R0..PT_R31,
 *   PT_NIP for PC, PT_LNK for LR). Index by PT_* macros, not raw offsets.
 *
 *   Endianness: 32-bit PowerPC on Linux is essentially always BE; the
 *   build matrix above doesn't include a LE 32-bit variant.
 */

#include "arch_inject.h"

const struct inject_arch inject_arch_powerpc = {
    .name              = "powerpc",
    .elf_machine       = EM_PPC,
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
