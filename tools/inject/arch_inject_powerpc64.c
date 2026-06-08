/*
 * arch_inject_powerpc64.c -- PowerPC 64-bit backend STUB (BE + LE).
 *
 * Phase 6 placeholder. Planned implementation:
 *
 *   PowerPC64 ELFv1 (BE) and ELFv2 (LE) ABIs:
 *     args: r3..r10
 *     return: r3 (with extras in r4 for >64-bit return; not needed for us)
 *     return-PC: lr; `blr` returns.
 *
 *   ELFv1 (BE) gotcha: a function's address is the address of its
 *   function descriptor (a struct of {entry_pc, toc_ptr, env}) in
 *   the .opd section, NOT its entry-point PC. To call a function:
 *     load r12 = function_descriptor->entry_pc
 *     load r2  = function_descriptor->toc_ptr
 *     ctr = r12; mtctr ctr; bctrl
 *   We need to set r2 correctly when calling glibc functions, else
 *   they segfault on the first TOC-relative load.
 *
 *   ELFv2 (LE): functions have local + global entry points (libcov's
 *   gen_patchlist.py handles this for instrumentation). For an injected
 *   call we should target the GLOBAL entry (which sets up r2 from r12).
 *   Set r12 = function_addr; r2 doesn't matter (global entry computes it).
 *
 *   Linux PowerPC64 syscall ABI:
 *     nr: r0
 *     args: r3..r8
 *     return: r3; cr0.SO on error
 *     instruction: sc = 0x44000002 (BE), 0x02000044 (LE bytes)
 *
 *   PTRACE_GETREGSET(NT_PRSTATUS): struct user_regs (64-bit GPRs;
 *   PT_R0..PT_R31, PT_NIP, PT_LNK, PT_CTR).
 */

#include "arch_inject.h"

const struct inject_arch inject_arch_powerpc64 = {
    .name              = "powerpc64",
    .elf_machine       = EM_PPC64,
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
