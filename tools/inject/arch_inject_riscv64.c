/*
 * arch_inject_riscv64.c -- RISC-V 64-bit backend STUB.
 *
 * Phase 6 placeholder. Planned implementation:
 *
 *   RV64 calling convention (rv64imafdc lp64d ABI):
 *     args: a0..a7  (x10..x17)
 *     return: a0 (and a1 for >64-bit)
 *     return-PC: ra (x1); `ret` is an alias for `jalr x0, x1, 0`
 *                -> set ra = trap_pc.
 *
 *   Linux RISC-V syscall ABI:
 *     nr: a7 (x17)
 *     args: a0..a5 (x10..x15)
 *     return: a0 (negative errno on failure)
 *     instruction: ECALL = 0x00000073 (always 4-byte; the C-extension
 *                  has no compressed ecall encoding)
 *
 *   PC alignment: RV64 PC must be 2-byte aligned (4 with the C-extension
 *   disabled). The trap_pc sentinel must respect this.
 *
 *   PTRACE_GETREGSET(NT_PRSTATUS): struct user_regs_struct with
 *   .pc and .regs[0..31] indexed by GPR number (regs[1] = ra, etc.).
 */

#include "arch_inject.h"

const struct inject_arch inject_arch_riscv64 = {
    .name              = "riscv64",
    .elf_machine       = EM_RISCV,
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
