/*
 * arch_inject_arm.c -- ARM (32-bit ARMv7) backend STUB.
 *
 * Phase 6 placeholder. Compiles cleanly into the cross build matrix so
 * that adding the real implementation later is a localised change.
 * At runtime, inject_attach() refuses with a clear message because
 * `supported = 0`.
 *
 * Planned implementation (when ready):
 *
 *   AAPCS32 (ARM EABI):
 *     args: r0..r3 (and stack for more)
 *     return: r0
 *     LR (r14): return address; function's BX LR / POP {..., pc}
 *               branches here -- we set it to trap_pc.
 *
 *   Linux ARM syscall ABI:
 *     nr: r7
 *     args: r0..r5
 *     return: r0
 *     instruction (ARM mode): SVC #0 = 0xEF000000
 *     instruction (Thumb mode): SVC #0 = 0xDF00 (16-bit)
 *
 *   Mode switching: ARM/Thumb mode is indicated by the LSB of the PC
 *   we set. The find_syscall_insn must scan for either encoding. Most
 *   libc on modern glibc-arm is built in ARM mode, but some musl /
 *   uClibc-ng builds use Thumb-only. Backend should prefer ARM-mode
 *   syscall sites when available and fall back to Thumb.
 *
 *   PTRACE_GETREGSET(NT_PRSTATUS) returns struct user_regs (16 uregs +
 *   uregs[15] = pc).
 */

#include "arch_inject.h"

const struct inject_arch inject_arch_arm = {
    .name              = "arm",
    .elf_machine       = EM_ARM,
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
