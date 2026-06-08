/*
 * arch_inject_aarch64.c -- aarch64 (ARMv8 64-bit) backend.
 *
 * Implements the full ptrace-variant ABI. The aarch64 ABI is friendlier
 * than x86_64 for our purposes because the return address lives in a
 * register (x30 = LR) rather than on the stack -- no stack manipulation
 * or memory write needed to plant the trap_pc.
 *
 * Key aarch64 facts used here:
 *
 *   Register set layout: PTRACE_GETREGSET with NT_PRSTATUS returns a
 *   `struct user_pt_regs` (asm/ptrace.h via sys/user.h). The
 *   31 general regs are user_pt_regs.regs[0..30] (x0..x30), with
 *   user_pt_regs.sp, user_pt_regs.pc, and user_pt_regs.pstate after.
 *
 *   AAPCS64 (Procedure Call Standard for the ARM 64-bit Architecture):
 *     args: x0..x7         (8 register args; we use up to 6)
 *     return: x0
 *     LR (link register, x30): return address; the function's RET
 *                              branches to it
 *     stack: 16-byte aligned at function entry
 *
 *   Linux aarch64 syscall ABI:
 *     nr: x8
 *     args: x0..x5
 *     return: x0 (negative errno on failure, encoded as a value in
 *                 the range [-4096, -1])
 *     instruction: SVC #0 = 0xD4000001 (encoded little-endian: 01 00 00 D4)
 *
 *   Trap-on-return convention: set x30 = trap_pc, set pc = func.
 *   The function's RET (`ret` opcode) branches to x30 = trap_pc, which
 *   is unmapped -> SIGSEGV -> caught by waitpid -> read x0 for the
 *   return value.
 *
 *   No stack push needed -- the caller (inject_call) doesn't need to
 *   write any target memory for the call setup itself (it only writes
 *   the function's argument strings into the scratch page, separately).
 */

#include "arch_inject.h"

#include <string.h>
#include <stdint.h>

/* The aarch64 NT_PRSTATUS regset layout, taken from the kernel's
 * arch/arm64/include/uapi/asm/ptrace.h. Defined locally rather than
 * including <sys/user.h> because that header only exposes the host
 * arch's user_pt_regs -- not aarch64's when this file is compiled on
 * x86_64. The injector binary contains every backend's setup code so
 * the runtime selector can pick one; therefore each backend's reg
 * definition must work without the target toolchain's headers.
 *
 * Layout is stable kernel UAPI: 31 GPRs (x0..x30), then sp, pc,
 * pstate. Total 34 u64 = 272 bytes. */
struct aarch64_user_pt_regs {
    uint64_t regs[31];      /* x0..x30 */
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

#define R(regs) ((struct aarch64_user_pt_regs *)((regs)->raw))

static void
aarch64_setup_call(struct inject_regs *regs,
                   uintptr_t func, uintptr_t trap_pc,
                   const uintptr_t *args, int n_args)
{
    struct aarch64_user_pt_regs *r = R(regs);

    uint64_t a[6] = {0};
    for (int i = 0; i < n_args && i < 6; i++) a[i] = (uint64_t)args[i];

    r->regs[0] = a[0];
    r->regs[1] = a[1];
    r->regs[2] = a[2];
    r->regs[3] = a[3];
    r->regs[4] = a[4];
    r->regs[5] = a[5];

    /* Link register = return PC. The function's epilogue does `ret`
     * which branches to x30, which we've set to trap_pc. */
    r->regs[30] = (uint64_t)trap_pc;

    r->pc = (uint64_t)func;
}

static void
aarch64_setup_syscall(struct inject_regs *regs,
                      uintptr_t syscall_pc,
                      long nr, const long *args, int n_args)
{
    struct aarch64_user_pt_regs *r = R(regs);

    uint64_t a[6] = {0};
    for (int i = 0; i < n_args && i < 6; i++) a[i] = (uint64_t)args[i];

    r->regs[8] = (uint64_t)nr;          /* x8 = syscall number */
    r->regs[0] = a[0];
    r->regs[1] = a[1];
    r->regs[2] = a[2];
    r->regs[3] = a[3];
    r->regs[4] = a[4];
    r->regs[5] = a[5];
    r->pc = (uint64_t)syscall_pc;
}

static uintptr_t
aarch64_get_retval(const struct inject_regs *regs)
{
    return (uintptr_t)R(regs)->regs[0];
}

static uintptr_t
aarch64_get_pc(const struct inject_regs *regs)
{
    return (uintptr_t)R(regs)->pc;
}

static void
aarch64_set_pc(struct inject_regs *regs, uintptr_t pc)
{
    R(regs)->pc = (uint64_t)pc;
}

static long
aarch64_find_syscall_insn(const void *buf, size_t len)
{
    /* SVC #0 = 0xD4000001 little-endian: bytes 01 00 00 D4.
     * Aarch64 instructions are word-aligned, but scanning byte-wise
     * is cheap and avoids assumptions about the buffer's alignment. */
    const uint8_t *b = (const uint8_t *)buf;
    if (len < 4) return -1;
    for (size_t i = 0; i + 3 < len; i++) {
        if (b[i] == 0x01 && b[i + 1] == 0x00 &&
            b[i + 2] == 0x00 && b[i + 3] == 0xD4) return (long)i;
    }
    return -1;
}

const struct inject_arch inject_arch_aarch64 = {
    .name              = "aarch64",
    .elf_machine       = EM_AARCH64,
    .supported         = 1,
    .setup_call        = aarch64_setup_call,
    .setup_syscall     = aarch64_setup_syscall,
    .get_retval        = aarch64_get_retval,
    .get_pc            = aarch64_get_pc,
    .set_pc            = aarch64_set_pc,
    .find_syscall_insn = aarch64_find_syscall_insn,
    .stack_return_addr = 0,           /* aarch64 RET uses LR (x30) */
    .get_sp            = NULL,        /* unused when stack_return_addr=0 */
    .pm_shellcode      = NULL,        /* phase 7 */
    .pm_build_sigframe = NULL,        /* phase 7 */
};
