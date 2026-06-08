/*
 * arch_inject_x86_64.c -- x86_64 backend for the injector.
 *
 * Implements the full ptrace-variant ABI (setup_call/setup_syscall/
 * get_retval/get_pc/set_pc/find_syscall_insn). Procmem-variant ops
 * (pm_shellcode / pm_build_sigframe) are populated in phase 7.
 *
 * Key x86_64 facts used here:
 *
 *   Register set layout: PTRACE_GETREGSET with NT_PRSTATUS returns a
 *   `struct user_regs_struct` (sys/user.h). Field offsets are stable
 *   per arch ABI. We index by field name not raw offset.
 *
 *   SysV AMD64 call ABI:
 *     args: rdi, rsi, rdx, rcx, r8, r9    (any past these go on the stack)
 *     return: rax
 *     rsp must be 16-byte aligned at the CALL site (which means 8 mod 16
 *     just before a RET inside the callee, which is the alignment we
 *     present here -- we push one 8-byte return address).
 *
 *   Linux x86_64 syscall ABI:
 *     nr: rax
 *     args: rdi, rsi, rdx, r10, r8, r9
 *           (note: r10 not rcx -- SYSCALL clobbers rcx)
 *     return: rax (negative errno on failure)
 *     instruction: 0x0F 0x05 (SYSCALL)
 *
 *   Trap-on-return convention: we want the function's RET to fault.
 *   Concretely: subtract 8 from rsp, write trap_pc there, set rip to
 *   the function. The function's epilogue does `ret` which pops our
 *   trap_pc into rip; trap_pc is unmapped -> SIGSEGV -> waitpid
 *   catches it -> we read rax.
 *
 *   Stack alignment: the function expects (rsp % 16) == 8 on entry
 *   (one return slot below a 16-byte boundary). We push exactly one
 *   8-byte slot (trap_pc), so if the target's rsp was 16-byte aligned
 *   when we attached (which it almost always is, since most code lives
 *   between calls where the alignment is restored), our adjusted rsp
 *   satisfies the ABI. If a target happens to be stopped mid-prologue
 *   with bad alignment, glibc functions like setenv/dlopen still
 *   tolerate it for our short call (no SSE locals that trap on
 *   misalign). We document this as an edge case.
 */

#include "arch_inject.h"

#include <string.h>
#include <stdint.h>

/* x86_64 NT_PRSTATUS regset layout. Defined locally (not via <sys/user.h>)
 * so the file compiles on every host arch -- the injector binary contains
 * every backend so the runtime selector can pick one, which means each
 * backend's reg definition must work without the target toolchain's
 * headers.
 *
 * Layout is stable kernel UAPI from arch/x86/include/uapi/asm/ptrace.h.
 * Matches glibc's `struct user_regs_struct` byte-for-byte (27 u64 = 216
 * bytes). */
struct x86_64_user_regs {
    uint64_t r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8;
    uint64_t rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs, eflags;
    uint64_t rsp, ss, fs_base, gs_base, ds, es, fs, gs;
};

#define R(regs) ((struct x86_64_user_regs *)((regs)->raw))

static void
x86_64_setup_call(struct inject_regs *regs,
                  uintptr_t func, uintptr_t trap_pc,
                  const uintptr_t *args, int n_args)
{
    struct x86_64_user_regs *r = R(regs);

    /* Break the kernel's syscall-restart logic.
     *
     * When we PTRACE_ATTACH a process blocked in a restartable syscall
     * (e.g. read() on stdin), the kernel queues a "restart this syscall
     * on resume" action. On PTRACE_CONT the kernel walks the signal-
     * delivery path and, if TS_RESTART_SYSCALL is set, decrements RIP
     * by 2 (the size of the SYSCALL instruction) so the syscall re-runs.
     *
     * That's exactly wrong for us: we've set RIP to the entry of our
     * target function; we don't want the kernel to back it up by 2,
     * which would land mid-padding before the function and SIGILL.
     *
     * orig_rax holds the original syscall number (set on syscall entry,
     * stays set for the lifetime of the kernel's syscall-restart book-
     * keeping). Setting it to (uint64_t)-1 tells the kernel "no syscall
     * is pending restart"; the signal-return path then leaves RIP
     * alone, and our redirected call runs at the address we asked for.
     *
     * This applies to *every* remote call we do, not just the first,
     * because setup_call is called repeatedly with a fresh copy of
     * regs_saved -- which carries the original orig_rax value.
     *
     * Symptom if you remove this: SIGILL at func-2 on the first call. */
    r->orig_rax = (uint64_t)-1;

    /* Place args 0..5 in their SysV AMD64 registers. Zero unused
     * arg slots so we don't accidentally hand the callee garbage. */
    uintptr_t a[6] = {0};
    for (int i = 0; i < n_args && i < 6; i++) a[i] = args[i];
    r->rdi = a[0];
    r->rsi = a[1];
    r->rdx = a[2];
    r->rcx = a[3];
    r->r8  = a[4];
    r->r9  = a[5];

    /* Stack alignment fixup. SysV AMD64 requires (rsp % 16) == 0 at
     * the CALL site, equivalently (rsp % 16) == 8 on the first
     * instruction of the callee (i.e. just after the 8-byte return
     * address has been pushed). We were attached at an arbitrary
     * point in the target so the saved rsp can have any alignment.
     * Round rsp DOWN to a 16-byte boundary first; then subtract 8
     * to reserve the return slot. The callee then sees the ABI-
     * required alignment.
     *
     * Why this matters: glibc internals use SSE moves (movaps) on
     * stack-allocated locals that fault if rsp is misaligned. setenv
     * in particular touches the environ linked list via aligned
     * loads. Without this fix we get a spurious SIGSEGV inside
     * setenv that the injector reports as "trap_pc mismatch".
     *
     * The cost is at most 15 bytes of stack consumed per call --
     * negligible (the scratch+arg writes go to our mmap'd page, not
     * the stack). We round DOWN so we don't write into existing
     * stack data above the saved rsp. */
    r->rsp &= ~(uint64_t)0xf;
    r->rsp -= 8;
    (void)trap_pc;  /* caller writes trap_pc to *rsp via target_write() */

    /* Reserve the stack slot for the return address. The function's
     * RET will pop this into rip; the actual VALUE written there
     * (trap_pc) is placed by inject_common.c::inject_call via
     * process_vm_writev after this function returns, because
     * setup_call is register-only and can't poke target memory
     * itself. The arch contract is:
     *   stack_return_addr == 1 -> caller writes trap_pc at get_sp()
     *   stack_return_addr == 0 -> caller does nothing (trap_pc lives
     *                             in a register set by setup_call)
     * x86_64 takes the first branch; aarch64 etc take the second. */

    /* Point execution at the function. */
    r->rip = func;
}

static void
x86_64_setup_syscall(struct inject_regs *regs,
                     uintptr_t syscall_pc,
                     long nr, const long *args, int n_args)
{
    struct x86_64_user_regs *r = R(regs);

    long a[6] = {0};
    for (int i = 0; i < n_args && i < 6; i++) a[i] = args[i];

    r->rax = nr;
    r->rdi = a[0];
    r->rsi = a[1];
    r->rdx = a[2];
    r->r10 = a[3];    /* note: r10 not rcx -- SYSCALL clobbers rcx */
    r->r8  = a[4];
    r->r9  = a[5];
    r->rip = syscall_pc;
}

static uintptr_t
x86_64_get_retval(const struct inject_regs *regs)
{
    return (uintptr_t)R(regs)->rax;
}

static uintptr_t
x86_64_get_pc(const struct inject_regs *regs)
{
    return (uintptr_t)R(regs)->rip;
}

static void
x86_64_set_pc(struct inject_regs *regs, uintptr_t pc)
{
    R(regs)->rip = pc;
}

static uintptr_t
x86_64_get_sp(const struct inject_regs *regs)
{
    return (uintptr_t)R(regs)->rsp;
}

static long
x86_64_find_syscall_insn(const void *buf, size_t len)
{
    /* SYSCALL = 0F 05. We scan for any occurrence. Even in a stripped
     * libc this is dense -- every syscall wrapper has one. The buffer
     * the caller hands us is a snapshot of libc's first text mapping
     * region (a few KB into .text is enough). */
    const uint8_t *b = (const uint8_t *)buf;
    if (len < 2) return -1;
    for (size_t i = 0; i + 1 < len; i++) {
        if (b[i] == 0x0F && b[i + 1] == 0x05) return (long)i;
    }
    return -1;
}

const struct inject_arch inject_arch_x86_64 = {
    .name              = "x86_64",
    .elf_machine       = EM_X86_64,
    .supported         = 1,
    .setup_call        = x86_64_setup_call,
    .setup_syscall     = x86_64_setup_syscall,
    .get_retval        = x86_64_get_retval,
    .get_pc            = x86_64_get_pc,
    .set_pc            = x86_64_set_pc,
    .find_syscall_insn = x86_64_find_syscall_insn,
    .stack_return_addr = 1,           /* x86_64 RET pops from stack */
    .get_sp            = x86_64_get_sp,
    .pm_shellcode      = NULL,        /* phase 7 */
    .pm_build_sigframe = NULL,        /* phase 7 */
};
