/*
 * arch_inject.h -- per-architecture backend interface for the injector.
 *
 * Mirrors libcov's src/arch.h philosophy:
 *
 *   - A tiny vtable; one struct per arch.
 *   - Zero `#ifdef ARCH` in the common code (inject_common.c, inject_ptrace.c,
 *     inject_procmem.c).
 *   - One arch_inject_<name>.c per backend, link-time selected by the build.
 *   - Stubs for not-yet-implemented arches keep the build matrix green and
 *     give a clear runtime error from the same code path that the real
 *     backends take.
 *
 * The full set of operations a backend must implement for the *ptrace*
 * injector to work:
 *
 *   1. setup_call()     -- prime a register set so that PTRACE_CONT will
 *                          execute a remote function call with up to 6
 *                          args; the call's return is rerouted to an
 *                          unmapped sentinel PC (trap_pc) so the resulting
 *                          SIGSEGV is caught by waitpid and the call's
 *                          return value can be read from the appropriate
 *                          register.
 *
 *   2. setup_syscall()  -- prime a register set so that PTRACE_SINGLESTEP
 *                          from a syscall-instruction location executes a
 *                          syscall with up to 6 args.
 *
 *   3. get_retval()     -- pull the function/syscall return value out of
 *                          the post-call register set.
 *
 *   4. get_pc() / set_pc() -- read/write the program counter inside the
 *                          opaque register state. The injector uses set_pc
 *                          to redirect the target before each remote call,
 *                          and get_pc for diagnostics + the syscall return.
 *
 *   5. find_syscall_insn() -- search a mapped chunk of libc for an arch-
 *                          appropriate syscall instruction (x86_64 SYSCALL,
 *                          aarch64 SVC #0, etc.). The injector overwrites
 *                          nothing -- it merely jumps the target to an
 *                          existing syscall insn it found in libc.
 *
 * Procmem-injector additions (phase 7) extend the vtable with shellcode
 * blobs and a sigreturn-frame builder; those are defined in the same
 * struct below with the `_pm_` prefix so the ptrace-only backends can
 * leave them NULL during the staged rollout.
 *
 * Return-trap convention (key design decision):
 *
 *   Every remote call uses the same "fake return address = unmapped page"
 *   trick. When the called function executes its return instruction the
 *   CPU transfers to a sentinel PC that we've validated is unmapped in
 *   the target; the resulting SIGSEGV is caught by waitpid; the injector
 *   reads the call's return value from the standard arch return-value
 *   register. This avoids any per-arch shellcode for the ptrace
 *   variant -- only the register-setup details differ across arches.
 */

#ifndef ARCH_INJECT_H
#define ARCH_INJECT_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <elf.h>

/* Maximum size for the NT_PRSTATUS register set across all supported arches.
 *
 *   x86_64 elf_prstatus = 336 bytes (incl. siginfo + 27-reg pr_reg)
 *   aarch64 elf_prstatus = 392 bytes
 *   The NT_PRSTATUS regset slice handed to PTRACE_GETREGSET is smaller
 *   (just pr_reg + a bit of context) but we size for the full struct
 *   to be safe; ptrace returns iov.iov_len with the actual count.
 *
 * 1024 is generous for every supported arch.
 */
#define INJECT_REGS_MAX 1024

/* Opaque per-arch register state. Backends serialise into raw[] in
 * whatever layout PTRACE_GETREGSET(NT_PRSTATUS) returns for the arch.
 * The size returned in iov.iov_len is preserved in `len` so the caller
 * can hand the same iovec back to PTRACE_SETREGSET. */
struct inject_regs {
    uint8_t raw[INJECT_REGS_MAX];
    size_t  len;
};

struct inject_arch {
    /* Identification ---------------------------------------------- */
    const char *name;       /* "x86_64", "aarch64", ... -- for log lines */
    int         elf_machine;/* EM_X86_64, EM_AARCH64, ... -- matched against
                               the target binary's ELF e_machine. */
    int         supported;  /* 1 if backend is fully implemented; 0 if it
                               is a build-only stub. inject_ptrace and
                               inject_procmem refuse to attach to an
                               unsupported arch with a clear message. */

    /* ---- ptrace-variant operations ----------------------------------- */

    /* Prime regs so that PTRACE_CONT from here executes `func(args...)`,
     * with the function's RET transferring to `trap_pc`. `n_args` is the
     * number of arguments in args[] (0..6); extra args are zeroed.
     *
     * Caller invariants:
     *   - regs were just loaded with PTRACE_GETREGSET(NT_PRSTATUS) so
     *     they reflect the target's current state.
     *   - trap_pc was validated against /proc/<pid>/maps and is known
     *     unmapped.
     *   - On stack-based ABIs (x86_64), the backend places trap_pc on
     *     the stack as the return address; the function's RET pops it.
     *   - On link-register ABIs (aarch64, arm, ppc, riscv), the
     *     backend writes trap_pc into the LR/return register; the
     *     function's RET returns through it. */
    void (*setup_call)(struct inject_regs *regs,
                       uintptr_t func, uintptr_t trap_pc,
                       const uintptr_t *args, int n_args);

    /* Prime regs so that PTRACE_SINGLESTEP at a syscall instruction
     * located at `syscall_pc` executes syscall(nr, args[0..n_args-1]).
     *
     * Each arch picks its own NR / arg register set per its kernel
     * syscall ABI (x86_64: rax,rdi,rsi,rdx,r10,r8,r9; aarch64:
     * x8,x0..x5; etc.). */
    void (*setup_syscall)(struct inject_regs *regs,
                          uintptr_t syscall_pc,
                          long nr, const long *args, int n_args);

    /* After a setup_call() that completed (trap fired at trap_pc) or a
     * setup_syscall() that completed (single-step finished), extract
     * the return value from the appropriate arch register.
     *
     * For setup_call: the function's RET register (rax / x0 / r3).
     * For setup_syscall: the syscall return register (rax / x0 / r3),
     * which by convention is the same on most arches. */
    uintptr_t (*get_retval)(const struct inject_regs *regs);

    /* Get/set program counter inside the opaque register state. The
     * injector uses set_pc to redirect the target to `func` before
     * PTRACE_CONT, and to `syscall_pc` before PTRACE_SINGLESTEP.
     * get_pc is used for diagnostics + paranoia (verifying we
     * actually stopped at the trap_pc we set). */
    uintptr_t (*get_pc)(const struct inject_regs *regs);
    void      (*set_pc)(struct inject_regs *regs, uintptr_t pc);

    /* Search a mapped byte buffer for an arch-appropriate syscall
     * instruction. Returns the byte offset within `buf` or -1 if
     * not found. The injector calls this against a chunk of libc's
     * .text region to locate a SYSCALL/SVC/ECALL/etc. that it can
     * jump to for remote syscalls. We never write to that location
     * (the syscall insn is already there), so this is non-invasive. */
    long (*find_syscall_insn)(const void *buf, size_t len);

    /* True iff this arch's calling convention requires the return
     * address to be on the stack (popped by the function's RET).
     * Set for x86_64 (RET pops); cleared for aarch64/arm/ppc/riscv
     * (RET branches through LR). When true, inject_call() reads
     * arch->get_sp(post-setup_call regs) and writes trap_pc at
     * that address via process_vm_writev. When false, no target
     * memory write is needed -- trap_pc is already in the LR/return
     * register from setup_call(). */
    int  stack_return_addr;

    /* Extract the stack pointer from a register set. Only meaningful
     * (and only called) when stack_return_addr is true. */
    uintptr_t (*get_sp)(const struct inject_regs *regs);

    /* ---- procmem-variant operations (phase 7) ------------------------ */
    /* Backends populate these only when the procmem injector is in
     * scope for that arch. NULL means: procmem not supported for this
     * arch yet (inject_procmem will refuse with a clear message). */

    /* Hand-assembled shellcode that does the equivalent of:
     *
     *     setenv(key0, val0, 1);
     *     setenv(key1, val1, 1);
     *     ...
     *     handle = dlopen(libpath, RTLD_NOW);
     *     <restore caller's regs from a stashed frame>
     *     <jump back to caller's original PC>
     *
     * The shellcode takes its arg list (addresses of strings, the
     * setenv/dlopen function pointers, the stashed register frame)
     * from a known offset relative to its entry point (the
     * inject_procmem main builds a parameter block in target memory
     * and embeds its address into the shellcode at fixup time).
     *
     * Returns the raw bytes + length. NULL/0 == not supported. */
    const uint8_t *(*pm_shellcode)(size_t *out_len);

    /* Build a complete rt_sigframe in `buf` (caller-allocated, sized
     * via prior call with buf=NULL to get the required size) that,
     * when consumed by the kernel's rt_sigreturn path, restores
     * `target_regs` plus a PC of `shellcode_entry`. Returns the
     * frame size on success, or 0 on failure / unsupported. */
    size_t (*pm_build_sigframe)(void *buf, size_t buflen,
                                const struct inject_regs *target_regs,
                                uintptr_t shellcode_entry);
};

/* Per-arch externs. inject_arch_select() picks one by ELF e_machine. */
extern const struct inject_arch inject_arch_x86_64;
extern const struct inject_arch inject_arch_aarch64;
extern const struct inject_arch inject_arch_arm;
extern const struct inject_arch inject_arch_mips;
extern const struct inject_arch inject_arch_mips64;
extern const struct inject_arch inject_arch_powerpc;
extern const struct inject_arch inject_arch_powerpc64;
extern const struct inject_arch inject_arch_riscv64;

/* Pick the backend for `elf_machine` (EM_X86_64, EM_AARCH64, ...).
 * Returns NULL if no backend matches the value at all (truly unknown
 * arch). Returns the matching backend even if its `supported` flag is
 * 0 -- the caller is expected to check `->supported` and refuse
 * politely with a clear message. */
const struct inject_arch *inject_arch_select(int elf_machine);

#endif /* ARCH_INJECT_H */
