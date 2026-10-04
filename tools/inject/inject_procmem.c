/*
 * inject_procmem.c -- ptrace-LESS libcov injector.
 *
 * STATUS: PHASE 7 -- runtime functionality not yet implemented; only the
 * design framework + CLI compiles. Invoking it prints a clear message
 * and exits 64. Build target is wired up so the cross-compile matrix
 * stays green and the implementation can land incrementally.
 *
 * Why a second injector?
 *
 *   The ptrace variant relies on PTRACE_ATTACH succeeding. It fails when:
 *
 *     (a) Another tracer is already attached (one-tracer rule). Common
 *         scenarios: the user is already debugging the daemon with gdb
 *         and doesn't want to disconnect; an anti-debug self-tracer is
 *         in place; a sandbox is attached as the tracer.
 *
 *     (b) Yama ptrace_scope >= 2 forbids non-root PTRACE_ATTACH even
 *         for same-UID processes. (Some hardened embedded distros set
 *         this.) Although note that the procmem variant ALSO needs
 *         /proc/<pid>/mem write, which requires the same trust
 *         boundary -- but it doesn't need the ATTACH ceremony.
 *
 *     (c) The injector wants to stay invisible in /proc/<pid>/status'
 *         TracerPid field. Useful when the target inspects that field
 *         itself (paranoid services that refuse to run if traced).
 *
 *   For (a) the procmem variant is the only option; for (c) it's the
 *   preferred one.
 *
 * Mechanism (the "dlinject" approach -- credit: DavidBuchanan314 PoC):
 *
 *   1. kill(pid, SIGSTOP) and poll /proc/<pid>/status until State: T.
 *      No PTRACE_ATTACH; the target's TracerPid stays 0.
 *
 *   2. Read /proc/<pid>/syscall to discover the target's current PC,
 *      SP, and (if mid-syscall) syscall number + args. We use SP to
 *      locate stack space for a forged sigreturn frame, and PC to plan
 *      the restore.
 *
 *      For arches where /proc/<pid>/syscall doesn't expose full
 *      register state, we read /proc/<pid>/stat (kstkesp, kstkeip)
 *      as a coarse fallback and dlinject our way around the missing
 *      bits using per-arch shellcode that re-snapshots regs.
 *
 *   3. Parse /proc/<pid>/maps the same way the ptrace variant does;
 *      resolve setenv/dlopen the same way.
 *
 *   4. Open /proc/<pid>/mem O_RDWR. Requires CAP_SYS_PTRACE or being
 *      the same UID with Yama allowing -- same trust boundary as the
 *      ptrace variant, just without becoming the tracer.
 *
 *   5. Use the remote-syscall trick to mmap a scratch+shellcode page.
 *      Without ptrace we can't single-step, so we build a tiny stage-1
 *      shellcode that:
 *        - saves all regs to a stash area we provide
 *        - performs mmap via the arch's syscall insn
 *        - re-raises SIGSTOP so we can read the result via /proc/mem
 *      Stage-1 is injected by overwriting bytes at the target's
 *      current PC and resuming with SIGCONT.
 *
 *   6. Write stage-2 shellcode + the rt_sigframe into target memory.
 *      Stage-2 calls setenv() N times then dlopen(), then sigreturns
 *      back to the original (saved by stage-1) register state.
 *
 *   7. Build a complete arch-specific rt_sigframe whose pretcontext
 *      points stage-2's entry, with all general regs pre-set to call
 *      the function with our args. The frame is placed on the target's
 *      stack (we have SP from step 2). Then we either:
 *        (a) overwrite a future instruction at PC with `syscall;
 *            rt_sigreturn`-equivalent that consumes our frame, OR
 *        (b) raise SIGUSR2 (which we know the target doesn't handle
 *            specially in most cases) and have the kernel install our
 *            forged frame as the signal-handler-context.
 *      Linux's rt_sigreturn restores state from the user-stack frame
 *      ABSOLUTELY -- including the PC -- so this jumps cleanly into
 *      stage-2.
 *
 *   8. SIGCONT the target. stage-2 runs setenv+dlopen+sigreturn,
 *      restoring the original PC and regs. Done.
 *
 * Per-arch parts needed:
 *
 *   - arch->pm_shellcode(): the stage-1 + stage-2 blobs as raw bytes.
 *     Hand-assembled per arch; small (50-200 bytes each). Stored as
 *     `.S` files (shellcode_x86_64.S etc) and pulled into the injector
 *     via `ld -r -b binary` linking.
 *
 *   - arch->pm_build_sigframe(): emits the arch-specific rt_sigframe
 *     layout (x86_64 rt_sigframe with fpregs; aarch64 sigframe with
 *     aarch64_ctx chain).
 *
 *   Both vtable slots are currently NULL on x86_64/aarch64 backends;
 *   the implementation is staged for a follow-up commit.
 *
 * Plan for the staged implementation:
 *
 *   Step A. x86_64 only. Hand-assemble stage-1 + stage-2 in
 *           shellcode_x86_64.S. Build sigframe in
 *           arch_inject_x86_64.c::x86_64_build_sigframe (uses
 *           struct rt_sigframe from arch/x86/include/asm/sigframe.h,
 *           reproduced in inject_procmem.c locally to avoid kernel
 *           header dependency).
 *
 *   Step B. aarch64.
 *
 *   Step C. Test parity with inject_ptrace via tools/inject/test/
 *           run_validation_inject.sh.
 *
 *   Until phases A-C land, this binary exits 64 (EX_USAGE-ish) with
 *   a clear error.
 */

/* _GNU_SOURCE is set by the Makefile (-D_GNU_SOURCE). */
#include "inject_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>

int
main(int argc, char **argv)
{
    (void)argc; (void)argv;
    fprintf(stderr,
"inject_procmem: not yet implemented (phase 7 staging).\n"
"\n"
"The ptrace-less injector is wired into the build matrix and the\n"
"per-arch backends but the runtime implementation (shellcode +\n"
"rt_sigframe forging) is pending. Use inject_ptrace for now.\n"
"\n"
"See inject_procmem.c top comment for the implementation plan.\n");
    return 64;
}
