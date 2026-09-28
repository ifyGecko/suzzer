/*
 * membarrier.h -- thin wrapper around the Linux membarrier(2) syscall used
 * only by the MT runtime (patch_mt.c). Splits cleanly into:
 *
 *   membarrier_init()        -- once at init. Detects whether
 *                               PRIVATE_EXPEDITED_SYNC_CORE is available on
 *                               this kernel and registers our process for
 *                               it; logs the result via libcov_logf.
 *
 *   membarrier_sync_core()   -- hot-path. After writing new instruction
 *                               bytes AND doing the cache maintenance
 *                               (__builtin___clear_cache), this issues an
 *                               IPI to every CPU running the process,
 *                               forcing each one to context-synchronize
 *                               (discard prefetched instructions). It does
 *                               NOT clean/invalidate caches itself -- that
 *                               is always the writer's job.
 *
 * Kernel floor:
 *   - PRIVATE_EXPEDITED_SYNC_CORE: Linux 4.16+ (per-arch; riscv gained it
 *     much later). On x86_64 the IPI's return path (iret) is the
 *     serializing instruction SDM 8.1.3 requires before running
 *     cross-modified code.
 *   - Without it (or with LIBCOV_SYNC_FALLBACK=tgkill) we fall back to a
 *     signal broadcast: LIBCOV_SYNC_SIGNO goes to every other thread
 *     (rt_tgsigqueueinfo, Linux 2.6.31+, listed from /proc/self/task) and
 *     membarrier_sync_core() waits, up to LIBCOV_SYNC_TIMEOUT_NS, for each
 *     to acknowledge from its handler. Taking the signal and returning is
 *     an exception return on that thread, which context-synchronizes it.
 *     Much heavier than the IPI (every peer is woken on every patch
 *     batch), and target-visible: syscalls that don't restart return
 *     EINTR. LIBCOV_SYNC_FALLBACK=off disables it; so does the target
 *     owning the signal (see membarrier_release_signal). Needs /proc; a
 *     broadcast from a chroot without it does nothing.
 *   - With neither, we rely on the per-write clear_cache only and log a
 *     warning at init. The residual race on weakly-ordered ISAs
 *     (aarch64/arm/mips/ppc/riscv) is small but non-zero: a peer thread
 *     that fetched ahead may execute the old bytes once before its
 *     I-cache picks up the change.
 */
#ifndef LIBCOV_MEMBARRIER_H
#define LIBCOV_MEMBARRIER_H

/* Idempotent. libcov_init calls it before installing the trap handler,
 * whose signal mask depends on membarrier_sync_signo(). */
void membarrier_init(void);
void membarrier_sync_core(void);

/* Whether a cross-core sync is active: membarrier(SYNC_CORE) or the
 * signal broadcast. When false, membarrier_sync_core() is a no-op. Either
 * way the caller must already have issued __builtin___clear_cache() for
 * every modified range. patch_mt.c uses this to elide the trailing call
 * when there is nothing to do and to decide whether to log the weak-ISA
 * init WARNING. */
int  membarrier_has_sync_core(void);

/* LIBCOV_SYNC_SIGNO while the signal broadcast is active, else -1. The
 * signal interposers in libcov.c keep it deliverable (unblocked) and
 * never let the trap handler's mask block it. */
int  membarrier_sync_signo(void);

/* The target wants the sync signal (it installed a handler for it):
 * restore SIG_DFL, stop broadcasting, and log `why`. Not for use in a
 * signal handler. */
void membarrier_release_signal(const char *why);

#endif
