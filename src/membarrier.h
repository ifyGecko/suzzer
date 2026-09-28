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
 *   - Without SYNC_CORE we rely on the per-write clear_cache only and log
 *     a warning at init. The residual
 *     race on weakly-ordered ISAs (aarch64/arm/mips/ppc/riscv) is small but
 *     non-zero: a peer thread that fetched ahead may execute the old bytes
 *     once before its I-cache picks up the change. For correctness it's
 *     identical to the ST-mode race window from a different cause; we
 *     accept it and document it.
 *
 * Alternative we did NOT implement (notes for the future):
 *   - Broadcast a no-op signal (e.g. tgkill SIGURG) to every peer thread.
 *     The signal-return path performs an instruction-serializing barrier
 *     on most arches. Heavier than membarrier but works on much older
 *     kernels (back to the 2.6 series). Worth adding if a real target
 *     can't be upgraded past 4.15.
 */
#ifndef LIBCOV_MEMBARRIER_H
#define LIBCOV_MEMBARRIER_H

void membarrier_init(void);
void membarrier_sync_core(void);

/* Whether PRIVATE_EXPEDITED_SYNC_CORE was successfully registered. When
 * true, membarrier_sync_core() broadcasts a context-synchronizing IPI.
 * When false, it is a no-op. Either way the caller must already have
 * issued __builtin___clear_cache() for every modified range. patch_mt.c
 * uses this to elide the trailing membarrier when it isn't available
 * and to decide whether to log the weak-ISA init WARNING. */
int  membarrier_has_sync_core(void);

#endif
