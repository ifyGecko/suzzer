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
 *                               bytes, this issues an IPI to every CPU the
 *                               process has run on, forcing each one to
 *                               serialize its instruction pipeline. Other
 *                               threads are guaranteed to see the new bytes
 *                               on their next fetch.
 *
 * Kernel floor:
 *   - PRIVATE_EXPEDITED_SYNC_CORE: Linux 4.16+. On x86_64 it's a no-op the
 *     kernel skips entirely (TSO + snoopy cache makes it unnecessary), but
 *     the call is still cheap (zero-IPI in that case).
 *   - On older kernels (< 4.16): no SYNC_CORE. We fall back to "writer
 *     thread's clear_cache only" and log a warning at init. The residual
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

#endif
