/*
 * patch_mt.c -- MT-safe patching primitives.
 *
 * Differences from patch_st.c:
 *
 *  (1) Per-entry atomic state machine on `e->patched` via cmpxchg, so
 *      concurrent arm/disarm requests on the same site serialize cleanly:
 *      only the winner does the byte-write; the loser no-ops.
 *
 *  (2) Writes are a single naturally-sized atomic store. At init every
 *      page holding a patch site is mprotect'ed R|W|X once (never
 *      dropping X, so peer threads keep executing), after which arm/disarm
 *      is one __atomic_store_n of the 2- or 4-byte encoding -- no syscall
 *      on the hot path.
 *
 *      Why not pwrite(/proc/self/mem)? That was the previous primary path
 *      and it TEARS: the kernel copies through memcpy, which for 2-4 byte
 *      lengths does byte-wise stores (rep movsb / split byte moves). A peer
 *      CPU could fetch UD2's first byte next to the original's second byte
 *      (e.g. `0f 07` = SYSRET -> #GP -> SIGSEGV), which crashed the 16-thread
 *      stress test roughly 1 run in 10 on x86_64. /proc/self/mem is now
 *      only a last-resort fallback for kernels that refuse R|W|X (W^X-strict
 *      / SELinux execmod), with a loud warning at init.
 *
 *  (3) Cross-CPU instruction visibility is two separate steps, and both
 *      are required on weakly-ordered ISAs:
 *
 *      a. Cache maintenance, after EVERY write: __builtin___clear_cache
 *         (aarch64 DC CVAU + IC IVAU, broadcast to the inner-shareable
 *         domain; arm/mips/riscv cacheflush syscalls; ppc dcbst/icbi).
 *         This makes the new bytes reachable by instruction fetch on
 *         every core. It compiles to nothing on x86 (coherent I-cache).
 *      b. Context synchronization, once per batch: membarrier(PRIVATE_
 *         EXPEDITED_SYNC_CORE) IPIs every CPU running this process so
 *         each one discards already-fetched/prefetched instructions.
 *         Without it, membarrier.c signals every peer thread instead
 *         (LIBCOV_SYNC_FALLBACK).
 *
 *      membarrier does NOT do (a): an earlier version skipped clear_cache
 *      whenever SYNC_CORE was active, which could leave peers -- and the
 *      writer itself -- fetching stale bytes on non-coherent I-caches.
 *
 * Atomicity argument for the byte-write:
 *
 *  - aarch64 / arm-ARM / mips / mips64 / powerpc / powerpc64 / riscv64:
 *    fixed-width 4-byte instructions naturally aligned by ISA. Aligned
 *    word stores are single-copy-atomic by architecture spec on all of
 *    these. A peer CPU's fetch sees either the old word or the new word.
 *
 *  - arm-Thumb / riscv64-compressed: 2-byte half-word stores naturally
 *    aligned. Single-copy-atomic on ARMv7+ and RV32IC/RV64IC.
 *
 *  - x86_64: the backend writes only 2 bytes (UD2 head) and
 *    libcov_max_patch_len is 2 (see tunables_x86_64.h). Intel SDM 8.1.1
 *    guarantees 16-bit stores are atomic when aligned, and (P6 onward)
 *    also when unaligned but contained in one cache line. We therefore
 *    accept any address whose 2 bytes don't span a 64-byte line; the
 *    generator's --threading mt mode applies the same rule.
 *
 * What we still don't claim:
 *
 *  - If the patch list contains addresses that violate the alignment
 *    assumption above, write_bytes() refuses the direct store and uses
 *    the (non-atomic) fallback path.
 *  - Architectural cross-modifying-code rules. The trap design is fixed
 *    (SIGILL from an illegal encoding), and neither UD2 nor UDF is in
 *    the architectures' blessed sets: x86 SDM 8.1.3 wants the executing
 *    core to serialize before running modified code, and the AArch64
 *    CMODX list (B/BL/NOP/BRK/SVC/HVC/SMC/ISB) excludes UDF. A peer that
 *    is fetching the site at the exact moment of the store may, per the
 *    spec, execute a CONSTRAINED UNPREDICTABLE mix. What we provide:
 *      - the store is single-copy atomic, so no torn encoding is ever
 *        in memory;
 *      - (3a) + (3b) above, so once patch_sync_batch_end() returns every
 *        CPU observes the new bytes (x86: SYNC_CORE's IPI + iret is the
 *        serializing event SDM 8.1.3 asks for).
 *    The residual window is a fetch racing the store itself. In practice
 *    that fetch returns the old or the new word, never a mix; this is the
 *    point the real-hardware MT validation (TODO.md) is meant to confirm.
 */
#define _GNU_SOURCE
#include "patch.h"
#include "arch.h"
#include "util.h"
#include "membarrier.h"

#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>

static long    g_pagesize      = 0;
static int     g_mem_fd        = -1;
static int     g_initialized   = 0;

/* 1 when every patched page was successfully made R|W|X at init, so
 * arm/disarm can use a direct atomic store. See header comment (2). */
static int     g_direct        = 0;

/* Cached at mt_init_once. When 1, patch_sync_batch_end() issues one
 * cross-core sync per batch -- the membarrier(SYNC_CORE) IPI, or the
 * signal broadcast on kernels without it (membarrier.h); when 0 it is a
 * no-op and peers rely on the per-write clear_cache alone (see header
 * comment (3)). */
static int     g_have_sync_core = 0;

/* Global spinlock that serializes the mprotect+write+mprotect dance in
 * the fallback path of write_bytes(). The per-entry e->lock is keyed on
 * a patch_entry, but mprotect's permission bits are keyed on the page.
 * With a large enough patch set, multiple entries share a code page;
 * concurrent fallback writes on those entries race on the page protection
 * (thread A restores PROT_READ|PROT_EXEC while thread B's memcpy is still
 * pending, faulting thread B's writer). The /proc/self/mem path does not
 * need this lock because pwrite bypasses VMA permission checks. */
static uint8_t g_fallback_lock = 0;

/* Make every page that holds a patch site R|W|X, once. The table is
 * sorted by address so consecutive entries share pages; each distinct
 * page is mprotect'ed once. Returns 0 if every page succeeded. */
static int make_sites_writable(void) {
    size_t n;
    struct patch_entry *t = config_table_mut(&n);
    if (!t) return -1;
    uintptr_t mask = ~((uintptr_t)g_pagesize - 1);
    uintptr_t last_lo = 0, last_hi = 0;
    for (size_t i = 0; i < n; i++) {
        uintptr_t lo = t[i].addr & mask;
        uintptr_t hi = (t[i].addr + t[i].len + (uintptr_t)g_pagesize - 1) & mask;
        if (lo >= last_lo && hi <= last_hi) continue;
        if (mprotect((void *)lo, hi - lo, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
            libcov_logf("patch_mt: mprotect RWX 0x%lx: %s",
                        (unsigned long)lo, strerror(errno));
            return -1;
        }
        last_lo = lo; last_hi = hi;
    }
    return 0;
}

static void mt_init_once(void) {
    if (g_initialized) return;
    g_pagesize = sysconf(_SC_PAGESIZE);
    if (make_sites_writable() == 0) {
        g_direct = 1;
        libcov_logf("patch_mt: code pages R|W|X; direct atomic-store patching");
    } else {
        g_mem_fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
        libcov_logf("patch_mt: WARNING -- cannot make code pages writable; "
                    "falling back to %s. These writes are NOT single-copy "
                    "atomic: a peer thread may execute a torn instruction.",
                    g_mem_fd >= 0 ? "pwrite(/proc/self/mem)" : "mprotect+memcpy");
    }
    membarrier_init();
    g_have_sync_core = membarrier_has_sync_core();
#if !defined(__x86_64__) && !defined(__i386__)
    if (!g_have_sync_core)
        libcov_logf("patch_mt: WARNING -- no cross-core sync (no membarrier(SYNC_CORE), "
                    "signal fallback off or refused) on a weakly-"
                    "ordered ISA: peer threads may fetch stale instruction bytes "
                    "after arm/disarm (missed or spurious traps)");
#endif
    g_initialized = 1;
}

/* mprotect the page(s) covering [addr, addr+len) with prot. Only used as
 * fallback when /proc/self/mem is unavailable. Async-signal-safe (mprotect
 * is on the POSIX safe list). */
static int protect_range(uintptr_t addr, size_t len, int prot) {
    long ps = g_pagesize;
    uintptr_t page = addr & ~((uintptr_t)ps - 1);
    uintptr_t end  = addr + len;
    size_t span = (size_t)(((end + ps - 1) & ~((uintptr_t)ps - 1)) - page);
    return mprotect((void *)page, span, prot);
}

/* Bounded-spin signal-safe lock for the fallback mprotect dance. See the
 * g_fallback_lock declaration above for why this is global, and why
 * recursive acquisition by the same thread cannot occur (the lock is held
 * only while executing libcov code on a non-patched page, so no in-flight
 * critical section can take its own trap). */
static inline void fallback_lock(void) {
    uint8_t expected = 0;
    unsigned spins = 0;
    while (!__atomic_compare_exchange_n(&g_fallback_lock, &expected, 1,
                                        0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        expected = 0;
        libcov_spin_backoff(&spins);
    }
}

static inline void fallback_unlock(void) {
    __atomic_store_n(&g_fallback_lock, 0, __ATOMIC_RELEASE);
}

/* Single write of `len` bytes at `addr`. The byte sequence is staged in a
 * caller-provided buffer first so the arch backend's write_illegal can
 * still target a normal pointer. Returns 0 on success. */
/* x86 cache-line size used for the unaligned-store atomicity rule. 64 on
 * every x86_64 part; the generator uses the same constant. */
#define LIBCOV_X86_CACHE_LINE 64

static int write_bytes(uintptr_t addr, const void *src, size_t len) {
#if defined(__x86_64__)
    /* x86: a 16-bit store that stays inside one cache line is single-copy
     * atomic even when unaligned (SDM 8.1.1). Plain `movw` rather than
     * __atomic_store_n, which requires natural alignment. x86 stores are
     * already release-ordered; the "memory" clobber stops the compiler
     * reordering around it. */
    if (g_direct && len == 2 &&
        (addr & (LIBCOV_X86_CACHE_LINE - 1)) <= LIBCOV_X86_CACHE_LINE - 2) {
        uint16_t v; memcpy(&v, src, 2);
        __asm__ volatile ("movw %1, %0"
                          : "=m" (*(volatile uint16_t *)addr)
                          : "r" (v)
                          : "memory");
        return 0;
    }
#endif
    /* Primary path: one single-copy-atomic store into the R|W|X page. */
    if (g_direct && (addr % len) == 0 && (len == 2 || len == 4)) {
        if (len == 2) {
            uint16_t v; memcpy(&v, src, 2);
            __atomic_store_n((uint16_t *)addr, v, __ATOMIC_RELEASE);
        } else {
            uint32_t v; memcpy(&v, src, 4);
            __atomic_store_n((uint32_t *)addr, v, __ATOMIC_RELEASE);
        }
        return 0;
    }
    /* Fallbacks below are NOT atomic w.r.t. peer instruction fetch. */
    if (g_mem_fd >= 0) {
        ssize_t w = pwrite(g_mem_fd, src, len, (off_t)addr);
        return (w == (ssize_t)len) ? 0 : -1;
    }
    /* mprotect dance. Keep PROT_EXEC throughout: dropping it (plain RW)
     * would SIGSEGV any peer thread executing the same page.
     *
     * Serialized globally via g_fallback_lock: mprotect's permission bits
     * are per-page, but the per-entry e->lock is keyed per-entry, so two
     * threads patching different entries on the same page can race --
     * one restoring PROT_READ|PROT_EXEC while the other's memcpy is
     * still pending. The global lock closes that window. */
    fallback_lock();
    int rv = -1;
    if (protect_range(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        memcpy((void *)addr, src, len);
        if (protect_range(addr, len, PROT_READ | PROT_EXEC) == 0) {
            rv = 0;
        }
    }
    fallback_unlock();
    return rv;
}

int patch_validate(const struct patch_entry *e) {
    if (e->len < libcov_min_patch_len || e->len > libcov_max_patch_len) return -1;
    return memcmp((void *)e->addr, e->orig, e->len) == 0 ? 0 : -1;
}

/* Acquire e->lock by spinning on a 0->1 cmpxchg, yielding after a bounded
 * spin (libcov_spin_backoff) so a preempted holder can run. The critical
 * section is one store + clear_cache. Safe in a signal handler:
 *
 *  - The same thread never recursively acquires the same entry's lock:
 *    patch_arm/disarm are called outside the trap PC's basic block, so a
 *    secondary trap from inside our critical section can only be on a
 *    *different* entry (a different address with its own lock).
 *  - A different thread may be holding the lock; we spin until they
 *    release. No futex/syscall blocking that would deadlock under a
 *    signal-context caller. */
static inline void entry_lock(struct patch_entry *e) {
    uint8_t expected = 0;
    unsigned spins = 0;
    while (!__atomic_compare_exchange_n(&e->lock, &expected, 1,
                                        0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        expected = 0;
        libcov_spin_backoff(&spins);
    }
}

static inline void entry_unlock(struct patch_entry *e) {
    __atomic_store_n(&e->lock, 0, __ATOMIC_RELEASE);
}

/* Write-bytes core, no cross-core sync. Cache maintenance is done here
 * unconditionally (header comment (3a)): membarrier(SYNC_CORE) only
 * context-synchronizes CPUs, it does not clean the D-cache or invalidate
 * the I-cache, so it cannot stand in for clear_cache on weak ISAs.
 * Compiles to nothing on x86.
 *
 * Always inlined by gcc -O2 in practice; named for readability. */
static inline int patch_write_inner(struct patch_entry *e, const void *bytes) {
    if (write_bytes(e->addr, bytes, e->len) != 0) return -1;
    __builtin___clear_cache((char *)e->addr, (char *)e->addr + e->len);
    return 0;
}

int patch_arm_unsynced(struct patch_entry *e) {
    entry_lock(e);
    int rv = 0;
    if (!e->patched) {
        /* A3: pwrite straight out of .rodata-backed trap pattern, no stack
         * staging via libcov_arch_write_illegal(). */
        if (patch_write_inner(e, libcov_arch_illegal_bytes(e->len)) == 0) {
            e->patched = 1;
        } else {
            rv = -1;
        }
    }
    entry_unlock(e);
    return rv;
}

int patch_disarm_unsynced(struct patch_entry *e) {
    entry_lock(e);
    int rv = 0;
    if (e->patched) {
        if (patch_write_inner(e, e->orig) == 0) {
            e->patched = 0;
        } else {
            rv = -1;
        }
    }
    entry_unlock(e);
    return rv;
}

void patch_sync_batch_end(void) {
    /* One IPI for the whole batch (handler trap pair, boundary rearm):
     * the context-synchronization step (3b). Cache maintenance (3a) was
     * already done per write in patch_write_inner. No-op when membarrier
     * isn't available; peers then pick the change up whenever they next
     * context-synchronize (exception return, etc.), which on weakly-
     * ordered ISAs is the documented residual window (init WARNING). */
    if (g_have_sync_core) membarrier_sync_core();
}

int patch_arm(struct patch_entry *e) {
    int rv = patch_arm_unsynced(e);
    if (rv == 0) patch_sync_batch_end();
    return rv;
}

int patch_disarm(struct patch_entry *e) {
    int rv = patch_disarm_unsynced(e);
    if (rv == 0) patch_sync_batch_end();
    return rv;
}

size_t patch_arm_all(void) {
    mt_init_once();

    size_t n;
    struct patch_entry *t = config_table_mut(&n);
    if (!t) return 0;

    uintptr_t self_lo, self_hi;
    util_self_range(&self_lo, &self_hi);

    size_t armed = 0, skipped = 0, validate_fail = 0;
    for (size_t i = 0; i < n; i++) {
        struct patch_entry *e = &t[i];
        if (self_lo && e->addr >= self_lo && e->addr < self_hi) {
            libcov_logf("patch_mt: refusing self-patch at 0x%lx", (unsigned long)e->addr);
            skipped++;
            continue;
        }
        if (patch_validate(e) != 0) {
            libcov_logf("patch_mt: stale entry at 0x%lx (bytes mismatch)",
                        (unsigned long)e->addr);
            validate_fail++;
            continue;
        }
        if (patch_arm(e) != 0) {
            libcov_logf("patch_mt: arm failed at 0x%lx: %s",
                        (unsigned long)e->addr, strerror(errno));
            continue;
        }
        armed++;
    }
    libcov_logf("patch_mt: armed=%zu skipped=%zu stale=%zu",
                armed, skipped, validate_fail);
    return armed;
}

/* A2: per-thread direct-mapped PC cache in front of the bsearch.
 *
 * The handler under leapfrog re-traps a small handful of hot sites
 * repeatedly (loops, frequently-taken edges). bsearch is O(log n) and
 * cache-cold for cold sites; the direct-mapped cache turns hot lookups
 * into a single compare-and-load. Cache holds entry pointers (NOT state)
 * so re-arm/disarm transitions don't invalidate it -- entries are
 * permanent in the patch table for the process's lifetime.
 *
 * NULL slots mean "uninitialized" -- never trust a NULL `pc` slot. Misses
 * fall back to bsearch and update the slot.
 *
 * 16 entries chosen as a good Pareto point: each slot is 16B (pc + ptr)
 * for 256B total, well inside L1d. Per-thread TLS so concurrent worker
 * threads don't fight each other's working sets. */
#define LIBCOV_PC_CACHE_SIZE 16
#define LIBCOV_PC_CACHE_MASK (LIBCOV_PC_CACHE_SIZE - 1)

struct pc_cache_slot {
    uintptr_t           pc;
    struct patch_entry *e;
};
static __thread struct pc_cache_slot g_pc_cache[LIBCOV_PC_CACHE_SIZE];

static inline unsigned pc_cache_idx(uintptr_t pc) {
    /* Fibonacci hash. Top LIBCOV_PC_CACHE_SIZE_LOG2 bits of the multiply
     * give a low-collision distribution across the address space. */
    return (unsigned)((pc * 0x9E3779B97F4A7C15ULL) >> 60) & LIBCOV_PC_CACHE_MASK;
}

/* Signal-safe binary search with a per-thread PC cache in front. The
 * returned pointer aliases the global table. */
struct patch_entry *patch_lookup(uintptr_t addr) {
    unsigned idx = pc_cache_idx(addr);
    if (g_pc_cache[idx].pc == addr) {
        struct patch_entry *e = g_pc_cache[idx].e;
        if (e) return e;
    }
    size_t n;
    struct patch_entry *t = config_table_mut(&n);
    if (!t || n == 0) return NULL;
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (t[mid].addr == addr) {
            g_pc_cache[idx].pc = addr;
            g_pc_cache[idx].e  = &t[mid];
            return &t[mid];
        }
        if (t[mid].addr <  addr) lo = mid + 1;
        else                     hi = mid;
    }
    return NULL;
}

size_t patch_rearm_set(struct patch_entry **set, size_t n) {
    size_t armed = 0;
    for (size_t i = 0; i < n; i++) {
        struct patch_entry *e = set[i];
        if (!e) continue;
        if (__atomic_load_n(&e->patched, __ATOMIC_RELAXED)) continue;
        if (patch_arm(e) == 0) armed++;
    }
    return armed;
}

size_t patch_rearm_all_disarmed(void) {
    size_t n;
    struct patch_entry *t = config_table_mut(&n);
    if (!t) return 0;
    size_t armed = 0;
    for (size_t i = 0; i < n; i++) {
        if (__atomic_load_n(&t[i].patched, __ATOMIC_RELAXED)) continue;
        if (patch_arm(&t[i]) == 0) armed++;
    }
    return armed;
}
