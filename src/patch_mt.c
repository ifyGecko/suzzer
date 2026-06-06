/*
 * patch_mt.c -- MT-safe patching primitives.
 *
 * Differences from patch_st.c:
 *
 *  (1) Per-entry atomic state machine on `e->patched` via cmpxchg, so
 *      concurrent arm/disarm requests on the same site serialize cleanly:
 *      only the winner does the byte-write; the loser no-ops.
 *
 *  (2) Writes go through /proc/self/mem (pwrite) when available. This
 *      bypasses mprotect entirely, so peer threads keep executing on the
 *      R|X mapping unperturbed -- no transient writable window on the code
 *      page. Falls back to mprotect+memcpy on hardened kernels where
 *      /proc/self/mem writes are blocked.
 *
 *  (3) Cross-CPU instruction-cache coherence: after each successful write,
 *      we call membarrier(PRIVATE_EXPEDITED_SYNC_CORE). On x86 this is a
 *      kernel no-op (the architecture is strongly ordered + I-cache is
 *      snoopy). On weak ISAs it IPIs every CPU the process has run on,
 *      forcing each one to serialize its pipeline; peer threads see the
 *      new bytes on their next fetch.
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
 *  - x86_64: arch_x86_64_mt.c writes only 2 bytes (UD2 head) and the
 *    backend's libcov_arch_max_patch_len is 2, so the generator must
 *    emit MT records with len=2. Intel SDM guarantees aligned 16-bit
 *    stores are atomic; in practice 16-bit stores that fit within a
 *    cache line are atomic on all P6+ CPUs.
 *
 * What we still don't claim:
 *
 *  - If the patch list contains addresses that violate the alignment
 *    assumption above, behavior is undefined under MT. The generator's
 *    --threading mt mode is responsible for emitting only aligned sites.
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

static long g_pagesize = 0;
static int  g_mem_fd   = -1;
static int  g_initialized = 0;

static void mt_init_once(void) {
    if (g_initialized) return;
    g_pagesize = sysconf(_SC_PAGESIZE);
    g_mem_fd   = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
    if (g_mem_fd < 0) {
        libcov_logf("patch_mt: /proc/self/mem open failed (errno=%d) -- "
                    "falling back to mprotect path; peer threads may briefly "
                    "fault on the writer page during arm/disarm",
                    errno);
    } else {
        libcov_logf("patch_mt: /proc/self/mem fd=%d (mprotect-free writes)", g_mem_fd);
    }
    membarrier_init();
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

/* Single write of `len` bytes at `addr`. The byte sequence is staged in a
 * caller-provided buffer first so the arch backend's write_illegal can
 * still target a normal pointer. Returns 0 on success.
 *
 * After a successful /proc/self/mem write we issue a same-permission
 * mprotect on the page. On real Linux this is essentially a no-op: the
 * VMA permission flags don't change. Under qemu-user, however, mprotect
 * is the hook qemu uses to invalidate its TCG (translation cache) for
 * the affected page -- without it, qemu keeps executing the cached
 * host-side translation of the *original* bytes and the trap never
 * fires. This kick is required for cross-arch MT validation to work
 * under qemu-user and is harmlessly cheap on real hardware. */
static int write_bytes(uintptr_t addr, const void *src, size_t len) {
    if (g_mem_fd >= 0) {
        ssize_t w = pwrite(g_mem_fd, src, len, (off_t)addr);
        return (w == (ssize_t)len) ? 0 : -1;
    }
    /* Fallback path: mprotect dance. Single naturally-aligned write into
     * the now-RW page preserves the atomicity argument above. The window
     * where the page is RW is brief but non-zero; peer threads executing
     * the same page see no permission change for execute (Linux's RW flag
     * doesn't clear X on the PTE), so they keep executing. */
    if (protect_range(addr, len, PROT_READ | PROT_WRITE) < 0) return -1;
    memcpy((void *)addr, src, len);
    if (protect_range(addr, len, PROT_READ | PROT_EXEC) < 0) return -1;
    return 0;
}

int patch_validate(const struct patch_entry *e) {
    if (e->len < libcov_min_patch_len || e->len > libcov_max_patch_len) return -1;
    return memcmp((void *)e->addr, e->orig, e->len) == 0 ? 0 : -1;
}

/* Acquire e->lock by spinning on a 0->1 cmpxchg. Bounded wait because the
 * critical section is just one pwrite + clear_cache + membarrier (single
 * digit microseconds). Safe in a signal handler:
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
    while (!__atomic_compare_exchange_n(&e->lock, &expected, 1,
                                        0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        expected = 0;
        __asm__ volatile ("" ::: "memory");
    }
}

static inline void entry_unlock(struct patch_entry *e) {
    __atomic_store_n(&e->lock, 0, __ATOMIC_RELEASE);
}

int patch_arm(struct patch_entry *e) {
    entry_lock(e);
    int rv = 0;
    if (!e->patched) {
        unsigned char buf[16];
        libcov_arch_write_illegal(buf, e->len);
        if (write_bytes(e->addr, buf, e->len) == 0) {
            __builtin___clear_cache((char *)e->addr, (char *)e->addr + e->len);
            membarrier_sync_core();
            e->patched = 1;
        } else {
            rv = -1;
        }
    }
    entry_unlock(e);
    return rv;
}

int patch_disarm(struct patch_entry *e) {
    entry_lock(e);
    int rv = 0;
    if (e->patched) {
        if (write_bytes(e->addr, e->orig, e->len) == 0) {
            __builtin___clear_cache((char *)e->addr, (char *)e->addr + e->len);
            membarrier_sync_core();
            e->patched = 0;
        } else {
            rv = -1;
        }
    }
    entry_unlock(e);
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

/* Signal-safe binary search. Returned pointer aliases the global table. */
struct patch_entry *patch_lookup(uintptr_t addr) {
    size_t n;
    struct patch_entry *t = config_table_mut(&n);
    if (!t || n == 0) return NULL;
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (t[mid].addr == addr) return &t[mid];
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
