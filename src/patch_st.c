#define _GNU_SOURCE
#include "patch.h"
#include "arch.h"
#include "util.h"

#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

static long g_pagesize = 0;

static void ensure_pagesize(void) {
    if (!g_pagesize) g_pagesize = sysconf(_SC_PAGESIZE);
}

/* mprotect the page(s) covering [addr, addr+len) with prot. Returns 0 on
 * success. Signal-safe (mprotect is async-signal-safe). */
static int protect_range(uintptr_t addr, size_t len, int prot) {
    long ps = g_pagesize;
    uintptr_t page = addr & ~((uintptr_t)ps - 1);
    uintptr_t end  = addr + len;
    size_t span = (size_t)(((end + ps - 1) & ~((uintptr_t)ps - 1)) - page);
    return mprotect((void *)page, span, prot);
}

int patch_validate(const struct patch_entry *e) {
    if (e->len < libcov_min_patch_len || e->len > libcov_max_patch_len) return -1;
    return memcmp((void *)e->addr, e->orig, e->len) == 0 ? 0 : -1;
}

int patch_arm(struct patch_entry *e) {
    ensure_pagesize();
    if (protect_range(e->addr, e->len, PROT_READ | PROT_WRITE) < 0) return -1;
    libcov_arch_write_illegal((void *)e->addr, e->len);
    if (protect_range(e->addr, e->len, PROT_READ | PROT_EXEC) < 0) return -1;
    __builtin___clear_cache((char *)e->addr, (char *)e->addr + e->len);
    e->patched = 1;
    return 0;
}

int patch_disarm(struct patch_entry *e) {
    ensure_pagesize();
    if (protect_range(e->addr, e->len, PROT_READ | PROT_WRITE) < 0) return -1;
    memcpy((void *)e->addr, e->orig, e->len);
    if (protect_range(e->addr, e->len, PROT_READ | PROT_EXEC) < 0) return -1;
    __builtin___clear_cache((char *)e->addr, (char *)e->addr + e->len);
    e->patched = 0;
    return 0;
}

size_t patch_arm_all(void) {
    size_t n;
    struct patch_entry *t = config_table_mut(&n);
    if (!t) return 0;

    uintptr_t self_lo, self_hi;
    util_self_range(&self_lo, &self_hi);

    size_t armed = 0, skipped = 0, validate_fail = 0;
    for (size_t i = 0; i < n; i++) {
        struct patch_entry *e = &t[i];
        if (self_lo && e->addr >= self_lo && e->addr < self_hi) {
            libcov_logf("patch: refusing self-patch at 0x%lx", (unsigned long)e->addr);
            skipped++;
            continue;
        }
        if (patch_validate(e) != 0) {
            libcov_logf("patch: stale entry at 0x%lx (bytes mismatch)", (unsigned long)e->addr);
            validate_fail++;
            continue;
        }
        if (patch_arm(e) != 0) {
            libcov_logf("patch: arm failed at 0x%lx: %s", (unsigned long)e->addr, strerror(errno));
            continue;
        }
        armed++;
    }
    libcov_logf("patch: armed=%zu skipped=%zu stale=%zu", armed, skipped, validate_fail);
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
        if (!e || e->patched) continue;
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
        if (t[i].patched) continue;
        if (patch_arm(&t[i]) == 0) armed++;
    }
    return armed;
}
