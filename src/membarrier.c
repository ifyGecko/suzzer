#define _GNU_SOURCE
#include "membarrier.h"
#include "util.h"

#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

/* The Linux constants live in <linux/membarrier.h>. That header isn't always
 * present (e.g. minimal toolchains). Provide our own copy of the bits we
 * use; the values are kernel-ABI-stable. */
#ifndef MEMBARRIER_CMD_QUERY
#define MEMBARRIER_CMD_QUERY 0
#endif
#ifndef MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE (1 << 7)
#endif
#ifndef MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (1 << 8)
#endif

static int g_have_sync_core = 0;

static long sys_membarrier(int cmd, unsigned int flags) {
#ifdef SYS_membarrier
    return syscall(SYS_membarrier, cmd, flags);
#else
    (void)cmd; (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

void membarrier_init(void) {
    long supported = sys_membarrier(MEMBARRIER_CMD_QUERY, 0);
    if (supported < 0) {
        libcov_logf("membarrier: kernel does not support membarrier (errno=%d) -- "
                    "MT runtime will rely on local clear_cache only; weakly-ordered "
                    "arches have a small residual cross-core I-cache race window",
                    errno);
        return;
    }
    if (!((unsigned long)supported & MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE)) {
        libcov_logf("membarrier: kernel lacks PRIVATE_EXPEDITED_SYNC_CORE "
                    "(supported_mask=0x%lx) -- MT runtime will rely on local "
                    "clear_cache only", (unsigned long)supported);
        return;
    }
    if (sys_membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0) < 0) {
        libcov_logf("membarrier: register PRIVATE_EXPEDITED_SYNC_CORE: errno=%d",
                    errno);
        return;
    }
    g_have_sync_core = 1;
    libcov_logf("membarrier: PRIVATE_EXPEDITED_SYNC_CORE active");
}

void membarrier_sync_core(void) {
    if (g_have_sync_core) {
        (void)sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0);
    }
    /* Else no-op: the caller is responsible for issuing clear_cache on the
     * writer's thread (see membarrier_has_sync_core()). On x86 (strong
     * ordering + snoopy cache) nothing more is needed. On weak ISAs
     * without membarrier, a peer thread may briefly observe stale bytes
     * -- documented in membarrier.h. */
}

int membarrier_has_sync_core(void) {
    return g_have_sync_core;
}
