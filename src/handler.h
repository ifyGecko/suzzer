#ifndef LIBCOV_HANDLER_H
#define LIBCOV_HANDLER_H

#include <signal.h>

enum libcov_mode { LIBCOV_MODE_ONESHOT = 0, LIBCOV_MODE_LEAPFROG = 1 };

/* Install the trap handler. The disposition that was in place before
 * (if any) is written to *prev_out so libcov.c can chain to it. */
int handler_install(enum libcov_mode mode, struct sigaction *prev_out);

/* Build the sa_mask for our trap handler: every signal blocked except the
 * synchronous fault signals. Blocking async signals while we patch code
 * stops a target signal handler from running instrumented code mid-patch
 * (self-deadlock on a patch_mt spinlock, or executing a page the ST path
 * has transiently made non-executable). Synchronous faults stay unblocked:
 * the kernel kills the process if one arrives while blocked. */
void handler_build_mask(sigset_t *mask);

/* Dispatch a trap that is not one of ours (pc not in the patch table) to
 * whatever handler the target believes it has installed for the trap
 * signal -- the pre-init disposition, or one it set later through our
 * sigaction()/signal() interposers. Defined in libcov.c. */
void libcov_chain_trap(int signo, siginfo_t *info, void *uctx);

#endif
