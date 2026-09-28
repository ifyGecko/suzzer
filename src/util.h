#ifndef LIBCOV_UTIL_H
#define LIBCOV_UTIL_H

#include <stdint.h>

/* Init-time logging. Writes "libcov: <msg>\n" to LIBCOV_LOG (or stderr if
 * unset). Never called from the signal handler. */
void libcov_log_init(void);
void libcov_logf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Returns load base of the first mapping whose pathname matches modname
 * (basename match). modname == NULL or "" -> match argv[0] basename.
 * Returns 0 on failure. */
uintptr_t util_module_base(const char *modname);

/* Returns [lo, hi) of libcov.so's own mapping (so we can refuse to patch
 * ourselves). Both 0 on failure. */
void util_self_range(uintptr_t *lo, uintptr_t *hi);

/* Spin-wait backoff for the signal-safe spinlocks (patch_mt.c entry and
 * fallback locks, boundary.c slot locks). Call once per failed acquire.
 * After LIBCOV_SPIN_YIELD_AFTER spins it yields the CPU: on a single-core
 * part with SCHED_FIFO threads, a pure spin can starve the lock holder
 * forever. sched_yield is a plain syscall with no libc state, so it is
 * safe in the trap handler. */
#define LIBCOV_SPIN_YIELD_AFTER 64u
void libcov_spin_backoff(unsigned *spins);

#endif
