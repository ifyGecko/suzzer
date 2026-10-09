#ifndef LIBCOV_UTIL_H
#define LIBCOV_UTIL_H

#include <stdint.h>
#include <stddef.h>

/* Init-time logging. Writes "libcov: <msg>\n" to LIBCOV_LOG (or stderr if
 * unset). Never called from the signal handler. After libcov_log_seal()
 * (end of init) a line is dropped unless the log fd still refers to the
 * file it did at init and is not a socket: the target may have reused
 * the fd number or dup2'd a socket onto fd 2. */
void libcov_log_init(void);
void libcov_log_seal(void);
void libcov_logf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Returns the load base of the first mapping whose pathname matches
 * modname, or 0. A bare name matches the basename; an absolute path (after
 * realpath) matches the full path; NULL or "" matches the main executable
 * exactly. A " (deleted)" suffix on the mapping is ignored. Logs a warning
 * if a bare name matches two different files. */
uintptr_t util_module_base(const char *modname);

/* Init-time snapshot of /proc/self/maps, so patch_arm_all can check that
 * a patch site is mapped before reading it (a patch list for another
 * build can point anywhere). util_range_in_module returns 1 if
 * [addr, addr+len) lies in readable, contiguous mappings of the file whose
 * base (as util_module_base computes it) is module_base, else 0; with no
 * snapshot loaded (maps unreadable) it returns 1, i.e. no check. Not
 * signal-safe. */
int  util_maps_load(void);
int  util_range_in_module(uintptr_t module_base, uintptr_t addr, size_t len);
void util_maps_free(void);

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
