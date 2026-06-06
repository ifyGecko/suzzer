/*
 * tunables_powerpc.h -- PowerPC 32-bit BE backend tunables.
 *
 * Override pattern: every knob is `#ifndef`-guarded. Edit the value next
 * to the `#define` below, OR pass -DLIBCOV_ARCH_PPC_FOO=bar at build
 * time. Either is fine; the -D wins.
 */
#ifndef LIBCOV_TUNABLES_POWERPC_H
#define LIBCOV_TUNABLES_POWERPC_H

#include <stdint.h>

/* LIBCOV_ARCH_PPC_NAME
 *   Backend identifier string. Exposed via libcov_arch_name.
 */
#ifndef LIBCOV_ARCH_PPC_NAME
#define LIBCOV_ARCH_PPC_NAME "powerpc"
#endif

/* LIBCOV_ARCH_PPC_ILLEGAL
 *   4-byte instruction word written by libcov_arch_write_illegal() to
 *   raise SIGILL at the patched site.
 *
 *   Default 0x00000000 -- the all-zero word is reserved as illegal by
 *   the PowerISA spec across all variants (32-bit and 64-bit, BE and LE).
 *   Raises a Program Check interrupt, which Linux delivers as SIGILL
 *   (ILL_ILLOPC).
 *
 *   This was historically a SIGTRAP backend (`tw 31,0,0` = 0x7FE00008).
 *   It is now SIGILL by default so a single signal handler covers every
 *   backend. To restore the legacy behavior:
 *     -DLIBCOV_ARCH_PPC_ILLEGAL=0x7FE00008u
 *     -DLIBCOV_TRAP_SIGNO=SIGTRAP
 *
 *   Override at build: -DLIBCOV_ARCH_PPC_ILLEGAL=0xDEADBEEFu
 *   Override in source: edit the value next to the #define below.
 */
#ifndef LIBCOV_ARCH_PPC_ILLEGAL
#define LIBCOV_ARCH_PPC_ILLEGAL 0x00000000u
#endif

/* LIBCOV_ARCH_PPC_MIN_PATCH_LEN
 * LIBCOV_ARCH_PPC_MAX_PATCH_LEN
 *   Fixed 4-byte instruction width on PowerPC.
 */
#ifndef LIBCOV_ARCH_PPC_MIN_PATCH_LEN
#define LIBCOV_ARCH_PPC_MIN_PATCH_LEN 4
#endif
#ifndef LIBCOV_ARCH_PPC_MAX_PATCH_LEN
#define LIBCOV_ARCH_PPC_MAX_PATCH_LEN 4
#endif

#endif /* LIBCOV_TUNABLES_POWERPC_H */
