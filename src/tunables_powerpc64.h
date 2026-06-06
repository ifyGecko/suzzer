/*
 * tunables_powerpc64.h -- PowerPC 64-bit backend tunables (BE and LE).
 *
 * Override pattern: every knob is `#ifndef`-guarded. Edit the value next
 * to the `#define` below, OR pass -DLIBCOV_ARCH_PPC64_FOO=bar at build
 * time. Either is fine; the -D wins.
 *
 * Encoding-wise this backend mirrors PPC32; only the ucontext layout
 * differs (handled in arch_powerpc64.c).
 */
#ifndef LIBCOV_TUNABLES_POWERPC64_H
#define LIBCOV_TUNABLES_POWERPC64_H

#include <stdint.h>

/* LIBCOV_ARCH_PPC64_NAME
 *   Backend identifier string. Exposed via libcov_arch_name.
 */
#ifndef LIBCOV_ARCH_PPC64_NAME
#define LIBCOV_ARCH_PPC64_NAME "powerpc64"
#endif

/* LIBCOV_ARCH_PPC64_ILLEGAL
 *   4-byte instruction word written by libcov_arch_write_illegal() to
 *   raise SIGILL at the patched site.
 *
 *   Default 0x00000000 -- same rationale as PPC32: PowerISA reserves the
 *   all-zero word as illegal across all variants; Linux delivers SIGILL.
 *
 *   This was historically a SIGTRAP backend (`tw 31,0,0` = 0x7FE00008).
 *   See tunables_powerpc.h for the LIBCOV_TRAP_SIGNO override recipe if
 *   you need the legacy behavior.
 *
 *   Override at build: -DLIBCOV_ARCH_PPC64_ILLEGAL=0xDEADBEEFu
 *   Override in source: edit the value next to the #define below.
 */
#ifndef LIBCOV_ARCH_PPC64_ILLEGAL
#define LIBCOV_ARCH_PPC64_ILLEGAL 0x00000000u
#endif

/* LIBCOV_ARCH_PPC64_MIN_PATCH_LEN
 * LIBCOV_ARCH_PPC64_MAX_PATCH_LEN
 *   Fixed 4-byte instruction width.
 */
#ifndef LIBCOV_ARCH_PPC64_MIN_PATCH_LEN
#define LIBCOV_ARCH_PPC64_MIN_PATCH_LEN 4
#endif
#ifndef LIBCOV_ARCH_PPC64_MAX_PATCH_LEN
#define LIBCOV_ARCH_PPC64_MAX_PATCH_LEN 4
#endif

#endif /* LIBCOV_TUNABLES_POWERPC64_H */
