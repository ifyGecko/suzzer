/*
 * tunables_mips64.h -- MIPS64 backend tunables (BE and LE).
 *
 * Override pattern: every knob is `#ifndef`-guarded. Edit the value next
 * to the `#define` below, OR pass -DLIBCOV_ARCH_MIPS64_FOO=bar at build
 * time. Either is fine; the -D wins.
 *
 * Encoding-wise this backend mirrors MIPS32; the only difference is the
 * ucontext layout (handled in arch_mips64.c) and ABI.
 */
#ifndef LIBCOV_TUNABLES_MIPS64_H
#define LIBCOV_TUNABLES_MIPS64_H

#include <stdint.h>

/* LIBCOV_ARCH_MIPS64_NAME
 *   Backend identifier string. Exposed via libcov_arch_name.
 */
#ifndef LIBCOV_ARCH_MIPS64_NAME
#define LIBCOV_ARCH_MIPS64_NAME "mips64"
#endif

/* LIBCOV_ARCH_MIPS64_ILLEGAL
 *   4-byte instruction word written by libcov_arch_write_illegal() to
 *   raise SIGILL at the patched site.
 *
 *   Default 0x40000000 -- same rationale as MIPS32: user-mode `MFC0`
 *   raises SIGILL via the Coprocessor Unusable handler on every Linux
 *   MIPS kernel.
 *
 *   This was historically a SIGTRAP backend (BREAK 0 = 0x0000000D). See
 *   tunables_mips.h for the LIBCOV_TRAP_SIGNO override recipe if you
 *   need the legacy behavior.
 *
 *   Override at build: -DLIBCOV_ARCH_MIPS64_ILLEGAL=0xDEADBEEFu
 *   Override in source: edit the value next to the #define below.
 */
#ifndef LIBCOV_ARCH_MIPS64_ILLEGAL
#define LIBCOV_ARCH_MIPS64_ILLEGAL 0x40000000u
#endif

/* LIBCOV_ARCH_MIPS64_MIN_PATCH_LEN
 * LIBCOV_ARCH_MIPS64_MAX_PATCH_LEN
 *   Fixed 4-byte instruction width.
 */
#ifndef LIBCOV_ARCH_MIPS64_MIN_PATCH_LEN
#define LIBCOV_ARCH_MIPS64_MIN_PATCH_LEN 4
#endif
#ifndef LIBCOV_ARCH_MIPS64_MAX_PATCH_LEN
#define LIBCOV_ARCH_MIPS64_MAX_PATCH_LEN 4
#endif

#endif /* LIBCOV_TUNABLES_MIPS64_H */
