/*
 * tunables_mips.h -- MIPS32 backend tunables (BE and LE).
 *
 * Override pattern: every knob is `#ifndef`-guarded. Edit the value next
 * to the `#define` below, OR pass -DLIBCOV_ARCH_MIPS_FOO=bar at build
 * time. Either is fine; the -D wins.
 */
#ifndef LIBCOV_TUNABLES_MIPS_H
#define LIBCOV_TUNABLES_MIPS_H

#include <stdint.h>

/* LIBCOV_ARCH_MIPS_NAME
 *   Backend identifier string. Exposed via libcov_arch_name.
 */
#ifndef LIBCOV_ARCH_MIPS_NAME
#define LIBCOV_ARCH_MIPS_NAME "mips"
#endif

/* LIBCOV_ARCH_MIPS_ILLEGAL
 *   4-byte instruction word written by libcov_arch_write_illegal() to
 *   raise SIGILL at the patched site.
 *
 *   Default 0x40000000 -- this encodes `MFC0 $0, $0`, a Coprocessor 0
 *   access from user mode. The Linux MIPS kernel unconditionally rejects
 *   user-mode COP0 access by delivering SIGILL (ILL_PRVOPC) via the
 *   Coprocessor Unusable handler, on every MIPS revision (r1..r6).
 *
 *   This was historically a SIGTRAP backend (BREAK 0 = 0x0000000D). It
 *   is now SIGILL by default so a single signal handler covers every
 *   backend; if you need the legacy behavior, override LIBCOV_TRAP_SIGNO
 *   in tunables.h and override this encoding here:
 *     -DLIBCOV_ARCH_MIPS_ILLEGAL=0x0000000Du
 *     -DLIBCOV_TRAP_SIGNO=SIGTRAP
 *
 *   Override at build: -DLIBCOV_ARCH_MIPS_ILLEGAL=0xDEADBEEFu
 *   Override in source: edit the value next to the #define below.
 *
 *   Constraints: 32-bit unsigned. Stored little-endian on mipsel, big-
 *   endian on mips, via memcpy() of the host-endian uint32_t value. Must
 *   decode to something the target CPU raises SIGILL for; if your target
 *   has odd COP0 emulation, override.
 */
#ifndef LIBCOV_ARCH_MIPS_ILLEGAL
#define LIBCOV_ARCH_MIPS_ILLEGAL 0x40000000u
#endif

/* LIBCOV_ARCH_MIPS_MIN_PATCH_LEN
 * LIBCOV_ARCH_MIPS_MAX_PATCH_LEN
 *   Fixed 4-byte instruction width. The generator avoids delay slots
 *   (instruction after a branch); never patch into one.
 */
#ifndef LIBCOV_ARCH_MIPS_MIN_PATCH_LEN
#define LIBCOV_ARCH_MIPS_MIN_PATCH_LEN 4
#endif
#ifndef LIBCOV_ARCH_MIPS_MAX_PATCH_LEN
#define LIBCOV_ARCH_MIPS_MAX_PATCH_LEN 4
#endif

#endif /* LIBCOV_TUNABLES_MIPS_H */
