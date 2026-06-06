/*
 * tunables_x86_64.h -- x86_64 backend tunables.
 *
 * Override pattern: every knob is `#ifndef`-guarded. Edit the value next
 * to the `#define` below, OR pass -DLIBCOV_ARCH_X86_64_FOO=bar at build
 * time. Either is fine; the -D wins.
 *
 * Threading note: the MT build (-DLIBCOV_THREADING_MT, set by the
 * Makefile) tightens MAX_PATCH_LEN to 2 because only a naturally-aligned
 * 2-byte UD2 write is single-copy-atomic per Intel SDM Vol 3 Sec 8.1.1
 * (also requires the site to not straddle a cache line; the generator's
 * --threading mt mode enforces that).
 */
#ifndef LIBCOV_TUNABLES_X86_64_H
#define LIBCOV_TUNABLES_X86_64_H

#include <stdint.h>

/* LIBCOV_ARCH_X86_64_NAME
 *   Backend identifier string. Appears in init-time logs and is exposed
 *   via the libcov_arch_name extern.
 */
#ifndef LIBCOV_ARCH_X86_64_NAME
#define LIBCOV_ARCH_X86_64_NAME "x86_64"
#endif

/* LIBCOV_ARCH_X86_64_ILLEGAL_BYTE0
 * LIBCOV_ARCH_X86_64_ILLEGAL_BYTE1
 *   Two bytes of UD2 (Intel Undefined Instruction), the canonical x86_64
 *   illegal encoding. Raises SIGILL (ILL_ILLOPC) on Linux unconditionally.
 *
 *   Default 0x0F 0x0B. There is no good reason to change these on a real
 *   x86_64 target; they are exposed for testing/diagnostic use.
 */
#ifndef LIBCOV_ARCH_X86_64_ILLEGAL_BYTE0
#define LIBCOV_ARCH_X86_64_ILLEGAL_BYTE0 0x0F
#endif
#ifndef LIBCOV_ARCH_X86_64_ILLEGAL_BYTE1
#define LIBCOV_ARCH_X86_64_ILLEGAL_BYTE1 0x0B
#endif

/* LIBCOV_ARCH_X86_64_NOP_BYTE
 *   Padding byte written after UD2 when patching a >2-byte instruction
 *   (ST build only; MT build never pads -- see threading note above).
 *
 *   Default 0x90 (NOP). The padding is never executed because UD2 fires
 *   first; this byte is unobservable at runtime but is fetched by the
 *   CPU's frontend, so it must decode to something benign.
 */
#ifndef LIBCOV_ARCH_X86_64_NOP_BYTE
#define LIBCOV_ARCH_X86_64_NOP_BYTE 0x90
#endif

/* LIBCOV_ARCH_X86_64_MIN_PATCH_LEN
 *   Minimum original-instruction length the runtime will accept. UD2 is
 *   2 bytes, so anything shorter cannot be safely patched.
 */
#ifndef LIBCOV_ARCH_X86_64_MIN_PATCH_LEN
#define LIBCOV_ARCH_X86_64_MIN_PATCH_LEN 2
#endif

/* LIBCOV_ARCH_X86_64_MAX_PATCH_LEN
 *   Maximum original-instruction length the runtime will accept.
 *
 *   ST default 15 (the x86_64 hardware max). The ST patch path writes
 *   UD2 + (len-2) NOP padding.
 *
 *   MT default 2 (UD2 only; see threading note above).
 *
 *   The MT override below kicks in when LIBCOV_THREADING_MT is defined
 *   (set by the Makefile for `make THREADING=mt`). To force a custom
 *   max length, pass -DLIBCOV_ARCH_X86_64_MAX_PATCH_LEN=N which wins
 *   over both defaults.
 */
#ifndef LIBCOV_ARCH_X86_64_MAX_PATCH_LEN
# if defined(LIBCOV_THREADING_MT)
#  define LIBCOV_ARCH_X86_64_MAX_PATCH_LEN 2
# else
#  define LIBCOV_ARCH_X86_64_MAX_PATCH_LEN 15
# endif
#endif

#endif /* LIBCOV_TUNABLES_X86_64_H */
