/*
 * tunables_aarch64.h -- aarch64 backend tunables.
 *
 * Override pattern: every knob is `#ifndef`-guarded. Edit the value next
 * to the `#define` below, OR pass -DLIBCOV_ARCH_AARCH64_FOO=bar at build
 * time. Either is fine; the -D wins.
 */
#ifndef LIBCOV_TUNABLES_AARCH64_H
#define LIBCOV_TUNABLES_AARCH64_H

#include <stdint.h>

/* LIBCOV_ARCH_AARCH64_NAME
 *   Backend identifier string. Exposed via libcov_arch_name.
 */
#ifndef LIBCOV_ARCH_AARCH64_NAME
#define LIBCOV_ARCH_AARCH64_NAME "aarch64"
#endif

/* LIBCOV_ARCH_AARCH64_ILLEGAL
 *   4-byte instruction word written by libcov_arch_write_illegal() to
 *   raise SIGILL at the patched site.
 *
 *   Default 0x00000000 -- the all-zero word decodes as UDF #0, which the
 *   ARM ARM defines as Permanently Undefined. Raises SIGILL (ILL_ILLOPC)
 *   on every aarch64 Linux kernel.
 *
 *   Override at build: -DLIBCOV_ARCH_AARCH64_ILLEGAL=0xDEADBEEFu
 *   Override in source: edit the value next to the #define below.
 *
 *   Constraints: 32-bit unsigned. Stored little-endian by memcpy() on
 *   aarch64 LE (the only ABI Linux supports today). Must decode as an
 *   undefined instruction; if you change this, verify under qemu-user
 *   or on real hardware before fuzzing.
 */
#ifndef LIBCOV_ARCH_AARCH64_ILLEGAL
#define LIBCOV_ARCH_AARCH64_ILLEGAL 0x00000000u
#endif

/* LIBCOV_ARCH_AARCH64_MIN_PATCH_LEN
 * LIBCOV_ARCH_AARCH64_MAX_PATCH_LEN
 *   Fixed 4-byte instruction width on aarch64. Both bounded to 4.
 */
#ifndef LIBCOV_ARCH_AARCH64_MIN_PATCH_LEN
#define LIBCOV_ARCH_AARCH64_MIN_PATCH_LEN 4
#endif
#ifndef LIBCOV_ARCH_AARCH64_MAX_PATCH_LEN
#define LIBCOV_ARCH_AARCH64_MAX_PATCH_LEN 4
#endif

#endif /* LIBCOV_TUNABLES_AARCH64_H */
