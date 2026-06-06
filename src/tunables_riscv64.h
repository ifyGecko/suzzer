/*
 * tunables_riscv64.h -- RISC-V 64-bit backend tunables.
 *
 * Override pattern: every knob is `#ifndef`-guarded. Edit the value next
 * to the `#define` below, OR pass -DLIBCOV_ARCH_RISCV64_FOO=bar at build
 * time. Either is fine; the -D wins.
 *
 * RISC-V mixes 2-byte (C extension) and 4-byte instructions. The runtime
 * picks the encoding from the entry's `len` (2 or 4) at arm time. For
 * a 4-byte patch site we write 0x00000000 (two c.unimp halfwords); the
 * first c.unimp traps before the second is decoded.
 */
#ifndef LIBCOV_TUNABLES_RISCV64_H
#define LIBCOV_TUNABLES_RISCV64_H

#include <stdint.h>

/* LIBCOV_ARCH_RISCV64_NAME
 *   Backend identifier string. Exposed via libcov_arch_name.
 */
#ifndef LIBCOV_ARCH_RISCV64_NAME
#define LIBCOV_ARCH_RISCV64_NAME "riscv64"
#endif

/* LIBCOV_ARCH_RISCV64_ILLEGAL_C
 *   2-byte halfword written for compressed (len=2) patch sites. Also
 *   used twice back-to-back when patching a 4-byte site.
 *
 *   Default 0x0000 -- c.unimp, defined by the RVC spec as permanently
 *   illegal. Raises SIGILL on Linux/riscv64.
 *
 *   Override at build: -DLIBCOV_ARCH_RISCV64_ILLEGAL_C=0xDEADu
 *   Override in source: edit the value next to the #define below.
 */
#ifndef LIBCOV_ARCH_RISCV64_ILLEGAL_C
#define LIBCOV_ARCH_RISCV64_ILLEGAL_C 0x0000u
#endif

/* LIBCOV_ARCH_RISCV64_ILLEGAL_W
 *   4-byte word written for non-compressed (len=4) patch sites.
 *
 *   Default 0x00000000 -- two back-to-back c.unimps. The first traps
 *   immediately; the second is never decoded.
 *
 *   Override at build: -DLIBCOV_ARCH_RISCV64_ILLEGAL_W=0xDEADBEEFu
 *   Override in source: edit the value next to the #define below.
 */
#ifndef LIBCOV_ARCH_RISCV64_ILLEGAL_W
#define LIBCOV_ARCH_RISCV64_ILLEGAL_W 0x00000000u
#endif

/* LIBCOV_ARCH_RISCV64_MIN_PATCH_LEN
 * LIBCOV_ARCH_RISCV64_MAX_PATCH_LEN
 *   Compressed (RVC) is 2 bytes; non-compressed is 4 bytes.
 */
#ifndef LIBCOV_ARCH_RISCV64_MIN_PATCH_LEN
#define LIBCOV_ARCH_RISCV64_MIN_PATCH_LEN 2
#endif
#ifndef LIBCOV_ARCH_RISCV64_MAX_PATCH_LEN
#define LIBCOV_ARCH_RISCV64_MAX_PATCH_LEN 4
#endif

#endif /* LIBCOV_TUNABLES_RISCV64_H */
