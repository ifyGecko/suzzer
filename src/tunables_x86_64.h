/*
 * tunables_x86_64.h -- x86_64 backend tunables.
 *
 * Override pattern: every knob is `#ifndef`-guarded. Edit the value next
 * to the `#define` below, OR pass -DLIBCOV_ARCH_X86_64_FOO=bar at build
 * time. Either is fine; the -D wins.
 *
 * Patch shape: head-only UD2 (2 bytes). The original instruction tail is
 * never touched -- the trap fires at UD2 before the tail is decoded, and
 * disarm restores the head, so the original instruction is intact. This
 * matches the MT backend's single-store contract (Intel SDM Vol 3 Sec
 * 8.1.1: naturally-aligned 2-byte stores are single-copy-atomic) and the
 * generator's --threading mt mode further requires sites that don't
 * straddle a 64-byte cache line.
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

/* LIBCOV_ARCH_X86_64_MIN_PATCH_LEN
 * LIBCOV_ARCH_X86_64_MAX_PATCH_LEN
 *   Patch length the runtime will accept. UD2 is 2 bytes; head-only
 *   patching means we always write exactly 2 bytes. Both ST and MT
 *   builds use the same value.
 */
#ifndef LIBCOV_ARCH_X86_64_MIN_PATCH_LEN
#define LIBCOV_ARCH_X86_64_MIN_PATCH_LEN 2
#endif
#ifndef LIBCOV_ARCH_X86_64_MAX_PATCH_LEN
#define LIBCOV_ARCH_X86_64_MAX_PATCH_LEN 2
#endif

#endif /* LIBCOV_TUNABLES_X86_64_H */
