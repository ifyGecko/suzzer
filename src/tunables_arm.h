/*
 * tunables_arm.h -- ARMv7 backend tunables (ARM + Thumb).
 *
 * Override pattern: every knob is `#ifndef`-guarded. Edit the value next
 * to the `#define` below, OR pass -DLIBCOV_ARCH_ARM_FOO=bar at build
 * time. Either is fine; the -D wins.
 *
 * Per-site mode selection: the generator records len=4 for ARM-mode
 * sites and len=2 for Thumb-mode sites. The runtime picks the encoding
 * from len at arm time. For 4-byte Thumb-2 instructions we patch only
 * the first 2 bytes with UDF.N -- the kernel traps before the back half
 * is decoded, and restore leaves the back half intact.
 */
#ifndef LIBCOV_TUNABLES_ARM_H
#define LIBCOV_TUNABLES_ARM_H

#include <stdint.h>

/* LIBCOV_ARCH_ARM_NAME
 *   Backend identifier string. Exposed via libcov_arch_name.
 */
#ifndef LIBCOV_ARCH_ARM_NAME
#define LIBCOV_ARCH_ARM_NAME "arm"
#endif

/* LIBCOV_ARCH_ARM_ILLEGAL_ARM
 *   4-byte instruction word written for ARM-mode (len=4) patch sites.
 *
 *   Default 0xE7F000F0 -- "permanently undefined" UDF encoding from the
 *   ARMv7-A ARM (section A8.8.247). Raises SIGILL on Linux/armhf.
 *   Stored little-endian on standard armhf builds.
 *
 *   Override at build: -DLIBCOV_ARCH_ARM_ILLEGAL_ARM=0xDEADBEEFu
 *   Override in source: edit the value next to the #define below.
 */
#ifndef LIBCOV_ARCH_ARM_ILLEGAL_ARM
#define LIBCOV_ARCH_ARM_ILLEGAL_ARM 0xE7F000F0u
#endif

/* LIBCOV_ARCH_ARM_ILLEGAL_THUMB
 *   2-byte instruction halfword written for Thumb-mode (len=2) patch
 *   sites, and for the first 2 bytes of 4-byte Thumb-2 sites.
 *
 *   Default 0xDE00 -- UDF.N (Thumb permanently undefined). Raises SIGILL
 *   on Linux/armhf.
 *
 *   Override at build: -DLIBCOV_ARCH_ARM_ILLEGAL_THUMB=0xDEADu
 *   Override in source: edit the value next to the #define below.
 */
#ifndef LIBCOV_ARCH_ARM_ILLEGAL_THUMB
#define LIBCOV_ARCH_ARM_ILLEGAL_THUMB 0xDE00u
#endif

/* LIBCOV_ARCH_ARM_MIN_PATCH_LEN
 * LIBCOV_ARCH_ARM_MAX_PATCH_LEN
 *   Thumb is 2 bytes minimum; ARM mode is 4 bytes maximum.
 */
#ifndef LIBCOV_ARCH_ARM_MIN_PATCH_LEN
#define LIBCOV_ARCH_ARM_MIN_PATCH_LEN 2
#endif
#ifndef LIBCOV_ARCH_ARM_MAX_PATCH_LEN
#define LIBCOV_ARCH_ARM_MAX_PATCH_LEN 4
#endif

#endif /* LIBCOV_TUNABLES_ARM_H */
