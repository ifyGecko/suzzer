/*
 * tunables.h -- project-wide tunables (cross-cutting knobs).
 *
 * Every knob in this file is `#ifndef`-guarded. There are two ways to
 * change a value, and either is fine:
 *
 *   1. Edit the default value next to the `#define` below.
 *   2. Pass -DLIBCOV_FOO=bar on the build line (the -D wins because the
 *      preprocessor sees it before the `#ifndef` is evaluated).
 *
 * For per-architecture knobs (illegal-instruction encodings, instruction
 * widths) see src/tunables_<arch>.h. This file holds only knobs that are
 * not specific to one backend.
 *
 * NOTE: this file is NOT the on-disk patch-list wire format -- that lives
 * in src/patchlist_format.h. Different file, different concern.
 */
#ifndef LIBCOV_TUNABLES_H
#define LIBCOV_TUNABLES_H

#include <signal.h>

/* ------------------------------------------------------------------ */
/* Trap signal                                                        */
/* ------------------------------------------------------------------ */

/* LIBCOV_TRAP_SIGNO
 *   Signal the trap-trampoline coverage runtime catches when a patched
 *   site executes. Every arch backend must encode an instruction sequence
 *   that raises this signal at the patched address.
 *
 *   Default SIGILL. Every shipped backend's default illegal-instruction
 *   encoding raises SIGILL on Linux. If you change this you must also
 *   change every per-arch ILLEGAL encoding you intend to build for, so
 *   that the encoding matches the signal.
 *
 *   Override at build: -DLIBCOV_TRAP_SIGNO=SIGTRAP
 *   Override in source: edit the value next to the #define below.
 */
#ifndef LIBCOV_TRAP_SIGNO
#define LIBCOV_TRAP_SIGNO SIGILL
#endif

/* ------------------------------------------------------------------ */
/* Coverage bitmap                                                    */
/* ------------------------------------------------------------------ */

/* LIBCOV_MAP_SIZE_POW2
 *   log2 of the coverage bitmap byte length. The bitmap is
 *   (1 << LIBCOV_MAP_SIZE_POW2) bytes.
 *
 *   Default 16 (= 64 KiB). Matches AFL/AFL++ default; tooling that reads
 *   the bitmap usually assumes 64 KiB unless told otherwise via the
 *   shm header's `map_size` field.
 *
 *   Override at build: -DLIBCOV_MAP_SIZE_POW2=15  (32 KiB)
 *   Override in source: edit the value next to the #define below.
 *
 *   Constraints: integer in [12, 20]. Smaller maps collide more; larger
 *   maps cost memory per snapshot slot. The shm layout in sink.h derives
 *   LIBCOV_MAP_SIZE and LIBCOV_MAP_MASK from this value.
 */
#ifndef LIBCOV_MAP_SIZE_POW2
#define LIBCOV_MAP_SIZE_POW2 16
#endif

/* ------------------------------------------------------------------ */
/* Init-time logging (util.c)                                         */
/* ------------------------------------------------------------------ */

/* LIBCOV_LOG_BUFFER_SIZE
 *   Size of the per-call stack buffer used by libcov_logf(). One message
 *   that exceeds this length is truncated to fit.
 *
 *   Default 512 bytes.
 *
 *   Override at build: -DLIBCOV_LOG_BUFFER_SIZE=1024
 *   Override in source: edit the value next to the #define below.
 */
#ifndef LIBCOV_LOG_BUFFER_SIZE
#define LIBCOV_LOG_BUFFER_SIZE 512
#endif

#endif /* LIBCOV_TUNABLES_H */
