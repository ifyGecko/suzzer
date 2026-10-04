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
 *   log2 of the coverage bitmap byte length under the legacy hashed-PC
 *   model (LIBCOV_COVERAGE_MODEL_SITE=0) only; the default site-id model
 *   auto-sizes the map from the patch count (LIBCOV_MAP_FUDGE below).
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
/* Coverage model: site_id-indexed (default) vs hashed-PC (legacy)    */
/* ------------------------------------------------------------------ */

/* LIBCOV_COVERAGE_MODEL_SITE
 *   Selects how sink_emit() derives the bitmap bucket index.
 *
 *     1 (default) -- site-id model. Each patch site has a dense id in
 *                    [0, N) assigned at config_load time (the file record
 *                    index). The bucket index *base* is that id, so at
 *                    N-gram length 1 (block coverage) idx == site_id and
 *                    the map has ZERO collisions. For N>=2 the last N-1
 *                    site ids are folded in (spread across the map first)
 *                    for path sensitivity, so collisions are possible only
 *                    in the fold step. The bitmap auto-sizes from the patch
 *                    count (see LIBCOV_MAP_FUDGE) -- LIBCOV_MAP_SIZE_POW2 is
 *                    NOT used in this mode.
 *
 *     0            -- legacy hashed-PC model. idx base = hash(pc) masked to
 *                     a fixed (1 << LIBCOV_MAP_SIZE_POW2) map, last N-1 PCs
 *                     XOR-folded. Bit-for-bit identical to historical libcov.
 *
 *   Override at build: -DLIBCOV_COVERAGE_MODEL_SITE=0
 */
#ifndef LIBCOV_COVERAGE_MODEL_SITE
#define LIBCOV_COVERAGE_MODEL_SITE 1
#endif

/* LIBCOV_MAP_FUDGE
 *   Headroom multiplier for the auto-sized site-id map:
 *     map_size = next_pow2(n_sites * LIBCOV_MAP_FUDGE), clamped.
 *   The extra slots above n_sites give the N-gram fold room to spread so
 *   distinct (cur, history) tuples collide less. Only consulted when
 *   LIBCOV_COVERAGE_MODEL_SITE=1. Default 16 (headroom for N=3 folds).
 *   For pure block coverage (N=1) the fudge only wastes (harmless) memory --
 *   a smaller value such as 2 is sufficient there.
 *
 *   Override at build: -DLIBCOV_MAP_FUDGE=8
 */
#ifndef LIBCOV_MAP_FUDGE
#define LIBCOV_MAP_FUDGE 16u
#endif

/* LIBCOV_MAP_MIN_POW2 / LIBCOV_MAP_MAX_POW2
 *   Soft clamps on the auto-sized site-id map (log2 byte length). The map
 *   never shrinks below 1<<MIN nor grows past 1<<MAX *for the fudge term* --
 *   but a hard floor of next_pow2(n_sites) is always honoured even above
 *   1<<MAX, so site_id always fits the mask and the N=1 zero-collision
 *   guarantee holds regardless of clamps.
 */
#ifndef LIBCOV_MAP_MIN_POW2
#define LIBCOV_MAP_MIN_POW2 12
#endif
#ifndef LIBCOV_MAP_MAX_POW2
#define LIBCOV_MAP_MAX_POW2 24
#endif

/* ------------------------------------------------------------------ */
/* Coverage collection scheme (N-gram window)                         */
/* ------------------------------------------------------------------ */

/* LIBCOV_NGRAM_N
 *   Length of the PC window combined into each bitmap bucket on every
 *   sink_emit(). Sets the "shape" of coverage collection without
 *   touching the bitmap layout (size, hash, saturation, atomics).
 *
 *   cur = site_id (default site-id model) or hash(pc) (legacy model).
 *
 *     N=1   block coverage  -- idx = cur; prev-PC window unused.
 *                              Cheapest. Bucket means "block was hit".
 *     N=2   edges           -- idx = (cur ^ prev[0]) & MASK.
 *                              Default. Bit-for-bit identical to the
 *                              historical libcov emit only under the
 *                              legacy model. Bucket means "edge
 *                              prev->cur was taken".
 *     N>=3  N-gram coverage -- idx = cur ^ prev[0] ^ ... ^ prev[N-2].
 *                              Bucket means "the last N control
 *                              transfers in this thread were this exact
 *                              tuple". More context, more sensitive to
 *                              path differences, slightly more collision
 *                              pressure for the same bitmap size.
 *
 *   Cost per emit: approximately (N-1) XORs and (N-1) TLS stores in the
 *   window-shift step. Bitmap layout (LIBCOV_MAP_SIZE_POW2) is unchanged
 *   regardless of N -- consumers of the bitmap do not need to know N.
 *   The first (N-1) emits per thread XOR with zero-initialised window
 *   slots, biasing toward low buckets; this is the same warmup bias AFL
 *   already exhibits at iter-1 and is harmless in practice.
 *
 *   Override at build: -DLIBCOV_NGRAM_N=4
 *   Override in source: edit the value next to the #define below.
 *
 *   Constraints: integer in [1, 8]. Higher N inflates TLS pressure and
 *   collision rate without proportional sensitivity gain; if you really
 *   need >8, raise this cap together with the static_assert in sink.h.
 */
#ifndef LIBCOV_NGRAM_N
#define LIBCOV_NGRAM_N 2
#endif

/* LIBCOV_NGRAM_ROTATE
 *   When 1, each prev[j] slot is rotated by a position-dependent amount
 *   (within the runtime map width) before being XORed into the index.
 *   With plain XOR (default) the history slots commute, so for N>=3 the
 *   windows A,B,C and B,A,C (same current site, permuted history) hash to
 *   the same bucket. Rotation breaks that symmetry so reordered histories
 *   index to distinct buckets. Recommended whenever N >= 3.
 *
 *     0     plain XOR (default; N=2 stays bit-identical to AFL).
 *     1     per-position rotation enabled.
 *
 *   Cost per emit: one additional shift + OR per prev slot. Still cheap
 *   relative to the trap-and-signal entry cost.
 *
 *   Note: setting this to 1 with N=2 changes the AFL-compatible math
 *   (the single prev slot is rotated before the XOR), so bitmaps will
 *   not be byte-identical to a stock libcov ST run -- they still encode
 *   edges, just under a different permutation of bucket indices.
 *
 *   Override at build: -DLIBCOV_NGRAM_ROTATE=1
 *   Override in source: edit the value next to the #define below.
 */
#ifndef LIBCOV_NGRAM_ROTATE
#define LIBCOV_NGRAM_ROTATE 0
#endif

/* ------------------------------------------------------------------ */
/* Iteration boundaries (boundary.c)                                  */
/* ------------------------------------------------------------------ */

/* LIBCOV_MARKER_REARM_TIMEOUT_NS
 *   A boundary marker that trapped stays disarmed until every thread that
 *   trapped on it has trapped again somewhere else (proof it executed the
 *   marker's original instruction; re-arming sooner makes it re-trap and
 *   fire a spurious boundary). If a holder hasn't trapped again within
 *   this many nanoseconds, the marker is re-armed anyway, so one idle or
 *   exited thread can't keep it disarmed for every other worker.
 *
 *   Default 1 ms. Larger values mean fewer spurious fires from threads
 *   descheduled right after their marker trap, at the cost of other
 *   workers missing boundaries for longer when a holder goes idle.
 *
 *   Override at build: -DLIBCOV_MARKER_REARM_TIMEOUT_NS=5000000ULL
 */
#ifndef LIBCOV_MARKER_REARM_TIMEOUT_NS
#define LIBCOV_MARKER_REARM_TIMEOUT_NS 1000000ULL
#endif

/* ------------------------------------------------------------------ */
/* MT cross-core sync fallback (membarrier.c)                         */
/* ------------------------------------------------------------------ */

/* LIBCOV_SYNC_SIGNO
 *   Signal libcov_mt.so sends to every peer thread after patching when
 *   the kernel lacks membarrier(PRIVATE_EXPEDITED_SYNC_CORE) (or with
 *   LIBCOV_SYNC_FALLBACK=tgkill). Returning from its handler is the
 *   context-synchronizing event. Must be a signal the target doesn't use:
 *   if it has a handler for it at init, or installs one later, libcov
 *   hands the signal back and turns the fallback off (WARNING).
 *
 *   Default SIGRTMAX - 2 (glibc reserves the lowest RT signals; targets
 *   that use RT signals usually count up from SIGRTMIN).
 *
 *   Override at build: -DLIBCOV_SYNC_SIGNO='(SIGRTMAX - 5)'
 */
#ifndef LIBCOV_SYNC_SIGNO
#define LIBCOV_SYNC_SIGNO (SIGRTMAX - 2)
#endif

/* LIBCOV_SYNC_TIMEOUT_NS
 *   How long a broadcast waits for every peer to acknowledge the sync
 *   signal. A thread in uninterruptible sleep, stopped, or with the
 *   signal blocked through a raw syscall never acknowledges in time; it
 *   isn't running user code then, and it context-synchronizes on its own
 *   way back to user mode. Every broadcast that times out costs this
 *   much, so keep it short.
 *
 *   Default 1 ms.
 *
 *   Override at build: -DLIBCOV_SYNC_TIMEOUT_NS=200000ULL
 */
#ifndef LIBCOV_SYNC_TIMEOUT_NS
#define LIBCOV_SYNC_TIMEOUT_NS 1000000ULL
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
