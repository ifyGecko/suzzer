/*
 * faultinj_classes.h -- the table of fault-injection "classes" libfaultinj
 *                       knows about, plus their errno + failure-mode pools.
 *
 * Everything in libfaultinj is keyed off a small integer class id (FI_CLS_*).
 * The class id selects:
 *   - which libc functions get hooked (e.g. FI_CLS_OPEN -> open + openat)
 *   - which errno value pool the deterministic PRNG draws from
 *   - which failure modes (return -1 / return 0 / return short) are legal
 *
 * The class table is an X-macro so adding a new class is a single-line
 * change here followed by per-class metadata table entries below. The
 * enum, the name table, and the per-class config arrays are all derived
 * from the same X-macro so they can never drift apart.
 *
 * NOTE: this file is included by libfaultinj.c only. It is NOT a public
 * header; consumers of libfaultinj configure it entirely through env
 * variables documented in README.md. The classes here ARE part of the
 * external ABI in the sense that LIBFAULTINJ_ENABLE and LIBFAULTINJ_DISABLE
 * parse the lower-cased class names below.
 */

#ifndef FAULTINJ_CLASSES_H
#define FAULTINJ_CLASSES_H

#include <errno.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Failure modes.                                                     */
/* ------------------------------------------------------------------ */

/* What kind of failure a hook can return when the dispatcher picks a
 * fault. Each class only enables a subset of these (see the per-class
 * mode arrays below). The dispatcher picks one mode uniformly at random
 * from the enabled subset using the same PRNG roll that selected the
 * errno -- so a given (seed, class, call_idx) always produces the same
 * (errno, mode) pair.
 *
 *   FI_MODE_FAIL_NEG1   "return -1, set errno"
 *                       Universal: every class supports this. Models a
 *                       hard syscall failure.
 *
 *   FI_MODE_FAIL_ZERO   "return 0, do NOT touch errno"
 *                       Read-family only. Models a clean EOF / peer-
 *                       closed-connection, which application code very
 *                       often mishandles ("I called recv() and it
 *                       returned 0, which I treated as a transient and
 *                       looped forever").
 *
 *   FI_MODE_FAIL_SHORT  "do a real call but truncate the byte count"
 *                       I/O classes only. Models short reads / short
 *                       writes which protocol parsers and log flushers
 *                       routinely mishandle. The truncation length is
 *                       picked deterministically from the PRNG roll
 *                       (see fi_decide in libfaultinj.c).
 */
enum fi_mode {
    FI_MODE_FAIL_NEG1  = 0,
    FI_MODE_FAIL_ZERO  = 1,
    FI_MODE_FAIL_SHORT = 2,
    FI_MODE_MAX
};

/* ------------------------------------------------------------------ */
/* The class table itself.                                            */
/* ------------------------------------------------------------------ */

/* X-macro entry:   X(ENUM_NAME, "lowercase_name")
 *
 * ENUM_NAME       -- used to name the enum value FI_CLS_<NAME>
 * "lowercase_name" -- the string the user types in LIBFAULTINJ_ENABLE /
 *                     LIBFAULTINJ_DISABLE, and the string printed in
 *                     log lines.
 *
 * Allocation classes (malloc / calloc / realloc / strdup / asprintf)
 * are deliberately ABSENT from this table. They overlap functionally
 * with tools/libdemalloc.c and combining the two requires a careful
 * LD_PRELOAD layering decision that the project is not ready to make
 * yet. See Design.md "Why no alloc class in v1" for the rationale.
 *
 * Likewise bind/listen/connect are absent: they fire once at daemon
 * init time, so faulting them returns boring "startup failed" crashes
 * rather than protocol-parser bugs. They are candidates for v2.
 */
#define FAULTINJ_CLASSES(X) \
    X(OPEN,    "open")      \
    X(READ,    "read")      \
    X(WRITE,   "write")     \
    X(CLOSE,   "close")     \
    X(RECV,    "recv")      \
    X(SEND,    "send")      \
    X(SOCKET,  "socket")    \
    X(ACCEPT,  "accept")

/* Enum of class ids. */
enum fi_class {
#define X(cls_id, _str) FI_CLS_##cls_id,
    FAULTINJ_CLASSES(X)
#undef X
    FI_CLS_MAX
};

/* ------------------------------------------------------------------ */
/* Per-class metadata.                                                */
/* ------------------------------------------------------------------ */

/* One entry per class: human name, allowed errno values, allowed
 * failure modes. Indexed by FI_CLS_*. */
struct fi_class_info {
    const char  *name;       /* lowercase ASCII, NUL-terminated         */
    const int   *errnos;     /* pool of errno values to draw from       */
    int          errno_count;
    const enum fi_mode *modes; /* pool of failure modes to draw from    */
    int          mode_count;
};

/* ------- per-class errno pools ---------------------------------- *
 *
 * Each pool reflects "errno values real Linux kernels actually return
 * for this call, and that real code paths visibly branch on". We
 * deliberately keep them small (<= 5 entries) so coverage of each
 * branch is dense per PRNG roll.
 *
 * Notes:
 *   open    -- EACCES/ENOENT/EMFILE/ENFILE/ENOMEM. ENOTDIR/EISDIR
 *              omitted because they require malformed paths; this is
 *              about failure of valid paths.
 *   read    -- EIO is the canonical "media failure". EINTR is a
 *              high-yield bug class on its own: many parsers don't
 *              loop on EINTR. EAGAIN is what nonblocking fds return
 *              under load.
 *   write   -- ENOSPC for full disks. EPIPE for closed peers. EIO,
 *              EAGAIN as above.
 *   close   -- EBADF is the classic "you double-closed me". EIO can
 *              be returned by close(2) when a buffered write fails
 *              at close time (NFS, etc.). EINTR is rare but real.
 *   recv    -- ECONNRESET for half-open TCP, EAGAIN for nonblocking,
 *              EINTR, EIO.
 *   send    -- EPIPE for closed peers (extremely common in daemons),
 *              ECONNRESET, ENOBUFS for queue-full, EAGAIN.
 *   socket  -- EMFILE/ENFILE are the realistic failures. ENOBUFS for
 *              kernel buffer exhaustion. EACCES if the kernel refuses
 *              the requested protocol.
 *   accept  -- EMFILE/ENFILE (same as socket), plus ECONNABORTED for
 *              a peer that hung up between connect and accept --
 *              a notorious source of "accept loop dies on first
 *              transient" bugs in network daemons.
 */
static const int fi_errnos_OPEN[]   = { EACCES, ENOENT, EMFILE, ENFILE, ENOMEM };
static const int fi_errnos_READ[]   = { EIO, EINTR, EAGAIN };
static const int fi_errnos_WRITE[]  = { EIO, ENOSPC, EPIPE, EAGAIN };
static const int fi_errnos_CLOSE[]  = { EBADF, EIO, EINTR };
static const int fi_errnos_RECV[]   = { EIO, ECONNRESET, EAGAIN, EINTR };
static const int fi_errnos_SEND[]   = { EPIPE, ECONNRESET, ENOBUFS, EAGAIN };
static const int fi_errnos_SOCKET[] = { EMFILE, ENFILE, ENOBUFS, EACCES };
static const int fi_errnos_ACCEPT[] = { EMFILE, ENFILE, ENOBUFS, ECONNABORTED };

/* ------- per-class failure-mode pools --------------------------- *
 *
 * Only OPEN/CLOSE/SOCKET/ACCEPT have a singular failure mode (return
 * -1). The I/O classes also support short and (for read-family) zero
 * returns.
 */
static const enum fi_mode fi_modes_OPEN[]   = { FI_MODE_FAIL_NEG1 };
static const enum fi_mode fi_modes_READ[]   = { FI_MODE_FAIL_NEG1,
                                                FI_MODE_FAIL_ZERO,
                                                FI_MODE_FAIL_SHORT };
static const enum fi_mode fi_modes_WRITE[]  = { FI_MODE_FAIL_NEG1,
                                                FI_MODE_FAIL_SHORT };
static const enum fi_mode fi_modes_CLOSE[]  = { FI_MODE_FAIL_NEG1 };
static const enum fi_mode fi_modes_RECV[]   = { FI_MODE_FAIL_NEG1,
                                                FI_MODE_FAIL_ZERO,
                                                FI_MODE_FAIL_SHORT };
static const enum fi_mode fi_modes_SEND[]   = { FI_MODE_FAIL_NEG1,
                                                FI_MODE_FAIL_SHORT };
static const enum fi_mode fi_modes_SOCKET[] = { FI_MODE_FAIL_NEG1 };
static const enum fi_mode fi_modes_ACCEPT[] = { FI_MODE_FAIL_NEG1 };

/* ------- final per-class metadata table -------------------------- *
 *
 * Indexed by FI_CLS_*. Generated from the X-macro so the order here
 * is locked to the enum order; if you reorder FAULTINJ_CLASSES, the
 * arrays above must follow in the same order or the build will
 * silently produce nonsense -- there's no way to assert this at
 * compile time without designated initializers + named class fields.
 * Adding _Static_assert(...) on FI_CLS_MAX is a cheap guardrail
 * against losing an entry entirely.
 */
static const struct fi_class_info fi_class_table[FI_CLS_MAX] = {
#define X(cls_id, cls_str) \
    [FI_CLS_##cls_id] = { \
        .name        = cls_str, \
        .errnos      = fi_errnos_##cls_id, \
        .errno_count = (int)(sizeof(fi_errnos_##cls_id) / sizeof(int)), \
        .modes       = fi_modes_##cls_id, \
        .mode_count  = (int)(sizeof(fi_modes_##cls_id) / sizeof(enum fi_mode)), \
    },
    FAULTINJ_CLASSES(X)
#undef X
};

_Static_assert(sizeof(fi_class_table) / sizeof(fi_class_table[0]) == FI_CLS_MAX,
               "fi_class_table missing entries vs FAULTINJ_CLASSES");

/* ------------------------------------------------------------------ */
/* errno -> name lookup (logging only, no semantic effect).           */
/* ------------------------------------------------------------------ */

/* Returns the short name ("ENOMEM") for an errno value. Used only by
 * the logger; falls back to "ERR" so the log line is still parseable
 * if a future class adds an errno not listed here.
 *
 * This is a switch rather than a table because the actual errno
 * integer values differ across architectures (MIPS in particular has
 * EAGAIN == 11 not 35), so a static table indexed by the int would be
 * wrong on at least one arch we care about. The switch compiles to a
 * jump table that the compiler can pack however the target ABI likes.
 */
static inline const char *fi_errno_name(int e)
{
    switch (e) {
    case EACCES:       return "EACCES";
    case ENOENT:       return "ENOENT";
    case EMFILE:       return "EMFILE";
    case ENFILE:       return "ENFILE";
    case ENOMEM:       return "ENOMEM";
    case EIO:          return "EIO";
    case EINTR:        return "EINTR";
    case EAGAIN:       return "EAGAIN";
    case ENOSPC:       return "ENOSPC";
    case EPIPE:        return "EPIPE";
    case EBADF:        return "EBADF";
    case ECONNRESET:   return "ECONNRESET";
    case ENOBUFS:      return "ENOBUFS";
    case ECONNABORTED: return "ECONNABORTED";
    default:           return "ERR";
    }
}

/* Returns the human label for a failure mode. Used only by the
 * logger. */
static inline const char *fi_mode_name(enum fi_mode m)
{
    switch (m) {
    case FI_MODE_FAIL_NEG1:  return "ret-1";
    case FI_MODE_FAIL_ZERO:  return "ret0";
    case FI_MODE_FAIL_SHORT: return "short";
    default:                 return "?";
    }
}

#endif /* FAULTINJ_CLASSES_H */
