/*
 * lcv_formats.h -- suzzer's published format definitions, header-only.
 *
 * Everything here is a contract with code that is not libcov: the patch
 * list (LCV3), the boundary sidecar (LCVB1), the coverage shared-memory
 * region (LCVS) and the remote-fuzzing wire protocol (SZR1). The prose
 * specification is docs/FORMATS.md; conformance vectors for the coverage
 * bucket formula are in test/vectors/.
 *
 * Consumers copy this one file at a pinned suzzer commit -- they do not
 * include it from a suzzer checkout and need not build suzzer. To keep that
 * possible the file:
 *   - includes only <stdint.h> (plus <stddef.h> for offsetof on a compiler
 *     that is neither gcc nor clang);
 *   - declares no functions, no runtime types (uintptr_t, ucontext, ...) and
 *     nothing from glibc;
 *   - is C11 and builds warning-free with
 *       -std=c11 -Wall -Wextra -Werror -Wshadow -Wstrict-prototypes
 *       -Wmissing-prototypes
 *     (`make test` compiles test/formats_strict.c with exactly those flags).
 *
 * The packed structs need the GNU `packed` attribute (gcc, clang). A
 * compiler without it can define LCV_PACKED itself before including this
 * file (e.g. empty, together with #pragma pack(push, 1)); the size asserts
 * below catch a layout that came out wrong.
 *
 * Byte order differs per format, see each section: LCV3 and LCVB1 are
 * little-endian on disk; the LCVS region is in the byte order of the
 * process that created it; SZR1 is big-endian (network order) on the wire.
 * The structs describe layout only -- a reader on a host of the other byte
 * order must swap each multi-byte field itself.
 *
 * Field names and layouts here are frozen: on-disk files and live regions
 * written by older builds stay byte-identical. See docs/FORMATS.md
 * "Versioning" for what may change and how.
 */
#ifndef LCV_FORMATS_H
#define LCV_FORMATS_H

#include <stdint.h>

/* Revision of this header. Bumped whenever a definition is added here, so a
 * vendored copy can say which one it is. Not a format version: each format
 * carries its own (LIBCOV_VERSION, LIBCOV_BOUNDARY_VERSION,
 * LIBCOV_SHM_VERSION, SZR_PROTO_VERSION). */
#define LCV_FORMATS_REV 1u

#ifndef LCV_PACKED
#  if defined(__GNUC__) || defined(__clang__)
#    define LCV_PACKED __attribute__((packed))
#  else
#    error "lcv_formats.h: define LCV_PACKED for this compiler (see header comment)"
#  endif
#endif

#if defined(__cplusplus)
#  define LCV_STATIC_ASSERT(c, m) static_assert(c, m)
#else
#  define LCV_STATIC_ASSERT(c, m) _Static_assert(c, m)
#endif

#if defined(__GNUC__) || defined(__clang__)
#  define LCV_OFFSETOF(t, f) __builtin_offsetof(t, f)
#else
#  include <stddef.h>          /* freestanding; only for other compilers */
#  define LCV_OFFSETOF(t, f) offsetof(t, f)
#endif

/* ===================================================================== *
 * LCV3 patch list -- the coverage sites                                  *
 * ===================================================================== *
 *
 * All multi-byte fields are little-endian, whatever the target's byte order.
 *
 *   [struct patchlist_header_v3]                          24 bytes
 *   [count x struct patchlist_record]                     14 bytes each
 *   [module name table]  at modules_offset, modules_size bytes:
 *                        module_count NUL-terminated basenames, back to back
 *   [module base table]  only if flags & LCV_FLAG_MODULE_BASES:
 *                        module_count x u64 link-time base addresses, at
 *                        LCV_MODULE_BASES_OFFSET(modules_offset, modules_size)
 *
 * record.offset is the site's address minus its module's link base (rizin's
 * `baddr`); record.orig[] holds the first `len` original bytes as they sit in
 * memory (target byte order); a site's id is its record index in the file. */

#define LIBCOV_MAGIC   "LCV3"
#define LIBCOV_VERSION 3u

/* Threading hint (header.threading): which libcov variant may load it. */
#define LIBCOV_TH_ANY 0u
#define LIBCOV_TH_ST  1u
#define LIBCOV_TH_MT  2u

/* header.flags. Bit 0 is defined; the others must be written 0, and readers
 * ignore bits they don't know. */
#define LCV_FLAG_MODULE_BASES (1u << 0)  /* a u64 link-base table follows the
                                          * name table (see layout above) */
#define LCV_FLAGS_KNOWN       LCV_FLAG_MODULE_BASES

/* File offset of the module base table: the end of the name table rounded
 * up to 8. */
#define LCV_MODULE_BASES_OFFSET(modules_offset, modules_size) \
    ((((uint64_t)(modules_offset) + (uint64_t)(modules_size)) + 7u) & ~(uint64_t)7u)

/* Widest site any arch patches: one 4-byte word on the fixed-width ISAs;
 * 2-byte sites (x86 UD2, arm-Thumb, riscv-C) use the first two bytes. */
#define LIBCOV_PATCH_ORIG_MAX 4u

/* Caps on the module name table. */
#define LIBCOV_MAX_MODULES         255u
#define LIBCOV_MAX_MODULES_BYTES   4096u

struct patchlist_header_v3 {
    char     magic[4];        /* "LCV3" */
    uint32_t version;         /* 3 */
    uint32_t count;           /* records following the header */
    uint8_t  threading;       /* LIBCOV_TH_* */
    uint8_t  flags;           /* LCV_FLAG_*; unknown bits are ignored */
    uint8_t  module_count;    /* 1..255 names in the name table */
    uint8_t  reserved;        /* 0 */
    uint32_t modules_offset;  /* file offset of the name table */
    uint32_t modules_size;    /* bytes in the name table, last byte NUL */
} LCV_PACKED;

struct patchlist_record {
    uint64_t offset;          /* address - link base of module[module_idx] */
    uint8_t  len;             /* bytes to patch and restore (2 or 4) */
    uint8_t  module_idx;      /* index into the name table */
    uint8_t  orig[LIBCOV_PATCH_ORIG_MAX]; /* first `len` bytes meaningful,
                                           * the rest 0 */
} LCV_PACKED;

LCV_STATIC_ASSERT(sizeof(struct patchlist_header_v3) == 24, "LCV3 header is 24 bytes");
LCV_STATIC_ASSERT(sizeof(struct patchlist_record) == 14, "LCV3 record is 14 bytes");
LCV_STATIC_ASSERT(LCV_OFFSETOF(struct patchlist_header_v3, modules_offset) == 16,
                  "LCV3 modules_offset sits at offset 16");
LCV_STATIC_ASSERT(LCV_OFFSETOF(struct patchlist_record, orig) == 10,
                  "LCV3 record orig[] sits at offset 10");

/* ===================================================================== *
 * LCVB1 boundary sidecar -- iteration markers                            *
 * ===================================================================== *
 *
 * Little-endian. [struct lcvb_header][count x struct lcvb_record].
 * record.offset is relative to module 0's link base (the same base the
 * patch list's module-0 offsets use), and must name a patch-list site.
 * A file with at least one END record is "paired" (BEGIN..END brackets one
 * iteration); one with only BEGIN records is "begin-only" (each BEGIN ends
 * the previous iteration). The header flags field is written 0 and readers
 * do not consult it. */

#define LIBCOV_BOUNDARY_MAGIC   "LCVB"
#define LIBCOV_BOUNDARY_VERSION 1u

#define LIBCOV_BOUNDARY_KIND_BEGIN 0
#define LIBCOV_BOUNDARY_KIND_END   1

#define LIBCOV_BOUNDARY_DEPTH_ANY  0   /* record.depth_filter values */
#define LIBCOV_BOUNDARY_DEPTH_ZERO 1

struct lcvb_header {
    char     magic[4];      /* "LCVB" */
    uint32_t version;       /* 1 */
    uint32_t count;
    uint32_t flags;         /* written 0; ignored by readers */
} LCV_PACKED;

struct lcvb_record {
    uint64_t offset;        /* from module 0's link base */
    uint8_t  kind;          /* LIBCOV_BOUNDARY_KIND_* */
    uint8_t  depth_filter;  /* LIBCOV_BOUNDARY_DEPTH_* */
    uint8_t  reserved[6];   /* 0 */
} LCV_PACKED;

LCV_STATIC_ASSERT(sizeof(struct lcvb_header) == 16, "LCVB1 header is 16 bytes");
LCV_STATIC_ASSERT(sizeof(struct lcvb_record) == 16, "LCVB1 record is 16 bytes");

/* ===================================================================== *
 * LCVS coverage region (shared memory)                                   *
 * ===================================================================== *
 *
 * Host byte order of the process that created it (a reader on another
 * byte order detects that from `version`, see docs/FORMATS.md).
 *
 *   offset 0               struct libcov_shm_header (72 bytes)
 *   bitmap_offset          live bitmap, map_size bytes
 *   ring_offset            ring_size slots, slot_stride bytes each:
 *                          struct libcov_ring_slot_hdr + map_size bytes
 *
 * A reader takes gen_current (acquire), reads slot ring[gen % ring_size],
 * and accepts it only if slot_gen == gen both before and after copying the
 * bitmap (seqlock; docs/FORMATS.md has the full protocol). */

#define LIBCOV_SHM_MAGIC        "LCVS"
#define LIBCOV_SHM_VERSION      1u
#define LIBCOV_SHM_FLAG_ACTIVE  (1u << 0)  /* boundaries active (ring in use) */
#define LIBCOV_SHM_FLAG_MT      (1u << 1)  /* written by MT-variant libcov */
/* The live bitmap at bitmap_offset is NOT maintained and a driver must read
 * the ring instead (libcov's ST boundary mode). */
#define LIBCOV_SHM_FLAG_LIVE_EMPTY (1u << 2)
/* Coverage scheme the bucket indices were built with. SCHEME says the bits
 * below are valid (older regions leave it clear); MODEL_PC = hashed-PC
 * model (clear = site-id); ROTATE = N-gram rotation; bits 8..11 = N. */
#define LIBCOV_SHM_FLAG_SCHEME     (1u << 3)
#define LIBCOV_SHM_FLAG_MODEL_PC   (1u << 4)
#define LIBCOV_SHM_FLAG_ROTATE     (1u << 5)
#define LIBCOV_SHM_NGRAM_SHIFT     8
#define LIBCOV_SHM_NGRAM_MASK      (0xfu << LIBCOV_SHM_NGRAM_SHIFT)
#define LIBCOV_SHM_NGRAM(flags) \
    (((flags) & LIBCOV_SHM_NGRAM_MASK) >> LIBCOV_SHM_NGRAM_SHIFT)

struct libcov_shm_header {
    char     magic[4];        /* "LCVS" */
    uint16_t version;         /* 1 */
    uint16_t ring_size;       /* slots in the ring */
    uint32_t map_size;        /* bitmap bytes; a power of two */
    uint32_t slot_stride;     /* bytes per ring slot (slot hdr + bitmap) */
    uint32_t flags;           /* LIBCOV_SHM_FLAG_* */
    uint32_t pad0;            /* 0; explicit, so the u64 fields sit at the
                               * same offsets on ABIs that align them to 4 */
    uint64_t gen_current;     /* atomic: highest gen assigned; its slot may
                               * not be stamped yet (check slot_gen) */
    uint64_t gen_init;        /* gen of the INIT snapshot (0 = none) */
    uint64_t bitmap_offset;   /* from the region base */
    uint64_t ring_offset;     /* from the region base */
    uint32_t publish_dropped; /* atomic: generations that never reached the
                               * ring (MT only; 0 under ST) */
    uint32_t owner_pid;       /* creator's pid ... */
    uint32_t owner_start;     /* ... and start time (clock ticks since boot,
                               * low 32 bits) */
    uint8_t  reserved[4];     /* 0; new fields only ever take these over */
};

LCV_STATIC_ASSERT(sizeof(struct libcov_shm_header) == 72, "shm header is 72 bytes");
LCV_STATIC_ASSERT(LCV_OFFSETOF(struct libcov_shm_header, map_size) == 8,
                  "map_size sits at offset 8");
LCV_STATIC_ASSERT(LCV_OFFSETOF(struct libcov_shm_header, flags) == 16,
                  "flags sits at offset 16");
LCV_STATIC_ASSERT(LCV_OFFSETOF(struct libcov_shm_header, gen_current) == 24,
                  "gen_current sits at offset 24");
LCV_STATIC_ASSERT(LCV_OFFSETOF(struct libcov_shm_header, bitmap_offset) == 40,
                  "bitmap_offset sits at offset 40");
LCV_STATIC_ASSERT(LCV_OFFSETOF(struct libcov_shm_header, publish_dropped) == 56,
                  "publish_dropped sits at offset 56");
LCV_STATIC_ASSERT(LCV_OFFSETOF(struct libcov_shm_header, owner_pid) == 60,
                  "owner_pid sits at offset 60");

struct libcov_ring_slot_hdr {
    uint64_t slot_gen;        /* atomic: 0 = empty/in-progress; otherwise gen */
    uint64_t tid;             /* publishing thread */
    uint64_t ns;              /* CLOCK_MONOTONIC at publish */
    uint64_t flags;           /* LIBCOV_SLOT_FLAG_*: what the snapshot holds */
};                            /* followed by map_size bytes of bitmap */

LCV_STATIC_ASSERT(sizeof(struct libcov_ring_slot_hdr) == 32, "slot header is 32 bytes");

/* Ring slot flags: exactly one is set on every published slot (written
 * before slot_gen is stamped). Slots from builds before these existed
 * carry 0.
 *   INIT  startup to the first boundary (header.gen_init).
 *   ITER  one iteration (one input).
 *   GAP   paired mode: what ran between an END and the next BEGIN. */
#define LIBCOV_SLOT_FLAG_INIT (1u << 0)
#define LIBCOV_SLOT_FLAG_ITER (1u << 1)
#define LIBCOV_SLOT_FLAG_GAP  (1u << 2)

/* ===================================================================== *
 * SZR1 remote-fuzzing protocol                                           *
 * ===================================================================== *
 *
 * One TCP connection between an executor (runs inputs; dials in) and a
 * brain (chooses inputs; listens). The executor sends the 4-byte magic
 * once, then both sides exchange frames:
 *
 *     [u32 length][u8 type][payload...]        length counts type + payload
 *
 * Every multi-byte integer is big-endian (network order); bitmap payloads
 * are raw uint8 counters. Lockstep: each INPUT gets exactly one COVERAGE or
 * CRASH reply carrying its id. Payload layouts are in the comments below
 * and in docs/FORMATS.md. */

#define SZR_MAGIC         "SZR1"   /* 4 bytes, sent once by the executor */
#define SZR_PROTO_VERSION 1u

enum szr_frame_type {
    SZR_HELLO    = 1,   /* executor -> brain, once after the magic        */
    SZR_INPUT    = 2,   /* brain -> executor: one test input              */
    SZR_COVERAGE = 3,   /* executor -> brain: one snapshot                */
    SZR_CRASH    = 4,   /* executor -> brain: the target failed an input  */
    SZR_BYE      = 5,   /* either direction: clean shutdown               */
};

/* HELLO payload:
 *   u16 proto_version
 *   u16 flags          SZR_HELLO_FLAG_*, N-gram N in bits 8..11
 *   u32 map_size       coverage bitmap length (bytes)
 *   u16 ring_size      snapshots the executor buffers per input (>= 1)
 *   u16 arch_len       <= SZR_HELLO_ARCH_MAX
 *   u8  arch[arch_len] free-form ASCII, e.g. "x86_64", "mips32be", "rv32" */
#define SZR_HELLO_FLAG_MT          0x1u   /* libcov MT variant */
#define SZR_HELLO_FLAG_LIVE_EMPTY  0x2u   /* libcov ST boundary mode */
#define SZR_HELLO_FLAG_SCHEME      0x4u   /* MODEL_PC/ROTATE/N are valid */
#define SZR_HELLO_FLAG_MODEL_PC    0x8u   /* hashed-PC model (clear: site-id) */
#define SZR_HELLO_FLAG_ROTATE      0x10u  /* N-gram rotation */
#define SZR_HELLO_NGRAM_SHIFT      8
#define SZR_HELLO_NGRAM_MASK       (0xfu << SZR_HELLO_NGRAM_SHIFT)
#define SZR_HELLO_FIXED_LEN        12u    /* payload bytes before arch[] */
#define SZR_HELLO_ARCH_MAX         64u

/* INPUT payload:
 *   u64 id             brain-chosen, non-zero, echoed in the reply
 *   u32 len
 *   u8  data[len] */
#define SZR_INPUT_HDR_LEN          12u

/* COVERAGE payload:
 *   u64 id             the input this snapshot answers (0: an unsolicited
 *                      INIT snapshot, see docs/FORMATS.md)
 *   u64 gen            executor's generation number (opaque to the brain)
 *   u8  kind           LIBCOV_SLOT_FLAG_* (1 init, 2 iter, 4 gap; 0 none)
 *   u32 map_size
 *   u8  bitmap[map_size] */
#define SZR_COVERAGE_HDR_LEN       21u

/* CRASH payload:
 *   u64 id
 *   u8  reason         enum szr_crash_reason
 *   i32 status         per-reason meaning, see below */
#define SZR_CRASH_LEN              13u

/* A brain treats a reason it does not know as an opaque crash; (reason,
 * status) is the deduplication key. New reasons are additive and do not
 * bump SZR_PROTO_VERSION. */
enum szr_crash_reason {
    SZR_CRASH_EXIT        = 1,  /* target process exited; status = exit code */
    SZR_CRASH_SIGNAL      = 2,  /* target killed by a signal; status = signo */
    SZR_CRASH_DELIVERY    = 3,  /* could not deliver to the target; status 0 */
    SZR_CRASH_MALFORMED   = 4,  /* executor rejected a malformed INPUT frame;
                                 * nothing was delivered; status 0; id is 0
                                 * if the payload was < 8 bytes */
    SZR_CRASH_GUEST_FAULT = 5,  /* guest fault; status = faulting PC (low 32
                                 * bits) or a cause code, per executor */
    SZR_CRASH_ORACLE      = 6,  /* a crash/assert check fired; status = the
                                 * oracle id or its PC */
    SZR_CRASH_HANG        = 7,  /* executor saw no forward progress */
    SZR_CRASH_TIMEOUT     = 8,  /* per-input budget exceeded */
};

#endif /* LCV_FORMATS_H */
