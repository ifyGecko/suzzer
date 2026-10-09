/*
 * relay_proto.h -- wire protocol between suzzer-relay (on the device) and
 * the off-device brain (tools/suzzer_brain.py).
 *
 * One persistent TCP connection. The relay dials the brain and sends the
 * 4-byte magic once, then both sides exchange length-prefixed frames:
 *
 *     [u32 length][u8 type][payload...]        length counts type + payload
 *
 * All multi-byte integers are network byte order (big-endian). The one
 * exception is the coverage bitmap payload, which is raw device-side uint8
 * saturating counters -- byte order is meaningless for single bytes, and
 * the relay has already decoded every header field on the device, so the
 * brain never parses a foreign-ABI shm header. See Design.md
 * "Remote coverage transport".
 */
#ifndef SUZZER_RELAY_PROTO_H
#define SUZZER_RELAY_PROTO_H

#define SZR_MAGIC         "SZR1"   /* 4 bytes, sent once by the relay */
#define SZR_PROTO_VERSION 1u

/* Frame types. */
enum szr_frame_type {
    SZR_HELLO    = 1,   /* relay -> brain, once after the magic           */
    SZR_INPUT    = 2,   /* brain -> relay: one test input                 */
    SZR_COVERAGE = 3,   /* relay -> brain: one snapshot                   */
    SZR_CRASH    = 4,   /* relay -> brain: the target died on an input    */
    SZR_BYE      = 5,   /* either direction: clean shutdown               */
};

/* HELLO payload (network byte order):
 *   u16 proto_version
 *   u16 flags          bit0 = target is MT, bit1 = ST boundary mode,
 *                      bit2 = bits 3..4 and 8..11 are valid (coverage scheme),
 *                      bit3 = hashed-PC model (clear: site-id),
 *                      bit4 = N-gram rotation, bits 8..11 = N-gram N
 *   u32 map_size       coverage bitmap length (bytes)
 *   u16 ring_size
 *   u16 arch_len
 *   u8  arch[arch_len] e.g. "x86_64"
 */
#define SZR_HELLO_FLAG_MT          0x1u
#define SZR_HELLO_FLAG_LIVE_EMPTY  0x2u
#define SZR_HELLO_FLAG_SCHEME      0x4u
#define SZR_HELLO_FLAG_MODEL_PC    0x8u
#define SZR_HELLO_FLAG_ROTATE      0x10u
#define SZR_HELLO_NGRAM_SHIFT      8

/* INPUT payload:
 *   u64 id             brain-chosen, echoed back in COVERAGE/CRASH
 *   u32 len
 *   u8  data[len]
 */

/* COVERAGE payload:
 *   u64 id             the input whose delivery produced this snapshot
 *                      (0 for the process's startup INIT snapshot)
 *   u64 gen            libcov generation number
 *   u8  kind           LIBCOV_SLOT_FLAG_* (1 init, 2 iter, 4 gap)
 *   u32 map_size
 *   u8  bitmap[map_size]
 */

/* CRASH payload:
 *   u64 id
 *   u8  reason         enum szr_crash_reason
 *   i32 status         exit code (EXIT) or signal number (SIGNAL); 0 otherwise
 */
enum szr_crash_reason {
    SZR_CRASH_EXIT     = 1,   /* target process exited between requests  */
    SZR_CRASH_SIGNAL   = 2,   /* target killed by a signal               */
    SZR_CRASH_DELIVERY = 3,   /* could not connect/deliver to the target */
    SZR_CRASH_MALFORMED = 4,  /* relay rejected a malformed INPUT frame
                               * (payload < 12 bytes or len overruns it);
                               * nothing was delivered, the target is fine.
                               * id is 0 if the payload was < 8 bytes. */
};

#endif /* SUZZER_RELAY_PROTO_H */
