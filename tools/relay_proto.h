/*
 * relay_proto.h -- SZR1, the wire protocol between an executor (here
 * suzzer-relay, on the device) and the off-device brain
 * (tools/suzzer_brain.py).
 *
 * One persistent TCP connection. The executor dials the brain and sends the
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
 *
 * The constants (SZR_MAGIC, SZR_PROTO_VERSION, frame types, HELLO flags,
 * payload lengths, crash reasons) and the payload layouts live in
 * src/lcv_formats.h, the header-only contract other executors vendor;
 * docs/FORMATS.md is the specification. This header is kept so existing
 * includes keep working.
 */
#ifndef SUZZER_RELAY_PROTO_H
#define SUZZER_RELAY_PROTO_H

#include "../src/lcv_formats.h"

#endif /* SUZZER_RELAY_PROTO_H */
