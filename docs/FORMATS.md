# suzzer formats

This document specifies the four formats suzzer shares with programs other than libcov, plus the coverage bucket formula. It is written so a third party can implement a reader or writer from it alone, without reading libcov's sources.

| Format | What it is | Byte order | Version |
|---|---|---|---|
| [LCV3](#1-lcv3-patch-list) | patch list: the coverage sites | little-endian | 3 |
| [LCVB1](#2-lcvb1-boundary-file) | boundary file: iteration markers | little-endian | 1 |
| [LCVS](#3-lcvs-shared-memory-region) | live coverage region (shared memory) | creator's host order | 1 |
| [SZR1](#4-szr1-protocol) | remote-fuzzing protocol, executor ↔ brain | big-endian | 1 |
| [Bucket formula](#5-coverage-bucket-formula) | how a sequence of sites becomes a bitmap | — | — |

Three companion artifacts sit next to this document:

- **`src/lcv_formats.h`**: the C definitions of every struct and constant below. It is header-only, depends only on `<stdint.h>`, and is C11-clean under `-std=c11 -Wall -Wextra -Werror -Wshadow -Wstrict-prototypes -Wmissing-prototypes`. Copy it at a pinned commit, or read it from a suzzer checkout your build is given; either way check the format versions it defines at compile time. `LCV_FORMATS_REV` names the revision.
- **`test/vectors/`**: conformance vectors for the bucket formula ([§5.6](#56-conformance-vectors)).
- **`test/fake_executor.py`**: a minimal SZR1 executor written from §4, used by `test/run_validation_brain.sh`.

Terms used throughout:

- **Executor**: the program that runs inputs and produces coverage. `suzzer-relay` plus libcov is one executor; an emulator, a QEMU plugin or a hardware-trace decoder can be another.
- **Brain**: the program that chooses inputs (`tools/suzzer_brain.py`).
- **Site**: an instrumented code location. **Module**: a binary image that holds sites (an executable, a shared library, a firmware image).
- **Link base** (`baddr`): the address a module is linked to run at (what rizin reports as `baddr`). PIE executables and shared libraries usually have link base 0.

All structs are packed, with no implicit padding. Offsets are in bytes from the start of the struct or file.

---

## 1. LCV3 patch list

The list of coverage sites, produced by `tools/gen_patchlist.py` and loaded by libcov (`LIBCOV_PATCHLIST`). Every multi-byte field is **little-endian**, whatever the target's byte order.

### 1.1 Layout

```
offset 0                 header                          24 bytes
offset 24                count × record                  14 bytes each
offset modules_offset    module name table               modules_size bytes
offset align8(modules_offset + modules_size)
                         module base table (optional)    module_count × 8 bytes
```

`align8(x) = (x + 7) & ~7`. The name table normally follows the records directly, but `modules_offset` is authoritative. A reader must bound every access by the explicit offsets and sizes. Bytes outside the regions above are ignored.

### 1.2 Header (`struct patchlist_header_v3`)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 4 | `magic` | `"LCV3"` |
| 4 | 4 | `version` | `3` |
| 8 | 4 | `count` | number of records |
| 12 | 1 | `threading` | `0` ANY, `1` ST, `2` MT (see below) |
| 13 | 1 | `flags` | bit 0 = `LCV_FLAG_MODULE_BASES`; other bits 0 |
| 14 | 1 | `module_count` | 1..255 |
| 15 | 1 | `reserved` | 0 |
| 16 | 4 | `modules_offset` | file offset of the name table |
| 20 | 4 | `modules_size` | name table bytes, 1..4096 |

**`threading`** says which libcov build may load the list. MT lists contain only sites the MT runtime can patch atomically (naturally aligned 2- or 4-byte words), and ST lists may contain any site. libcov refuses a list whose hint is neither ANY nor its own variant. Other consumers can ignore the field. They should prefer ANY or ST lists, which hold every site the generator selected.

**`flags`**: writers set only the bits defined here. Readers **ignore bits they don't know**. They must not reject a file for them.

### 1.3 Record (`struct patchlist_record`)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 8 | `offset` | site address − link base of `module_idx` |
| 8 | 1 | `len` | bytes patched at the site: 2 or 4 |
| 9 | 1 | `module_idx` | index into the name table, `< module_count` |
| 10 | 4 | `orig` | the first `len` original bytes; the rest 0 |

- **`site_id`** is a record's index in the file (0-based), assigned before any sorting by address. It is the bucket base under the site-id model ([§5](#5-coverage-bucket-formula)), so record order is part of the coverage contract. A consumer must assign ids by file position.
- **`offset`** is relative to the module's **link base**. `gen_patchlist.py` computes `offset = address − baddr`. To get a runtime address, add the module's runtime base: libcov uses the start of the module's lowest mapping in `/proc/self/maps`. For a module loaded at its link base, the runtime address is `link_base + offset`.
- **`orig[]`** is the raw instruction bytes as they sit in memory, in the **target's** byte order. For example, a MIPS BE instruction `0x27bdffe0` is stored `27 bd ff e0`. `len` bytes are meaningful (x86 sites are 2 bytes: the head of the instruction that UD2 overwrites).

### 1.4 Module name table

`module_count` NUL-terminated names, back to back. The last byte of the table is NUL and no name is empty. Each name is the basename the module is mapped under (e.g. `target_simple`, `libfoo.so.1.2.3`). Module 0 is the binary given to `gen_patchlist.py` positionally, and modules 1.. are its `--module` arguments in order.

### 1.5 Module base table (`LCV_FLAG_MODULE_BASES`)

If `flags & 1`, a table of `module_count` little-endian `u64` link bases starts at `align8(modules_offset + modules_size)`. Entry *i* is module *i*'s link base, from rizin's `baddr`, or `--base` for a raw image. Padding bytes before it are 0.

It exists so consumers without `/proc/self/maps` (emulators, bare-metal, offline tools) can turn `offset` back into an address: `address = base[module_idx] + offset`. `gen_patchlist.py` writes it by default, and `--no-module-bases` leaves it out. libcov resolves addresses from the runtime mapping as before. It reads the table only to log a mismatch for a fixed-address module mapped elsewhere.

Readers from before the table existed never read `flags` and bound every read by explicit offsets, so they load a file with the table exactly as they load one without. `test/run_validation_generator.sh` (its test 5) checks this by loading the file with and without the table and with the flag bit cleared, which is what such a reader sees. If a table runs past the end of the file, ignore it.

### 1.6 Reader checklist

Reject the file if:
- the magic or version is wrong;
- `count × 14` doesn't fit after the header (compute this without overflow);
- `module_count` is 0;
- `modules_size` is 0 or > 4096;
- the name table runs past the end of the file, or doesn't end in NUL;
- a name is empty;
- any `module_idx ≥ module_count`.

---

## 2. LCVB1 boundary file

Marks where one iteration (one input) begins and ends, produced by `tools/gen_boundary.py` and loaded by libcov (`LIBCOV_BOUNDARY_LIST`). It is **little-endian**.

```
offset 0     header       16 bytes
offset 16    count × record   16 bytes each
```

**Header** (`struct lcvb_header`)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 4 | `magic` | `"LCVB"` |
| 4 | 4 | `version` | `1` |
| 8 | 4 | `count` | records |
| 12 | 4 | `flags` | written 0; readers don't consult it |

**Record** (`struct lcvb_record`)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 8 | `offset` | marker address − **module 0's** link base |
| 8 | 1 | `kind` | `0` BEGIN, `1` END |
| 9 | 1 | `depth_filter` | `0` any depth, `1` depth zero only |
| 10 | 6 | `reserved` | 0 |

- Offsets use the same convention as LCV3 module-0 offsets. Each marker must be a site in the patch list. A marker that isn't a site never fires (libcov logs a warning).
- **Paired mode**: the file holds at least one END record. BEGIN increments a nesting depth and END decrements it. The span from BEGIN to the matching END is one iteration. With `depth_filter=1`, only depth-0 transitions fire, so recursion doesn't split an iteration. What runs between an END and the next depth-0 BEGIN is a *gap* (harness code, not an input).
- **Begin-only mode**: there are no END records. Every BEGIN ends the current iteration and starts the next. `depth_filter` has no effect here.
- At every boundary the N-gram history is reset ([§5.3](#53-history-prev-update-and-reset)).

---

## 3. LCVS shared-memory region

The region libcov creates at `LIBCOV_SHM_PATH`: the live bitmap, plus a ring of per-iteration snapshots. Every field is in the **host byte order of the process that created it**. A reader on another byte order detects this from `version`, which reads as 1 in the right order. Only `magic` (bytes) and `map_size`/`slot_stride`/`ring_size` sit before the first 8-byte field, so a foreign reader can locate everything from them.

### 3.1 Layout

```
0               header (72 bytes)
bitmap_offset   live bitmap, map_size bytes
ring_offset     ring_size slots, slot_stride bytes each:
                  slot header (32 bytes) + map_size bytes of bitmap
```

libcov writes `bitmap_offset = 72`, `ring_offset = 72 + map_size` and `slot_stride = 32 + map_size`. Readers must use the header fields rather than assume these values.

### 3.2 Header (`struct libcov_shm_header`)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 4 | `magic` | `"LCVS"` |
| 4 | 2 | `version` | `1` |
| 6 | 2 | `ring_size` | number of slots (libcov: 2..16) |
| 8 | 4 | `map_size` | bitmap bytes, a power of two |
| 12 | 4 | `slot_stride` | bytes per slot |
| 16 | 4 | `flags` | `LIBCOV_SHM_FLAG_*` below |
| 20 | 4 | `pad0` | 0 |
| 24 | 8 | `gen_current` | **atomic**: highest generation assigned |
| 32 | 8 | `gen_init` | generation of the INIT snapshot, 0 = none |
| 40 | 8 | `bitmap_offset` | from the region base |
| 48 | 8 | `ring_offset` | from the region base |
| 56 | 4 | `publish_dropped` | **atomic**: generations that never reached the ring (MT only) |
| 60 | 4 | `owner_pid` | creator's pid |
| 64 | 4 | `owner_start` | creator's start time, clock ticks since boot, low 32 bits |
| 68 | 4 | `reserved` | 0 |

The offsets of `publish_dropped` and `owner_pid` are pinned by `_Static_assert`s in `lcv_formats.h`.

**Ownership.** `owner_pid` and `owner_start` let libcov recognise its own region after an in-place `exec` (it reattaches and keeps the contents) and leave another live process's region alone. A non-libcov writer should set them to its own pid and start time, or to 0 if they don't apply. Readers need not use them.

### 3.3 Flags

| Bit | Name | Meaning |
|---|---|---|
| 0 | `ACTIVE` | boundaries are active; the ring is in use |
| 1 | `MT` | written by MT-variant libcov |
| 2 | `LIVE_EMPTY` | the live bitmap is not maintained; read the ring |
| 3 | `SCHEME` | bits 4, 5 and 8..11 are valid |
| 4 | `MODEL_PC` | hashed-PC model (clear: site-id model) |
| 5 | `ROTATE` | N-gram rotation on |
| 8..11 | N | N-gram length, 1..8 |

`MT` and `LIVE_EMPTY` describe libcov's internals. Another writer sets them only if they apply to it: `LIVE_EMPTY` if it doesn't keep the bitmap at `bitmap_offset` up to date. With boundaries off, `bitmap_offset` holds the cumulative map. libcov's MT boundary mode keeps accumulating non-worker coverage there, and its ST boundary mode leaves it zero (`LIVE_EMPTY`).

### 3.4 Ring slot header (`struct libcov_ring_slot_hdr`)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 8 | `slot_gen` | **atomic**: 0 = empty or being written; otherwise the generation |
| 8 | 8 | `tid` | publishing thread |
| 16 | 8 | `ns` | `CLOCK_MONOTONIC` at publish |
| 24 | 8 | `flags` | exactly one of `INIT` (1), `ITER` (2), `GAP` (4); 0 from old builds |

- **INIT**: coverage from startup to the first boundary; its generation is in `gen_init`.
- **ITER**: one iteration. In begin-only mode each later BEGIN publishes the iteration it ends. In paired mode an END publishes the BEGIN..END span.
- **GAP**: paired mode only. A depth-0 BEGIN publishes what ran since the previous END.

A fuzzer wanting one snapshot per input keeps the ITER slots.

### 3.5 Generations and the seqlock protocol

Generations start at 1 and increase by one per published snapshot. Generation *g* lives in slot `g % ring_size`.

**Writer**, per snapshot:
1. `g = atomic_add_fetch(&gen_current, 1)` (acq_rel).
2. Store `slot_gen = 0` (relaxed), then a release fence.
3. Write `tid`, `ns`, `flags` and the bitmap.
4. Store `slot_gen = g` (release).

libcov's ST runtime emits straight into the next slot's bitmap. It zeroes `slot_gen` of slot `g+1` and fences before clearing that bitmap, which is the same protocol in a different order.

**Reader**, for generation *g* (`src/ring_reader.h`, `rr_read_slot`):
1. `now = load(gen_current, acquire)`. If `now < g`, it isn't published yet; retry later. If `now − g ≥ ring_size`, it was **overrun** (overwritten); skip ahead and count the loss. Under libcov's ST runtime the slot after `now` is already being refilled, so the oldest generation that is reliably readable is `now − ring_size + 2`. A reader that asks for `now − ring_size + 1` can see `slot_gen = 0` until its retries run out. Treat that as lost too.
2. `pre = load(slot_gen, acquire)`. If `pre ≠ g`, the slot is still being written or is torn; retry.
3. Copy the bitmap, `tid`, `ns` and `flags`.
4. Acquire fence, then `post = load(slot_gen, relaxed)`. If `post ≠ g`, the copy is torn; retry.

`gen_current` may name a generation whose slot isn't stamped yet. Readers must check `slot_gen` and must not trust `gen_current` alone.

- **Overrun.** After an overrun, resume at `gen_current − ring_size + 2`, the oldest generation still readable. The writer may already be clearing the slot after `gen_current`.
- **Dropped generations.** Under MT, a generation can be dropped and never stamped (counted in `publish_dropped`). Bound the retries in steps 2 and 4, and treat a generation that never stamps as lost. Readers wait for `magic == "LCVS"` (and, if they need the ring, `flags & ACTIVE`) before using the region.

---

## 4. SZR1 protocol

One TCP connection between an **executor**, which runs inputs and dials in, and a **brain**, which chooses inputs and listens. `suzzer-relay` is one executor. Any program that follows this section can stand in for it, and the brain doesn't care which one it is talking to.

### 4.1 Framing

The executor sends the 4 bytes `"SZR1"` once. After that, both directions carry frames:

```
u32 length      counts type + payload (so length ≥ 1)
u8  type
u8  payload[length − 1]
```

Every multi-byte integer is **big-endian**. Bitmaps are raw `u8` counters. `suzzer-relay` rejects frames over 64 MiB. Keep frames below that.

### 4.2 Frames

| Type | Name | Direction | Payload |
|---|---|---|---|
| 1 | HELLO | executor → brain, once, right after the magic | see 4.3 |
| 2 | INPUT | brain → executor | `u64 id`, `u32 len`, `u8 data[len]` |
| 3 | COVERAGE | executor → brain | `u64 id`, `u64 gen`, `u8 kind`, `u32 map_size`, `u8 bitmap[map_size]` |
| 4 | CRASH | executor → brain | `u64 id`, `u8 reason`, `i32 status` |
| 5 | BYE | either | empty |

Fixed lengths are `SZR_INPUT_HDR_LEN` (12), `SZR_COVERAGE_HDR_LEN` (21) and `SZR_CRASH_LEN` (13).

### 4.3 HELLO

| Field | Meaning |
|---|---|
| `u16 proto_version` | `1` |
| `u16 flags` | below |
| `u32 map_size` | length of every bitmap this executor will send |
| `u16 ring_size` | snapshots the executor buffers per input; an executor that delivers one snapshot per input may send `1`. The brain only logs it |
| `u16 arch_len` | ≤ 64 |
| `u8 arch[arch_len]` | free-form ASCII naming the target, e.g. `x86_64`, `mips32be`, `rv32`. The brain only logs it and records it in its run config |

HELLO flags:

| Bit | Name | Meaning |
|---|---|---|
| 0 | `MT` | libcov-specific: the target runs MT libcov |
| 1 | `LIVE_EMPTY` | libcov-specific: ST boundary mode |
| 2 | `SCHEME` | bits 3, 4 and 8..11 are valid |
| 3 | `MODEL_PC` | hashed-PC model (clear: site-id) |
| 4 | `ROTATE` | N-gram rotation |
| 8..11 | N | N-gram length |

As in LCVS, `MT` and `LIVE_EMPTY` describe libcov, and another executor sets them only if they apply. An executor whose bitmaps follow §5 sets `SCHEME` and describes its scheme, so the brain can tell maps from different schemes apart.

### 4.4 Lockstep

- **HELLO when ready.** An executor may connect and send HELLO only once it can take inputs (an emulator booting its firmware first, say). The reference brain waits `--hello-timeout` (600 s) for HELLO, then `--io-timeout` for each reply.
- **Each INPUT gets exactly one reply**, COVERAGE or CRASH, carrying the INPUT's `id`. The brain sends the next INPUT only after the reply. Ids are chosen by the brain, start at 1 and are never 0.
- **Unsolicited INIT snapshot**: before replying to the first INPUT, an executor **may** send one COVERAGE frame with `id = 0` and `kind = INIT` (1), its startup coverage. It is not a reply. The brain logs it and keeps waiting for the real reply. `suzzer-relay` doesn't send one.
- **COVERAGE**: `kind` is a slot flag (`1` INIT, `2` ITER, `4` GAP; `0` = nothing was published, sent with an all-zero bitmap so lockstep still advances). The brain scores only `ITER`. `gen` is the executor's generation counter, opaque to the brain. `map_size` equals HELLO's.
- **BYE** from the brain ends the session; the executor closes. BYE from the executor in place of a reply also ends the session cleanly. A frame of an unknown type is ignored.

### 4.5 Crash reasons

| Value | Name | `status` |
|---|---|---|
| 1 | `EXIT` | the target process exited; its exit code |
| 2 | `SIGNAL` | the target was killed by a signal; the signal number |
| 3 | `DELIVERY` | the input could not be delivered; 0 |
| 4 | `MALFORMED` | the executor rejected a malformed INPUT frame (payload < 12 bytes or `len` overruns it); nothing ran; 0. `id` is 0 if the payload was < 8 bytes |
| 5 | `GUEST_FAULT` | the target faulted (emulator/bare-metal/hardware); the faulting PC (low 32 bits) or a cause code, documented per executor |
| 6 | `ORACLE` | a crash or assert check fired; the oracle id or its PC |
| 7 | `HANG` | the executor detected no forward progress |
| 8 | `TIMEOUT` | the per-input budget was exceeded |

Reasons 5–8 are for executors whose target isn't a Linux process. `suzzer-relay` may report `TIMEOUT` if it ever gains per-input deadlines.

A brain **must treat a reason it doesn't know as an opaque crash**. `(reason, status)` is the deduplication key. The reference brain names reasons 1–8 in its log and `.info` sidecars, prints `status` in hex for `GUEST_FAULT` and `ORACLE`, and saves `HANG`/`TIMEOUT` inputs under `hangs/`, counted apart from crashes and not minimized by default.

---

## 5. Coverage bucket formula

How libcov turns the sequence of sites a thread executes into bitmap buckets. An executor whose bitmaps should mean the same as libcov's must reproduce this exactly. The C reference is `sink_emit` in `src/sink.h`.

### 5.1 Parameters

| Parameter | Values | libcov build option |
|---|---|---|
| model | **site-id** (default) or **hashed-PC** | `LIBCOV_COVERAGE_MODEL_SITE=1/0` |
| N | 1..8; default 2 | `LIBCOV_NGRAM_N` |
| rotate | 0 (default) or 1 | `LIBCOV_NGRAM_ROTATE` |
| `map_size` | a power of two | [§5.5](#55-map-size) |

Let `mask = map_size − 1` and `W = max(N − 1, 1)`. Each thread keeps a history `prev[0..W−1]` of 32-bit values, all 0 at start. Arithmetic below is on unsigned integers: `u64` wraps mod 2⁶⁴, and `^` is XOR.

### 5.2 One emit

When a site emits (which executions emit: [§5.7](#57-which-executions-emit)):

```
mix(v):                       # v: u64
    v ^= v >> 33
    v  = v * 0xff51afd7ed558ccd       (mod 2^64)
    v ^= v >> 33
    return v

site-id model, site id s:
    cur     = s
    cur_win = mix(s) & mask                                  # sink_spread

hashed-PC model, address pc in module m with runtime base base[m]:
    off     = (pc − base[m]) mod 2^P      # P = pointer width of the target
    cur     = mix(off ^ (m * 0x9E3779B97F4A7C15 mod 2^64)) & mask    # sink_hash_pc
    cur_win = cur

idx = cur
if N ≥ 2:
    for j in 0 .. W−1:
        idx ^= rotate ? rot(prev[j], j) : prev[j]
idx &= mask

bitmap[idx] = min(bitmap[idx] + 1, 255)                     # saturating u8

if N ≥ 2:
    prev[W−1 .. 1] = prev[W−2 .. 0]      # shift; the oldest drops off
    prev[0] = site-id model ? cur_win : (cur_win >> 1)
```

- At N = 1, `idx = cur`, and under the site-id model it is exactly the site id, so there are no collisions.
- At N = 2, under the hashed-PC model, the formula is AFL's `cur ^ (prev >> 1)`.
- The site-id model folds the *spread* id into history but uses the *raw* id as the base. Since `s < map_size` ([§5.5](#55-map-size)), the base needs no masking.
- The counter saturates at 255 and never wraps or decrements. libcov's MT build reaches the same value with an atomic compare-and-swap loop.

### 5.3 History: `prev` update and reset

`prev` is per thread. It is reset to all zeros:
- at startup;
- at every iteration boundary that fires ([§2](#2-lcvb1-boundary-file)), so history never leaks from one input into the next.

A boundary that fires normally publishes a snapshot. There are two libcov exceptions:
- Under MT, a thread's first boundary resets its history without publishing.
- The first `LIBCOV_BOUNDARY_INIT_GRACE` boundaries (default 0) neither publish nor reset. Their coverage is merged into the INIT snapshot.

An executor that runs one input per snapshot resets it before each input.

### 5.4 Rotation

With `rotate = 1`, let `bits = log2(map_size)`:

```
step = max(1, (bits − 1) / W)            # integer division
for j in 0 .. W−1:
    r = 1 + j * step
    if r ≥ bits: r = 1 + (r mod (bits − 1))
    rot_r[j] = r

rot(v, j) = ((v << rot_r[j]) | (v >> (bits − rot_r[j]))) & mask
```

`rot` rotates within the map width. Each slot then permutes `[0, map_size)`, so `{A,B,C}` and `{B,A,C}` fold to different buckets. The vectors record `map_bits` and `rot_amounts` for each rotated scheme.

### 5.5 Map size

Under the hashed-PC model, `map_size = 2^16` (`LIBCOV_MAP_SIZE_POW2`) by default.

Under the site-id model, libcov sizes the map from the number of sites `n` in the patch list (`compute_map_size` / `sink_map_size_for`):

```
FUDGE = 2              if N ≤ 1
        16 << (N − 2)  otherwise          # LIBCOV_MAP_FUDGE
MIN   = 2^12                               # LIBCOV_MAP_MIN_POW2
MAX   = 2^24                               # LIBCOV_MAP_MAX_POW2
n     = max(n, 1)
size  = min(next_pow2(n × FUDGE), MAX)
size  = max(size, MIN, next_pow2(n))       # every site id fits, even above MAX
```

The three constants can be overridden when libcov is built. HELLO and the LCVS header always carry the actual `map_size`, so a consumer reads it rather than recomputing it. `test/vectors/map_size.jsonl` tabulates the rule for the default constants.

### 5.6 Conformance vectors

`test/vectors/` holds one directory per scheme and map size, `<model>_n<N>_r<R>_<map_size>`. It covers models site and pc, N ∈ {1, 2, 3, 4, 8}, rotation off and on, and map sizes 4 KiB, 64 KiB and 1 MiB. Each directory contains:

- `scheme.json`: the parameters, derived values (`map_bits`, `rot_amounts`, `lcvs_scheme_flags`), the PC model's `module_bases`, and summary counts.
- `sequence.bin`: the emits, little-endian. The site model uses `u32 site_id`. The PC model uses `u64 pc` + `u8 module_idx`. The all-ones record (`ffffffff`, or 9 × `ff`) is a history reset, i.e. an iteration boundary.
- `expected.bin`: the bitmap after replaying the sequence into a zeroed map with a zeroed history.

The sequences include repeated sites past saturation, self-loops, every permutation of three sites, resets mid-sequence, three modules (one above 4 GiB) and a long pseudo-random walk.

The vectors are generated by `test/gen_vectors.c` compiled against `src/sink.h` itself (`make vectors`). `make test` fails if the committed copy differs from what the runtime produces. `test/vectors_check.py` is a second, independent implementation of §5 that reproduces every vector.

**Scheme-compatible.** An implementation is scheme-compatible for a scheme (model, N, rotate) when it reproduces that scheme's vectors byte for byte. To match libcov's bitmaps for the same target it must also:
- produce the same emit stream ([§5.7](#57-which-executions-emit));
- use the same site ids: patch-list record order (§1.3) for the site-id model, or the same module bases and module indices for the hashed-PC model;
- use the same `map_size`;
- reset history at the same points (§5.3).

Saturation, the `prev` update and the map-size rule are all part of the contract. The bitmap's *storage* is not: how and where an executor keeps it, threading, and atomics are its own business.

The vectors test the formula over a given emit stream. Some of their sequences repeat a site back to back, which libcov's `leapfrog` mode would collapse into one emit ([§5.7](#57-which-executions-emit)); they are there to test saturation and the formula, not libcov's arming.

### 5.7 Which executions emit

§5.2 runs once per **emit**. In libcov, an emit is a trap at an armed site, so which executions emit depends on how libcov re-arms sites. An executor that wants its bitmaps to match libcov's has to produce the same emit stream, not just the same formula.

- **`leapfrog` mode** (`LIBCOV_MODE`, the default and the fuzzing mode): when a site traps, libcov disarms it and re-arms the site that trapped before it. A site therefore emits every time it executes, *unless it was the last site to emit in this thread*. Back-to-back executions of the same site, such as a block looping on itself with no other site in between, collapse into **one** emit. libcov never produces a self-edge (the same site twice in a row), and its counters count separate visits rather than executions. This is exact for a single-threaded target. Under `libcov_mt.so` with several threads it is approximate, because the patched code is shared: one thread can disarm a site for another.
- **`oneshot` mode**: a site emits at most once until it is re-armed. With `LIBCOV_BOUNDARY_REARM=all` or `touched`, that means once per iteration; with `none`, once per process. Use it for sanity checks, not fuzzing.
- **Boundary markers**: a marker's own emit happens **before** the snapshot is published and the history is reset (§5.3). The BEGIN marker's hit therefore lands in the snapshot it closes:
  - the GAP snapshot in paired mode;
  - the previous ITER in begin-only mode;
  - INIT, for the first boundary.

  An iteration's first emit is the next site after the marker, with a zeroed history. An END marker's hit lands inside the ITER it closes. A marker whose instruction libcov emulates (`emulate`, `src/patchlist_format.h`) stays armed and emits on every hit, so it can emit twice in a row: the one exception to "no self-edge". It also clears the leapfrog "last site", so the next site always emits.

To be comparable with libcov in its default mode, an executor that sees every execution should:
1. skip an emit when the site is the same site that emitted last in that thread;
2. count a boundary marker's hit before resetting the history.

An executor that counts every execution still produces valid scheme-compatible buckets for the emits it makes. Its maps will just contain extra self-edge buckets and higher counts on tight loops.

---

## 6. Versioning

What may change without a version bump is additive and ignorable by old readers. Everything else bumps the format's version, and old readers then refuse the new data.

| Format | No bump (additive) | Needs a bump |
|---|---|---|
| LCV3 | defining a new `flags` bit for an optional table placed after the existing regions, at an offset derived from them (like the module base table) | changing a header or record field, the record size, `site_id` assignment, or the meaning of `offset`/`orig` |
| LCVB1 | none so far: `flags` and `reserved` are written 0 and not read | anything else |
| LCVS | a new field taking over `reserved` bytes, with 0 meaning "not provided"; a new flag bit | moving or resizing any field; changing the slot layout or the seqlock protocol |
| SZR1 | a new crash reason (brains treat unknown reasons as opaque); a new HELLO flag bit; a new frame type the other side may ignore | changing a payload layout or the lockstep rules (`SZR_PROTO_VERSION`) |
| Bucket formula | none: any change alters every bitmap. A new scheme must get new parameter values (and SCHEME bits), and the vectors gain directories for it | changing §5 for an existing scheme |

`lcv_formats.h` changes only by addition. Its `LCV_FORMATS_REV` increments with each addition, so a vendored copy can say which revision it is.
