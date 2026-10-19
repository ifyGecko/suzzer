# suzzer TODO: publish the formats as a contract other executors can consume

## Goal

Make suzzer's on-disk, shared-memory and wire formats into a **documented, versioned contract** that other coverage producers can implement without linking libcov.

**Status: S0–S6 are done** (commit 8fb13ae, "Publish suzzer's formats as a contract for other executors"). This file is kept as the record of what the contract promises.

The first consumer is the ember firmware emulator (its plan lived in ember's tree). An emulator, a QEMU plugin or a hardware-trace decoder could then:
- read suzzer's site lists,
- produce bitmaps with the same meaning as libcov's,
- and be driven by `suzzer_brain.py`.

suzzer's own purpose doesn't change: coverage for embedded Linux userland without recompiling, plus the on-device fuzzing workflow.

## Ground rules

- **No consumer-specific code.** Nothing in suzzer names ember (or any other consumer) in code, build or tests. Changes are justified by being generic.
- **Backward compatible.** Existing patch lists, boundary files, LCVS readers and brain/relay pairs keep working. Each change is additive or covered by a version check.
- **libcov runtime unaffected.** No behaviour or performance change. All validation suites (`test/run_all.sh`, cross-arch runs) stay green.
- **Consumers don't link.** A consumer copies the format header and test vectors at a pinned commit, or reads them from a suzzer checkout it is given. Nothing here may require a consumer to build suzzer.

---

## S0. Format specification (`docs/FORMATS.md`)

**What:** one document that a third party can implement from without reading libcov's sources.

**Requirements:**
- **LCV3 patch list:**
  - header, record and module-name table layouts;
  - all fields little-endian;
  - `orig[]` is the raw in-memory bytes, in the target's byte order;
  - `offset` = address − the module's link base (`gen_patchlist.py:966`);
  - `site_id` = record index in the file, assigned before sorting;
  - the meaning of the `threading` field;
  - version rules;
  - the S2 extension.
- **LCVB1 boundary file:** header and record layouts, `kind`, `depth_filter`, paired vs begin-only semantics, and offsets relative to module 0's base.
- **LCVS shared-memory region:**
  - layout, field offsets (the `_Static_assert`s in `src/boundary.h`) and header byte order;
  - the flags, including the scheme bits `SCHEME/MODEL_PC/ROTATE/NGRAM`;
  - the ring slot header, slot flags `INIT/ITER/GAP`, and the seqlock read/write protocol (`src/ring_reader.h:203`);
  - the ownership fields.
- **SZR1 protocol:**
  - framing, every frame type and payload;
  - lockstep rules: one INPUT gets exactly one COVERAGE or CRASH, and an INIT frame comes first with `id=0`;
  - HELLO flags and the arch string;
  - crash reasons, including S3.

  Describe the two ends by **role**: *executor* (dials the brain and runs inputs) and *brain*. `suzzer-relay` is one executor.
- **Coverage bucket formula**, given exactly for each scheme, with the constants from `src/sink.h:145-230`:
  - `sink_spread` and `sink_hash_pc`;
  - the N-gram fold, with and without rotation;
  - saturating 8-bit counters;
  - the `prev` update rule;
  - the map-size rule (`compute_map_size`, `src/libcov.c:89`; `LIBCOV_MAP_FUDGE/MIN_POW2/MAX_POW2`).

  State which parts a consumer must match for its bitmaps to be "scheme-compatible".
- **Versioning policy:** what changes need a version bump for each format, and that LCVS fields only ever take over reserved bytes (already stated in `boundary.h`).

**Done when:** a reviewer can write a reader and writer for each format from the document alone. Check this with the S5 vectors and an independent Python reader.

## S1. Header-only format definitions (`src/lcv_formats.h`)

**What:** separate the definitions of the formats from the runtime code, so consumers can copy one file.

**Requirements:**
- Move these into `src/lcv_formats.h`:
  - the patch-list header and record structs, magic, version and `LIBCOV_TH_*` (from `src/patchlist_format.h`);
  - the LCVB1 structs, the LCVS header and slot header, and every `LIBCOV_SHM_*` / `LIBCOV_SLOT_*` constant (from `src/boundary.h`);
  - the SZR1 constants (from `tools/relay_proto.h`).
- Requirements on the new file:
  - it depends only on `<stdint.h>` and C11 `_Static_assert`;
  - no glibc, `ucontext`, `uintptr_t` runtime types, or libcov functions;
  - it is pure C11 and builds warning-free with `-std=c11 -Wall -Wextra -Werror -Wshadow -Wstrict-prototypes -Wmissing-prototypes`, the strictest consumer flags known.
- `patchlist_format.h`, `boundary.h` and `relay_proto.h` include it and keep only runtime declarations. Every existing `#include` keeps compiling.
- Field names and layouts are unchanged, so existing on-disk files and live regions stay byte-identical.
- `make test` builds a tiny translation unit that includes only `lcv_formats.h` with the strict flags above.

**Done when:** all suites pass, and `lcv_formats.h` compiles on its own with those strict flags.

## S2. Module link base in the patch list

**What:** record each module's link-time base address (`baddr`), so consumers without `/proc/self/maps` (emulators, bare-metal, offline tools) can turn offsets back into addresses without guessing.

**Requirements:**
- Additive encoding inside LCV3, with no version bump:
  - set the header `flags` bit `LCV_FLAG_MODULE_BASES (1u<<0)`;
  - append a `u64[module_count]` little-endian table at `align8(modules_offset + modules_size)`.
- This works because the current reader never checks `flags` (`src/config.c:71`, comment only) and bounds every read by explicit offsets, so old readers ignore both. **A regression test proves it:** an old-format reader fed a new file loads it identically.
- Update the `flags` comment in `patchlist_format.h` and `config.c`: bit 0 is defined, the other bits must be 0, and readers ignore bits they don't know.
- `gen_patchlist.py` always writes the table, with rizin's `baddr` for each module. `--no-module-bases` turns it off.
- libcov runtime: it may log a mismatch between the recorded base and the actual mapping for non-PIE modules (debug aid only). No behaviour change.

**Done when:**
- old and new readers load old and new files identically;
- `test/shm_bitmap.py` and every tool that reads patch lists still work.

## S3. SZR1 crash reasons that don't assume a process

**What:** generic reasons for executors whose target isn't a Linux process (emulators, bare-metal, hardware).

**Requirements:**
- Add to `enum szr_crash_reason`:

  | Reason | Value | `status` meaning |
  |---|---|---|
  | `SZR_CRASH_GUEST_FAULT` | 5 | faulting PC, low 32 bits, or a cause code (documented per executor) |
  | `SZR_CRASH_ORACLE` | 6 | a crash/assert check fired; `status` = the oracle id or PC |
  | `SZR_CRASH_HANG` | 7 | no forward progress detected by the executor |
  | `SZR_CRASH_TIMEOUT` | 8 | per-input budget exceeded |

- These are additive values, so `SZR_PROTO_VERSION` stays 1. Document in S0 that a brain must treat unknown reasons as opaque crashes, which it already does: `(reason, status)` is the dedup key (`suzzer_brain.py:281,313`).
- `suzzer_brain.py`:
  - name the new reasons in logs, the `.info` sidecar and status events;
  - print `status` in hex for `GUEST_FAULT` and `ORACLE`;
  - for `HANG`/`TIMEOUT`: save the input, but by default don't run the minimizer (each probe costs a full timeout); `--minimize-timeouts` opts in.
- `status_tui.py` shows hangs and timeouts separately from crashes.
- `suzzer-relay` doesn't change, but it may report `TIMEOUT` if it ever gains per-input deadlines.

**Done when:** `test/run_validation_relay.sh` still passes, plus a new brain unit test that feeds a fake executor's frames carrying each new reason.

## S4. Accept raw firmware images in the site/boundary generators

**What:** let `gen_patchlist.py` and `gen_boundary.py` work on raw binaries (bootloaders, RTOS images), not only on ELF files.

**Requirements:**
- New options, shared through `rz_resolve.py` or a common helper:
  - `--raw` together with `--base ADDR --arch mips|arm|riscv|... --bits 32|64 --endian big|little`;
  - these map onto the rizin flags `-m ADDR -a ARCH -b BITS -e cfg.bigendian=…`.
- With `--raw`, module 0's `baddr` is `--base`, written to the S2 table.
- Existing safety rules apply unchanged: the MIPS `entry` strategy, rejecting delay slots, the overlap checks, and `--threading` filtering. Default `--threading` is `any` for raw images.
- `orig[]` is the image's own bytes; `--endian` only selects how the disassembler reads them.
- Optional `--symbols FILE` (`nm`-style or a Ghidra export) to name functions for `--root`, `--cutoff` and boundary resolution when a raw image has no symbols.

**Done when:**
- `test/run_validation_generator.sh` gains raw-image cases (MIPS BE/LE and RV32 if rizin supports it);
- an ELF and the same image as `objcopy -O binary` + `--base` produce identical records.

## S5. Conformance vectors for the coverage formula (`test/vectors/`)

**What:** machine-readable reference data proving an implementation reproduces `sink_emit` exactly.

**Requirements:**
- A generator `test/gen_vectors.c` built from `src/sink.h` itself, so the vectors can't drift from the runtime. For each scheme it writes:
  - site model and hashed-PC model;
  - N ∈ {1, 2, 4, 8}, rotation on and off;
  - map sizes 4 KiB, 64 KiB and 1 MiB.
- Output format, one vector per file:
  - `scheme.json`: model, N, rotate, map_size, and for the PC model the module bases;
  - `sequence.bin`: little-endian `u32 site_id` (or `u64 pc` + `u8 module_idx` for the PC model);
  - `expected.bin`: the raw bitmap.
- Sequences include:
  - repeated sites (saturation past 255);
  - self-loops;
  - a reset of `prev` mid-sequence, marked in the sequence by a sentinel;
  - more than one module.
- `make vectors` regenerates them; `make test` checks that the committed vectors match the generator.
- An independent pure-Python implementation (`test/vectors_check.py`) checks the vectors, cross-checking the formula against a second implementation.

**Done when:** both C and Python agree on every vector, and S0 points at the vectors.

## S6. Executor-neutral wording and HELLO conventions

**What:** small clarifications so another executor can stand in for `suzzer-relay` without the brain caring.

**Requirements:**
- `suzzer_brain.py`: user-facing messages say "executor" where they now say "relay" (e.g. "no relay connected" at `:185`). Option names stay the same, so nothing breaks.
- HELLO arch string: document it as free-form ASCII ≤ 64 bytes (e.g. `x86_64`, `mips32be`, `rv32`). The brain only logs it and records it in `run_config`.
- HELLO `ring_size`: document that an executor delivering one snapshot per input may send 1.
- Document (in S0) that `LIVE_EMPTY` and `MT` describe libcov specifically, and that another executor sets them only if they apply.
- `HOWTO.md`: a short "writing your own executor" section pointing at S0, S1 and S5.

**Done when:** a fake executor written only from S0 (the Python test from S3) completes a brain session.

---

## Order and dependencies

```
S1 ── S0 ── S5
S2 ── S4
S3 ── S6
```

All items are independent of any consumer. A consumer can start before any of them lands:
- it can hand-copy today's structs;
- it can pass module bases on its command line;
- and it can send numeric crash codes.
