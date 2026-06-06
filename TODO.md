# TODO

Items deferred from the current scope, ordered roughly by when they'll
become blocking. Captured here so design context isn't lost.

## Done since last revision

- **N-gram coverage scheme**: `LIBCOV_NGRAM_N` (1..8) selects block
  coverage (N=1), AFL-style edges (N=2, default, bit-for-bit identical
  to the historical emit), or N-gram coverage (N>=3) at build time.
  `LIBCOV_NGRAM_ROTATE` adds per-position rotation to defeat XOR-
  commutativity collisions at higher N. Bitmap layout, hash,
  saturation, and atomic emit path are independent of N -- existing
  consumers and the snapshot ring need no changes. Per-thread prev-PC
  storage grew from a single `uint16_t` to a `uint16_t[N-1]` window;
  the boundary publish path clears the whole window per-iter. Both ST
  and MT validated end-to-end at N=1/2/4/8 plus rotate; cross-arch
  smoke confirms every backend still builds and links clean.
- **Iteration boundary**: per-target sidecar (LCVB1) names marker
  addresses; on each hit libcov publishes the live bitmap to a snapshot
  ring in shm, clears the live bitmap, and applies a configurable re-arm
  policy (`none` / `all` / `touched`). Drivers read snapshots via a
  seqlock pattern with per-slot generation stamps -- desync detection
  is structural. Per-thread depth tracking, touched-set, and deferred
  marker re-arm are `__thread` under `libcov_mt.so`. `tools/gen_boundary.py`
  generates the sidecar; `test/target_loop.c` is the canonical long-running
  target; `test/fuzz_driver.c` is the boundary-aware reader.
- **Multi-thread support**: `libcov_mt.so` is a separate brick. TLS
  `prev_loc`, atomic saturating bitmap, atomic per-site spinlock,
  `/proc/self/mem` mprotect-free writes, `membarrier(SYNC_CORE)` for
  cross-CPU I-cache visibility, graceful fallback on older kernels.
  Native validation passes; 32-thread / 10,000-iter stress is clean.
- **LCV2 wire format**: bumped magic and added a `threading` hint byte.
  Library accepts both LCV1 (legacy) and LCV2; refuses mismatched MT/ST
  patch lists with a clear log line. Multi-module is the natural LCV3
  extension (header field is already reserved).
- **x86_64 MT backend**: UD2 head-only patches (single atomic 2-byte
  write per Intel SDM 8.1.1), no NOP padding. Generator's
  `--threading mt` skips x86 sites that would straddle a 64-byte cache
  line (Intel doesn't guarantee atomicity in that case).

## Daemon-fuzzing feature work (next focus)

The PoC validates the trampoline mechanism end-to-end across 11 backends
(x86_64, aarch64, arm + thumb, mips/mipsel/mips64/mips64el, powerpc,
powerpc64 BE+LE, riscv64) and both threading variants. The next phase
makes it useful against network daemons.

- **Paired begin/end boundary markers** for nested request handlers
  (HTTP/2 streams, SOAP envelopes, recursive dispatchers). The current
  boundary mechanism handles begin-only markers; paired-mode depth
  scoping is the natural next iteration on `boundary.c`.
- **Multi-module patch list (LCV3)**: header carries a module name
  table; each record has a module_idx. Loader resolves each module's
  base via `/proc/self/maps`. Lets us instrument linked libraries
  (libssl, libxml2, etc.) where parser bugs typically live.
- **Signal-mask hardening**: intercept `sigprocmask` / `pthread_sigmask`
  and silently strip the trap signal from any "block" set, so a daemon
  that masks signals around critical sections can't accidentally kill
  itself by deferring a synchronous trap.
- **Daemon lifecycle resilience**: explicit handling around chroot,
  drop-privileges, daemonize, closefrom -- confirm everything we need is
  mapped (not just fd-held) before the daemon's setup runs.
- **Fork-per-connection support**: hook `fork()` in libcov so each child
  gets its own bitmap segment; library writes the per-child segment name
  to a control fd the driver listens on.
- **Hot-loop policy**: per-site hit cap in leapfrog mode (env-configurable
  threshold; auto-disarm above N hits) to keep traffic-jammed parser
  inner loops from collapsing throughput.
- **dlopen hook**: instrument libraries loaded *after* libcov init
  (plugins, lazily-loaded modules). Probably an LCV3 extension.

## N-gram follow-ups

- **Runtime-selectable N**. Today `LIBCOV_NGRAM_N` is purely compile-
  time so the hot path stays branch-free and fully unrollable. If a
  user wants to A/B different N values without rebuilding, add a
  `LIBCOV_NGRAM_RUNTIME` tunable: compile-time `N` becomes the
  *maximum* and an env var picks the actual window length at init,
  clamped to `[1, max]`. Costs one runtime-resolved loop bound per
  emit, which is negligible relative to the trap-and-signal entry.
- **Hybrid coverage publish**. Some research workflows want both
  AFL-style edges and an N-gram view at the same time. Requires an
  extra bitmap region in the shm layout (header field for
  `aux_bitmap_offset` + `aux_scheme_n`) and consumer support. Hold
  until a concrete consumer needs it.
- **Tag N in the shm header**. Consumers today don't need to know
  `N` (the bitmap is opaque buckets), but if a future
  AFL-mode-vs-N-gram-mode comparison tool wants to dispatch on the
  producer's scheme, pack `N` into the spare upper bytes of
  `hdr->flags` (additive; old readers ignore them).

## MT follow-ups

- **Real-hardware MT cross-validation**. `run_cross_mt.sh` is full-run
  for `x86_64` and `aarch64` (where qemu-user happens to cooperate) and
  build-only for the other 9 backends, because qemu-user's TCG cache
  cannot be invalidated without an mprotect perm change, which strips
  PROT_EXEC and SIGSEGVs peer guest fetches. On real hardware our
  `/proc/self/mem` write + `membarrier(SYNC_CORE)` is the correct
  primitive, but we have no real-hardware test bed for ARM/MIPS/PPC/
  RISC-V at the moment. Set up CI on real boards (raspberry pi for
  arm/aarch64, mips dev kit, ppc64 box, riscv64 hifive) and add to the
  validation matrix.
- **MT raw-`clone(2)` stress harness**. `target_simple_mt.c` uses
  pthreads. Targets that spin threads via raw `clone(2)` (less common
  but real -- some old daemons, some custom runtimes) need a separate
  stress harness to exercise the same races without the libc/pthread
  shim. Probably `target_simple_clone.c` that calls `clone()` directly
  with `CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND`.
- **MT membarrier fallback via tgkill**. For Linux < 4.16 without
  `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE`, broadcast a no-op signal
  (`tgkill SIGURG`) to every peer thread; the signal-return path
  performs an instruction-serializing barrier on most arches. Heavier
  than membarrier but works on kernels back to the 2.6 series. Add
  when a real target needs it.
- **MT-aware hot-loop policy**. The per-site hit cap (above) is more
  important under MT: a hot loop hit by 32 threads at 10kHz each will
  consume serious CPU in trap+spinlock overhead. Auto-disarm above
  threshold N (per-site, atomic counter) keeps throughput stable.

## Patch-list generator improvements

The generator now supports hand-picked instrumentation slices via
`--root` / `--cutoff` / `--max-depth` (see `tools/gen_patchlist.py` and
the README section "Selective instrumentation"). Items below are
follow-ups worth doing as the tool sees real-world use.

### Slice resolution / quality

- **Indirect-call resolution**. Static slicing via rizin's `callrefs`
  misses function pointers, vtables, switch-via-table dispatch, and
  callback-driven flows (libevent, glib, JS-engine bytecode dispatch).
  Options, roughly in order of effort:
    1. Heuristic: collect any function whose address is taken (rizin
       `axt @ <fn-entry>` returns xrefs *to* the function -- including
       DATA refs that suggest the address is being stored). Optionally
       union them into the reachable set under a `--include-addr-taken`
       flag.
    2. Value-set analysis via Ghidra (headless) -- much heavier dep, but
       resolves table-driven dispatch on simple parsers.
    3. Runtime augmentation: run the binary once under a tracer
       (uftrace, eBPF uprobes, even our own `LIBCOV_MODE=oneshot` with a
       broad initial slice) to record which addresses actually get
       called from where, then re-generate a slice anchored on the
       runtime call graph. Hybrid static+dynamic is usually the right
       answer for production fuzzing.

- **Tail-call detection**. Rizin classifies some `jmp` instructions as
  `CALL` and others as `JMP`/`CODE`. Today we only follow `CALL`. Add a
  pass that inspects the jump target: if it's the entry of another
  function in the analyzed set AND the source block is the function's
  terminator, count it as a tail-call edge. Gate behind `--follow-tail`
  to keep default behavior conservative.

- **Address-taken roots**. Often the user knows "this callback gets
  registered with foo_set_handler" but doesn't know who calls the
  handler. Allow `--root @0x401234` to read a function-pointer value
  from a constant address (rizin `pv8 @ <addr>`) and treat the
  dereferenced address as the root. Useful for vtable / dispatch-table
  fuzzing.

- **Per-basic-block cutoff**. Today cutoffs are function-granular;
  excising "everything below this basic block inside function X" is
  more surgical. Implement as an extension of `--cutoff` accepting
  `FUNC+0x40` syntax: BFS over basic blocks inside that function instead
  of functions, excluding the named block and its successors.

- **Negative slicing (`--exclude-reachable`)**. Subtract the slice
  reachable from a "noisy" root (e.g. the logging subsystem) from the
  main slice. Useful for keeping hot-loop logging code out of coverage.

- **Backward slicing (`--callers-of`)**. Given a leaf function X,
  instrument every function that can reach X. Inverse of `--root`. Good
  for fault localization after a crash: "what could have led to this
  trap?"

### Symbol & address ergonomics

- **Globbing in --root/--cutoff**. Accept `--root 'parse_*'` and expand
  via fnmatch against the function list. Easier than chaining ten
  `--root` flags by hand.

- **Slice file format**. Accept `--root-file PATH` containing one
  symbol/address per line, optionally with comments. Lets users keep
  the slice spec under version control instead of in shell history.

- **Improved stripped-binary resolution**. With no symbols, the
  function list is all `fcn.<hex>`. The generator should accept a
  user-supplied symbol map (`name=0xADDR` lines) as `--symbols PATH` so
  the user can name the entry points they care about.

### Visualization / dry-run

- **Dot/Graphviz dump**. `--dump-graph slice.dot` after BFS to render
  the slice as a call graph. Easier to spot missing branches than
  reading the linear `--print-reachable` output.

- **Slice diff**. `--diff baseline.lcv` to print which functions are in
  the new patchlist but not the baseline (and vice versa). Useful when
  iterating on cutoff lists.

### Performance / correctness

- **Cache the rizin session**. Today `pick_sites` does one `rizin -q -c
  "aaa; afbj @ X"` per function, re-running `aaa` each time. For a
  500-function binary that's the single biggest wall-clock cost. Move
  to a persistent rizin process via FIFO/socket (poor-man's rzpipe
  without the Python dep), or batch all `afbj`/`pdj` queries into one
  session like `build_call_graph` already does.

- **Verify slice against runtime hits**. After a fuzz run, diff the
  bitmap's hit set against the static slice. Bitmap edges not in the
  slice are bugs in our slicing (or indirect-call gaps); slice entries
  with zero hits are dead code the user can prune from the patchlist
  next round.

- **Selectivity-aware MT generation**. When `--threading mt`
  drops sites for cache-line straddling, the user currently only sees
  a count. Print the dropped offsets under `--verbose` so the user can
  decide whether to nudge the source to re-emit those instructions on
  aligned boundaries.

## Tooling / transport

- **`suzzer-relay`**: tiny standalone tool to be deployed on the target
  device. mmaps the libcov bitmap and serves bytes over TCP/Unix on
  request. Keeps libcov small and signal-safe; transport stays pluggable
  (TCP/serial/MQTT/whatever the device speaks).
- **`suzzer-driver`**: minimal fuzz loop using the bitmap, the relay,
  and a configurable input mutator (radamsa? zzuf?). Replaces the
  current `test/fuzz_driver.c` proof-of-concept.

## Forkserver (separate tool, not core)

Forkserver-style execution model is **not** appropriate for daemon
fuzzing (daemons don't fork-per-request in general), but is the right
tool for **short-lived target binaries** fuzzed at high throughput
(parsers, CLI tools, format converters). When that use case arrives:

- Build a standalone `suzzer-forkserver` binary that takes a target +
  patch list and exposes an AFL++-compatible control pipe interface
  (handshake + per-iter "go" + child pid/status messages).
- Reuses the libcov library wholesale; just adds the fork-loop wrapper
  in a separate process.
- Keep it cleanly separate from core libcov so daemon-fuzzing doesn't
  drag in forkserver complexity.

## Architecture work after current backends

- **i386**: trivial extension of x86_64 (UD2 same, PC = `REG_EIP`).
- **mips r6 / nanoMIPS**: validate the BREAK encoding still triggers
  RI/SIGTRAP cleanly. Probably no change.
- **arm64 BE**: aarch64_be toolchain exists in Debian; verify illegal
  opcode and PC accessor under qemu-aarch64_be-static.
- **s390x**: low priority (uncommon in embedded), but mainframes exist.

## Hardening to defer until a real target needs it

- **Refuse to clear our trap handler**: today we intercept `sigaction`
  for the trap signo, but a target using `rt_sigaction` syscall directly
  would bypass us. If we see this in the wild, add a syscall-level
  interceptor via seccomp-bpf or `libsyscall_intercept`.
- **Per-thread coverage maps**: only if a real target's threading model
  produces uselessly noisy edge attribution.
- **W^X-strict embedded kernels**: today our two-step (R|W → R|X) works
  on all common Linux configurations. If we hit one that refuses, fall
  back to opening `/proc/self/mem` and writing through that — it
  bypasses page protection for ptrace-style debugging.
