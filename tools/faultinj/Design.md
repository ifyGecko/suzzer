# libfaultinj — Design Rationale

This document captures *why* libfaultinj looks the way it does. The
README covers *how* to use it; this covers the design decisions, the
tradeoffs considered, and the things deliberately deferred to v2.

* * *

## Problem statement

Embedded network daemons (the suzzer fuzzing target) are full of
error-handling paths that almost never execute on a fuzz harness's
host. On real hardware in the field, `open()` returns `EMFILE` once
in a while, `recv()` returns `0` because the peer hung up, `write()`
returns short because the disk is full. On the fuzz harness:

- the filesystem has unlimited handles
- loopback never times out
- `/tmp` never runs out of space
- a buffered write never fails

So fuzzers like AFL++ / honggfuzz / libFuzzer find bugs only in the
"happy path" parser. The error-handling code — which is statistically
where the *novel* memory-safety bugs live in mature software — never
gets traversed.

The classical solution from the FATE / EIO literature is **software
fault injection**: synthetically fail real calls so the program is
forced down its error-handling paths. The variants in the wild are:

1. **Kernel-level**: a kernel module that intercepts syscalls and
   returns failure. Highest fidelity. Not portable across kernel
   versions or architectures. Not viable for suzzer (heterogeneous
   embedded targets).
2. **`ptrace`-level**: a user-space tracer that catches syscall
   entries and rewrites returns. Portable to anything Linux runs.
   Performance overhead per syscall is prohibitive for fuzzing-rate
   workloads.
3. **libc-level**: an `LD_PRELOAD`'d shim that wraps libc symbols.
   Skips programs that bypass libc (rare on Linux). Generic across
   arches. Cheap.

We're (3). The trade is loss of fidelity for raw call paths that
skip libc (`syscall(2)` directly, hand-rolled syscall wrappers,
golang-style runtimes); the win is "build it once, run on every
target".

* * *

## Why a separate library, not a libcov extension

`libcov` is already an LD_PRELOAD that lives in the target process.
Tempting to bolt fault injection onto it. We didn't, for three
reasons:

1. **Constructor-order coupling.** `libcov` runs at constructor
   priority 101 because it has to arm SIGILL handling + memory
   patching before any of the target's own ctors fire. Fault
   injection has the opposite requirement: it should be configured
   late so it can read env vars set by the harness without
   interfering with libcov's bootstrap.

2. **LEGO-brick principle.** suzzer's design explicitly favours
   small composable libraries (single-threaded vs multi-threaded
   coverage, ptrace vs procmem injector, libdemalloc, libforksrv).
   A single user might want libcov + libforksrv with libfaultinj
   off; another might want libfaultinj alone with no coverage.
   Coupling them throws that away.

3. **Independent build / version.** `libcov` is rebuilt with each
   threading variant per arch (44 build cells). libfaultinj has no
   ST/MT distinction — it would slow the libcov matrix without
   benefit if folded in.

So libfaultinj is a standalone tool under `tools/faultinj/`, mirroring
`tools/inject/` and `tools/libdemalloc.c`.

* * *

## Why no allocator hooks in v1

`malloc` / `calloc` / `realloc` / `free` are arguably the highest-
yield class for fault injection: OOM-path bugs are nearly universal
in C code. But:

- `tools/libdemalloc.c` already replaces the allocator with a
  guard-page + canary instrumentation. It's the OTHER LD_PRELOAD
  shim that catches heap bugs.
- The composition question — does libfaultinj wrap libdemalloc's
  allocator (libdemalloc-with-fault), wrap libc's allocator
  (libdemalloc disabled), or refuse to load when libdemalloc is
  detected? — has non-obvious correctness implications. Faulting
  `malloc` to NULL before libdemalloc's guard-page setup is fine.
  Faulting AFTER libdemalloc allocates a guard-paged region would
  leak that region. Subtler still: a user might want libdemalloc
  for production heap-bug detection AND fault injection on the
  OOM path; we'd need an explicit composition mode.

Solving that correctly requires a careful design pass we haven't
done yet. So v1 deliberately omits the alloc class. Adding it later
is a one-line entry in `FAULTINJ_CLASSES` in `faultinj_classes.h` +
a per-class errno pool. No architectural changes needed.

* * *

## Why those specific 14 functions

The selection criteria, applied to every candidate:

| Criterion | Question |
| --- | --- |
| Bug yield | Does real network-daemon code commonly check this call's return, and do real bugs hide in the unchecked branch? |
| Composability | Can we fault this without breaking libcov / libforksrv / libdemalloc themselves? |
| Reachability | Does this call fire during the protocol-parser hot path (good), or only at daemon init (low yield)? |
| Implementation cost | Does the libc signature have variadic / msghdr / iovec complications that would balloon the hook code? |

The 14 selected (`open`, `openat`, `read`, `pread`, `write`,
`pwrite`, `close`, `recv`, `recvfrom`, `send`, `sendto`, `socket`,
`accept`, `accept4`) maximize all four. Specific decisions:

- **`bind` / `listen` / `connect` dropped** from the v1 socket
  family. They fire once at daemon init; faulting them produces
  uninteresting "service didn't start" crashes, not protocol bugs.
- **`recvmsg` / `sendmsg` deferred** because the `msghdr` interface
  with `iovec` arrays makes "short send" semantics ambiguous (which
  iov entry? which byte within it?). The single-buffer variants
  give us most of the bug yield with a quarter of the code.
- **`readv` / `writev` deferred** for the same iovec reason.
- **`fopen` / `fread` / `fwrite` / `fclose` deferred** because the
  stdio buffering layer means a "fault" at `fread` doesn't
  correspond 1:1 with the underlying `read`. Counting and short-
  return semantics get murky.
- **`stat` / `access` deferred** — moderate bug yield (TOCTOU,
  permission-check failure paths) but lower than the I/O classes,
  so v2.
- **`getaddrinfo` / `gethostbyname` deferred** — high yield but
  the implementation is deeply threaded and stateful inside glibc;
  the hook semantics would be tricky.
- **`printf` family skipped** entirely — return codes are almost
  never checked, so the bug yield is tiny, and faulting them
  silently breaks debug output.
- **`mmap` / `mprotect` / `munmap` skipped** — used internally by
  `libcov` (patching) and `libdemalloc` (guard pages). Faulting
  them inside the shim itself is asking for self-corruption.
- **`signal` / `sigaction` / `sigprocmask` skipped** — `libcov`'s
  SIGILL trap handler is installed via `sigaction`. Faulting it
  would disable coverage.
- **`fork` / `vfork` / `clone` / `waitpid` / `execve` skipped** —
  process-control calls. `libforksrv` depends on these working
  correctly inter-iter.
- **`dlopen` / `dlsym` / `dlclose` skipped** — shim internals.
- **`pthread_*` skipped** — too stateful; spurious failures wedge
  the target. v2 for `_mt` workloads.

* * *

## The determinism contract

The single most important property of libfaultinj is that the same
(seed, target binary, input bytes, env) tuple **always** produces
the same fault sequence. Without this:

- Reproducing a crash that ships from a long-running fuzz campaign
  becomes a wild goose chase.
- Bisecting which fault caused a crash is impossible.
- Sharing a repro with another team member requires also sharing
  process state, which can't be serialized.

The contract is implemented by making the decision for "call N of
class C" a pure function of `(seed, C, N)`:

```
roll  = xoshiro256**(splitmix64(seed ^ class_hash ^ N))
fault = (roll >> 32) < prob_threshold_32
errno = errno_pool[roll & 0xff % pool_size]
mode  = mode_pool [(roll >> 8) & 0xff % pool_size]
short = 1 + (roll >> 16) % (count - 1)
```

The PRNG advances **once per hooked call**. There is no global PRNG
state. This matters for two reasons:

1. **Out-of-order calls don't perturb each other.** Thread A's
   `read()` at idx=7 produces the same decision regardless of how
   many `read()`s thread B is making concurrently.

2. **Fork servers stay deterministic.** When the harness executes
   the target once and forks N times, each child sees the same
   `(seed, C, idx)` for the call it makes. Per-iter reset of
   counters is unnecessary — the harness changes `seed` between
   iters (via a fresh execve) and call-idx state per process is
   correct out of the box.

Two ancillary points:

- **Budget cap behavior.** `LIBFAULTINJ_MAX_FAULTS` only **suppresses**
  faults; it never adds them. So raising the cap reveals more faults
  from the same seed (the prefix of injections is unchanged), and
  lowering the cap truncates the sequence. This makes bisecting
  ("which of the 5 injected faults caused the crash?") work by
  monotonically reducing `MAX_FAULTS` until the crash goes away.

- **Probability vs. cap.** With `PROB=1.0` and `MAX_FAULTS=1`, the
  first eligible call is faulted, the rest pass through. With
  `PROB=0.001` and `MAX_FAULTS=999`, every call rolls 1-in-1000.
  The two knobs are orthogonal; the (seed, PROB) pair determines
  WHICH calls are eligible to fault, and MAX_FAULTS limits HOW
  MANY actually do.

* * *

## The PRNG

`xoshiro256**` seeded via three rounds of `SplitMix64` from
`(seed, class_id, call_idx)`. Both algorithms are public-domain,
~30 lines each, no library deps.

Why this combination:

- **`SplitMix64` mixes** the inputs. Without it, close `(seed, idx)`
  pairs would produce close first xoshiro outputs. SplitMix64 is
  the standard finalizer used by xoshiro's own author for this
  exact purpose.
- **xoshiro256\*\* is uniform** in the upper 32 bits and well-
  distributed across all positions. We only pull ONE output per
  call so we don't need long-period properties; we need fast,
  zero-state seeding.
- **No xorshift / LCG / `rand()`.** Those have visible biases in
  the upper bits, which is exactly the bits we use for the
  probability comparison. A 1-in-1000 probability with a biased
  PRNG would have visibly non-uniform fault clustering.

Cost: ~5 multiplies, ~6 XORs, ~1 rotate per decision. Negligible
versus the syscall it's wrapped around.

* * *

## Per-class errno pools

We pick from a small fixed pool per class instead of a single
hard-coded value or a "random integer". Rationale:

- **Branch coverage.** Many target codepaths branch on errno value
  (`if (errno == EAGAIN) retry`). A single hard-coded errno would
  only exercise one branch of those tests.
- **Realism.** The chosen pool reflects what real Linux kernels
  return for each call in real failure scenarios. `recv()` returning
  `ECONNRESET` is something every TCP daemon must handle; `read()`
  returning `EINTR` is something every protocol parser should loop
  on but often doesn't.
- **Small enough to enumerate.** With 4 entries in the open pool,
  every seed/idx combo eventually hits each. Larger pools would
  scatter coverage thinner.

Why a fixed pool (not env-configurable per class)? Configurability
adds env-var surface area for negligible gain. Users who really
want a specific errno can disable the class via
`LIBFAULTINJ_DISABLE` and `LD_PRELOAD` their own one-function shim.

* * *

## Per-class failure modes

Three modes:

- `FI_MODE_FAIL_NEG1` — return -1 + errno.
- `FI_MODE_FAIL_ZERO` — return 0 without errno (read-family only).
  Models clean EOF / peer-closed; a notorious source of "I treated
  zero as a transient and looped forever" bugs.
- `FI_MODE_FAIL_SHORT` — call libc with a truncated count, return
  what it returns. The truncation length is `1 + roll % (count - 1)`
  so it's strictly in `[1, count - 1]`.

Per-class mode pools (see `faultinj_classes.h`):

- `OPEN` / `CLOSE` / `SOCKET` / `ACCEPT` — only `FAIL_NEG1`. These
  calls have no meaningful "short" or "zero" failure.
- `READ` / `RECV` — `FAIL_NEG1`, `FAIL_ZERO`, `FAIL_SHORT`. Read-
  family supports all three.
- `WRITE` / `SEND` — `FAIL_NEG1`, `FAIL_SHORT`. Zero return on
  write isn't a Linux thing; "wrote nothing" is short-of-1.

The short-mode count uses bits 16..47 of the PRNG roll to avoid
correlation with the mode choice (bits 8..15) and the errno choice
(bits 0..7). With a 64-bit roll, all three picks are independent.

* * *

## Threading

Per-class call counters are `__atomic_fetch_add(..., RELAXED)`.
RELAXED is correct here because the counter value is the *only*
shared state and is used solely to derive a roll value. There's no
release semantics needed; threads see *some* value for the counter,
and which value they see doesn't affect correctness of subsequent
state (it just biases which fault decision they get).

The global `faults_so_far` counter is also RELAXED. It can overshoot
`MAX_FAULTS` under contention (multiple threads cross the cap at
roughly the same time), which produces N+1 or N+2 faults instead of
exactly N. We consider this acceptable in v1; the alternative is a
CAS loop or a mutex, both of which slow the hot path.

Strict per-thread determinism — same `(seed, C, N)` always produces
the same fault on the same thread — would require per-thread
counters (a `__thread int` or pthread key). v2.

* * *

## Async-signal-safe logging

The logger writes one line per injection via `syscall(SYS_write, ...)`.
We deliberately do **not** use `write(2)` because we OWN the
`write()` symbol — that would be infinite recursion. We deliberately
do not use `fprintf` because:

- `fprintf` allocates internally (stdio buffer reallocation).
  Faulting `malloc` from a signal handler is asking for trouble.
- `fprintf` is not async-signal-safe per POSIX.
- Some target stdio configurations buffer aggressively; lines would
  not show up until process exit.

Integer formatting is hand-rolled (`fi_append_u64`, `fi_append_x64`)
into a stack buffer; a single `syscall(SYS_write, ...)` emits the
whole line atomically. No multi-line interleaving under MT.

* * *

## Self-protection: which fds we refuse to fault

By default:

- fds `0`, `1`, `2` (stdio) unless `LIBFAULTINJ_SKIP_STDIO=0`.
- `LIBFORKSRV_CTLFD` / `LIBFORKSRV_STSFD` if either env var is set.
- The log file fd (so the logger doesn't recurse through itself).
- Anything in `LIBFAULTINJ_SKIP_FDS` (user-supplied).

We do NOT auto-skip the libcov shm fd. Rationale: libcov keeps the
shm mapped via `mmap`, not accessed via `read`/`write`/`close` in
the hot path. If libcov ever does `read()`/`write()` on the shm fd,
we'd fault it, but libcov's own error handling there is robust
(the shm is treated as best-effort coverage; failures degrade
gracefully). Adding a runtime `fstat`-against-dev/ino check on
every I/O call would cost more than it saves.

* * *

## Open-ended discussions / deferred

- **Path-based skip lists.** Letting the user say "never fault
  `open()` on `/etc/passwd`" would be reasonable. Deferred because
  parsing CSV of paths inside an async-signal-safe context is
  non-trivial.
- **Per-class errno weighting.** Currently all errnos in a class
  pool are equiprobable. Weighting (e.g. `EAGAIN` 3x more likely
  than `EIO` for `read`) might better model realistic failure
  distributions. Deferred — we'd need data on real-world errno
  frequencies first.
- **Adaptive probabilities.** Bumping per-class probability when a
  class has been producing new coverage (and lowering it when it
  hasn't) is a known win in coverage-guided fuzzing. Needs harness
  integration. v2+.
- **Exhaustive enumeration mode.** Replay the same input with
  fault@call#1, fault@call#2, ..., fault@call#N. High signal but
  expensive. v2 candidate.
- **Per-thread call counters.** See "Threading" above. v2.
- **Allocation class.** See "Why no allocator hooks in v1" above.
- **`recvmsg` / `sendmsg` / `readv` / `writev`**. v2.

* * *

## Things we got right that aren't obvious

A handful of small decisions that look minor but have non-obvious
upside, worth remembering when extending the library:

- **Log open() bypasses our own hook** via `real_open`. If we'd
  routed it through the hook, our own log-file creation could be
  faulted, which is hilariously self-defeating.
- **`close()` always actually closes the fd**, even when we report
  failure. Linux semantics say close releases the fd regardless;
  the bug class we're targeting is "code retries close() after
  the first failure", which then hits `EBADF` on the second try
  — a real bug, observable only if we mimic real Linux behavior.
- **PROB scaled to a uint32 threshold**, compared against
  `(uint32_t)(roll >> 32)`. Integer-only hot path; no FP in the
  decision function.
- **Budget cap counted only AFTER a fault is rolled.** So the
  decision pattern (which calls are eligible) is independent of
  `MAX_FAULTS`. Raising the budget reveals more faults from the
  same seed; lowering truncates. Bisection by `MAX_FAULTS` works.
- **X-macro for the class table.** Adding a class is one line in
  `FAULTINJ_CLASSES` plus two arrays (errnos, modes). No risk of
  forgetting an entry in the enum vs the metadata table — the
  `_Static_assert` catches the most common mistake.
