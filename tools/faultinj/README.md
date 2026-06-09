# libfaultinj — deterministic libc-level fault injection for suzzer

`libfaultinj.so` is an `LD_PRELOAD` shim that intercepts a curated set
of libc functions and occasionally returns failure instead of calling
through. Every fault decision is a **pure function of a user-supplied
64-bit seed plus the (class, call-index) of the call**, which is what
gives you the determinism / reproducibility contract: same env vars +
same input bytes = same fault sequence.

It is one of the LEGO bricks that ships under `suzzer/tools/`. Use it
to find bugs that other fuzzers can't reach — the bugs that hide
behind error-handling paths that are never normally taken because the
relevant `open()` / `read()` / `recv()` / etc. rarely fails on the
fuzz harness's host filesystem and loopback.

* * *

## Quickstart

```sh
# Build the .so plus the two test targets for the host arch.
make -C tools/faultinj

# Sanity-check that everything works end-to-end.
make -C tools/faultinj validate
```

The build artefacts land under `tools/faultinj/build/<arch>/`:

```
build/x86_64/libfaultinj.so
build/x86_64/target_faultinj_simple
build/x86_64/target_faultinj_net
```

To run a target binary of your own with random faults:

```sh
LD_PRELOAD=./tools/faultinj/build/x86_64/libfaultinj.so \
LIBFAULTINJ_SEED=0xdeadbeef \
LIBFAULTINJ_PROB=0.001 \
LIBFAULTINJ_MAX_FAULTS=1 \
LIBFAULTINJ_LOG=/tmp/faultinj.log \
./your_target < your_input
```

To reproduce a crash you caught earlier, use the **exact same env
vars + input bytes**:

```sh
LD_PRELOAD=./tools/faultinj/build/x86_64/libfaultinj.so \
LIBFAULTINJ_SEED=0xdeadbeef \
LIBFAULTINJ_PROB=0.001 \
LIBFAULTINJ_MAX_FAULTS=1 \
./your_target < crashing_input
```

That's it. No separate replay tool; the library *is* the replay tool.

* * *

## Cross-arch build

```sh
make -C tools/faultinj ARCH=aarch64
make -C tools/faultinj all-arch    # every supported arch
```

Supported `ARCH=` values: `x86_64`, `aarch64`, `arm`, `mips`,
`mipsel`, `mips64`, `mips64el`, `powerpc`, `powerpc64`,
`powerpc64le`, `riscv64`. You need the matching cross-toolchain
installed (`aarch64-linux-gnu-gcc`, etc.).

* * *

## What gets hooked

The v1 hook set is deliberately small and biased toward the call
classes with the highest bug yield for embedded network daemons.

| Class    | Hooked functions                                | Failure modes                       |
| -------- | ----------------------------------------------- | ----------------------------------- |
| `open`   | `open`, `openat`                                | `-1` + errno                        |
| `read`   | `read`, `pread`                                 | `-1` + errno, `0` (EOF), short read |
| `write`  | `write`, `pwrite`                               | `-1` + errno, short write           |
| `close`  | `close`                                         | `-1` + errno (fd is still released) |
| `recv`   | `recv`, `recvfrom`                              | `-1` + errno, `0` (peer closed), short |
| `send`   | `send`, `sendto`                                | `-1` + errno, short send            |
| `socket` | `socket`                                        | `-1` + errno                        |
| `accept` | `accept`, `accept4`                             | `-1` + errno                        |

The errno values chosen per fault are picked deterministically from a
small per-class pool (see `faultinj_classes.h`).

**Not hooked in v1**:

- `malloc` / `calloc` / `realloc` — overlap with `tools/libdemalloc.c`
  needs a careful design decision still to be made.
- `recvmsg` / `sendmsg` / `readv` / `writev` — vectorised I/O; v2.
- `fopen` / `fread` / `fwrite` / `fclose` — stdio buffering layer
  complicates call-index accounting; v2.
- `bind` / `listen` / `connect` — fire once at daemon init; would
  produce boring "service didn't start" crashes.
- `mmap` / `mprotect` / `munmap` — used internally by `libcov` and
  `libdemalloc`; too risky to fault.
- `signal` / `sigaction` — used internally by `libcov`.
- `fork` / `execve` / `pthread_*` — too stateful.

* * *

## Environment-variable ABI

This is the full configuration surface. Every variable is read once,
at the LD_PRELOAD'd shim's constructor time, and cached.

| Variable                  | Default | Meaning |
| ------------------------- | ------- | ------- |
| `LIBFAULTINJ_SEED`        | unset   | **Required for any injection.** 64-bit unsigned integer (decimal, `0x` hex, `0` octal). Without it the library is loaded but never faults. |
| `LIBFAULTINJ_PROB`        | `0.001` | Per-call fault probability as a float in `[0, 1]`. Parsed with `strtod`. `1.0` faults every eligible call. |
| `LIBFAULTINJ_MAX_FAULTS`  | `1`     | Hard cap on total injections per `execve`. `1` matches the classic single-fault hypothesis. Set higher for more aggressive runs. |
| `LIBFAULTINJ_WARMUP`      | `0`     | Skip the first N calls **per class** before any can be faulted. Lets a daemon's init sequence (config load, listening sockets, etc.) complete before fault injection begins. |
| `LIBFAULTINJ_ENABLE`      | (all)   | Comma-separated allowlist of class names: `open,read,close`. If set, only listed classes are eligible to fault. |
| `LIBFAULTINJ_DISABLE`     | (none)  | Comma-separated denylist, applied **after** `ENABLE`. Example: enable everything except close → `LIBFAULTINJ_DISABLE=close`. |
| `LIBFAULTINJ_SKIP_STDIO`  | `1`     | When `1`, fds `0`, `1`, `2` are never faulted. Set to `0` to allow stdin/stdout/stderr injection. |
| `LIBFAULTINJ_SKIP_FDS`    | (none)  | Comma-separated list of additional fds to never fault. Useful for the harness's own control/data pipes. |
| `LIBFAULTINJ_LOG`         | unset   | Path to an append-mode log file. One line per injection. |
| `LIBFAULTINJ_LOG_FD`      | unset   | Alternative to `LIBFAULTINJ_LOG` when the harness already has an fd open. Takes precedence over `LIBFAULTINJ_LOG`. |

### Class names

`open`, `read`, `write`, `close`, `recv`, `send`, `socket`, `accept`.

Use these exact lowercase strings in `LIBFAULTINJ_ENABLE` and
`LIBFAULTINJ_DISABLE`. Unknown names are silently ignored — typos
won't error out; they just won't match anything.

### Auto-detected fds

Two well-known fork-server fds are added to the skip list
automatically if the env vars are set:

- `LIBFORKSRV_CTLFD` → its integer value is added to the skip list.
- `LIBFORKSRV_STSFD` → its integer value is added to the skip list.

This means you can stack libfaultinj after `libforksrv.so` in
`LD_PRELOAD` without worrying about the protocol pipes getting
corrupted by injected faults.

* * *

## Stacking with other suzzer LD_PRELOADs

The expected ordering, when stacking multiple suzzer shims:

```sh
LD_PRELOAD="path/to/libcov_<st|mt>.so:path/to/libforksrv.so:path/to/libfaultinj.so[:path/to/libdemalloc.so]"
```

- `libcov` first so its priority-101 constructor arms coverage before
  anything else.
- `libforksrv` next so its `__libc_start_main` hook is in place by
  the time the loader hands off.
- `libfaultinj` next. We avoid touching anything `libcov` or
  `libforksrv` uses internally so order between us and them is
  flexible, but this order is the documented one.
- `libdemalloc` last (or omitted in v1) — see the "Not hooked"
  section above re: `malloc`.

* * *

## Log format

When `LIBFAULTINJ_LOG` or `LIBFAULTINJ_LOG_FD` is set, every
injection writes a single line:

```
faultinj seed=0xdeadbeef cls=open idx=3 errno=ENOMEM(12) mode=ret-1
```

Fields:

- `seed`  — `LIBFAULTINJ_SEED` as hex (the value that produced the
  decision).
- `cls`   — class name (lowercase).
- `idx`   — per-class call index (0-based; the Nth call of this
  class in this execve).
- `errno` — symbolic name + numeric value of the injected errno.
- `mode`  — failure mode applied:
  - `ret-1`  — returned `-1` and set errno.
  - `ret0`   — returned `0` (read/recv only, no errno set).
  - `short`  — returned a positive value less than the caller's
    requested count.

The formatter is async-signal-safe; no `printf`, no allocation. The
writer is `syscall(SYS_write, ...)` so it bypasses libfaultinj's own
`write()` hook and any other shim in the chain — no recursion.

* * *

## Examples

### Single-fault, single iteration (the classic case)

```sh
LD_PRELOAD=./build/x86_64/libfaultinj.so \
LIBFAULTINJ_SEED=0x1 \
LIBFAULTINJ_PROB=0.01 \
LIBFAULTINJ_MAX_FAULTS=1 \
./build/x86_64/target_faultinj_simple /tmp
```

### Exhaustive: every eligible call faults

```sh
LD_PRELOAD=./build/x86_64/libfaultinj.so \
LIBFAULTINJ_SEED=0x1 \
LIBFAULTINJ_PROB=1.0 \
LIBFAULTINJ_MAX_FAULTS=99999 \
./build/x86_64/target_faultinj_simple /tmp
```

### Only fault `read()` calls, log to file, after 5-call warmup

```sh
LD_PRELOAD=./build/x86_64/libfaultinj.so \
LIBFAULTINJ_SEED=0xabc \
LIBFAULTINJ_PROB=0.5 \
LIBFAULTINJ_MAX_FAULTS=10 \
LIBFAULTINJ_WARMUP=5 \
LIBFAULTINJ_ENABLE=read \
LIBFAULTINJ_LOG=/tmp/faultinj.log \
./your_daemon
```

### Fault everything except `close()`

```sh
LIBFAULTINJ_DISABLE=close ...
```

### Use with a fork-server (suzzer's libforksrv)

```sh
LD_PRELOAD=./build/x86_64/libcov_st.so:./build/x86_64/libforksrv.so:./build/x86_64/libfaultinj.so \
LIBCOV_PATCHLIST=... \
LIBFORKSRV_CTLFD=198 \
LIBFORKSRV_STSFD=199 \
LIBFAULTINJ_SEED=0xfeed \
LIBFAULTINJ_PROB=0.001 \
LIBFAULTINJ_MAX_FAULTS=1 \
./your_target
```

`LIBFORKSRV_CTLFD` / `LIBFORKSRV_STSFD` get auto-added to the
fd-skip list so faultinj won't corrupt the fork-server pipes.

* * *

## Reproducing a crash

Every crash found while libfaultinj is loaded is fully described by
five pieces of information:

1. the target binary (and its dependencies)
2. the input bytes
3. `LIBFAULTINJ_SEED`
4. `LIBFAULTINJ_PROB`
5. `LIBFAULTINJ_MAX_FAULTS`

(`WARMUP`, `ENABLE`/`DISABLE`, `SKIP_*` matter too, but most
campaigns leave those at defaults.)

If your harness saves all five alongside each crashing input,
reproducing the crash is literally:

```sh
LD_PRELOAD=.../libfaultinj.so \
LIBFAULTINJ_SEED=<saved> \
LIBFAULTINJ_PROB=<saved> \
LIBFAULTINJ_MAX_FAULTS=<saved> \
./target < saved_input
```

* * *

## Threading

All per-class call counters use `__atomic_fetch_add(..., RELAXED)`
so a multithreaded target won't race-corrupt the state. The fault
*decision* for any given `(class, call_idx)` is a pure function of
the seed, so the *set* of injection points is reproducible.

What is **not** currently reproducible is the cross-thread
*interleaving*: if threads A and B both call `read()`, which one
gets `call_idx = 7` depends on scheduling. A per-thread call counter
(strict per-thread reproducibility) is a v2 concern.

* * *

## Files

```
tools/faultinj/
├── README.md                      <-- you are here
├── Design.md                      <-- design rationale + tradeoffs
├── Makefile                       <-- standalone build
├── libfaultinj.c                  <-- the shim
├── faultinj_classes.h             <-- class table + errno/mode pools
├── faultinj_prng.h                <-- deterministic xoshiro256** PRNG
└── test/
    ├── target_faultinj_simple.c   <-- file-I/O exerciser
    ├── target_faultinj_net.c      <-- socket-API exerciser
    └── run_validation_faultinj.sh <-- 10-assertion validation harness
```

Run `make validate` from `tools/faultinj/` to assert all of:

- Inert mode (no seed) = no-LD_PRELOAD baseline.
- Armed mode produces injections.
- Same env = byte-identical output (determinism contract).
- Different seeds = different output (PRNG sanity).
- `MAX_FAULTS=1` caps at exactly one injection.
- `WARMUP=K` blocks all faults when K > total calls.
- `DISABLE=cls` suppresses cls.
- `ENABLE=cls` restricts to cls.
- Log file is parseable.
- `SKIP_STDIO=0` allows fault on fd 1.

* * *

## Limitations

- **Allocation calls aren't hooked yet.** Composing with
  `libdemalloc.so` cleanly is a future design decision.
- **Single execve scope.** Per-class call counters reset only on
  `execve`, not on `fork`. If your target forks and you want each
  child to be a "fresh" fault-injection iteration, the harness
  needs to feed a different `LIBFAULTINJ_SEED` per execve (the
  fork-server pattern) — libfaultinj does not currently re-read
  env vars or a shm channel mid-execve.
- **`recvmsg` / `sendmsg` / `readv` / `writev` not faulted.** Code
  paths that go through them remain immune in v1.
- **Strict per-thread determinism not yet guaranteed** — see
  "Threading" above.

* * *

## License

Apache-2.0 — same as the rest of suzzer.
