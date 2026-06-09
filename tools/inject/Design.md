# suzzer libcov injector -- Design Document

Companion to `tools/inject/README.md`. The README is user-facing
("how do I use this"); this document is implementer-facing ("how does
it work, why is it built this way, what are the failure modes").

It is the source of truth for the injector's design, mechanism,
per-architecture details, and every documented edge case. If you're
about to change a tunable, modify the call mechanism, or add a new
arch backend, read this first.

---

## 1. Goals and motivation

libcov instruments a target by replacing chosen instruction bytes with
a trap encoding, then catching the resulting CPU trap in a signal
handler. To do that it needs to run its `constructor(101)` inside the
target process: parse `/proc/self/maps`, mmap the bitmap, build the
sorted patch table, install the SIGILL handler, and so on.

The simplest way to get libcov's constructor to run is `LD_PRELOAD`:

```sh
LD_PRELOAD=/path/to/libcov.so my_target
```

The dynamic linker loads libcov before main(), runs its constructor,
and we're off to the races. This is what every example in suzzer's
top-level docs uses.

**The problem** -- on real embedded targets you often can't restart
the process you want to instrument:

- A watchdog respawns it if it dies.
- It comes up at boot under PID 1's supervision, and you don't get
  shell access until after boot is well past.
- It's the network service you SSH'd in through; killing it kicks you
  off the device.
- Restarting it loses live state (in-flight connections, learned
  routes, sensor calibration data) that's hard to reproduce.

**Solution**: attach to the *running* process and inject libcov.so
post-hoc. The constructor still runs (dlopen handles that), produces
the same end-state as the `LD_PRELOAD` path, and the target keeps
serving traffic with coverage now flowing into the shm bitmap.

This document describes how that injection is done.

---

## 2. Trust boundary

Injection is a privileged operation. The injector needs to:

- Read `/proc/<pid>/maps` and `/proc/<pid>/exe`.
- Open the target's libc on the host filesystem (or via
  `/proc/<pid>/root/`).
- `PTRACE_ATTACH` the target (or, for the procmem variant, write to
  `/proc/<pid>/mem`).
- `PTRACE_SETREGSET` and `PTRACE_CONT` the target through remote
  calls.

The OS gates these operations with the standard ptrace permission
model:

| Condition | Result |
|---|---|
| Injector is root (or has `CAP_SYS_PTRACE`) | All operations permitted |
| Injector and target are the same UID, `/proc/sys/kernel/yama/ptrace_scope` = 0 | All operations permitted |
| `ptrace_scope` = 1 (default on Ubuntu/Debian) | Only the direct parent of the target can attach; other same-UID processes need `prctl(PR_SET_PTRACER)` from the target |
| `ptrace_scope` = 2 | Only `CAP_SYS_PTRACE` can attach |
| `ptrace_scope` = 3 | Nobody can attach (sysctl-locked) |

Plus the **one-tracer rule**: if gdb / strace / another tool is
already attached, `PTRACE_ATTACH` fails with `EPERM`. The injector's
phase-7 `inject_procmem` variant works around this by using
`/proc/<pid>/mem` writes and `SIGSTOP`/`SIGCONT` for synchronisation
without becoming the tracer.

The injector deliberately does NOT try to bypass any of these
controls. If the kernel says you can't, you can't.

---

## 3. High-level architecture

```
                              ┌───────────────────────────────┐
                              │   YOU                          │
                              │     pgrep <target>             │
                              │     inject_ptrace -P ... <pid> │
                              │                  libcov.so     │
                              └─────────────┬─────────────────┘
                                            │
                              ┌─────────────▼─────────────────┐
                              │ inject_ptrace                  │
                              │                                │
                              │ 1. PTRACE_ATTACH               │
                              │ 2. Parse /proc/<pid>/maps      │
                              │ 3. ELF-resolve setenv,         │
                              │    dlopen,                     │
                              │    dlerror in target libc      │
                              │ 4. Find syscall insn in libc   │
                              │ 5. Remote mmap (single-step    │
                              │    through that syscall insn)  │
                              │    -> scratch page in target   │
                              │ 6. Stage env strings + libpath │
                              │    in scratch                  │
                              │ 7. For each env var:           │
                              │       remote-call setenv(...)  │
                              │ 8. remote-call dlopen(...)     │
                              │ 9. Restore saved regs;         │
                              │    PTRACE_DETACH               │
                              │                                │
                              │ Target resumes from exact      │
                              │ pre-inject PC with libcov      │
                              │ fully initialised.             │
                              └────────────────────────────────┘

           Inside the target, after detach:
           ┌─────────────────────────────────────────────────────────────┐
           │ ELF interpreter (ld.so) resolved the dlopen call as a       │
           │ side-effect; libcov.so is now mapped + its constructor      │
           │ has run (parsed patchlist, armed every site, installed      │
           │ SIGILL handler). Bitmap is open and being written to.       │
           │                                                              │
           │ The original execution context (rsp, all callee-saved       │
           │ regs, signal mask, fs_base, gs_base) is exactly what it     │
           │ was at PTRACE_ATTACH time.                                  │
           └─────────────────────────────────────────────────────────────┘
```

The injector binary is a one-shot: it does the above sequence and
exits. State persistence is the target's job (libcov's mmap'd regions,
patched code, installed handler all survive the injector's exit
because they live in the target's address space).

---

## 4. The trap-on-return convention

This is the single design choice that makes the per-arch backend
table tiny.

### 4.1 Problem

To run a function call in a remote process via ptrace we need to:

1. Set up the target's registers so PC = function, args in arg regs.
2. Resume the target.
3. Know when the call returned.
4. Read the return value.

The hard part is (3): how does the injector know the function
finished? Three classical options:

- **Software breakpoint at the return PC**: requires us to know
  *where* the function will return to. For `dlopen` deep inside
  glibc's loader, that's hard.
- **Insert a SIGTRAP after the function via shellcode**: requires
  per-arch shellcode (a `call func; int3` or `bl func; brk #0`
  sequence). Adds bytes to manage per arch.
- **Hijack the return address to point at unmapped memory**: every
  arch already faults on instruction fetch from an unmapped page;
  the kernel delivers `SIGSEGV` synchronously to the faulting thread;
  `waitpid` in the injector catches it.

We chose option 3, the **return-trap sentinel**. Concretely:

- Pick a guaranteed-unmapped page (`INJECT_TRAP_PC_DEFAULT = 0xdead0000`,
  validated against `/proc/<pid>/maps` at attach time; if it ever
  collides, scan down by page).
- Before resuming, plant that sentinel as the function's "return
  address" in whatever register/stack slot the arch uses for it.
- Resume.
- The function's `RET` / `ret` / `bx lr` / `blr` transfers to the
  sentinel.
- The CPU faults on instruction fetch; kernel sends `SIGSEGV` with
  `si_addr = sentinel`; injector's `waitpid` returns.
- Injector reads the return-value register (`rax`, `x0`, `r3`, etc.)
  and proceeds.

This eliminates per-arch shellcode for the ptrace variant. The only
per-arch logic is "where do I put the return address?" -- on the
stack for x86_64, in `x30` for aarch64, in `lr` for arm/ppc/riscv.
That's a `setup_call()` callback per arch and a `stack_return_addr`
boolean.

### 4.2 Why a sentinel and not 0x0

Userspace address 0 has special meaning for the kernel (NULL pointer
check elision, MAP_FIXED special-case, etc.). Using 0 as the sentinel
would still SIGSEGV but would muddle log output and could trip kernel
hardening. `0xdead0000` is a recognisable magic number that's clearly
"this is the injector's sentinel", and it's well outside any plausible
userspace mapping on every Linux arch we care about (canonical low
addresses on aarch64 / x86_64 stop at ~0x500000 for binaries).

### 4.3 Sentinel collision handling

`inject_pick_trap_pc()` walks `/proc/<pid>/maps` and checks whether
the default sentinel is inside any mapping. If yes (it never is in
practice, but we don't want a silent infinite loop), it walks down by
page size until it finds an unmapped address. Bails after 1024
attempts (would mean the target's address space is wedged enough that
injection is moot).

### 4.4 Sentinel verification on the return

When the SIGSEGV fires we read `siginfo_t.si_addr` via
`PTRACE_GETSIGINFO` and check it matches `trap_pc`. If it doesn't,
the function faulted INTERNALLY (not at our trap) -- typically because
we mis-set its arguments or registers, or because the function itself
hit a bug in some failure path. The injector logs the actual
fault address + PC for diagnosis and aborts the injection.

---

## 5. Remote syscall via single-step

The injector needs to run one remote `mmap(NULL, 4096, PROT_R|W,
MAP_PRIVATE|ANON, -1, 0)` to allocate a scratch page for staging env
strings and the libpath. This uses a slightly different mechanism
than function calls: we **single-step through a `syscall` instruction
that already exists in libc** (no code injection at all).

### 5.1 Finding the syscall instruction

`arch->find_syscall_insn()` scans the first 64 KB of libc's `.text`
mapping for the arch's syscall-class encoding:

| Arch       | Encoding           | Bytes              |
|------------|--------------------|--------------------|
| x86_64     | `SYSCALL`          | `0F 05`            |
| aarch64    | `SVC #0`           | `01 00 00 D4` (LE) |
| arm        | `SVC #0` / `swi 0` | `00 00 00 EF` (ARM mode) |
| mips       | `SYSCALL`          | `0C 00 00 00` (LE) |
| ppc        | `sc`               | `02 00 00 44` (LE) |
| riscv64    | `ECALL`            | `73 00 00 00`      |

Every libc has dozens of these in its first 64 KB (one per syscall
wrapper). We never modify the instruction; we just point the target's
PC at it.

### 5.2 Single-step semantics

`PTRACE_SINGLESTEP` runs exactly one instruction in the target and
delivers `SIGTRAP`. For the syscall path:

1. `setup_syscall()` writes the syscall number into the syscall-NR
   register, args into arg registers, PC into the syscall insn
   address.
2. `PTRACE_SETREGSET` commits.
3. `PTRACE_SINGLESTEP` runs the SYSCALL/SVC/etc; the kernel handles
   the syscall in its entirety; the next instruction after the syscall
   would be whatever's there in libc, but the kernel posts SIGTRAP
   before it executes.
4. `waitpid` catches the SIGTRAP.
5. `PTRACE_GETREGSET` reads the regs; the return value is in the
   syscall-return register (same as the function-return on most
   arches; rax/x0/r3).

The single-step convention works for syscalls because syscalls are
atomic from the user-program's perspective: the SYSCALL instruction
runs, the kernel does whatever, then control returns to user code.
The single-step "interrupt after the next user instruction" semantic
fires after that whole atomic block.

### 5.3 Why single-step the syscall instead of return-trap mmap?

We could in principle make a function call to libc's `mmap` wrapper
via the return-trap mechanism. But:

- libc's mmap wrapper does its own argument validation, may set
  errno, may need `__libc_lock` (a mutex). For a single allocation
  we'd be paying for that complexity.
- The raw syscall has a well-defined, arch-stable ABI. No glibc
  internals.
- Single-step is one ptrace round-trip; the return-trap is two
  (SETREGSET + CONT + waitpid).

So mmap uses single-step; subsequent setenv + dlopen calls use the
return-trap convention.

---

## 6. End-to-end ptrace flow

This expands the diagram in §3 with concrete syscalls and the
relevant arch backend hooks.

### 6.1 Attach

```
ptrace(PTRACE_ATTACH, pid, 0, 0)
waitpid(pid, &status, __WALL)         // wait for group-stop notification
proc_target_machine(pid)              // read /proc/<pid>/exe ELF e_machine
arch = inject_arch_select(e_machine)  // pick the per-arch vtable
if (!arch->supported) bail with clear msg
ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &regs_saved)
proc_maps_load(pid)                   // parse /proc/<pid>/maps
trap_pc = inject_pick_trap_pc(maps)   // 0xdead0000 default; check unmapped
```

### 6.2 Symbol resolution

```
setenv  = resolve_lib_symbol(pid, maps, "libc.so*", "setenv")
dlopen  = resolve_dlopen(pid, maps, &is_libc_mode)
            // 1. libc:dlopen           (glibc 2.34+, musl)
            // 2. libc:__libc_dlopen_mode (older glibc) -- sets
            //    is_libc_mode=1; caller ORs 0x80000000 into flags
            // 3. libdl:dlopen          (only if libdl already loaded)
dlerror = resolve_lib_symbol(pid, maps, "libc.so*", "dlerror")  // optional

// Locate syscall instruction in libc for the remote-mmap step
libc_buf = target_read(pid, libc_base, 64K)
off      = arch->find_syscall_insn(libc_buf, 64K)
syscall_pc = libc_base + off
```

### 6.3 Scratch allocation (remote mmap, single-step)

```
regs = regs_saved
arch->setup_syscall(&regs, syscall_pc, NR_mmap,
                    [0, 4096, PROT_R|W, MAP_PRIVATE|ANON, -1, 0])
ptrace(PTRACE_SETREGSET, ...)
ptrace(PTRACE_SINGLESTEP, ...) ; waitpid -> SIGTRAP
ptrace(PTRACE_GETREGSET, ...)
scratch = arch->get_retval(&regs)
```

If `(long)scratch < 0 && (long)scratch > -4096`, the syscall returned
a negative errno; we bail. Otherwise `scratch` is the address of a
4 KB anonymous RW page in the target.

### 6.4 Env staging

We split the scratch page in half: low end holds the libpath string
(staged when dlopen runs); high end is a bump arena for env "KEY\0VAL\0"
pairs. The split avoids a collision between the two staging paths.

For each `-e KEY=VAL`:

```
k_addr = target_write(pid, scratch + cursor, "KEY\0")  // and bump cursor
v_addr = target_write(pid, scratch + cursor, "VAL\0")  // and bump cursor
inject_call(setenv, [k_addr, v_addr, 1])  -> returns 0 on success
```

### 6.5 dlopen

```
p_addr = target_write(pid, scratch + 0, "/path/to/libcov_st.so\0")
mode = RTLD_NOW
if (is_libc_mode) mode |= 0x80000000   // __RTLD_DLOPEN
inject_call(dlopen, [p_addr, mode]) -> returns the dlopen handle
if handle == 0:
    inject_dlerror(...)  // best-effort diagnostic
    bail
```

dlopen running in the target context invokes the dynamic linker,
which:

1. mmaps `libcov_st.so` into the target's address space.
2. Resolves its dynamic relocations.
3. Calls its constructor (priority 101 -- libcov_init).
4. Returns a handle.

libcov_init reads its env vars (which we just set), arms patches,
installs the SIGILL handler. All inside the target's process context.

### 6.6 Detach

```
ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &regs_saved)   // exact pre-inject state
ptrace(PTRACE_DETACH, pid, 0, 0)
proc_maps_free()
```

Target resumes from exactly where it was when we attached. Because
all our remote calls (a) ran with a fresh copy of `regs_saved` and
(b) wrote only to the scratch page we allocated, the target's stack
and heap are unmodified by our injection. The single 4 KB scratch
page stays mapped (we don't munmap -- libcov references the env
strings via getenv pointers; munmap'ing would invalidate them).

---

## 7. inject_call deep-dive (the critical path)

```c
int inject_call(struct inject_session *s, uintptr_t func,
                const uintptr_t *args, int n_args, uintptr_t *retval)
{
    /* 1. Start from a fresh snapshot of saved regs. We DO NOT carry
     * state from previous calls -- if call N polluted some register,
     * call N+1 gets a clean baseline. */
    struct inject_regs regs = s->regs_saved;

    /* 2. Arch primes regs for func(args...) with return going to
     * trap_pc. For x86_64, ALSO reserves a stack slot for the
     * return address (we still need to WRITE trap_pc to that slot
     * below). For aarch64 etc., writes trap_pc to LR directly. */
    s->arch->setup_call(&regs, func, s->trap_pc, args, n_args);

    /* 3. If the arch is stack-based, write trap_pc to the freshly-
     * reserved stack slot. Done via process_vm_writev so we don't
     * have to ptrace POKEDATA. */
    if (s->arch->stack_return_addr) {
        uintptr_t sp = s->arch->get_sp(&regs);
        target_write(s->pid, sp, &s->trap_pc, sizeof s->trap_pc);
    }

    /* 4. Commit regs + run. */
    pt_setregs(s->pid, &regs);
    int status = pt_cont_and_wait(s->pid, 0);

    /* 5. Stop should be SIGSEGV at trap_pc. */
    if (WSTOPSIG(status) != SIGSEGV) bail;
    siginfo_t si;
    ptrace(PTRACE_GETSIGINFO, ...);
    if (si.si_addr != s->trap_pc) bail with diagnostic;

    /* 6. Read return value. */
    pt_getregs(s->pid, &regs);
    *retval = s->arch->get_retval(&regs);
    return 0;
}
```

### 7.1 Bug-fixes in this path (documented because they're easy to lose)

**x86_64 stack alignment.** SysV AMD64 ABI requires `rsp % 16 == 8`
on function entry (i.e. just after the 8-byte return address has
been pushed). The target's saved `rsp` at `PTRACE_ATTACH` can have
ANY alignment because the target was stopped mid-execution.
`x86_64_setup_call()` rounds `rsp` DOWN to a 16-byte boundary before
reserving the 8-byte return slot:

```c
r->rsp &= ~(uint64_t)0xf;
r->rsp -= 8;
```

Without this, glibc internals using `movaps` on stack locals (which
setenv does via the internal `__libc_lock`) fault on misalignment.
Symptom: a spurious SIGSEGV inside setenv that the injector reports
as "trap_pc mismatch" with `si_addr` somewhere in the TLS error
path (typically a small number like 0xa where `*errno` is being
written via `fs:(%rax)` with rax loaded from a misaligned stack
local).

**x86_64 syscall-restart suppression.** When `PTRACE_ATTACH` catches
a thread blocked in a restartable syscall (`read()` on stdin etc.),
the kernel queues a "restart this syscall on resume" action. On
`PTRACE_CONT` the kernel's signal-return path checks
`TS_RESTART_SYSCALL` and, if set, decrements RIP by 2 (the size of
the SYSCALL instruction) so the syscall re-runs.

That's wrong for us: we've redirected RIP to the entry of our target
function and we DON'T want the kernel to back it up by 2 (which
would land mid-padding before the function and trigger SIGILL when
the CPU decodes garbage).

The kernel inspects `orig_rax` to decide whether a syscall is
pending. `x86_64_setup_call()` sets `orig_rax = (uint64_t)-1`
before commit, telling the kernel "no syscall pending"; the kernel
then leaves RIP alone.

Symptom without this fix: SIGILL at `func - 2` on the FIRST remote
call (subsequent calls work because the syscall-restart state is
cleared after the first signal delivery).

Both fixes are inside `arch_inject_x86_64.c` with full WHY comments
next to them. Don't lift them without re-reading the explanation.

### 7.2 Per-arch differences

| Arch    | Return-addr mechanism                  | Notes                          |
|---------|---------------------------------------|--------------------------------|
| x86_64  | Reserve stack slot, write trap_pc there | Stack alignment + orig_rax fix |
| aarch64 | LR (x30) = trap_pc                   | No stack write needed          |
| arm     | LR (r14) = trap_pc                   | TODO: ARM/Thumb mode dispatch  |
| mips/64 | $31 (ra) = trap_pc                   | TODO: branch delay slot care   |
| ppc/64  | LR = trap_pc                          | TODO: ELFv1 function descriptors |
| riscv64 | ra (x1) = trap_pc                     | TODO: 4-byte trap_pc alignment |

---

## 8. Per-arch backend interface

`arch_inject.h`:

```c
struct inject_arch {
    const char *name;          // "x86_64", "aarch64", ...
    int         elf_machine;   // EM_X86_64 etc.
    int         supported;     // 1 = full impl; 0 = build-only stub

    /* ptrace-variant ops */
    void (*setup_call)(struct inject_regs *,
                       uintptr_t func, uintptr_t trap_pc,
                       const uintptr_t *args, int n_args);
    void (*setup_syscall)(struct inject_regs *,
                          uintptr_t syscall_pc,
                          long nr, const long *args, int n_args);
    uintptr_t (*get_retval)(const struct inject_regs *);
    uintptr_t (*get_pc)(const struct inject_regs *);
    void      (*set_pc)(struct inject_regs *, uintptr_t pc);
    long      (*find_syscall_insn)(const void *buf, size_t len);

    int       stack_return_addr;   // 1 if RET pops from stack
    uintptr_t (*get_sp)(const struct inject_regs *);

    /* procmem-variant ops (phase 7, NULL otherwise) */
    const uint8_t *(*pm_shellcode)(size_t *out_len);
    size_t (*pm_build_sigframe)(void *buf, size_t buflen,
                                const struct inject_regs *target_regs,
                                uintptr_t shellcode_entry);
};
```

### 8.1 Register state opacity

`struct inject_regs { uint8_t raw[1024]; size_t len; }` is opaque to
common code; only backends interpret it. Each backend defines its
own per-arch struct (e.g. `x86_64_user_regs`, `aarch64_user_pt_regs`)
that mirrors the kernel's `NT_PRSTATUS` regset layout for that arch.

The definitions are **inlined into each `arch_inject_<arch>.c`** rather
than pulled from `<sys/user.h>`. Why: `<sys/user.h>` only exposes the
HOST arch's regset; cross-compiling the aarch64 backend on an x86_64
host wouldn't see `struct user_pt_regs`. The injector ships every
backend in every binary (the runtime selector picks one), so each
backend's regset definition must work on every host.

`sizeof(raw) = 1024` is generous for every backend (the largest
observed is aarch64's ~272 bytes including extras).

### 8.2 Adding a new backend

To turn a stub into a full backend:

1. In `arch_inject_<arch>.c`:
   - Define the per-arch `struct <arch>_user_regs` mirroring the
     kernel's NT_PRSTATUS layout.
   - Implement `setup_call`, `setup_syscall`, `get_retval`, `get_pc`,
     `set_pc`, `find_syscall_insn`.
   - If the arch is stack-based (only x86_64 today), set
     `stack_return_addr = 1` and implement `get_sp`.
   - Flip `supported = 1`.
2. Update `syscall_nr_mmap()` in `inject_common.c` with the arch's
   `__NR_mmap` number.
3. Re-run `tools/inject/test/run_validation_inject.sh` (native) or
   the cross matrix script.

Look at `arch_inject_x86_64.c` and `arch_inject_aarch64.c` for the
shape. The stubs have detailed per-arch implementation notes in their
top comments.

---

## 9. /proc parsing and ELF symbol resolution

`inject_common.c` implements a small `/proc/<pid>/maps` parser and a
linear-scan ELF dynsym lookup. Both are deliberately minimal.

### 9.1 /proc/<pid>/maps

```c
struct proc_map { uintptr_t start, end, file_off; char perms[5]; char path[PATH_MAX]; };
struct proc_map_table { struct proc_map *m; size_t n, cap; };
```

`proc_maps_load(pid, t)` parses every line; `proc_maps_find_lib(t,
"libc.so*")` returns the first mapping whose basename matches the
fnmatch glob, with the executable mapping preferred so we land on
`.text` not `.data`.

### 9.2 ELF dynsym

`elf_lookup_symbol(path, name, &vaddr)`:

1. mmap the ELF.
2. Walk `PT_DYNAMIC` looking for `DT_SYMTAB`, `DT_STRTAB`,
   `DT_GNU_HASH` / `DT_HASH`.
3. Use the hash to find `symcnt`; for libs without any hash (rare),
   walk until we see an empty sentinel entry.
4. Linear scan: for each symbol, if its name matches and it's
   defined (`st_shndx != SHN_UNDEF`) and it's `STT_FUNC` /
   `STT_GNU_IFUNC` / `STT_OBJECT`, record its `st_value`.
5. Return the LAST match (matches the dynamic linker's
   highest-version-wins behaviour for unversioned external refs).

Runtime address = `load_base + st_value` where `load_base` =
`map.start - (map.file_off - first_PT_LOAD.p_offset) - first_PT_LOAD.p_vaddr`.

### 9.3 Why linear scan instead of hash lookup

Hash lookup with `DT_GNU_HASH` is fast but adds ~100 lines of code
to implement correctly across glibc/musl/uClibc. We do maybe 4
lookups per injection (setenv, dlopen, dlerror, optional fallbacks).
At ~5000 dynsyms per libc, that's 20000 strcmps per injection -- a
few milliseconds. Not worth the complexity tradeoff for a one-shot
tool.

If the injector becomes a long-running service in some future use,
revisit.

### 9.4 dlopen fallback chain

`resolve_dlopen` tries, in order:

1. `libc.so*:dlopen`        (glibc >= 2.34, musl, uClibc-ng)
2. `libc.so*:__libc_dlopen_mode` (older glibc; flag bit `0x80000000`
                                  required in mode arg, see
                                  `inject_dlopen` in `inject_common.c`)
3. `libdl.so*:dlopen`       (only if libdl is already loaded)

The chicken-and-egg case (libdl needed but not loaded) is documented
and refused with a clear message. We can't dlopen libdl without
having dlopen first; the only general solution is to ask the user to
link the target with `-ldl` (or use a newer glibc).

### 9.5 Symbol versioning

We deliberately do NOT implement full GNU symbol versioning
(`DT_VERSYM` / `DT_VERDEF` / `DT_VERNEED`). For the symbols we care
about (setenv, dlopen) the highest version is what the dynamic
linker would pick for an unversioned external reference, and our
"last match wins" linear scan approximates that closely enough.

Theoretically wrong on libraries that ship multiple incompatible
versions of `dlopen`, but no production libc does that.

---

## 10. Target memory I/O

`target_write` and `target_read` use `process_vm_writev` /
`process_vm_readv` (Linux 3.2+). Single syscall per transfer, no
ptrace word-by-word dance. Suitable for staging strings up to page-
size; for larger transfers (would need on the procmem variant for
shellcode) we'd split into multiple iovecs.

Failure modes:
- `EFAULT`: remote address isn't mapped or isn't writable in target.
- `EPERM`: target died, or trust boundary changed mid-call.
- `ESRCH`: target gone.

The injector logs the errno and bails. No retry logic; one-shot semantic.

---

## 11. Env-var staging

libcov reads its config (`LIBCOV_PATCHLIST`, `LIBCOV_SHM_PATH`,
`LIBCOV_MODE`, `LIBCOV_LOG`, ...) via `getenv()` in its constructor.
For the constructor to see our values, we need to populate the
target's environ BEFORE dlopen runs.

We do this by calling `setenv()` in the target via the remote call
mechanism. setenv takes care of:

- Allocating the "KEY=VAL" string via the target's malloc.
- Inserting it into `__environ`.
- Re-syncing the `environ` pointer if the array got relocated.

Alternatives considered:

- **Modify environ array directly via /proc/<pid>/mem**: works but
  is fragile -- glibc may relocate environ on first setenv, getenv
  walks the old __environ pointer, etc. The setenv-in-target
  approach delegates all that to glibc.
- **dlopen with a special env-init hook**: would require libcov to
  expose such a hook, violating the "standalone injector, don't
  touch libcov" constraint.
- **dlopen and let libcov read via /proc/<pid>/environ**: would
  require modifying libcov.

setenv-in-target won. Trade-off: requires setenv to resolve in
target libc (essentially always true on glibc/musl/uClibc; never a
problem in practice).

### 11.1 Scratch arena layout

The 4 KB scratch page is split:

```
[0 ..  scratch_len/2)  : low end -- libpath string for dlopen
[scratch_len/2 .. end) : high end -- bump arena for "KEY\0VAL\0" pairs
```

The split avoids the path string and env strings colliding when
written by `inject_dlopen` and `inject_setenv` independently. Per-
session bump cursor (function-local `static size_t env_cursor`)
tracks the high-end position across multiple `inject_setenv` calls.

For typical libcov configs (5-6 env vars, ~20-40 chars each, plus a
60-80 char libpath) 4 KB is ample. `--scratch-size` raises it for
exotic cases (lots of `-e` or unusually long paths).

---

## 12. Procmem variant (phase 7 stub)

`inject_procmem.c` is currently a stub: it parses CLI args and exits
with ENOSYS. The full design lives in the file's top comment; this
section gives the architectural summary.

### 12.1 Why it exists

The ptrace variant becomes unavailable when:

- Another tracer is already attached (one-tracer rule). Common in
  production where ops have gdb/strace sessions running.
- The target inspects `/proc/<pid>/status` and refuses to run if
  `TracerPid != 0` (anti-debug).

The procmem variant achieves the same end-state without
`PTRACE_ATTACH`.

### 12.2 Mechanism (planned)

1. `kill(pid, SIGSTOP)`; poll `/proc/<pid>/status` until State: T.
2. Read `/proc/<pid>/syscall` for current PC + SP (when stopped
   inside a syscall, this gives us the full register snapshot we
   need).
3. Open `/proc/<pid>/mem` O_RDWR. Same trust boundary as ptrace
   (CAP_SYS_PTRACE or same UID + Yama allows).
4. Build per-arch shellcode that calls setenv + dlopen then
   sigreturns back to the saved registers. Hand-assembled per arch
   into `.S` files, linked as binary blobs via `ld -r -b binary`.
5. Build a complete rt_sigframe on the target's stack containing
   the original register state + a PC pointing at our shellcode
   entry.
6. Patch a few bytes at the current PC with a `mov rax, NR_rt_sigreturn;
   syscall` (or arch equivalent) that consumes our forged frame.
7. `kill(pid, SIGCONT)`. Target executes our patched instructions
   which sigreturn into our shellcode; shellcode does the work and
   sigreturns to the original state.

### 12.3 What's needed to land it

The `pm_shellcode` and `pm_build_sigframe` slots in the arch vtable
are reserved. Implementation order (in the file's top comment):

- Step A: x86_64 shellcode + sigframe.
- Step B: aarch64.
- Step C: validation parity with `inject_ptrace` via the existing
  harness (just add a second `INJ` env knob).

Until then, the binary builds, the CLI is wired up, but the actual
runtime exits 64 with a clear message.

---

## 13. Validation strategy

Two scripts under `tools/inject/test/`:

### 13.1 `run_validation_inject.sh` (native)

4 assertions per (injector, threading) pair = 8 native cells today
(only inject_ptrace × {st, mt}). Each cell:

- **A. Determinism**: feed identical inputs twice into two separate
  injected target processes; cumulative bitmaps must be byte-identical.
  Catches non-determinism in the injection (e.g. if our remote calls
  somehow polluted target state differently on each run).
- **B. Differentiation**: feed two different input sets; bitmaps
  must differ. Uses **leapfrog** mode (not oneshot) because oneshot
  bitmaps with a sparse patch set (MT's 13 patches vs ST's 35) can
  easily hit the same edge set and look identical even when paths
  through the patched code are different. Leapfrog accumulates hit
  counts which differ across input sets even when the touched-edge
  set is identical.
- **C. Leapfrog**: under MODE=leapfrog, max byte in the bitmap must
  be >= 2 (i.e. some edge fired twice; loop_sum's inner branch
  guarantees this).
- **D. Output unchanged**: target's stdout under injection (modulo
  the PID-print line) must match the baseline un-injected stdout for
  the same inputs. This is the corruption canary: any injection bug
  that smashes target registers, stack, or fs_base will diverge the
  output.

The target is `target_inject_loop` -- a long-running stdin-driven
program with the same branch graph as libcov's `target_simple`. The
script feeds inputs via a fifo, gives libcov ~200 ms to record (no
boundary mode here, so no explicit sync point), then snapshots the
bitmap.

Both ST and MT runs use SEPARATE patch lists (`--threading st` vs
`--threading mt`) because libcov enforces the LCV3 threading hint at
init. Documented + handled by the script.

### 13.2 `run_validation_inject_cross.sh`

Builds every backend (11 ARCH cells) and runs the native validation
for x86_64. Other arches are BUILD_ONLY:

- `aarch64` is full-backend-supported but qemu-user's ptrace is too
  weak for our use case; runtime validation needs real ARM hardware.
- The other 9 are stub backends.

Final report: `FULL_PASS=1 BUILD_ONLY=10 FAIL=0`.

### 13.3 Why no boundary-mode tests

The injector is orthogonal to libcov's boundary mechanism: once
libcov is loaded, boundary mode works the same whether libcov got
loaded via LD_PRELOAD or via injection. libcov's own
`run_validation_boundary.sh` covers boundary mode; we don't duplicate
those assertions here.

---

## 14. File layout

```
tools/inject/
  Makefile                       -- standalone build (own ARCH map; no
                                    coupling to top-level Makefile)
  README.md                      -- user-facing
  Design.md                      -- this document

  inject_ptrace.c                -- main() for the ptrace variant
  inject_procmem.c               -- main() for the procmem variant (stub)

  inject_common.h                -- shared types + public API
  inject_common.c                -- /proc parser, ELF symbol resolver,
                                    target memory I/O, ptrace wrappers,
                                    inject_session lifecycle, remote
                                    call/syscall orchestration, env
                                    staging, dlopen/dlerror wrappers

  arch_inject.h                  -- per-arch backend vtable
  arch_inject_x86_64.c           -- full backend
  arch_inject_aarch64.c          -- full backend
  arch_inject_arm.c              -- stub
  arch_inject_mips.c             -- stub
  arch_inject_mips64.c           -- stub
  arch_inject_powerpc.c          -- stub
  arch_inject_powerpc64.c        -- stub
  arch_inject_riscv64.c          -- stub

  test/
    target_inject_loop.c         -- long-running test target
    run_validation_inject.sh     -- 8-assertion native validation
    run_validation_inject_cross.sh
                                 -- cross-build matrix + native run
```

Build output:

```
tools/inject/build/<arch>/
    inject_ptrace
    inject_procmem
    target_inject_loop            (only after `make test`)
    *.o
```

Disjoint from `build/<arch>/` at the project root so libcov's build
and the injector's build never collide.

---

## 15. What this doesn't do

Out of scope, documented to set expectations:

1. **libdemalloc injection**: only libcov is in scope right now.
   libdemalloc would add a different staging path (replacing
   malloc/free hooks); planned for a follow-up.
2. **Static target binaries**: no dynamic linker, can't dlopen.
   Injector detects (no `ld-linux*` in maps) and refuses.
3. **Cross-arch injection** (e.g. running an x86_64 injector against
   an aarch64 target via qemu-user): would need a non-native ptrace
   layer + per-arch backends for the injector's host as well as the
   target's arch. Not implemented; would be a major refactor.
4. **Persistent / re-attach state**: each `inject_ptrace` invocation
   is one-shot. Re-injecting the same libcov is a no-op (dlopen
   refcounts); to reconfigure you'd need to restart the target (or
   wait for a hypothetical `inject_eject` follow-up).
5. **Process tree injection**: injects into one PID. To instrument
   a fork-heavy daemon, inject into each worker individually, or
   inject into the parent before the forks happen (libcov mappings
   propagate via CoW).
6. **JIT / self-modifying target code**: out of scope for the
   injector (and out of scope for libcov itself; documented in
   libcov's main Design.md).

---

## 16. Backlog (notes for future work)

- **Phase 7: procmem variant runtime.** Hand-assembled x86_64 +
  aarch64 shellcodes; sigframe builders. Most of the work is in
  understanding the kernel's rt_sigframe layout per-arch.
- **Stub arch backends.** Implementation notes in each
  `arch_inject_<arch>.c` top comment. arm + Thumb dispatch + MIPS
  branch-delay-slot care + PPC64 ELFv1 function descriptors are the
  three non-trivial parts.
- **Cross-arch testing via qemu-user.** Investigate which arches'
  qemu-user ptrace emulation is good enough; document the matrix.
  Currently `aarch64` is the leading candidate.
- **libdemalloc injection.** Different staging path (malloc/free
  hooks); would warrant a separate `inject_libdemalloc.c` or a
  generalisation of `inject_ptrace.c` to take any .so + env tuple.
- **Re-injection / library unload.** dlclose-from-target.
- **Per-thread injection synchronisation.** For very large MT targets
  where libcov_mt's bringup needs to happen at a particular point in
  every worker thread, not just the one we attached. Not currently
  needed because libcov_mt's atomics + spinlocks handle concurrent
  thread state correctly.

---

## 17. Glossary

| Term | Meaning |
|---|---|
| Return-trap sentinel | The unmapped address (default `0xdead0000`) we plant as the fake return PC for remote function calls. SIGSEGV-at-sentinel signals "function done". |
| Scratch page | The single 4 KB RW-only mmap'd page in target memory used to stage env strings + libpath string. |
| Stack-based return / LR-based return | x86_64 is stack-based (RET pops); aarch64/arm/ppc/riscv are LR-based (RET branches through LR/x30/r14/lr/ra). Backend vtable's `stack_return_addr` distinguishes. |
| LCV3 threading hint | libcov's per-patchlist annotation (`--threading st|mt` in gen_patchlist) that libcov enforces at init. Wrong type -> libcov refuses + stays inert. |
| Procmem variant | The ptrace-LESS injector (phase 7). Uses SIGSTOP + /proc/<pid>/mem writes + sigreturn-frame forging instead of PTRACE_ATTACH. |
| Trap-on-return convention | Our remote-call mechanism. See §4. |
| Single-step-syscall convention | Our remote-syscall mechanism. See §5. |
| `__libc_dlopen_mode` | Older-glibc symbol for dlopen-from-inside-libc. Takes a mode flag that requires the `__RTLD_DLOPEN` bit (0x80000000) to be set. The injector handles this transparently when this fallback is selected. |
