# Ghidra Jython ports of the suzzer generators

These are **Ghidra Jython 2.7** ports of the rizin-based tools one directory
up. They generate the same sidecar files from the program currently open in
Ghidra, with **no rizin / rzpipe dependency**:

| Ghidra script (here)        | rizin original (`tools/`)        | Produces |
|-----------------------------|----------------------------------|----------|
| `gen_patchlist_ghidra.py`   | `gen_patchlist.py`               | LCV3 patch list |
| `gen_boundary_ghidra.py`    | `gen_boundary.py`                | LCVB1 boundary sidecar |
| `ghidra_resolve.py`         | `rz_resolve.py`                  | shared name/address resolver (imported, not run) |

The **output is byte-for-byte the same wire format** as the rizin tools
(`src/patchlist_format.h`, `src/boundary.h`, `docs/FORMATS.md`). Everything
that decides *which* bytes get written — per-arch site selection
(terminator / entry), the MT single-copy-atomic filtering, the
`--root`/`--cutoff`/`--max-depth` call-graph slice, the overlap check and
the LCV3/LCVB packing — is ported unchanged. Only the data source differs:
the rizin commands (`aaa`, `aflj`, `afbj`, `pdj`, `afij @@F`, `ij`, `isj`,
`iSj`) are replaced by the Ghidra Program API on the already-analysed program.

The rizin versions are kept and remain the reference implementation.

## Installing Jython (Ghidra 11.4+ / 12.x)

These are **Jython 2.7** scripts. Older Ghidra (≤ 11.3) bundled Jython, so
they ran with no setup. Ghidra **11.4+ / 12.x no longer bundles Jython**, so
add it back as an extension:

- In the GUI: *File → Install Extensions → +*, pick the bundled
  `Extensions/Ghidra/ghidra_<ver>_PUBLIC_<date>_Jython.zip`, and restart.
- Or headless: unzip that file into `<ghidra>/Ghidra/Extensions/` so a
  `Jython/` module (with `lib/jython-standalone-2.7.x.jar`) appears there.

If you would rather not manage the Jython extension, the project can instead
provide PyGhidra-compatible (Python 3) copies — ask; these files are kept
Jython-2.7 on purpose.

## How the rizin commands map to Ghidra

| rizin                              | Ghidra Program API |
|------------------------------------|--------------------|
| `rzpipe.open` + `aaa`              | `currentProgram` (import + auto-analysis) |
| `ij` bin info                      | `Language`: processor, size, endianness; `getImageBase()` |
| `aflj` (functions)                 | `FunctionManager.getFunctions(True)` |
| `afbj @ fn` (basic blocks)         | `BasicBlockModel.getCodeBlocksContaining(body, monitor)` |
| `pdj N @ addr` (instructions)      | `Listing.getInstructions(block, True)` |
| op type call/jmp/ret/indirect      | `Instruction.getFlowType()` (`isCall`/`isJump`/`isTerminal`/`isComputed`) |
| `afij @@F` callrefs (CALL only)    | `Function.getCalledFunctions(monitor)` |
| `isj` / `iSj`                      | `SymbolTable` / `Memory` blocks |

## Running them (headless)

Analyse the target in a Ghidra project, then run the script as a
`-postScript` so it operates on the analysed program:

```bash
# patch list for the whole binary
analyzeHeadless <proj_dir> <proj_name> -import ./target_exe \
    -postScript gen_patchlist_ghidra.py /tmp/out.lcv --threading st

# re-run on an already-imported program
analyzeHeadless <proj_dir> <proj_name> -process target_exe \
    -postScript gen_patchlist_ghidra.py /tmp/out.lcv --root main --threading mt

# boundary sidecar, verified against the patch list
analyzeHeadless <proj_dir> <proj_name> -process target_loop \
    -postScript gen_boundary_ghidra.py /tmp/loop.lcvb iter_begin:begin \
        --patchlist /tmp/out.lcv
```

Put this directory on Ghidra's script path (Script Manager → *Manage Script
Directories*, or `-scriptPath tools/ghidra`) so the scripts find
`ghidra_resolve.py` and each other. You can also run them from the GUI Script
Manager on the open program, passing arguments via the script-arguments
mechanism.

## Interface differences from the rizin tools (by necessity)

* **No positional `<binary>`.** Module 0 is the program open in Ghidra, so
  the first positional is the **output path**. `gen_patchlist_ghidra.py
  OUT.lcv [options]`; `gen_boundary_ghidra.py OUT.lcvb SPEC... [options]`.
* **No `--raw/--base/--arch/--bits/--endian`.** A headerless image's
  processor, base and byte order are chosen when you import it into Ghidra.
  `--symbols FILE` is kept, to name functions Ghidra left as `FUN_xxxx`
  (same `nm` / `ADDR NAME` / Ghidra-CSV formats as the rizin tool).
* **`--module NAME:PROJECTPATH`** opens an additional module from the **same
  Ghidra project** (it must already be imported and analysed there);
  `PROJECTPATH` is the program's path inside the project, e.g. `/libfoo.so`.
  The rizin tool took a filesystem path instead.
* **Name prefixes.** rizin decorates names (`sym.`/`dbg.`/`fcn.`/`sym.imp.`);
  Ghidra names are bare. The default exclusion of PLT/import stubs is done by
  skipping **thunk** functions (`Function.isThunk()`), the CRT/init stubs by
  a name regex, and the "heuristic function" skip (rizin `fcn.*`) targets
  Ghidra's default-named **`FUN_xxxx`** functions (`--include-fcn` to keep
  them).

Everything else — `--include-pat`, `--exclude-pat`, `--no-default-exclude`,
`--strategy`, `--threading`, `--root`/`--cutoff`/`--max-depth`/
`--print-reachable`, `--fail-on-overlap`, `--allow-empty`,
`--no-module-bases`, and the `SYM[:kind[:depth_filter]]` boundary specs —
behaves exactly as documented for the rizin tools in `HOWTO.md`.

## Notes

* These require the program to be **auto-analysed** first (headless `-import`
  does this; `-process` assumes it was analysed when imported).
* Ghidra's ELF loader already resolves PPC64 ELFv1 `.opd` descriptors, so the
  `fix_elfv1_nop_entries` fixup is a defensive best-effort here rather than a
  routine step.
* The trap design is unchanged and load-bearing: SIGILL via illegal
  instruction encodings. These scripts only *select sites and record original
  bytes*; the runtime does the patching.

## Verified against the rizin tools

Cross-checked on `x86_64` (terminator strategy, ST and MT) and `mips`
(MIPS32 BE, entry strategy) by generating the sidecars both ways and diffing:

* **Boundary sidecars (`.lcvb`) were byte-identical** on both arches.
* **Patch lists overlapped on the large majority of sites.** All differences
  come down to two analysis-level disagreements, not porting bugs:
  1. **Ghidra ends a basic block at a `call`; rizin does not.** So Ghidra
     emits one extra (valid, restorable) probe for the pre-call portion of a
     call-containing block. The call itself is still instrumented in both, so
     it is strictly finer coverage, nothing lost.
  2. **The two tools exclude slightly different CRT/init stubs by default**
     (rizin by name regex; the port by `isThunk()` + a CRT-name regex). These
     stubs are unreachable from `main`, so a `--root main` slice makes the
     tools agree almost exactly.
* Invariants held: every x86 MT site satisfies the single-fetch-block atomic
  rule, and no MIPS entry site landed in a branch delay slot.
