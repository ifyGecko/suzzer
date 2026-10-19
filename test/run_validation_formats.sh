#!/usr/bin/env bash
# The published formats (docs/FORMATS.md) match what suzzer writes.
#
# test/formats_reader.py is an independent reader written from the spec.
# Fed real output -- a patch list and a boundary file from the generators,
# and the coverage region libcov leaves behind after a boundary run of
# target_loop -- it must accept every file and agree with what is known
# about it independently:
#
#   1. LCV3: every record valid; the module base table equals rizin's baddr;
#      offsets equal the ones gen_boundary.py reads.
#   2. LCVB1: the iter_begin marker is a begin-only record on a patch-list
#      site.
#   3. LCVS: host byte order; ACTIVE and (ST) LIVE_EMPTY set; the scheme
#      bits say site-id/N=2/no rotation (the defaults); map_size follows the
#      map-size rule (§5.5) for this patch list's site count; every stamped
#      ring slot sits at gen % ring_size, holds exactly one slot kind, and
#      the newest one is gen_current; gen_init names an INIT slot.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
B="$ROOT/build/$ARCH"
TARGET="$B/target_loop"
LIB="$B/libcov_st.so"
for f in "$TARGET" "$LIB"; do
    [[ -e "$f" ]] || { echo "missing $f. Run 'make'." >&2; exit 1; }
done
if [[ "$ARCH" != "$(uname -m)" ]]; then
    echo "SKIP: runs the target natively (ARCH=$ARCH)"; exit 0
fi

WORK=$(mktemp -d)
keep_work_on_failure() {
    local rc=$?
    if [[ $rc -eq 0 ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK" >&2; fi
    return $rc
}
trap keep_work_on_failure EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
R="$ROOT/test/formats_reader.py"

echo ">> generate a patch list and a boundary file for target_loop"
"$ROOT/tools/gen_patchlist.py" "$TARGET" "$WORK/t.lcv" \
    --include-pat '^dbg\.(main|classify|loop_sum|cmdline|process_one|iter_begin)$' \
    >/dev/null 2>"$WORK/gen.log" || fail "gen_patchlist: $(tail -3 "$WORK/gen.log")"
"$ROOT/tools/gen_boundary.py" "$TARGET" "$WORK/t.lcvb" iter_begin:begin \
    --patchlist "$WORK/t.lcv" >/dev/null 2>"$WORK/bnd.log" \
    || fail "gen_boundary: $(tail -3 "$WORK/bnd.log")"
python3 "$R" lcv3 "$WORK/t.lcv" > "$WORK/lcv3.json" || fail "reader rejected the patch list"
python3 "$R" lcvb "$WORK/t.lcvb" > "$WORK/lcvb.json" || fail "reader rejected the boundary file"

echo ">> 1. LCV3"
python3 - "$ROOT/tools" "$TARGET" "$WORK/t.lcv" "$WORK/lcv3.json" <<'EOF'
import json, sys, rzpipe
sys.path.insert(0, sys.argv[1])
from gen_boundary import patchlist_offsets
target, lcv, js = sys.argv[2:]
p = json.load(open(js))
if p["modules"] != ["target_loop"] or not p["records"]:
    sys.exit(f"FAIL: modules {p['modules']}, {len(p['records'])} records")
rz = rzpipe.open(target, flags=["-2"])
baddr = rz.cmdj("ij")["bin"]["baddr"]
if p["module_bases"] != [baddr]:
    sys.exit(f"FAIL: module_bases {p['module_bases']} != rizin baddr {baddr:#x}")
if {r["offset"] for r in p["records"]} != patchlist_offsets(lcv):
    sys.exit("FAIL: record offsets differ from gen_boundary's reading")
if [r["site_id"] for r in p["records"]] != list(range(len(p["records"]))):
    sys.exit("FAIL: site ids are not the record indices")
print(f"   OK: {len(p['records'])} records, base {baddr:#x}, offsets agree")
EOF

echo ">> 2. LCVB1"
python3 - "$WORK/lcvb.json" "$WORK/lcv3.json" <<'EOF'
import json, sys
b, p = (json.load(open(f)) for f in sys.argv[1:])
offs = {r["offset"] for r in p["records"] if r["module_idx"] == 0}
if b["mode"] != "begin-only" or len(b["records"]) != 1:
    sys.exit(f"FAIL: {b}")
r = b["records"][0]
if r["kind"] != "begin" or r["offset"] not in offs:
    sys.exit(f"FAIL: marker {r} is not a begin record on a site")
print(f"   OK: begin-only, marker at +{r['offset']:#x} is a site")
EOF

echo ">> 3. LCVS (a live region left by a boundary run)"
printf '42\n99\n-3\nabc\nhello\n' | LD_PRELOAD="$LIB" LIBCOV_PATCHLIST="$WORK/t.lcv" \
    LIBCOV_BOUNDARY_LIST="$WORK/t.lcvb" LIBCOV_SHM_PATH="$WORK/cov.shm" \
    LIBCOV_LOG="$WORK/run.log" "$TARGET" >/dev/null 2>&1 \
    || fail "target_loop under libcov: $(tail -5 "$WORK/run.log")"
[[ -s "$WORK/cov.shm" ]] || fail "no region at $WORK/cov.shm"
python3 "$R" lcvs "$WORK/cov.shm" > "$WORK/lcvs.json" || fail "reader rejected the region"
python3 - "$WORK/lcvs.json" "$WORK/lcv3.json" "$ROOT/test" <<'EOF'
import json, sys
s, p = (json.load(open(f)) for f in sys.argv[1:3])
sys.path.insert(0, sys.argv[3])
from vectors_check import map_size_for
errs = []
if s["byte_order"] != ("little" if sys.byteorder == "little" else "big"):
    errs.append(f"byte order {s['byte_order']}")
if not s["active"] or not s["live_empty"] or s["mt"]:
    errs.append(f"flags {s['flags']:#x}: want ACTIVE|LIVE_EMPTY, not MT")
if s["scheme"] != {"model": "site", "rotate": 0, "n": 2}:
    errs.append(f"scheme {s['scheme']}")
want = map_size_for(len(p["records"]), 2)
if s["map_size"] != want:
    errs.append(f"map_size {s['map_size']}, rule gives {want} for {len(p['records'])} sites")
if s["bitmap_offset"] != 72 or s["ring_offset"] != 72 + s["map_size"] \
        or s["slot_stride"] != 32 + s["map_size"]:
    errs.append("layout offsets differ from libcov's documented values")
slots = s["slots"]
if not slots or slots[-1]["gen"] != s["gen_current"]:
    errs.append(f"newest slot {slots[-1:]} != gen_current {s['gen_current']}")
if any(sl["kind"] not in ("init", "iter", "gap") for sl in slots):
    errs.append(f"slot kinds {[sl['kind'] for sl in slots]}")
if s["gen_init"] and s["gen_init"] in [sl["gen"] for sl in slots]:
    if next(sl for sl in slots if sl["gen"] == s["gen_init"])["kind"] != "init":
        errs.append("gen_init does not name an INIT slot")
if s["live_nonzero"]:
    errs.append("LIVE_EMPTY set but the live bitmap is not empty")
if errs:
    sys.exit("FAIL: " + "; ".join(errs))
print(f"   OK: map_size {s['map_size']}, ring {s['ring_size']}, gens up to "
      f"{s['gen_current']}, slots {[(sl['gen'], sl['kind']) for sl in slots]}")
EOF

echo
echo "ALL FORMAT VALIDATIONS PASSED ($ARCH)"
