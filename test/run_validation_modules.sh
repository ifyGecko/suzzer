#!/usr/bin/env bash
# Module resolution (util_module_base + the generator's module names).
#
# The patch list names each module by basename, and the runtime finds it
# in /proc/self/maps. That has to survive how binaries really get run:
#
#   1. symlink: patch list generated from, and target run through, a
#      symlink (busybox-style). The name must be the real file's.
#   2. renamed copy: generated from one name, run under another. Refused
#      with a hint; LIBCOV_MODULE_RENAME=old=new maps it.
#   3. deleted: the binary was replaced/removed after exec, so its maps
#      entry ends in " (deleted)".
#   4. same basename twice: two different libdup.so in two directories.
#      libcov warns that the name is ambiguous; LIBCOV_MODULE_RENAME with
#      an absolute path picks the right one (every site validates).
set -uo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK=$(mktemp -d)
# Kept (and its path printed) when the suite fails: the generator and
# target logs in it are how you debug.
keep_work_on_failure() {
    local rc=$?
    if [[ $rc -eq 0 ]]; then rm -rf "$WORK"; else echo "logs kept in $WORK" >&2; fi
    return $rc
}
trap keep_work_on_failure EXIT
ARCH="${ARCH:-$(uname -m)}"
B="$ROOT/build/$ARCH"
GEN="$ROOT/tools/gen_patchlist.py"
fail=0 ran=0
bad() { echo "FAIL: $*"; fail=1; }

[[ -x "$B/target_simple" ]] || { echo "missing $B/target_simple. Run 'make'." >&2; exit 1; }
want=$("$B/target_simple" 42)

edges() { python3 "$ROOT/test/shm_bitmap.py" stats "$1" | cut -d' ' -f1; }

for th in st mt; do
    LIB="$B/libcov_$th.so"
    [[ -f "$LIB" ]] || { echo "SKIP: $LIB missing"; continue; }
    ran=$((ran + 1))
    run() {  # <lcv> <log> <shm> <exe> [env...] -- runs "<exe> 42"
        local lcv=$1 log=$2 shm=$3 exe=$4; shift 4
        rm -f "$shm"
        env LIBCOV_PATCHLIST="$lcv" LIBCOV_LOG="$log" LIBCOV_SHM_PATH="$shm" \
            "$@" LD_PRELOAD="$LIB" "$exe" 42
    }
    covered() {  # <out> <shm> <log> <what>: same output as bare + coverage
        [[ "$1" == "$want" ]] || { bad "$th/$4: output differs: [$1]"; return 1; }
        [[ -f "$2" && "$(edges "$2")" -gt 0 ]] \
            || { bad "$th/$4: no coverage; log: $(grep -E 'config|init' "$3" | tail -3)"; return 1; }
        return 0
    }

    # 1. symlink
    mkdir -p "$WORK/sym"; ln -sf "$B/target_simple" "$WORK/sym/app"
    "$GEN" "$WORK/sym/app" "$WORK/sym.lcv" --threading $th >/dev/null 2>"$WORK/sym.gen" \
        || bad "$th/symlink: gen"
    out=$(run "$WORK/sym.lcv" "$WORK/sym.log" "$WORK/sym.shm" "$WORK/sym/app")
    if covered "$out" "$WORK/sym.shm" "$WORK/sym.log" symlink; then
        grep -q "module\[0\] 'target_simple'" "$WORK/sym.log" \
            && echo "   OK: $th/symlink: named after the real file, coverage collected" \
            || bad "$th/symlink: module not named 'target_simple': $(grep 'module\[' "$WORK/sym.log" | head -3)"
    fi

    # 2. renamed copy
    mkdir -p "$WORK/ren"; cp "$B/target_simple" "$WORK/ren/app2"
    "$GEN" "$B/target_simple" "$WORK/ren.lcv" --threading $th >/dev/null 2>&1 \
        || bad "$th/renamed: gen"
    out=$(run "$WORK/ren.lcv" "$WORK/ren1.log" "$WORK/ren1.shm" "$WORK/ren/app2")
    if [[ "$out" == "$want" ]] && grep -q "LIBCOV_MODULE_RENAME=target_simple=app2" "$WORK/ren1.log"; then
        echo "   OK: $th/renamed: refused with a LIBCOV_MODULE_RENAME hint"
    else
        bad "$th/renamed: no hint without the override: $(grep config "$WORK/ren1.log")"
    fi
    out=$(run "$WORK/ren.lcv" "$WORK/ren2.log" "$WORK/ren2.shm" "$WORK/ren/app2" \
              LIBCOV_MODULE_RENAME=target_simple=app2)
    covered "$out" "$WORK/ren2.shm" "$WORK/ren2.log" renamed+override \
        && echo "   OK: $th/renamed: LIBCOV_MODULE_RENAME=target_simple=app2 resolves it"

    # 3. deleted before exec: run it through an inherited fd
    mkdir -p "$WORK/del"; cp "$B/target_simple" "$WORK/del/app3"
    "$GEN" "$WORK/del/app3" "$WORK/del.lcv" --threading $th >/dev/null 2>&1 \
        || bad "$th/deleted: gen"
    out=$( exec 3<"$WORK/del/app3"; rm -f "$WORK/del/app3"
           run "$WORK/del.lcv" "$WORK/del.log" "$WORK/del.shm" /proc/self/fd/3 )
    covered "$out" "$WORK/del.shm" "$WORK/del.log" deleted \
        && echo "   OK: $th/deleted: ' (deleted)' mapping resolved"
done

(( ran )) || { echo "FAIL: no libcov_{st,mt}.so in $B -- nothing ran; build with: make && make THREADING=mt"; exit 1; }

# 4. same basename, different files
D="$WORK/dup"; mkdir -p "$D/a" "$D/b"
# No DT_SONAME, linked by path: both copies load (--no-as-needed, since
# b/ provides no symbol a/ doesn't).
cat >"$D/libdup.c" <<'C'
#if VARIANT == 1
int dup_pad(int x) {            /* shifts dup_fn to another offset in a/ */
    int r = 0;
    for (int i = 0; i < x; i++) r += (i & 1) ? i * 3 : i ^ x;
    return r;
}
#endif
int dup_fn(int x) {
    if (x > 3) return x * VARIANT;
    if (x < 0) return -x;
    return x + VARIANT;
}
C
printf 'int dup_fn(int);\n#include <stdio.h>\nint main(void){printf("%%d\\n",dup_fn(7));return 0;}\n' >"$D/main.c"
${CC:-gcc} -O0 -g -fPIC -shared -DVARIANT=1 -o "$D/a/libdup.so" "$D/libdup.c" \
 && ${CC:-gcc} -O0 -g -fPIC -shared -DVARIANT=2 -o "$D/b/libdup.so" "$D/libdup.c" \
 && ${CC:-gcc} -O0 -g -no-pie -o "$D/main" "$D/main.c" \
        -Wl,--no-as-needed "$D/a/libdup.so" "$D/b/libdup.so" \
 || { bad "dup: build"; }
if [[ -x "$D/main" ]]; then
    LIB="$B/libcov_st.so"
    "$GEN" "$D/main" "$D/dup.lcv" --module "libdup.so:$D/b/libdup.so" \
        --include-pat '^dbg\.dup_fn$' >/dev/null 2>&1 || bad "dup: gen"
    LIBCOV_PATCHLIST="$D/dup.lcv" LIBCOV_LOG="$D/1.log" LIBCOV_SHM_PATH="$D/1.shm" \
        LD_PRELOAD="$LIB" "$D/main" >/dev/null
    grep -q "ambiguous" "$D/1.log" \
        && echo "   OK: dup: ambiguous basename reported" \
        || bad "dup: no ambiguity warning: $(grep -E 'config|stale' "$D/1.log")"
    LIBCOV_PATCHLIST="$D/dup.lcv" LIBCOV_LOG="$D/2.log" LIBCOV_SHM_PATH="$D/2.shm" \
        LIBCOV_MODULE_RENAME="libdup.so=$D/b/libdup.so" LD_PRELOAD="$LIB" "$D/main" >/dev/null
    if grep -q "stale=0" "$D/2.log" && ! grep -q "ambiguous" "$D/2.log" \
            && grep -q "module\[1\] '.*' base=" "$D/2.log"; then
        echo "   OK: dup: absolute-path rename picks b/libdup.so, every site validates"
    else
        bad "dup: override: $(grep -E 'config|stale|ambig' "$D/2.log")"
    fi
fi

[[ $fail -eq 0 ]] && echo "ALL MODULE RESOLUTION VALIDATIONS PASSED ($ARCH)" || exit 1
