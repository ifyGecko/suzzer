#!/usr/bin/env bash
# -O2 PIE targets. Every other suite uses -O0 -no-pie builds; real targets
# have tail calls, cold splits (foo.cold), jump tables, shrink-wrapped
# prologues and a load base that moves under ASLR. For target_simple and
# target_dispatch built -O2 -fPIE -pie, whole-binary patch lists, and each
# of ST leapfrog, ST oneshot and MT leapfrog:
#
#   1. target output (and exit code) is identical with and without libcov;
#   2. the same input gives the same bitmap on two runs (ST; ASLR moves
#      the base between them, the bitmap must not care);
#   3. different inputs give different bitmaps.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${ARCH:-$(uname -m)}"
B="$ROOT/build/$ARCH"

for f in "$B/libcov_st.so" "$B/libcov_mt.so" "$B/target_simple_o2pie" \
         "$B/target_dispatch_o2pie"; do
    [[ -e "$f" ]] || { echo "missing $f. Run 'make', 'make THREADING=mt' and 'make -C test o2pie ARCH=$ARCH BUILD=$B'." >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

for t in target_simple_o2pie target_dispatch_o2pie; do
    for th in st mt; do
        "$ROOT/tools/gen_patchlist.py" "$B/$t" "$WORK/$t.$th.lcv" --threading "$th" \
            >/dev/null 2>"$WORK/$t.$th.gen.log" \
            || fail "gen_patchlist $t --threading $th: $(tail -3 "$WORK/$t.$th.gen.log")"
    done
    echo ">> $t: $(grep -oE 'wrote [0-9]+ records' "$WORK/$t.st.gen.log") (st)," \
         "$(grep -oE 'wrote [0-9]+' "$WORK/$t.mt.gen.log") (mt)"
done

# run <tag> <target> <th> <mode> <args...> -> $WORK/<tag>.{out,rc,bitmap}
run() {
    local tag="$1" t="$2" th="$3" mode="$4"; shift 4
    local shm="$WORK/$tag.shm"
    rm -f "$shm"
    set +e
    LD_PRELOAD="$B/libcov_$th.so" LIBCOV_PATCHLIST="$WORK/$t.$th.lcv" \
        LIBCOV_SHM_PATH="$shm" LIBCOV_MODE="$mode" LIBCOV_LOG="$WORK/$tag.log" \
        "$B/$t" "$@" > "$WORK/$tag.out" 2>&1
    echo $? > "$WORK/$tag.rc"
    set -e
    grep -q "init: ready" "$WORK/$tag.log" || fail "$tag: libcov not ready: $(tail -3 "$WORK/$tag.log")"
    python3 "$ROOT/test/shm_bitmap.py" extract "$shm" "$WORK/$tag.bitmap"
}

bare() {  # bare <tag> <target> <args...>
    local tag="$1" t="$2"; shift 2
    set +e
    "$B/$t" "$@" > "$WORK/$tag.out" 2>&1
    echo $? > "$WORK/$tag.rc"
    set -e
}

same_output() {  # same_output <bare-tag> <libcov-tag>
    cmp -s "$WORK/$1.out" "$WORK/$2.out" && cmp -s "$WORK/$1.rc" "$WORK/$2.rc" \
        || fail "$2: output/rc differs from bare run ($(cat "$WORK/$1.rc") vs $(cat "$WORK/$2.rc"))"
}

check_target() {  # check_target <target> <input A> <input B> [more inputs...]
    local t="$1"; shift
    local inputs=("$@")
    for th_mode in st:leapfrog st:oneshot mt:leapfrog; do
        local th=${th_mode%%:*} mode=${th_mode##*:}
        for i in "${inputs[@]}"; do
            bare "bare.$t.$i" "$t" "$i"
            run "$t.$th.$mode.$i" "$t" "$th" "$mode" "$i"
            same_output "bare.$t.$i" "$t.$th.$mode.$i"
        done
        local a="${inputs[0]}" b="${inputs[1]}"
        if [[ $th == st ]]; then
            run "$t.$th.$mode.$a.again" "$t" "$th" "$mode" "$a"
            cmp -s "$WORK/$t.$th.$mode.$a.bitmap" "$WORK/$t.$th.$mode.$a.again.bitmap" \
                || fail "$t $th/$mode: input $a gave different bitmaps on two runs"
        fi
        cmp -s "$WORK/$t.$th.$mode.$a.bitmap" "$WORK/$t.$th.$mode.$b.bitmap" \
            && fail "$t $th/$mode: inputs $a and $b gave identical bitmaps"
        echo "   OK: $t $th/$mode: output unchanged for ${#inputs[@]} inputs," \
             "$([[ $th == st ]] && echo "deterministic, ")inputs differ"
    done
}

check_target target_simple_o2pie 42 -3 0 hello 99
check_target target_dispatch_o2pie 7 1 0 2 5

echo
echo "ALL -O2 PIE VALIDATIONS PASSED ($ARCH)"
