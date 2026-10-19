#!/usr/bin/env bash
# Build test/gen_vectors.c once per coverage scheme and write the
# conformance vectors (docs/FORMATS.md "Conformance vectors").
#
#   test/gen_vectors.sh OUTDIR          (re)generate OUTDIR (make vectors)
#   test/gen_vectors.sh --check DIR     regenerate into a temp dir and fail
#                                       if DIR differs (make test)
#
# Schemes: model site|pc x N in {1,2,3,4,8} x rotate 0|1, each at map
# sizes 4 KiB, 64 KiB and 1 MiB, plus map_size.json (the site-id model's
# map-size rule for N = 1..8). Native 64-bit host compiler only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CC="${CC:-gcc}"
CHECK=0
if [[ "${1:-}" == "--check" ]]; then CHECK=1; shift; fi
[[ $# -eq 1 ]] || { echo "usage: $0 [--check] DIR" >&2; exit 2; }
DEST="$1"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
OUT="$TMP/vectors"
mkdir -p "$OUT" "$TMP/bin"

build() {   # build NAME CPPFLAGS...
    local name=$1; shift
    "$CC" -O1 -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Werror \
        -I"$ROOT/src" "$@" \
        -o "$TMP/bin/$name" "$ROOT/test/gen_vectors.c"
}

for model in site pc; do
    m=$([[ $model == site ]] && echo 1 || echo 0)
    for n in 1 2 3 4 8; do
        for r in 0 1; do
            name="${model}_n${n}_r${r}"
            build "$name" -DLIBCOV_COVERAGE_MODEL_SITE=$m -DLIBCOV_NGRAM_N=$n \
                  -DLIBCOV_NGRAM_ROTATE=$r
            "$TMP/bin/$name" "$OUT"
        done
    done
done

# The map-size rule, from the runtime's sink_map_size_for (site-id model).
for n in 1 2 3 4 5 6 7 8; do
    build "mapsize_n$n" -DLIBCOV_COVERAGE_MODEL_SITE=1 -DLIBCOV_NGRAM_N=$n
    "$TMP/bin/mapsize_n$n" --map-size-table
done > "$OUT/map_size.jsonl"

cp "$ROOT/test/vectors_README.txt" "$OUT/README.txt"

if [[ $CHECK -eq 1 ]]; then
    if ! diff -rq "$DEST" "$OUT" >"$TMP/diff.txt" 2>&1; then
        echo "FAIL: committed vectors in $DEST differ from what src/sink.h produces:" >&2
        head -20 "$TMP/diff.txt" >&2
        echo "(run 'make vectors' if the formula change is intended -- it breaks" \
             "every consumer's bitmaps; see docs/FORMATS.md \"Versioning\")" >&2
        exit 1
    fi
    echo "vectors: $DEST matches src/sink.h ($(ls -d "$OUT"/*/ | wc -l) vectors)"
else
    if [[ -e "$DEST" && ! -e "$DEST/map_size.jsonl" ]]; then
        echo "refusing to replace $DEST: not a vectors directory" >&2
        exit 1
    fi
    rm -rf "$DEST"
    mkdir -p "$(dirname "$DEST")"
    cp -r "$OUT" "$DEST"
    echo "vectors: wrote $(ls -d "$DEST"/*/ | wc -l) vectors to $DEST"
fi
