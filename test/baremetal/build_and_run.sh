#!/bin/bash
# Self-contained baremetal coverage test: build a tiny MIPS image (libcov
# freestanding core + an instrumented app), run it under qemu-system-mips,
# read coverage fingerprints over the gdbstub, assert determinism +
# differentiation. No dependency on any other project.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../../src"; TOOLS="$HERE/../../tools"
CROSS=mips-linux-gnu-
OUT="$HERE/_out"; mkdir -p "$OUT"
BM="-O2 -g -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -mno-abicalls -mabi=32 -march=mips32r2 -EB -G0 -I$SRC"
DEFS="-DLIBCOV_PLAT_BAREMETAL_MIPS -DLIBCOV_THREADING_ST -DLIBCOV_ARCH_MIPS_ILLEGAL=0x00000038u \
 -DLIBCOV_BM_MODULE_LO=0x80100000ull -DLIBCOV_BM_MODULE_HI=0x80140000ull \
 -DLIBCOV_BM_ARENA_LO=0x80200000ull -DLIBCOV_BM_ARENA_HI=0x80300000ull"
CC=${CROSS}gcc
C() { $CC $BM $DEFS -c "$1" -o "$2" || { echo "CC FAIL $1"; exit 3; }; }
LD() { $CC $BM -nostdlib -nostartfiles -no-pie -static -Wl,-T,"$HERE/test.ld" -EB -mno-abicalls -o "$1" "${@:2}" 2>/dev/null; }

# compile core + app + startup
C "$SRC/arch_mips.c"                   "$OUT/arch_mips.o"
C "$SRC/core_bm.c"                     "$OUT/core_bm.o"
C "$SRC/plat_baremetal_mips.c"         "$OUT/plat.o"
C "$SRC/plat_baremetal_mips_vector.S"  "$OUT/vector.o"
C "$HERE/app.c"                        "$OUT/app.o"
C "$HERE/main.c"                       "$OUT/main.o"
C "$HERE/test_start.S"                 "$OUT/start.o"
CORE="$OUT/arch_mips.o $OUT/core_bm.o $OUT/plat.o $OUT/vector.o $OUT/app.o $OUT/main.o $OUT/start.o"

# pass 1: link without a patchlist to read symbol addresses
LD "$OUT/app1.elf" $CORE || { echo "LINK1 FAIL"; exit 3; }
# generate the patchlist from the app's function entries
python3 "$TOOLS/gen_patchlist_baremetal.py" --objdump ${CROSS}objdump --elf "$OUT/app1.elf" \
    --base 0x80100000 --module test --out-c "$OUT/patchlist.c" \
    app_run app_a app_b app_c app_leaf || { echo "GEN FAIL"; exit 3; }
C "$OUT/patchlist.c" "$OUT/patchlist.o"
# pass 2: final link (patchlist is data appended after .text; func addrs stable)
LD "$OUT/app.elf" $CORE "$OUT/patchlist.o" || { echo "LINK2 FAIL"; exit 3; }

# run under qemu + read results over gdb
cat > "$OUT/read.gdb" <<'G'
tbreak test_done
continue
printf "INIT=%d NRUNS=%d MAP=%u\n", g_init_rc, g_nruns, libcov_map_size
set $i = 0
while $i < g_nruns
  printf "RUN in=%d edges=%d hash=0x%08x\n", g_runs[$i].input, g_runs[$i].edges, g_runs[$i].hash
  set $i = $i + 1
end
G
"$HERE/qemu_read.sh" "$OUT/app.elf" $((26000 + RANDOM % 3000)) "$OUT/read.gdb" 2>/dev/null \
    | grep -E "INIT=|RUN " > "$OUT/result.txt"
echo "=== raw results ==="; cat "$OUT/result.txt"
