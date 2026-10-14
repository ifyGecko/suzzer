#!/bin/bash
# qemu_read.sh ELF PORT GDBCMDFILE  -- boot ELF under qemu-system-mips malta
# paused, run the gdb batch commands in GDBCMDFILE against its gdbstub, print
# gdb output, then kill qemu. Self-contained; no project dependencies.
set -u
ELF="$1"; PORT="$2"; CMDS="$3"
pkill -f "qemu-system-mips.*gdb tcp::$PORT" 2>/dev/null
qemu-system-mips -M malta -cpu 24Kc -m 128 -nographic -no-reboot \
    -kernel "$ELF" -S -gdb tcp::$PORT >/tmp/qemu_read_qemu.log 2>&1 &
QPID=$!
# wait (up to ~5s) for the gdbstub port to accept connections
for i in $(seq 1 50); do
    (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && { exec 3>&- 3<&-; break; }
    sleep 0.1
done
timeout 20 gdb-multiarch -q -batch -nx \
    -ex "set pagination off" -ex "set confirm off" \
    -ex "set architecture mips:isa32r2" \
    -ex "target remote :$PORT" \
    -x "$CMDS" "$ELF" 2>&1
RC=$?
kill -9 $QPID 2>/dev/null
exit $RC
