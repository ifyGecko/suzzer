# Test harness Makefile. Invoked from the top-level Makefile with:
#   ARCH=<arch>  CROSS=<prefix>  BUILD=<absolute build dir>

ARCH  ?= $(shell uname -m)
CROSS ?=
BUILD ?= ../build/$(ARCH)

CC      := $(CROSS)gcc
CFLAGS  ?= -O0 -g -Wall -Wextra

# Emit a .d sidecar per output so editing a header (directly or transitively,
# e.g. tunables.h via sink.h) rebuilds the dependent target. -include'd below.
DEPFLAGS := -MMD -MP
CFLAGS   += $(DEPFLAGS)

.PHONY: all clean mt loop demalloc multimod o2pie

all: $(BUILD)/target_simple $(BUILD)/target_loop $(BUILD)/target_orderable \
     $(BUILD)/target_dispatch $(BUILD)/target_markers $(BUILD)/fuzz_driver

# pthread MT stress target + multi-worker boundary target and its ring
# reader. Built on demand by the MT validation scripts.
mt: $(BUILD)/target_simple_mt $(BUILD)/target_loop_mt $(BUILD)/ring_dump

# Multi-module target + helper .so. Built on demand by
# run_validation_multimod.sh which exercises LCV3's multi-module path.
multimod: $(BUILD)/target_multimod $(BUILD)/libmultimod_helper.so

# Boundary-aware loop target. Built by `all` since the driver only works
# against a long-running target; an explicit `loop` alias is offered for
# clarity in scripts.
loop: $(BUILD)/target_loop

# Heap-bug exerciser for libdemalloc validation. Built on demand by
# run_validation_demalloc.sh; not pulled by `all` because libdemalloc
# itself is opt-in.
demalloc: $(BUILD)/target_demalloc

# -no-pie keeps test addresses static for easy patch-list generation.
# -fno-stack-protector trims function prologue noise.
# ARM is built in ARM mode by default; an explicit thumb target_simple is
# built separately when needed (see target_simple_thumb rule below).
TARGET_CFLAGS := -no-pie -fno-stack-protector
ifeq ($(ARCH),arm)
  TARGET_CFLAGS += -marm
endif

$(BUILD)/target_simple: target_simple.c
	$(CC) $(CFLAGS) $(TARGET_CFLAGS) -o $@ $<

$(BUILD)/target_loop: target_loop.c
	$(CC) $(CFLAGS) $(TARGET_CFLAGS) -o $@ $<

# Ordering-sensitive target for the N-gram checks in
# run_validation_coverage_options.sh.
$(BUILD)/target_orderable: target_orderable.c
	$(CC) $(CFLAGS) $(TARGET_CFLAGS) -o $@ $<

# Generator regressions (run_validation_generator.sh): function-pointer
# dispatch + a block whose callee may exit.
$(BUILD)/target_dispatch: target_dispatch.c
	$(CC) $(CFLAGS) $(TARGET_CFLAGS) -o $@ $<

# -O2 PIE builds of the ground-truth targets (run_validation_o2pie.sh).
# Every other target is -O0 -no-pie; real targets have tail calls, cold
# splits, jump tables and shrink-wrapped prologues, and a load base that
# moves under ASLR.
O2PIE_CFLAGS := -O2 -g -Wall -fPIE -pie -fno-stack-protector $(DEPFLAGS)
ifeq ($(ARCH),arm)
  O2PIE_CFLAGS += -marm
endif
o2pie: $(BUILD)/target_simple_o2pie $(BUILD)/target_dispatch_o2pie

$(BUILD)/target_simple_o2pie: target_simple.c
	$(CC) $(O2PIE_CFLAGS) -o $@ $<

$(BUILD)/target_dispatch_o2pie: target_dispatch.c
	$(CC) $(O2PIE_CFLAGS) -o $@ $<

# Boundary-marker emulation (run_validation_marker_emulation.sh).
$(BUILD)/target_markers: target_markers.c
	$(CC) $(CFLAGS) $(TARGET_CFLAGS) -o $@ $<

# Thumb variants: only built when explicitly asked (make thumb).
$(BUILD)/target_simple_thumb: target_simple.c
	$(CC) $(CFLAGS) -no-pie -fno-stack-protector -mthumb -o $@ $<

$(BUILD)/target_markers_thumb: target_markers.c
	$(CC) $(CFLAGS) -no-pie -fno-stack-protector -mthumb -o $@ $<

.PHONY: thumb
thumb: $(BUILD)/target_simple_thumb $(BUILD)/target_markers_thumb

# Driver pulls struct definitions from ../src/{boundary,sink}.h for the
# shm layout; no separate header install step needed.
#
# -Wl,--as-needed + -latomic pulls in libatomic only when the toolchain
# can't synthesize 64-bit atomics natively (32-bit arches: mips, mipsel,
# powerpc). On 64-bit arches __atomic_load_8 is inline and the library
# stays unlinked.
$(BUILD)/fuzz_driver: fuzz_driver.c ../src/boundary.h ../src/sink.h
	$(CC) -O2 -g -Wall -Wextra $(DEPFLAGS) -I../src -o $@ fuzz_driver.c \
	    -Wl,--as-needed -latomic

$(BUILD)/target_simple_mt: target_simple_mt.c
	$(CC) $(CFLAGS) $(TARGET_CFLAGS) -pthread -o $@ $<

$(BUILD)/target_loop_mt: target_loop_mt.c
	$(CC) $(CFLAGS) $(TARGET_CFLAGS) -pthread -o $@ $<

# Passive ring reader for targets that iterate on their own
# (run_validation_boundary_mt.sh). Same build shape as fuzz_driver.
$(BUILD)/ring_dump: ring_dump.c ../src/boundary.h
	$(CC) -O2 -g -Wall -Wextra $(DEPFLAGS) -I../src -o $@ ring_dump.c \
	    -Wl,--as-needed -latomic

# target_demalloc deliberately keeps the libc allocator behavior under
# LD_PRELOAD interception, so it is a normal -no-pie -O0 build.
$(BUILD)/target_demalloc: target_demalloc.c
	$(CC) $(CFLAGS) $(TARGET_CFLAGS) -o $@ $<

# Multi-module pair: a shared library + a -no-pie executable that calls
# into it. The executable links against the helper so the loader maps the
# .so at run time; gen_patchlist.py is given both with --module so each
# gets its own module_idx in the LCV3 output.
$(BUILD)/libmultimod_helper.so: libmultimod_helper.c libmultimod_helper.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ libmultimod_helper.c

$(BUILD)/target_multimod: target_multimod.c libmultimod_helper.h \
                          $(BUILD)/libmultimod_helper.so
	$(CC) $(CFLAGS) $(TARGET_CFLAGS) -I. -o $@ target_multimod.c \
	    -L$(BUILD) -lmultimod_helper -Wl,-rpath,$(abspath $(BUILD))

# Pull in the generated header dependencies (-MMD -MP above). Wildcard so a
# missing/first build is fine; files live next to their targets in $(BUILD).
-include $(wildcard $(BUILD)/*.d)

clean:
	rm -rf $(BUILD)/target_simple $(BUILD)/target_orderable $(BUILD)/target_dispatch \
	       $(BUILD)/target_markers $(BUILD)/target_markers_thumb \
	       $(BUILD)/target_simple_o2pie $(BUILD)/target_dispatch_o2pie $(BUILD)/target_simple_thumb \
	       $(BUILD)/target_simple_mt $(BUILD)/target_loop \
	       $(BUILD)/target_loop_mt $(BUILD)/ring_dump \
	       $(BUILD)/target_demalloc $(BUILD)/fuzz_driver \
	       $(BUILD)/target_multimod $(BUILD)/libmultimod_helper.so \
	       $(BUILD)/*.d
