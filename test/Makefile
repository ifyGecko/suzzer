# Test harness Makefile. Invoked from the top-level Makefile with:
#   ARCH=<arch>  CROSS=<prefix>  BUILD=<absolute build dir>

ARCH  ?= $(shell uname -m)
CROSS ?=
BUILD ?= ../build/$(ARCH)

CC      := $(CROSS)gcc
CFLAGS  ?= -O0 -g -Wall -Wextra

.PHONY: all clean mt loop

all: $(BUILD)/target_simple $(BUILD)/target_loop $(BUILD)/fuzz_driver

# pthread MT stress target. Built on demand by the MT validation scripts.
mt: $(BUILD)/target_simple_mt

# Boundary-aware loop target. Built by `all` since the driver only works
# against a long-running target; an explicit `loop` alias is offered for
# clarity in scripts.
loop: $(BUILD)/target_loop

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

# Thumb variant: only built when explicitly asked (make thumb).
$(BUILD)/target_simple_thumb: target_simple.c
	$(CC) $(CFLAGS) -no-pie -fno-stack-protector -mthumb -o $@ $<

.PHONY: thumb
thumb: $(BUILD)/target_simple_thumb

# Driver pulls struct definitions from ../src/{boundary,sink}.h for the
# shm layout; no separate header install step needed.
#
# -Wl,--as-needed + -latomic pulls in libatomic only when the toolchain
# can't synthesize 64-bit atomics natively (32-bit arches: mips, mipsel,
# powerpc). On 64-bit arches __atomic_load_8 is inline and the library
# stays unlinked.
$(BUILD)/fuzz_driver: fuzz_driver.c ../src/boundary.h ../src/sink.h
	$(CC) -O2 -g -Wall -Wextra -I../src -o $@ fuzz_driver.c \
	    -Wl,--as-needed -latomic

$(BUILD)/target_simple_mt: target_simple_mt.c
	$(CC) $(CFLAGS) $(TARGET_CFLAGS) -pthread -o $@ $<

clean:
	rm -rf $(BUILD)/target_simple $(BUILD)/target_simple_thumb \
	       $(BUILD)/target_simple_mt $(BUILD)/target_loop \
	       $(BUILD)/fuzz_driver
