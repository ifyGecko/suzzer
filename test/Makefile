# Test harness Makefile. Invoked from the top-level Makefile with:
#   ARCH=<arch>  CROSS=<prefix>  BUILD=<absolute build dir>

ARCH  ?= $(shell uname -m)
CROSS ?=
BUILD ?= ../build/$(ARCH)

CC      := $(CROSS)gcc
CFLAGS  ?= -O0 -g -Wall -Wextra

.PHONY: all clean

all: $(BUILD)/target_simple $(BUILD)/fuzz_driver

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

# Thumb variant: only built when explicitly asked (make thumb).
$(BUILD)/target_simple_thumb: target_simple.c
	$(CC) $(CFLAGS) -no-pie -fno-stack-protector -mthumb -o $@ $<

.PHONY: thumb
thumb: $(BUILD)/target_simple_thumb

$(BUILD)/fuzz_driver: fuzz_driver.c
	$(CC) -O2 -g -Wall -Wextra -o $@ $<

clean:
	rm -rf $(BUILD)/target_simple $(BUILD)/target_simple_thumb $(BUILD)/fuzz_driver
