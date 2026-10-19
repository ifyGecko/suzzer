/*
 * target_raw.c -- a freestanding "firmware" image for the raw-image
 * generator tests (test/run_validation_generator.sh, test 6).
 *
 * No libc, no startup code, one fixed load address: the suite links it
 * with -nostdlib -Ttext=BASE -e fw_entry, then objcopy -O binary's the
 * .text section into a raw image, so the same code exists both as an ELF
 * and as a bootloader-style blob loaded at BASE. Never run.
 */
volatile unsigned int sink_reg;

__attribute__((noinline)) static unsigned int classify(unsigned int v) {
    if (v & 1) return v * 3 + 1;
    if (v > 100) return v / 2;
    return v + 7;
}

__attribute__((noinline)) static unsigned int checksum(const unsigned char *p,
                                                       unsigned int n) {
    unsigned int s = 0;
    for (unsigned int i = 0; i < n; i++) s = (s << 1) ^ p[i];
    return s;
}

__attribute__((noinline)) void handle(unsigned int v) {
    unsigned char buf[8];
    for (int i = 0; i < 8; i++) buf[i] = (unsigned char)(v >> i);
    sink_reg = classify(v) ^ checksum(buf, 8);
}

void fw_entry(void) {
    for (unsigned int v = 0;; v++) handle(v);
}
