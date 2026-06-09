/*
 * target_faultinj_simple.c -- file-I/O exerciser for the libfaultinj
 *                             validation harness.
 *
 * Performs a fixed, ordered sequence of open/read/write/close calls
 * on a known-valid file. The sequence is deterministic so that, for a
 * given LIBFAULTINJ_SEED, the harness can assert the SAME set of
 * faults gets injected across separate runs (the determinism contract).
 *
 * Every libc call's return code is printed in a one-line-per-call
 * "E:" record that the validation script greps for. The records are
 * written via puts() to fd 1 (which we ask libfaultinj to skip by
 * default, so our reporting channel is uncontaminated).
 *
 * Built with -O0 -no-pie -fno-stack-protector so addresses are stable
 * if anyone wants to disasm a faulted run.
 *
 * Output schema (one line per call):
 *
 *   E:open#<n> rc=<int> errno=<int>
 *   E:read#<n> rc=<int> errno=<int>
 *   E:write#<n> rc=<int> errno=<int>
 *   E:close#<n> rc=<int> errno=<int>
 *   E:done injected=<observed_failure_count>
 *
 * Argv:
 *
 *   argv[1] = path to a directory the target is allowed to write into
 *             (usually /tmp/faultinj_test_$$); defaulted if unset.
 *   argv[2] = number of "rounds" of (open/write/read/close) to do;
 *             defaulted to 8.
 *
 * Rationale for the round shape: a single round wouldn't exercise the
 * call-index axis of the determinism contract (we'd only ever see
 * call #0 of each class). Eight rounds gives the validation script
 * enough call indices to probabilistically observe at least one fault
 * at PROB=0.1, while still being fast.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int observed_failures = 0;

/* Returns the return code; prints a line documenting the call. We
 * deliberately do NOT use fprintf -- our output goes to stdout, which
 * the harness skips for fault injection, so plain puts is fine. */
#define REPORT(name_, n_, rc_) do {                                    \
        int _saved_errno = errno;                                      \
        char _line[128];                                               \
        int  _w = snprintf(_line, sizeof _line,                        \
                           "E:" name_ "#%d rc=%ld errno=%d\n",         \
                           (int)(n_), (long)(rc_), _saved_errno);      \
        if (_w > 0) (void)!write(1, _line, (size_t)_w);                \
        if ((long)(rc_) < 0 || _saved_errno != 0) observed_failures++; \
        errno = 0;                                                     \
    } while (0)

int main(int argc, char **argv)
{
    const char *dir    = (argc > 1) ? argv[1] : "/tmp";
    int         rounds = (argc > 2) ? atoi(argv[2]) : 8;
    if (rounds < 1) rounds = 1;
    if (rounds > 64) rounds = 64;  /* sanity */

    char path[256];
    snprintf(path, sizeof path, "%s/faultinj_target.dat", dir);

    /* Pre-create the file so a 1st-round failed open doesn't poison
     * the rest of the run with bogus ENOENT downstream. */
    int prep = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (prep >= 0) {
        const char *seed_data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        (void)!write(prep, seed_data, 32);
        close(prep);
    }
    /* Reset errno so the seed-write's incidental errno doesn't bleed
     * into the first REPORT(). */
    errno = 0;

    for (int i = 0; i < rounds; i++) {
        /* open */
        int fd = open(path, O_RDWR);
        REPORT("open", i, fd);

        if (fd >= 0) {
            /* write */
            const char buf_w[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
            ssize_t w = write(fd, buf_w, sizeof buf_w - 1);
            REPORT("write", i, w);

            /* Rewind via lseek so the read sees the bytes we just
             * wrote. lseek isn't hooked by libfaultinj so this is
             * an honest seek. We ignore failures here -- they'd be
             * libc bugs unrelated to fault injection. */
            (void)lseek(fd, 0, SEEK_SET);
            errno = 0;

            /* read */
            char buf_r[32];
            ssize_t r = read(fd, buf_r, sizeof buf_r);
            REPORT("read", i, r);

            /* close */
            int c = close(fd);
            REPORT("close", i, c);
        }
    }

    char done[64];
    int  dn = snprintf(done, sizeof done,
                       "E:done injected=%d\n", observed_failures);
    if (dn > 0) (void)!write(1, done, (size_t)dn);

    /* Clean up our scratch file -- the validation script wants the
     * /tmp scratch dir to be removable. */
    (void)unlink(path);

    return 0;
}
