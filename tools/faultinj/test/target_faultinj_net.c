/*
 * target_faultinj_net.c -- socket-API exerciser for the libfaultinj
 *                          validation harness.
 *
 * Uses socketpair(AF_UNIX, SOCK_STREAM, 0) to get a connected pair of
 * sockets without touching the network stack -- no port conflicts, no
 * loopback timing, no need for the test machine to allow binds to
 * 127.0.0.1. socketpair() is NOT hooked by libfaultinj (it's not in
 * the v1 class set), so the pair is always available; we then
 * exercise the hooked calls (socket, accept, recv, send) against the
 * pair.
 *
 * Note about accept(): we call it against the connected (non-listening)
 * socketpair fd, so the REAL return is always -1/EINVAL. A faulted
 * accept also returns -1 but sets errno from the FI_CLS_ACCEPT pool
 * (EMFILE / ENFILE / ENOBUFS / ECONNABORTED). The harness greps for
 * those errnos to distinguish faulted from unfaulted accept calls.
 *
 * Output schema (one line per call):
 *
 *   E:socket#<n> rc=<int> errno=<int>
 *   E:accept#<n> rc=<int> errno=<int>
 *   E:send#<n>   rc=<int> errno=<int>
 *   E:recv#<n>   rc=<int> errno=<int>
 *   E:done injected_or_faulted=<count>
 *
 * Argv:
 *
 *   argv[1] = number of rounds (default 8)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int observed_failures = 0;

#define REPORT(name_, n_, rc_) do {                                    \
        int _saved_errno = errno;                                      \
        char _line[128];                                               \
        int  _w = snprintf(_line, sizeof _line,                        \
                           "E:" name_ "#%d rc=%ld errno=%d\n",         \
                           (int)(n_), (long)(rc_), _saved_errno);      \
        if (_w > 0) (void)!write(1, _line, (size_t)_w);                \
        if ((long)(rc_) < 0) observed_failures++;                      \
        errno = 0;                                                     \
    } while (0)

int main(int argc, char **argv)
{
    int rounds = (argc > 1) ? atoi(argv[1]) : 8;
    if (rounds < 1) rounds = 1;
    if (rounds > 64) rounds = 64;

    /* Connected pair: sp[0] and sp[1] talk to each other. socketpair
     * itself is not in our class set; the call counters are not
     * touched here. */
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
        fprintf(stderr, "socketpair: %s\n", strerror(errno));
        return 1;
    }

    /* Mark both ends nonblocking. If a send() in a given round is
     * faulted (returns -1 without enqueueing bytes), the subsequent
     * recv() would otherwise block forever waiting for data that
     * never arrives. With O_NONBLOCK an empty recv returns -1/EAGAIN
     * promptly and the test moves on. fcntl is not in our hook set
     * so this isn't perturbed by injection. */
    fcntl(sp[0], F_SETFL, fcntl(sp[0], F_GETFL, 0) | O_NONBLOCK);
    fcntl(sp[1], F_SETFL, fcntl(sp[1], F_GETFL, 0) | O_NONBLOCK);
    errno = 0;

    for (int i = 0; i < rounds; i++) {
        /* socket() -- standalone call. We close immediately if it
         * worked so the fd table doesn't grow. A faulted call returns
         * -1, so the close branch is skipped. */
        int s = socket(AF_INET, SOCK_STREAM, 0);
        REPORT("socket", i, s);
        if (s >= 0) {
            /* The close() here goes through libfaultinj's close hook
             * too, but with armed seed it competes with the actual
             * faultable calls. We don't report it. */
            close(s);
            errno = 0;
        }

        /* accept() against sp[0]. Unfaulted -> -1/EINVAL because sp[0]
         * is not a listener. Faulted -> -1 with errno from the accept
         * pool. The harness uses the errno value to distinguish. */
        int a = accept(sp[0], NULL, NULL);
        REPORT("accept", i, a);
        if (a >= 0) close(a);  /* shouldn't happen, but tidy up */

        /* send() one byte through sp[0]. */
        const char payload[32] = "abcdefghijklmnopqrstuvwxyz01234";
        ssize_t ws = send(sp[0], payload, sizeof payload, 0);
        REPORT("send", i, ws);

        /* recv() on sp[1]. Unfaulted -> sizeof(payload) (or short if
         * send was short). Faulted: -1, or 0, or a short positive. */
        char rbuf[32];
        ssize_t rs = recv(sp[1], rbuf, sizeof rbuf, 0);
        REPORT("recv", i, rs);

        /* If the previous send was successful and we recv'd LESS than
         * what we sent (e.g. real partial send was 14 bytes), drain
         * any leftover bytes so the next iter starts clean. We use
         * MSG_DONTWAIT so this is non-blocking. */
        while (1) {
            ssize_t drain = recv(sp[1], rbuf, sizeof rbuf, MSG_DONTWAIT);
            if (drain <= 0) break;
        }
        errno = 0;
    }

    close(sp[0]);
    close(sp[1]);

    char done[64];
    int  dn = snprintf(done, sizeof done,
                       "E:done injected_or_faulted=%d\n", observed_failures);
    if (dn > 0) (void)!write(1, done, (size_t)dn);
    return 0;
}
