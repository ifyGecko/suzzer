/*
 * target_netd.c -- a tiny single-process TCP "network daemon" used as the
 * template remote-fuzzing target. It is NOT a fork-per-connection server:
 * one process accepts connections in a loop and handles each request inline,
 * so all coverage lands in one libcov region (the tractable model for the
 * remote template; see HOWTO.md Pattern C and its limitations).
 *
 * Paired boundary markers wrap the request handler:
 *   for (;;) { c = accept(); req_begin(); handle(req); req_end(); close(c); }
 * so libcov publishes one ITER snapshot per request (handle()'s coverage)
 * and a GAP snapshot for the accept/read between requests. suzzer-relay
 * delivers one input per connection and forwards each snapshot to the brain.
 *
 * Usage: target_netd <port-file>
 *   Binds 127.0.0.1 on an ephemeral port, writes "<port>\n" to <port-file>
 *   (so the relay/test can discover it without a fixed port), then serves.
 *
 * Input 'X...' calls abort() -- the planted crash path the relay reports.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* Marker shape as in target_paired.c/target_loop.c: the impossible branch
 * gives the first block a patchable, emulatable multi-byte terminator. */
__attribute__((noinline, used)) void req_begin(unsigned i) {
    if (i == 0xffffffffu) abort();
    __asm__ __volatile__("" : : "r"(i) : "memory");
}
__attribute__((noinline, used)) void req_end(unsigned i) {
    if (i == 0xffffffffu) abort();
    __asm__ __volatile__("" : : "r"(i) : "memory");
}

__attribute__((noinline)) static int work_a(const char *b, int n) {
    int s = 0;
    for (int i = 1; i < n; i++) s += (b[i] & 1) ? 1 : 2;   /* even/odd branch */
    return s;
}
__attribute__((noinline)) static int work_b(const char *b, int n) {
    return (n > 4 && b[1] == 'z') ? 42 : 7;
}
__attribute__((noinline)) static int work_c(const char *b, int n) {
    return b[n - 1] == '!' ? 100 : 0;
}
__attribute__((noinline)) static int deep(const char *b, int n) {
    return (b[2] == '/' || b[3] == '/') ? n * 2 : n;      /* "path"-ish */
}

/* Branchy request parser: distinct first bytes take distinct paths, so
 * different inputs produce different coverage. 'X' is the crash path. */
__attribute__((noinline)) static int handle(const char *b, int n) {
    if (n <= 0) return -1;                 /* E:empty */
    int r;
    switch (b[0]) {
    case 'A': r = work_a(b, n); break;
    case 'B': r = work_b(b, n); break;
    case 'C': r = work_c(b, n); break;
    case 'X': abort();                     /* planted crash */
    default:  r = 0; break;
    }
    if (n > 8) r += deep(b, n);
    return r;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port-file>\n", argv[0]);
        return 2;
    }
    const char *port_file = argv[1];

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;                        /* ephemeral */
    if (bind(srv, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 1; }
    if (listen(srv, 16) < 0) { perror("listen"); return 1; }

    socklen_t al = sizeof a;
    if (getsockname(srv, (struct sockaddr *)&a, &al) < 0) { perror("getsockname"); return 1; }
    unsigned port = ntohs(a.sin_port);

    /* Publish the chosen port atomically (write temp, rename). */
    char tmp[256];
    snprintf(tmp, sizeof tmp, "%s.tmp", port_file);
    FILE *pf = fopen(tmp, "w");
    if (!pf) { perror("fopen port-file"); return 1; }
    fprintf(pf, "%u\n", port);
    fclose(pf);
    rename(tmp, port_file);

    for (unsigned i = 0;; i++) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;
        req_begin(i);
        char buf[512];
        ssize_t n = read(c, buf, sizeof buf);
        int r = handle(buf, (int)n);
        char reply[64];
        int rl = snprintf(reply, sizeof reply, "R:%d\n", r);
        (void)!write(c, reply, (size_t)rl);
        req_end(i);
        close(c);
    }
    return 0;
}
