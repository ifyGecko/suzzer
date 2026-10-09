/*
 * suzzer-relay.c -- on-device coverage relay for remote (over-IP) fuzzing.
 *
 * Runs on the target device. Spawns a single-process network daemon under
 * libcov, then bridges between the daemon and an off-device "brain" over one
 * TCP connection (protocol in relay_proto.h):
 *
 *   - delivers each INPUT frame to the daemon's own listening port
 *     (127.0.0.1:<target-port>), one connection per input;
 *   - wakes on the libcov boundary eventfd, reads the snapshot ring with the
 *     shared seqlock reader (src/ring_reader.h), and sends the request's ITER
 *     snapshot back as a COVERAGE frame;
 *   - reports a dead daemon as a CRASH frame and restarts it.
 *
 * The relay parses the shm header on the device, so the brain never sees a
 * foreign-ABI header: COVERAGE carries decoded map_size + raw uint8 counters.
 * Lockstep: one INPUT in flight at a time; every INPUT gets exactly one
 * COVERAGE or CRASH reply. See HOWTO.md Pattern C and Design.md
 * "Remote coverage transport".
 *
 * This is a reference template, not a hardened server: plain TCP, no auth,
 * single daemon, single-process targets. Limitations are documented.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "relay_proto.h"
#include "../src/ring_reader.h"

/* ---- small byte/IO helpers ------------------------------------------- */

static int write_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        p += w; n -= (size_t)w;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t n) {
    uint8_t *p = buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;  /* EOF */
        p += r; n -= (size_t)r;
    }
    return 0;
}

static void put_u16(uint8_t *p, uint16_t v) { v = htons(v); memcpy(p, &v, 2); }
static void put_u32(uint8_t *p, uint32_t v) { v = htonl(v); memcpy(p, &v, 4); }
static void put_u64(uint8_t *p, uint64_t v) { v = htobe64(v); memcpy(p, &v, 8); }
static uint64_t get_u64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return be64toh(v); }
static uint32_t get_u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return ntohl(v); }

/* Send one frame: [u32 len][u8 type][payload], len = 1 + plen. */
static int send_frame(int fd, uint8_t type, const void *payload, uint32_t plen) {
    uint8_t hdr[5];
    put_u32(hdr, plen + 1);
    hdr[4] = type;
    if (write_all(fd, hdr, 5) < 0) return -1;
    if (plen && write_all(fd, payload, plen) < 0) return -1;
    return 0;
}

/* Receive one frame. Allocates *payload (plen bytes); caller frees. */
static int recv_frame(int fd, uint8_t *type, uint8_t **payload, uint32_t *plen) {
    uint8_t lenbuf[4];
    if (read_all(fd, lenbuf, 4) < 0) return -1;
    uint32_t len = get_u32(lenbuf);
    if (len < 1 || len > (64u << 20)) return -1;   /* 64 MiB sanity cap */
    uint8_t t;
    if (read_all(fd, &t, 1) < 0) return -1;
    uint32_t pl = len - 1;
    uint8_t *buf = NULL;
    if (pl) {
        buf = malloc(pl);
        if (!buf) return -1;
        if (read_all(fd, buf, pl) < 0) { free(buf); return -1; }
    }
    *type = t; *payload = buf; *plen = pl;
    return 0;
}

/* ---- TCP ------------------------------------------------------------- */

static int connect_tcp(const char *host, const char *port) {
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Deliver one input to the daemon on 127.0.0.1:<port>: connect, write all,
 * half-close, drain the reply. Returns 0 on success, -1 if we couldn't
 * connect/write (the daemon is probably dead). */
static int deliver(unsigned port, const uint8_t *data, uint32_t len) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    if (len && write_all(fd, data, len) < 0) { close(fd); return -1; }
    shutdown(fd, SHUT_WR);
    /* Drain the daemon's reply; EOF arrives after it closes, which (for a
     * paired-marker target) happens after req_end has fired the boundary. */
    uint8_t sink[256];
    while (read(fd, sink, sizeof sink) > 0) { }
    close(fd);
    return 0;
}

/* ---- target lifecycle ------------------------------------------------- */

struct target_cfg {
    char      **argv;        /* target + args, NULL-terminated */
    const char *lib, *plist, *blist, *shm;
    int         notify_fd;   /* inherited eventfd, passed via env */
};

static pid_t spawn_target(const struct target_cfg *c) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        setenv("LD_PRELOAD", c->lib, 1);
        setenv("LIBCOV_PATCHLIST", c->plist, 1);
        setenv("LIBCOV_BOUNDARY_LIST", c->blist, 1);
        setenv("LIBCOV_SHM_PATH", c->shm, 1);
        if (!getenv("LIBCOV_MODE")) setenv("LIBCOV_MODE", "leapfrog", 1);
        char fdbuf[16];
        snprintf(fdbuf, sizeof fdbuf, "%d", c->notify_fd);
        setenv("LIBCOV_BOUNDARY_NOTIFY_FD", fdbuf, 1);
        /* Keep the eventfd open across exec (libcov re-opens nothing). */
        int fl = fcntl(c->notify_fd, F_GETFD);
        if (fl >= 0) fcntl(c->notify_fd, F_SETFD, fl & ~FD_CLOEXEC);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); close(devnull); }
        execv(c->argv[0], c->argv);
        perror("execv target");
        _exit(127);
    }
    return pid;
}

/* Read the ephemeral port the daemon wrote to its port-file. */
static int read_port_file(const char *path, unsigned timeout_ms, unsigned *port) {
    unsigned waited = 0;
    for (;;) {
        FILE *f = fopen(path, "r");
        if (f) {
            unsigned p = 0;
            int ok = fscanf(f, "%u", &p) == 1 && p != 0;
            fclose(f);
            if (ok) { *port = p; return 0; }
        }
        if (waited >= timeout_ms) return -1;
        struct timespec sl = {0, 10000000};  /* 10 ms */
        nanosleep(&sl, NULL);
        waited += 10;
    }
}

/* ---- snapshot capture ------------------------------------------------- */

struct capture {
    uint8_t *buf;        /* map_size bytes */
    size_t   map_size;
    int      have;       /* copied anything */
    int      have_iter;  /* copied an ITER snapshot (preferred) */
    uint64_t gen;
    uint64_t kind;
};

static void cap_cb(uint64_t gen, const uint8_t *bm, size_t map_size,
                   uint64_t tid, uint64_t ns, uint64_t flags, void *user) {
    (void)tid; (void)ns;
    struct capture *c = user;
    int is_iter = (flags == LIBCOV_SLOT_FLAG_ITER);
    /* Prefer the ITER snapshot (this request's handler coverage); fall back
     * to the latest non-ITER (INIT/GAP) only if no ITER appeared. */
    if (is_iter || !c->have_iter) {
        memcpy(c->buf, bm, map_size);
        c->gen = gen; c->kind = flags; c->have = 1;
        if (is_iter) c->have_iter = 1;
    }
}

/* Clear a pending eventfd notification. The eventfd is non-blocking
 * (EFD_NONBLOCK), so a read on an empty counter returns EAGAIN rather than
 * blocking -- essential, since we drain before the first boundary ever
 * fires. */
static void drain_eventfd(int efd) {
    uint64_t v;
    while (read(efd, &v, sizeof v) == (ssize_t)sizeof v) { }
}

static void usage(const char *a0) {
    fprintf(stderr,
      "usage: %s --brain HOST:PORT --port-file PATH --libcov SO\n"
      "          --patchlist LCV --boundary LCVB [--shm PATH] -- TARGET [args...]\n"
      "  Spawns TARGET under libcov, bridges coverage to the brain over TCP.\n"
      "  TARGET must bind 127.0.0.1 and write its port to PATH (see target_netd.c).\n",
      a0);
}

int main(int argc, char **argv) {
    const char *brain = NULL, *port_file = NULL, *lib = NULL;
    const char *plist = NULL, *blist = NULL, *shm = NULL;
    char **targv = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { targv = &argv[i + 1]; break; }
        else if (!strcmp(argv[i], "--brain") && i + 1 < argc) brain = argv[++i];
        else if (!strcmp(argv[i], "--port-file") && i + 1 < argc) port_file = argv[++i];
        else if (!strcmp(argv[i], "--libcov") && i + 1 < argc) lib = argv[++i];
        else if (!strcmp(argv[i], "--patchlist") && i + 1 < argc) plist = argv[++i];
        else if (!strcmp(argv[i], "--boundary") && i + 1 < argc) blist = argv[++i];
        else if (!strcmp(argv[i], "--shm") && i + 1 < argc) shm = argv[++i];
        else { usage(argv[0]); return 2; }
    }
    if (!brain || !port_file || !lib || !plist || !blist || !targv || !targv[0]) {
        usage(argv[0]); return 2;
    }
    char brain_host[256], *brain_port;
    snprintf(brain_host, sizeof brain_host, "%s", brain);
    brain_port = strchr(brain_host, ':');
    if (!brain_port) { fprintf(stderr, "--brain must be HOST:PORT\n"); return 2; }
    *brain_port++ = 0;

    char shm_buf[128];
    if (!shm) {
        snprintf(shm_buf, sizeof shm_buf, "/tmp/libcov_relay_%d", (int)getpid());
        shm = shm_buf;
    }
    signal(SIGPIPE, SIG_IGN);

    /* Non-blocking so drain_eventfd never blocks on an empty counter; no
     * CLOEXEC so the target inherits it for LIBCOV_BOUNDARY_NOTIFY_FD. */
    int efd = eventfd(0, EFD_NONBLOCK);
    if (efd < 0) { perror("eventfd"); return 1; }

    struct target_cfg cfg = { targv, lib, plist, blist, shm, efd };

    /* ---- spawn target, discover its port, attach to coverage ---- */
    unlink(shm);
    unlink(port_file);
    pid_t pid = spawn_target(&cfg);
    if (pid < 0) return 1;

    unsigned target_port = 0;
    if (read_port_file(port_file, 3000, &target_port) != 0) {
        fprintf(stderr, "relay: target never published its port to %s\n", port_file);
        kill(pid, SIGKILL); waitpid(pid, NULL, 0); return 1;
    }

    void *shm_base = NULL; size_t shm_size = 0, map_size = 0;
    if (rr_attach(shm, 1 /*require_active*/, 3000,
                  &shm_base, &shm_size, &map_size) != 0) {
        fprintf(stderr, "relay: coverage region never activated at %s\n", shm);
        kill(pid, SIGKILL); waitpid(pid, NULL, 0); return 1;
    }
    volatile struct libcov_shm_header *hdr = shm_base;

    /* ---- connect to the brain, send HELLO ---- */
    int bfd = connect_tcp(brain_host, brain_port);
    if (bfd < 0) {
        fprintf(stderr, "relay: cannot connect to brain %s:%s\n", brain_host, brain_port);
        kill(pid, SIGKILL); waitpid(pid, NULL, 0); return 1;
    }
    { int one = 1; setsockopt(bfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one); }
    if (write_all(bfd, SZR_MAGIC, 4) < 0) { perror("send magic"); return 1; }

    struct utsname un;
    uname(&un);
    uint16_t arch_len = (uint16_t)strlen(un.machine);
    uint32_t hflags = __atomic_load_n((uint32_t *)&hdr->flags, __ATOMIC_ACQUIRE);
    uint8_t hello[12 + sizeof un.machine];
    put_u16(hello + 0, (uint16_t)SZR_PROTO_VERSION);
    uint16_t wire_flags = 0;
    if (hflags & LIBCOV_SHM_FLAG_MT)         wire_flags |= SZR_HELLO_FLAG_MT;
    if (hflags & LIBCOV_SHM_FLAG_LIVE_EMPTY) wire_flags |= SZR_HELLO_FLAG_LIVE_EMPTY;
    if (hflags & LIBCOV_SHM_FLAG_SCHEME) {
        wire_flags |= SZR_HELLO_FLAG_SCHEME;
        if (hflags & LIBCOV_SHM_FLAG_MODEL_PC) wire_flags |= SZR_HELLO_FLAG_MODEL_PC;
        if (hflags & LIBCOV_SHM_FLAG_ROTATE)   wire_flags |= SZR_HELLO_FLAG_ROTATE;
        wire_flags |= (uint16_t)(LIBCOV_SHM_NGRAM(hflags) << SZR_HELLO_NGRAM_SHIFT);
    }
    put_u16(hello + 2, wire_flags);
    put_u32(hello + 4, (uint32_t)map_size);
    put_u16(hello + 8, (uint16_t)hdr->ring_size);
    put_u16(hello + 10, arch_len);
    memcpy(hello + 12, un.machine, arch_len);
    if (send_frame(bfd, SZR_HELLO, hello, 12u + arch_len) < 0) {
        perror("send HELLO"); return 1;
    }

    uint8_t *scratch = malloc(map_size);
    uint8_t *capbuf  = malloc(map_size);
    uint8_t *txbuf   = malloc(map_size + 64);
    if (!scratch || !capbuf || !txbuf) { fprintf(stderr, "relay: OOM\n"); return 1; }

    /* ---- main loop: one INPUT -> one COVERAGE or CRASH ---- */
    int rc = 0;
    for (;;) {
        uint8_t type, *payload = NULL; uint32_t plen = 0;
        if (recv_frame(bfd, &type, &payload, &plen) < 0) break;  /* brain gone */
        if (type == SZR_BYE) { free(payload); break; }
        if (type != SZR_INPUT || plen < 12) { free(payload); continue; }

        uint64_t id = get_u64(payload);
        uint32_t len = get_u32(payload + 8);
        if (12u + len > plen) { free(payload); continue; }
        const uint8_t *data = payload + 12;

        uint64_t prev_gen = __atomic_load_n((uint64_t *)&hdr->gen_current,
                                            __ATOMIC_ACQUIRE);
        drain_eventfd(efd);

        int delivered = deliver(target_port, data, len);

        /* Wait for the boundary notification, then collect snapshots. The
         * eventfd is the wakeup; gen_current is the source of truth. */
        struct pollfd pfd = { efd, POLLIN, 0 };
        poll(&pfd, 1, 2000);
        drain_eventfd(efd);

        uint64_t new_gen = __atomic_load_n((uint64_t *)&hdr->gen_current,
                                           __ATOMIC_ACQUIRE);
        struct capture cap = { capbuf, map_size, 0, 0, 0, 0 };
        struct rr_stats st = {0};
        uint64_t cg = prev_gen;
        rr_drain_to(shm_base, &cg, new_gen, scratch, map_size, &st, cap_cb, &cap);

        /* Did the daemon die handling this input? */
        int status = 0;
        pid_t w = waitpid(pid, &status, WNOHANG);
        int dead = (w == pid);

        if (dead) {
            uint8_t cb[13];
            put_u64(cb, id);
            if (WIFSIGNALED(status)) { cb[8] = SZR_CRASH_SIGNAL; put_u32(cb + 9, (uint32_t)WTERMSIG(status)); }
            else                     { cb[8] = SZR_CRASH_EXIT;   put_u32(cb + 9, (uint32_t)WEXITSTATUS(status)); }
            if (send_frame(bfd, SZR_CRASH, cb, sizeof cb) < 0) { free(payload); break; }

            /* Restart the daemon and re-attach for the next input. */
            munmap(shm_base, shm_size); shm_base = NULL;
            unlink(shm); unlink(port_file);
            pid = spawn_target(&cfg);
            if (pid < 0) { free(payload); rc = 1; break; }
            if (read_port_file(port_file, 3000, &target_port) != 0 ||
                rr_attach(shm, 1, 3000, &shm_base, &shm_size, &map_size) != 0) {
                fprintf(stderr, "relay: restart failed\n");
                free(payload); rc = 1; break;
            }
            hdr = shm_base;
            free(payload);
            continue;
        }

        if (delivered < 0 && !cap.have) {
            /* Couldn't even connect, but the process is still alive -- report
             * it so the brain isn't left waiting. */
            uint8_t cb[13];
            put_u64(cb, id); cb[8] = SZR_CRASH_DELIVERY; put_u32(cb + 9, 0);
            if (send_frame(bfd, SZR_CRASH, cb, sizeof cb) < 0) { free(payload); break; }
            free(payload);
            continue;
        }

        /* Normal path: send the request's snapshot (prefer ITER). If nothing
         * was published (unexpected for a paired-marker target), send an
         * empty map so the brain's lockstep still advances. */
        put_u64(txbuf + 0, id);
        put_u64(txbuf + 8, cap.have ? cap.gen : new_gen);
        txbuf[16] = (uint8_t)(cap.have ? cap.kind : 0);
        put_u32(txbuf + 17, (uint32_t)map_size);
        if (cap.have) memcpy(txbuf + 21, capbuf, map_size);
        else          memset(txbuf + 21, 0, map_size);
        if (send_frame(bfd, SZR_COVERAGE, txbuf, 21u + (uint32_t)map_size) < 0) {
            free(payload); break;
        }
        free(payload);
    }

    if (shm_base) munmap(shm_base, shm_size);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    unlink(shm); unlink(port_file);
    close(bfd); close(efd);
    free(scratch); free(capbuf); free(txbuf);
    return rc;
}
