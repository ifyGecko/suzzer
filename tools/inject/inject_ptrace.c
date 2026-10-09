/*
 * inject_ptrace.c -- ptrace-based libcov injector.
 *
 * Attaches to a running PID via PTRACE_ATTACH, runs remote syscalls and
 * function calls in the target via the "trap-on-return" convention,
 * stages env strings + the libcov path into a target-side scratch page,
 * calls setenv() once per requested env var, then dlopen()s libcov.so
 * (or libcov_mt.so) into the target. Restores registers and detaches.
 *
 * The target resumes from exactly where it was at attach time, but now
 * has libcov's constructor(101) having run: patch table armed, signal
 * handler installed, shared bitmap mapped. End-state is identical to
 * the LD_PRELOAD-at-spawn path.
 *
 * Threading: the injector itself is single-threaded. The TARGET may be
 * multi-threaded (libcov_mt.so case); ptrace attaches all threads
 * via __WALL and only one thread (the one we PTRACE_ATTACHed) runs the
 * remote calls. The other target threads stay stopped because Linux
 * group-stop semantics suspend the whole tgid when one thread is being
 * traced and the others receive SIGSTOP. libcov_mt's atomic bitmap +
 * spinlocked patch table means it's safe to bring up while other
 * threads are mid-execution, so this works without further per-thread
 * coordination from the injector.
 *
 * Limitations (full list in tools/inject/README.md):
 *   - Target must be dynamically linked (no static binaries).
 *   - Target must already have libc in its address space (essentially
 *     always true for non-static binaries).
 *   - PTRACE_ATTACH must succeed (Yama ptrace_scope, CAP_SYS_PTRACE,
 *     one-tracer rule -- use inject_procmem if another tracer holds
 *     the slot).
 *   - libcov.so must be reachable from the target's filesystem view
 *     (chroot/container caveats; injector auto-tries /proc/<pid>/root/).
 */

/* _GNU_SOURCE is set by the Makefile (-D_GNU_SOURCE). */
#include "inject_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <sys/stat.h>
#include <dlfcn.h>

static void
usage(const char *prog)
{
    fprintf(stderr,
"Usage: %s [options] <pid> <libcov.so>\n"
"\n"
"  Inject libcov.so into the running process <pid> via PTRACE_ATTACH +\n"
"  remote dlopen.\n"
"\n"
"Env-var setup (libcov reads these in its constructor):\n"
"  -e KEY=VAL        set env var in target before dlopen (repeatable)\n"
"  -P <patchlist>    sugar for -e LIBCOV_PATCHLIST=<patchlist>\n"
"  -S <shm>          sugar for -e LIBCOV_SHM_PATH=<shm>\n"
"  -M <mode>         sugar for -e LIBCOV_MODE=<mode>    (oneshot|leapfrog)\n"
"  -L <log>          sugar for -e LIBCOV_LOG=<log>\n"
"  -B <boundary>     sugar for -e LIBCOV_BOUNDARY_LIST=<boundary>\n"
"\n"
"dlopen flags:\n"
"  --rtld-now        dlopen with RTLD_NOW (default)\n"
"  --rtld-lazy       dlopen with RTLD_LAZY\n"
"\n"
"Debug:\n"
"  --dry-run         attach, resolve symbols, print the plan; do NOT call\n"
"                    setenv/dlopen. Detaches cleanly.\n"
"  --scratch-size N  bytes to allocate for the in-target scratch page\n"
"                    (default 4096). Increase if you have many or long\n"
"                    -e values.\n"
"  -v                verbose; -vv for debug-level.\n"
"  -h                this help.\n"
"\n"
"Exit status:\n"
"  0  injected; libcov's coverage region exists and carries the LCVS magic\n"
"  1  attach / symbol resolution / remote setenv / dlopen failed\n"
"  2  usage error (bad option, pid, --scratch-size or library path)\n"
"  3  dlopen succeeded but libcov appears inert: no coverage region with\n"
"     the LCVS magic at the -S path (default /libcov_<pid>). Re-run with\n"
"     -L <logfile> to see why, and -e LIBCOV_REQUIRE=1 to make libcov\n"
"     abort instead of running inert.\n"
"\n"
"Example:\n"
"  sudo %s -P /tmp/t.lcv -S /libcov_dropbear -M leapfrog \\\n"
"          $(pgrep dropbear) build/x86_64/libcov_st.so\n",
        prog, prog);
}

/* Exit status when dlopen succeeded but libcov's constructor apparently
 * did not set up a coverage region (it ran inert). */
#define INJECT_EXIT_INERT 3

/* Look up KEY in the target's *initial* environment (/proc/<pid>/environ).
 * Returns 0 and copies the value into out, or -1 if absent/unreadable. */
static int
target_initial_env(pid_t pid, const char *key, char *out, size_t outlen)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/environ", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t klen = strlen(key);
    char buf[4096];
    size_t n = 0;
    int c, found = -1;
    /* Entries are NUL-separated; overlong ones are skipped. */
    while ((c = fgetc(f)) != EOF) {
        if (c != 0) {
            if (n < sizeof buf - 1) buf[n++] = (char)c;
            continue;
        }
        buf[n] = 0;
        if (n > klen && !strncmp(buf, key, klen) && buf[klen] == '=') {
            snprintf(out, outlen, "%s", buf + klen + 1);
            found = 0;   /* keep scanning: last one wins, like getenv */
        }
        n = 0;
    }
    fclose(f);
    return found;
}

/* Value libcov's getenv(KEY) will see in the target: the last -e/-S/...
 * entry for KEY (we setenv them in order), else the target's initial env. */
static const char *
effective_env(const struct env_list *envs, pid_t pid, const char *key,
              char *buf, size_t buflen)
{
    const char *v = NULL;
    for (int i = 0; i < envs->n; i++)
        if (!strcmp(envs->items[i].key, key)) v = envs->items[i].val;
    if (v) return v;
    if (target_initial_env(pid, key, buf, buflen) == 0) return buf;
    return NULL;
}

/* Does `path` (as seen by the injector) start with libcov's "LCVS" shm
 * magic? */
static int
has_lcvs_magic(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) return 0;
    char m[4];
    ssize_t r = read(fd, m, sizeof m);
    close(fd);
    return r == (ssize_t)sizeof m && !memcmp(m, "LCVS", 4);
}

/* Check whether libcov set up its coverage region, following libcov's own
 * LIBCOV_SHM_PATH rules (src/sink_shm.c): unset -> /libcov_<pid>; "%p"
 * expands to the pid; a name with no '/' other than an optional leading
 * one is a POSIX shm object (/dev/shm/NAME, falling back to $TMPDIR/NAME
 * or /tmp/NAME); anything else is a filesystem path. Each candidate is
 * tried through /proc/<pid>/root (or /proc/<pid>/cwd for a relative path)
 * first so chrooted/containerised targets resolve correctly, then as-is.
 * Returns 1 if a region with the LCVS magic exists; fills where/wherelen
 * with the path checked (the first candidate when none matched). */
static int
coverage_region_ok(const struct env_list *envs, pid_t pid,
                   char *where, size_t wherelen)
{
    char envbuf[PATH_MAX], raw[PATH_MAX], name[PATH_MAX + 16];
    const char *v = effective_env(envs, pid, "LIBCOV_SHM_PATH",
                                  envbuf, sizeof envbuf);
    if (!v || !*v) {
        snprintf(raw, sizeof raw, "/libcov_%d", (int)pid);
    } else {
        size_t o = 0;
        for (const char *p = v; *p && o < sizeof raw - 1; p++) {
            if (p[0] == '%' && p[1] == 'p') {
                o += (size_t)snprintf(raw + o, sizeof raw - o, "%d", (int)pid);
                if (o >= sizeof raw) o = sizeof raw - 1;
                p++;
            } else if (p[0] == '%' && p[1] == '%') {
                raw[o++] = '%'; p++;
            } else {
                raw[o++] = *p;
            }
        }
        raw[o] = 0;
    }

    int is_shm = 1;
    for (const char *p = raw + (raw[0] == '/'); *p; p++)
        if (*p == '/') { is_shm = 0; break; }

    const char *cands[2];
    int ncand = 0;
    char tmpbuf[PATH_MAX], fb[2 * PATH_MAX + 2];
    if (is_shm) {
        const char *bare = raw[0] == '/' ? raw + 1 : raw;
        snprintf(name, sizeof name, "/dev/shm/%s", bare);
        cands[ncand++] = name;
        const char *tmpdir = effective_env(envs, pid, "TMPDIR",
                                           tmpbuf, sizeof tmpbuf);
        if (!tmpdir || !*tmpdir) tmpdir = "/tmp";
        snprintf(fb, sizeof fb, "%s/%s", tmpdir, bare);
        cands[ncand++] = fb;
    } else {
        cands[ncand++] = raw;
    }

    snprintf(where, wherelen, "%s", cands[0]);
    for (int i = 0; i < ncand; i++) {
        char viaproc[2 * PATH_MAX + 96];
        snprintf(viaproc, sizeof viaproc, "/proc/%d/%s/%s", (int)pid,
                 cands[i][0] == '/' ? "root" : "cwd",
                 cands[i][0] == '/' ? cands[i] + 1 : cands[i]);
        if (has_lcvs_magic(viaproc) || has_lcvs_magic(cands[i])) {
            snprintf(where, wherelen, "%s", cands[i]);
            return 1;
        }
    }
    return 0;
}

/* Strict decimal parse for a pid: whole string, > 0, fits pid_t. */
static int
parse_pid(const char *s, pid_t *out)
{
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end != 0 || v <= 0 || v > INT_MAX) return -1;
    *out = (pid_t)v;
    return 0;
}

static int
resolve_lib_path(const char *user_path, char *out, size_t outlen)
{
    /* Resolve to an absolute path. If the user gave a relative one, make
     * it absolute (relative to the injector's CWD). The target's dlopen
     * will receive this exact string -- it must work from the target's
     * filesystem view; absolute is the only sane choice. */
    if (user_path[0] == '/') {
        if (strlen(user_path) >= outlen) {
            LOG_ERR("library path too long");
            return -1;
        }
        snprintf(out, outlen, "%s", user_path);
    } else {
        char *real = realpath(user_path, NULL);
        if (!real) {
            LOG_ERR("realpath '%s': %s", user_path, strerror(errno));
            return -1;
        }
        snprintf(out, outlen, "%s", real);
        free(real);
    }
    /* Sanity: the file should exist and be readable from the injector's
     * perspective. We can't easily check the target's view, but a
     * missing file here is virtually always a mistake. */
    struct stat st;
    if (stat(out, &st) < 0) {
        LOG_ERR("stat %s: %s -- libcov.so won't be reachable from target either",
                out, strerror(errno));
        return -1;
    }
    if (!(st.st_mode & S_IRUSR)) {
        LOG_ERR("%s is not readable", out);
        return -1;
    }
    return 0;
}

int
main(int argc, char **argv)
{
    struct env_list envs = {0};
    int dry_run = 0;
    int rtld_flags = 0x00000002;     /* RTLD_NOW */
    size_t scratch_size = 4096;

    static struct option opts[] = {
        { "rtld-now",    no_argument,       0, 1001 },
        { "rtld-lazy",   no_argument,       0, 1002 },
        { "dry-run",     no_argument,       0, 1003 },
        { "scratch-size",required_argument, 0, 1004 },
        { "help",        no_argument,       0, 'h'  },
        { 0, 0, 0, 0 },
    };

    int c;
    while ((c = getopt_long(argc, argv, "e:P:S:M:L:B:vh", opts, NULL)) != -1) {
        switch (c) {
        case 'e':
            if (env_list_add_kv(&envs, optarg) < 0) return 2;
            break;
        case 'P':
            if (env_list_add(&envs, "LIBCOV_PATCHLIST", optarg) < 0) return 2;
            break;
        case 'S':
            if (env_list_add(&envs, "LIBCOV_SHM_PATH", optarg) < 0) return 2;
            break;
        case 'M':
            if (env_list_add(&envs, "LIBCOV_MODE", optarg) < 0) return 2;
            break;
        case 'L':
            if (env_list_add(&envs, "LIBCOV_LOG", optarg) < 0) return 2;
            break;
        case 'B':
            if (env_list_add(&envs, "LIBCOV_BOUNDARY_LIST", optarg) < 0) return 2;
            break;
        case 'v':
            inject_verbose++;
            break;
        case 1001: rtld_flags = 0x00000002; break;   /* RTLD_NOW */
        case 1002: rtld_flags = 0x00000001; break;   /* RTLD_LAZY */
        case 1003: dry_run = 1; break;
        case 1004: {
            /* strtoul silently accepts "-1" (as ULONG_MAX) and trailing
             * junk; reject both. Base 0: decimal, 0x hex or 0 octal. */
            char *end;
            const char *a = optarg;
            while (*a == ' ' || *a == '\t') a++;
            errno = 0;
            unsigned long v = strtoul(a, &end, 0);
            if (*a == '-' || end == a || *end != 0 || errno == ERANGE) {
                LOG_ERR("invalid --scratch-size '%s' (expected a byte count, "
                        "e.g. 8192 or 0x2000)", optarg);
                return 2;
            }
            scratch_size = (size_t)v;
            if (scratch_size < 256) {
                LOG_ERR("--scratch-size minimum is 256 bytes");
                return 2;
            }
            break;
        }
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }

    if (optind + 2 != argc) {
        usage(argv[0]);
        return 2;
    }

    pid_t pid;
    if (parse_pid(argv[optind], &pid) < 0) {
        LOG_ERR("invalid pid '%s' (expected a positive decimal process id)",
                argv[optind]);
        return 2;
    }
    const char *user_libpath = argv[optind + 1];

    char libpath[PATH_MAX];
    if (resolve_lib_path(user_libpath, libpath, sizeof libpath) < 0) return 2;

    /* If the user didn't set LIBCOV_PATCHLIST via -e or -P, libcov will
     * be inert -- warn but don't refuse. The user may be using the
     * injector to debug-load libcov without instrumenting. */
    int have_patchlist = 0;
    for (int i = 0; i < envs.n; i++) {
        if (!strcmp(envs.items[i].key, "LIBCOV_PATCHLIST")) {
            have_patchlist = 1;
            break;
        }
    }
    if (!have_patchlist) {
        LOG_INFO("warning: no LIBCOV_PATCHLIST set; libcov will run inert "
                 "(constructor returns without arming)");
    }

    struct inject_session s;
    if (inject_attach(&s, pid) < 0) return 1;

    if (inject_resolve_symbols(&s) < 0) {
        inject_detach(&s);
        return 1;
    }

    if (dry_run) {
        printf("=== dry-run plan for pid=%d arch=%s ===\n", (int)pid, s.arch->name);
        printf("  trap_pc     = 0x%lx\n", (unsigned long)s.trap_pc);
        printf("  syscall_pc  = 0x%lx\n", (unsigned long)s.syscall_pc);
        printf("  setenv      = 0x%lx\n", (unsigned long)s.addr_setenv);
        printf("  dlopen      = 0x%lx (%s)\n",
               (unsigned long)s.addr_dlopen,
               s.dlopen_is_libc_mode ? "__libc_dlopen_mode" : "dlopen");
        if (s.addr_dlerror)
            printf("  dlerror     = 0x%lx\n", (unsigned long)s.addr_dlerror);
        printf("  libpath     = %s\n", libpath);
        printf("  rtld_flags  = 0x%x%s\n", rtld_flags,
               s.dlopen_is_libc_mode ? " (will OR __RTLD_DLOPEN=0x80000000)" : "");
        printf("  env vars (%d):\n", envs.n);
        for (int i = 0; i < envs.n; i++)
            printf("    %s=%s\n", envs.items[i].key, envs.items[i].val);
        printf("=== end plan (no remote calls performed) ===\n");
        inject_detach(&s);
        return 0;
    }

    if (inject_alloc_scratch(&s, scratch_size) < 0) {
        inject_detach(&s);
        return 1;
    }

    /* setenv loop. We do these BEFORE dlopen so libcov's constructor
     * sees them via getenv(). */
    for (int i = 0; i < envs.n; i++) {
        if (inject_setenv(&s, envs.items[i].key, envs.items[i].val) < 0) {
            inject_detach(&s);
            return 1;
        }
    }

    /* The big one. */
    uintptr_t handle = 0;
    if (inject_dlopen(&s, libpath, rtld_flags, &handle) < 0) {
        inject_detach(&s);
        return 1;
    }
    if (!handle) {
        char err[512];
        if (inject_dlerror(&s, err, sizeof err) == 0 && err[0]) {
            LOG_ERR("target dlopen('%s') returned NULL: %s", libpath, err);
        } else {
            LOG_ERR("target dlopen('%s') returned NULL (dlerror not available "
                    "or empty)", libpath);
        }
        inject_detach(&s);
        return 1;
    }
    LOG_INFO("dlopen handle = 0x%lx", (unsigned long)handle);

    /* Detach. Saved regs restore -> target resumes from exact prior PC
     * with libcov fully initialised. */
    inject_detach(&s);

    printf("injected %s into pid %d (arch=%s, handle=0x%lx)\n",
           libpath, (int)pid, s.arch->name, (unsigned long)handle);

    /* dlopen returning a handle only means the library loaded. libcov's
     * constructor runs inside that dlopen and, on any init failure, logs
     * and returns inert (unless LIBCOV_REQUIRE is set). The first thing a
     * working init does is create the coverage region with the LCVS magic,
     * so its absence means coverage will never appear. */
    char region[PATH_MAX];
    if (!coverage_region_ok(&envs, pid, region, sizeof region)) {
        fflush(stdout);
        fprintf(stderr,
                "inject: WARNING: libcov appears inert in pid %d: no coverage "
                "region with LCVS magic at %s\n"
                "inject:   re-run with -L <logfile> to see libcov's init log, "
                "and -e LIBCOV_REQUIRE=1 to make libcov abort instead of "
                "running inert; exiting with status %d\n",
                (int)pid, region, INJECT_EXIT_INERT);
        return INJECT_EXIT_INERT;
    }
    LOG_INFO("coverage region %s present (LCVS)", region);
    return 0;
}
