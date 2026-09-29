/*
 * target_reexec.c -- daemons that exec themselves (sshd, nginx upgrade).
 *
 *   a         -- work_a() only.
 *   b         -- work_b() only.
 *   reexec    -- work_a(), 3 iteration markers, then execv(/proc/self/exe)
 *                in place (same pid) into "after": 3 more markers and
 *                work_b(). libcov's re-init in the new image must attach
 *                to the shared region, not zero it under the driver.
 *   forkexec  -- work_a(), then fork a child that execs "b" while this
 *                process stays alive, then work_a() again. The child must
 *                not clobber the live parent's region.
 *
 * Prints "pid=<n>" (and "child=<n>" for forkexec) so the test can find
 * per-process regions (LIBCOV_SHM_PATH with %p).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

__attribute__((noinline)) int work_a(int x) {
    int r = 0;
    if (x > 3) r += x * 7; else r -= x;
    if (r % 5 == 0) r++;
    return r;
}

__attribute__((noinline)) int work_b(int x) {
    int r = 1;
    for (int i = 0; i < x; i++) r = (r & 1) ? r * 3 + 1 : r / 2;
    return r;
}

/* Iteration marker, shaped like target_loop's: the impossible branch
 * gives the first block a patchable multi-byte terminator. */
__attribute__((noinline, used)) void iter_begin(unsigned iter) {
    if (iter == 0xffffffffu) abort();
    __asm__ __volatile__("" : : "r"(iter) : "memory");
}

static void markers(unsigned from) {
    for (unsigned i = from; i < from + 3; i++) iter_begin(i);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *m = argv[1];
    printf("pid=%d\n", (int)getpid());
    fflush(stdout);
    if (!strcmp(m, "a")) {
        printf("a=%d\n", work_a(argc + 5));
    } else if (!strcmp(m, "b")) {
        printf("b=%d\n", work_b(argc + 5));
    } else if (!strcmp(m, "reexec")) {
        printf("a=%d\n", work_a(argc + 5));
        markers(0);
        fflush(stdout);
        char *args[] = { argv[0], (char *)"after", NULL };
        execv("/proc/self/exe", args);
        perror("execv");
        return 1;
    } else if (!strcmp(m, "after")) {
        markers(3);
        printf("b=%d\n", work_b(argc + 5));
    } else if (!strcmp(m, "forkexec")) {
        printf("a=%d\n", work_a(argc + 5));
        fflush(stdout);
        pid_t c = fork();
        if (c == 0) {
            char *args[] = { argv[0], (char *)"b", NULL };
            execv("/proc/self/exe", args);
            _exit(127);
        }
        int st = 0;
        waitpid(c, &st, 0);
        printf("child=%d rc=%d\n", (int)c, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        printf("a=%d\n", work_a(argc + 1));
    }
    return 0;
}
