/*
 * fuzz_driver.c -- toy external driver. mmaps the libcov bitmap, executes
 * the target under LD_PRELOAD with each argv input from stdin lines, and
 * prints a summary of newly-discovered edges per run.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdint.h>

#define MAP_SIZE 65536u

static int open_bitmap(const char *path, uint8_t **out) {
    int fd = open(path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) { perror("open bitmap"); return -1; }
    if (ftruncate(fd, MAP_SIZE) < 0) { perror("ftruncate"); close(fd); return -1; }
    void *m = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) { perror("mmap"); return -1; }
    *out = (uint8_t *)m;
    return 0;
}

static unsigned count_set(const uint8_t *map) {
    unsigned c = 0;
    for (unsigned i = 0; i < MAP_SIZE; i++) if (map[i]) c++;
    return c;
}

static unsigned count_new(const uint8_t *cur, uint8_t *cumulative) {
    unsigned newly = 0;
    for (unsigned i = 0; i < MAP_SIZE; i++) {
        if (cur[i] && !cumulative[i]) { newly++; cumulative[i] = cur[i]; }
    }
    return newly;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
                "usage: %s <libcov.so> <patchlist> <target> [target args...]\n"
                "  Inputs read from stdin, one per line, appended as the LAST argv.\n",
                argv[0]);
        return 2;
    }
    const char *lib = argv[1];
    const char *plist = argv[2];
    const char *target = argv[3];

    char bitmap_path[128];
    snprintf(bitmap_path, sizeof bitmap_path, "/tmp/libcov_driver_%d", (int)getpid());

    uint8_t *bitmap = NULL;
    if (open_bitmap(bitmap_path, &bitmap) < 0) return 1;

    uint8_t cumulative[MAP_SIZE];
    memset(cumulative, 0, sizeof cumulative);

    char line[1024];
    unsigned iter = 0;
    while (fgets(line, sizeof line, stdin)) {
        size_t L = strlen(line);
        if (L && line[L - 1] == '\n') line[L - 1] = 0;

        /* Zero map for this iteration. */
        memset(bitmap, 0, MAP_SIZE);

        pid_t pid = fork();
        if (pid == 0) {
            char envlib[512], envmap[256], envmod[512];
            snprintf(envlib, sizeof envlib, "LD_PRELOAD=%s", lib);
            snprintf(envmap, sizeof envmap, "LIBCOV_SHM_PATH=%s", bitmap_path);
            snprintf(envmod, sizeof envmod, "LIBCOV_PATCHLIST=%s", plist);
            putenv(envlib);
            putenv(envmap);
            putenv(envmod);

            int nargs = argc - 3 + 1 + 1; /* target + passed-args + input + NULL */
            char **ar = calloc(nargs + 1, sizeof(char *));
            int k = 0;
            ar[k++] = (char *)target;
            for (int i = 4; i < argc; i++) ar[k++] = argv[i];
            ar[k++] = line;
            ar[k++] = NULL;

            /* Redirect target stdout to /dev/null for cleaner driver output. */
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) { dup2(devnull, 1); close(devnull); }

            execv(target, ar);
            perror("execv");
            _exit(127);
        }
        int st = 0;
        waitpid(pid, &st, 0);

        unsigned hit = count_set(bitmap);
        unsigned newly = count_new(bitmap, cumulative);
        printf("iter=%u input=%-20s hit=%u new=%u total=%u exit=%d\n",
               iter++, line, hit, newly, count_set(cumulative),
               WIFEXITED(st) ? WEXITSTATUS(st) : -WTERMSIG(st));
        fflush(stdout);
    }
    unlink(bitmap_path);
    return 0;
}
