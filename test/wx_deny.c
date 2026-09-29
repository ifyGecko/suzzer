/*
 * wx_deny.c -- run a command as if under a W^X-enforcing kernel.
 *
 *   wx_deny <cmd> [args...]
 *
 * Installs a seccomp filter that makes mprotect() and pkey_mprotect()
 * fail with EACCES whenever the new protection asks for both PROT_WRITE
 * and PROT_EXEC -- what SELinux (execmem) or PaX MPROTECT do -- then
 * execs the command (the filter and LD_PRELOAD are inherited). Lets the
 * tests exercise libcov's no-RWX fallbacks on an ordinary kernel.
 */
#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#  define WX_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#  define WX_ARCH AUDIT_ARCH_AARCH64
#elif defined(__riscv) && __riscv_xlen == 64
#  define WX_ARCH AUDIT_ARCH_RISCV64
#else
#  error "wx_deny: add this host's AUDIT_ARCH"
#endif

#ifndef __NR_pkey_mprotect
#  define __NR_pkey_mprotect -1
#endif

/* Low 32 bits of syscall argument 2 (the protection). */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#  define PROT_ARG offsetof(struct seccomp_data, args[2])
#else
#  define PROT_ARG (offsetof(struct seccomp_data, args[2]) + 4)
#endif

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <cmd> [args...]\n", argv[0]);
        return 2;
    }
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, WX_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)__NR_pkey_mprotect, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, PROT_ARG),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, PROT_WRITE | PROT_EXEC),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROT_WRITE | PROT_EXEC, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { (unsigned short)(sizeof f / sizeof f[0]), f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        perror("wx_deny: seccomp");
        return 2;
    }
    execvp(argv[1], argv + 1);
    perror("wx_deny: exec");
    return 127;
}
