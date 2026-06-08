/*
 * arch_inject_mips.c -- MIPS32 (mips, mipsel) backend STUB.
 *
 * Phase 6 placeholder. `supported = 0` -> inject_attach refuses.
 *
 * Planned implementation:
 *
 *   O32 ABI (mipsel/mips default on glibc):
 *     args: $4..$7 (a0..a3); 5th+ on stack (with the first 16 bytes
 *           of stack reserved even for the register args -- "shadow"
 *           area).
 *     return: $2 (v0)
 *     return-PC: $31 (ra); function's `jr ra` branches there.
 *               -> set $31 = trap_pc.
 *
 *   Linux MIPS O32 syscall ABI:
 *     nr: $2 (v0)
 *     args: $4..$7 (a0..a3); 5th/6th on stack at offsets 16/20
 *     return: $2 (v0), with $7 (a3) = 0 on success / 1 on error
 *     instruction: SYSCALL = 0x0000000C (ALL endians; this is the
 *                  function code; the actual word value depends on
 *                  endianness, but the SYSCALL opcode is just 0x0C
 *                  in the opcode field).
 *                  Encoded little-endian: 0C 00 00 00
 *                  Encoded big-endian:    00 00 00 0C
 *
 *   Delay slot: MIPS branches have a delay slot. We don't issue
 *   branches ourselves, but PTRACE_SINGLESTEP semantics for the
 *   syscall need to step past the SYSCALL insn proper (no delay
 *   slot for SYSCALL).
 *
 *   PTRACE_GETREGSET(NT_PRSTATUS): struct user (uses pt_regs internally).
 *   $4..$7 live at regs[4..7]; $31 at regs[31]; pc at the dedicated
 *   `cp0_epc` field via the prstatus layout.
 */

#include "arch_inject.h"

const struct inject_arch inject_arch_mips = {
    .name              = "mips",
    .elf_machine       = EM_MIPS,
    .supported         = 0,
    .setup_call        = NULL,
    .setup_syscall     = NULL,
    .get_retval        = NULL,
    .get_pc            = NULL,
    .set_pc            = NULL,
    .find_syscall_insn = NULL,
    .pm_shellcode      = NULL,
    .pm_build_sigframe = NULL,
};
