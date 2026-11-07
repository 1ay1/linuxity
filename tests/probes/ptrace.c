// ptrace.c -- a guest tracing a guest: TRACEME, the exec stop, syscall
// stops, GETREGSET, PEEKDATA/POKEDATA, a breakpoint, single-step, SIGSTOP
// delivery, GETSIGINFO, the exit, and the errors around them.
//
// Every step is a yes/no or a stable errno, so native Linux and linuxity
// give the same trace. linuxity is the tracee's real tracer and emulates the
// guest's, which is what this pins.
#define _GNU_SOURCE
#include "probe.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SIGCHLD
#define SIGCHLD 17
#endif
#define LX_NA 2
#define LX_CHECK(pre, cond) ((pre) ? ((cond) ? 1 : 0) : LX_NA)

static long do_fork(void) {
    fflush(stdout);
#ifdef SYS_fork
    return LX_SYS0(SYS_fork);
#else
    return LX_SYS5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
#endif
}
static long pt(long req, long pid, long addr, long data) {
    return LX_SYS4(SYS_ptrace, req, pid, addr, data);
}
static long wait_st(long pid, int* st) { return LX_SYS4(SYS_wait4, pid, st, 0x40000000 /*__WALL*/, 0); }

static volatile long probe_word = 0x1122334455667788L;
__attribute__((noinline)) static long target(long x) { return x * 2; }

struct regs {
#if defined(__x86_64__)
    unsigned long r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi,
        orig_rax, rip, cs, eflags, rsp, ss, fs_base, gs_base, ds, es, fs, gs;
#else
    unsigned long x[31], sp, pc, pstate;
#endif
};
static long getregs(long pid, struct regs* r) {
    struct iovec io = {r, sizeof *r};
    return pt(PTRACE_GETREGSET, pid, 1 /*NT_PRSTATUS*/, (long)&io);
}
static unsigned long reg_pc(const struct regs* r) {
#if defined(__x86_64__)
    return r->rip;
#else
    return r->pc;
#endif
}
static long reg_nr(const struct regs* r) {
#if defined(__x86_64__)
    return (long)r->orig_rax;
#else
    return (long)r->x[8];
#endif
}

int main(void) {
    int st = 0;
    // ---- errors first: nothing is traced yet
    lx_emit("ptrace", pt(PTRACE_PEEKDATA, 1, 0, 0), "PEEKDATA on an untraced task is ESRCH");
    lx_emit("ptrace", pt(PTRACE_CONT, 999999, 0, 0), "CONT on a missing pid is ESRCH");
    lx_emit("ptrace", pt(PTRACE_ATTACH, LX_SYS0(SYS_getpid), 0, 0), "attaching to yourself is EPERM");

    // ---- TRACEME + exec: the child stops with SIGTRAP after the exec
    long p = do_fork();
    if (p == 0) {
        if (pt(PTRACE_TRACEME, 0, 0, 0) != 0) LX_SYS1(SYS_exit_group, 9);
        static char* const av[] = {"/bin/true", 0};
        static char* const ev[] = {0};
        LX_SYS3(SYS_execve, "/bin/true", av, ev);
        LX_SYS1(SYS_exit_group, 8);
    }
    long w = wait_st(p, &st);
    lx_emit("ptrace", LX_CHECK(w == p, WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP), "TRACEME + exec stops with SIGTRAP");
    lx_emit("ptrace", pt(PTRACE_SETOPTIONS, p, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC), "SETOPTIONS");
    lx_emit("ptrace", pt(PTRACE_SETOPTIONS, p, 0, 0x40000000), "SETOPTIONS with an unknown bit is EINVAL");
    // syscall-entry stop, with the number visible
    pt(PTRACE_SYSCALL, p, 0, 0);
    w = wait_st(p, &st);
    struct regs r;
    long g = getregs(p, &r);
    lx_emit("ptrace", LX_CHECK(w == p, WIFSTOPPED(st) && WSTOPSIG(st) == (SIGTRAP | 0x80)),
            "PTRACE_SYSCALL stops at a syscall entry (TRACESYSGOOD)");
    lx_emit("ptrace", LX_CHECK(g == 0, reg_nr(&r) >= 0 && reg_nr(&r) < 1024), "GETREGSET shows a syscall number");
    pt(PTRACE_SYSCALL, p, 0, 0);
    w = wait_st(p, &st);
    lx_emit("ptrace", LX_CHECK(w == p, WIFSTOPPED(st) && WSTOPSIG(st) == (SIGTRAP | 0x80)), "...and at its exit");
    static siginfo_t si;
    lx_emit("ptrace", pt(PTRACE_GETSIGINFO, p, 0, (long)&si), "GETSIGINFO at a syscall stop");
    lx_emit("ptrace", LX_CHECK(1, si.si_signo == SIGTRAP), "...is SIGTRAP");
    // run it out: count stops until the exit
    int stops = 0;
    for (; stops < 10000; ++stops) {
        pt(PTRACE_SYSCALL, p, 0, 0);
        if (wait_st(p, &st) != p || WIFEXITED(st) || WIFSIGNALED(st)) break;
    }
    lx_emit("ptrace", LX_CHECK(1, WIFEXITED(st) && WEXITSTATUS(st) == 0), "a traced /bin/true exits 0");
    lx_emit("ptrace", LX_CHECK(1, stops > 10 && (stops % 2) == 1), "an odd number of stops: pairs plus exit_group");
    lx_emit("ptrace", pt(PTRACE_CONT, p, 0, 0), "CONT after the exit is ESRCH");

    // ---- memory, a breakpoint, single-step, a signal stop
    p = do_fork();
    if (p == 0) {
        pt(PTRACE_TRACEME, 0, 0, 0);
        LX_SYS2(SYS_kill, LX_SYS0(SYS_getpid), SIGSTOP);
        long v = target(21);
        LX_SYS1(SYS_exit_group, v == 42 && probe_word == 0x0102030405060708L ? 0 : 3);
    }
    w = wait_st(p, &st);
    lx_emit("ptrace", LX_CHECK(w == p, WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP), "a traced task's SIGSTOP stops it");
    static long word;
    long rr = pt(PTRACE_PEEKDATA, p, (long)&probe_word, (long)&word);
    lx_emit("ptrace", LX_CHECK(rr == 0, word == 0x1122334455667788L), "PEEKDATA reads the tracee");
    lx_emit("ptrace", pt(PTRACE_POKEDATA, p, (long)&probe_word, 0x0102030405060708L), "POKEDATA writes it");
    rr = pt(PTRACE_PEEKDATA, p, 0x8, (long)&word);
    lx_emit("ptrace", rr, "PEEKDATA of an unmapped address is EIO");
    static long orig;
    pt(PTRACE_PEEKTEXT, p, (long)&target, (long)&orig);
#if defined(__x86_64__)
    const long bp = (orig & ~0xffL) | 0xcc;
#else
    const long bp = (orig & ~0xffffffffL) | 0xd4200000L;
#endif
    pt(PTRACE_POKETEXT, p, (long)&target, bp);
    pt(PTRACE_CONT, p, 0, 0);   // the SIGSTOP is suppressed
    w = wait_st(p, &st);
    g = getregs(p, &r);
    lx_emit("ptrace", LX_CHECK(w == p, WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP), "a breakpoint stops with SIGTRAP");
#if defined(__x86_64__)
    const int at_bp = g == 0 && reg_pc(&r) == (unsigned long)&target + 1;
    r.rip = (unsigned long)&target;
    { struct iovec io = {&r, sizeof r}; pt(PTRACE_SETREGSET, p, 1, (long)&io); }
#else
    const int at_bp = g == 0 && reg_pc(&r) == (unsigned long)&target;
#endif
    lx_emit("ptrace", LX_CHECK(1, at_bp), "...at the breakpoint's address");
    pt(PTRACE_POKETEXT, p, (long)&target, orig);
    lx_emit("ptrace", pt(PTRACE_SINGLESTEP, p, 0, 0), "SINGLESTEP");
    w = wait_st(p, &st);
    lx_emit("ptrace", LX_CHECK(w == p, WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP), "...stops after one instruction");
    pt(PTRACE_CONT, p, 0, 0);
    w = wait_st(p, &st);
    lx_emit("ptrace", LX_CHECK(w == p, WIFEXITED(st) && WEXITSTATUS(st) == 0), "it finishes with the poked value");

    // ---- SEIZE + INTERRUPT, then DETACH lets it run on
    p = do_fork();
    if (p == 0) {
        static const long ts[2] = {0, 300000000};
        LX_SYS2(SYS_nanosleep, ts, 0);
        LX_SYS1(SYS_exit_group, 5);
    }
    lx_emit("ptrace", pt(PTRACE_SEIZE, p, 0, 0), "SEIZE a running child");
    lx_emit("ptrace", pt(PTRACE_INTERRUPT, p, 0, 0), "INTERRUPT it");
    w = wait_st(p, &st);
    lx_emit("ptrace", LX_CHECK(w == p, WIFSTOPPED(st) && (st >> 16) == PTRACE_EVENT_STOP),
            "...it stops with PTRACE_EVENT_STOP");
    lx_emit("ptrace", pt(PTRACE_DETACH, p, 0, 0), "DETACH");
    w = wait_st(p, &st);
    lx_emit("ptrace", LX_CHECK(w == p, WIFEXITED(st) && WEXITSTATUS(st) == 5), "a detached child runs on and exits");
    return 0;
}
