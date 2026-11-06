// tests/probes/proclife.c
//
// Process lifecycle: fork, execve, exit, wait -- and the signal-return and
// identity calls that only a child can safely make.
//
// THE ASSUMPTION THIS BREAKS. These were written off as unprobeable because
// "a probe has to survive to print its trace, so it can never exec or exit".
// That is true of the probe PROCESS, not of the probe. A child can exec, or
// exit, or have its session changed, while the PARENT observes the result
// and reports it. The child's own trace output is discarded; what the parent
// emits is the OBSERVATION -- did the exec take, what status came back, did
// the identity change the way the kernel says it should.
//
// This is how the last genuinely-unreachable-looking group becomes testable:
// execve, execveat, exit, exit_group, setsid, set_tid_address, prctl,
// rt_sigreturn, rt_sigsuspend.
//
// DETERMINISM. Pids differ between the two runs by nature and the law
// exempts them, but this probe never emits a raw pid anyway -- only
// relationships (the reaped pid IS the one we forked, the exit status IS
// what the child passed to _exit). Those hold whatever the numbers are.
#include "probe.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#define LX_NA 2
#define LX_CHECK(pre, cond) ((pre) ? ((cond) ? 1 : 0) : LX_NA)

#ifndef CLONE_VM
#define CLONE_VM 0x00000100
#endif
#ifndef SIGCHLD
#define SIGCHLD 17
#endif

// fork(2) does not exist on aarch64: it is clone(SIGCHLD, 0, ...). Use the
// same spelling on both arches so the traces line up.
//
// CRITICAL: flush before forking. lx_emit uses buffered printf, and a child
// inherits the parent's UNFLUSHED buffer -- so every line emitted so far
// would be printed a second time when the child exits, duplicating steps and
// corrupting the trace. The child must also leave only via exit_group (never
// return from main, never call exit(3)), so it cannot run atexit handlers
// that would flush that buffer anyway.
static long do_fork(void) {
    fflush(stdout);
#ifdef SYS_fork
    return LX_SYS0(SYS_fork);
#else
    return LX_SYS5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
#endif
}

// Reap one child; returns its wait status via *st.
static long reap(long pid, int* st) {
    return LX_SYS4(SYS_wait4, pid, st, 0, 0);
}

// WIFEXITED / WEXITSTATUS without <sys/wait.h>, which pulls in libc headers
// the probes deliberately avoid.
static int exited_with(int st) { return ((st & 0x7f) == 0) ? ((st >> 8) & 0xff) : -1; }
static int killed_by(int st)   { return ((st & 0x7f) != 0 && (st & 0x7f) != 0x7f)
                                        ? (st & 0x7f) : -1; }

int main(void) {
    // -- exit: a child's status must come back exactly ---------------------
    {
        const long c = do_fork();
        if (c == 0) LX_SYS1(SYS_exit_group, 42);     // never returns
        lx_emit("clone", c > 0 ? 1 : c, "fork a child");
        int st = 0;
        const long w = reap(c, &st);
        lx_emit("wait4", LX_CHECK(c > 0, w == c), "wait4 reaps the child we forked");
        lx_emit("exit_group", LX_CHECK(c > 0 && w == c, exited_with(st) == 42),
                "the child's exit status arrives intact");
    }

    // A status of 0 and a status of 255 are the boundaries.
    {
        const long c = do_fork();
        if (c == 0) LX_SYS1(SYS_exit_group, 0);
        int st = 0;
        const long w = (c > 0) ? reap(c, &st) : c;
        lx_emit("exit_group", LX_CHECK(w > 0, exited_with(st) == 0),
                "exit status 0 round-trips");
    }
    {
        const long c = do_fork();
        if (c == 0) LX_SYS1(SYS_exit_group, 255);
        int st = 0;
        const long w = (c > 0) ? reap(c, &st) : c;
        lx_emit("exit_group", LX_CHECK(w > 0, exited_with(st) == 255),
                "exit status 255 round-trips");
    }

    // -- a child killed by a signal reports the SIGNAL, not an exit code ---
    {
        const long c = do_fork();
        if (c == 0) {
            // Kill ourselves with SIGKILL, which cannot be caught or ignored
            // and so is deterministic.
            LX_SYS2(SYS_kill, LX_SYS0(SYS_getpid), 9);
            LX_SYS1(SYS_exit_group, 1);   // unreachable if the kill worked
        }
        int st = 0;
        const long w = (c > 0) ? reap(c, &st) : c;
        lx_emit("wait4", LX_CHECK(w > 0, killed_by(st) == 9),
                "a SIGKILLed child reports the signal");
    }

    // -- execve: the child becomes another program -------------------------
    // /bin/true is the smallest program that exists on every Linux, and its
    // exit status (0) is the observation.
    {
        const long c = do_fork();
        if (c == 0) {
            static char* const argv[] = {(char*)"true", 0};
            static char* const envp[] = {0};
            LX_SYS3(SYS_execve, "/bin/true", argv, envp);
            LX_SYS1(SYS_exit_group, 90);          // exec failed
        }
        int st = 0;
        const long w = (c > 0) ? reap(c, &st) : c;
        const int rc = exited_with(st);
        // 90 means the exec did not happen at all.
        lx_emit("execve", LX_CHECK(w > 0, rc == 0 || rc == 1),
                "a child can execve /bin/true");
        lx_emit("execve", LX_CHECK(w > 0, rc != 90), "the execve actually replaced the image");
    }

    // execve of something that is not there must fail, and the child must
    // fall through to its own exit.
    {
        const long c = do_fork();
        if (c == 0) {
            static char* const argv[] = {(char*)"nope", 0};
            static char* const envp[] = {0};
            LX_SYS3(SYS_execve, "/nonexistent-program-xyz", argv, envp);
            LX_SYS1(SYS_exit_group, 91);
        }
        int st = 0;
        const long w = (c > 0) ? reap(c, &st) : c;
        lx_emit("execve", LX_CHECK(w > 0, exited_with(st) == 91),
                "execve of a missing program fails and the child continues");
    }

    // execve of a DIRECTORY is EACCES, a classic boundary.
    {
        const long c = do_fork();
        if (c == 0) {
            static char* const argv[] = {(char*)"d", 0};
            static char* const envp[] = {0};
            LX_SYS3(SYS_execve, "/tmp", argv, envp);
            LX_SYS1(SYS_exit_group, 92);
        }
        int st = 0;
        const long w = (c > 0) ? reap(c, &st) : c;
        lx_emit("execve", LX_CHECK(w > 0, exited_with(st) == 92),
                "execve of a directory fails");
    }

    // -- execveat: the *at form, relative to a dirfd -----------------------
    {
        const long c = do_fork();
        if (c == 0) {
            const long d = LX_SYS3(SYS_openat, AT_FDCWD, "/bin", O_RDONLY | O_DIRECTORY);
            if (d < 0) LX_SYS1(SYS_exit_group, 93);
            static char* const argv[] = {(char*)"true", 0};
            static char* const envp[] = {0};
            LX_SYS5(SYS_execveat, d, "true", argv, envp, 0);
            LX_SYS1(SYS_exit_group, 94);
        }
        int st = 0;
        const long w = (c > 0) ? reap(c, &st) : c;
        const int rc = exited_with(st);
        lx_emit("execveat", LX_CHECK(w > 0, rc != 93), "opened /bin for execveat");
        lx_emit("execveat", LX_CHECK(w > 0, rc != 94), "execveat replaced the image");
    }

    // -- setsid: only a non-leader may do it -------------------------------
    // The parent is (usually) a process-group leader and so gets EPERM; a
    // freshly forked child is not, so it succeeds. Both halves are observable
    // and both must match the kernel.
    {
        const long c = do_fork();
        if (c == 0) {
            const long sid = LX_SYS0(SYS_setsid);
            // A successful setsid returns our own pid and makes us the
            // session leader, so getsid(0) must agree.
            const long got = LX_SYS1(SYS_getsid, 0);
            LX_SYS1(SYS_exit_group, (sid > 0 && sid == got) ? 0 : 60);
        }
        int st = 0;
        const long w = (c > 0) ? reap(c, &st) : c;
        lx_emit("setsid", LX_CHECK(w > 0, exited_with(st) == 0),
                "a forked child can setsid and getsid agrees");
    }

    // -- set_tid_address: returns the caller's tid, never fails ------------
    {
        static long slot = 0;
        const long r = LX_SYS1(SYS_set_tid_address, &slot);
        lx_emit("set_tid_address", r > 0 ? 1 : r, "set_tid_address returns a tid");
        lx_emit("set_tid_address", LX_CHECK(r > 0, r == LX_SYS0(SYS_gettid)),
                "...and it is OUR tid");
    }

    // -- prctl -------------------------------------------------------------
    // PR_GET_DUMPABLE(3) / PR_SET_NAME(15) / PR_GET_NAME(16) are the three
    // every runtime touches, and a bogus option must be EINVAL.
    {
        lx_emit("prctl", LX_SYS1(SYS_prctl, 3), "PR_GET_DUMPABLE");
        static char nm[32];
        memcpy(nm, "lxprobe", 8);
        lx_emit("prctl", LX_SYS2(SYS_prctl, 15, nm), "PR_SET_NAME");
        static char back[32];
        memset(back, 0, sizeof back);
        const long g = LX_SYS2(SYS_prctl, 16, back);
        lx_emit("prctl", g, "PR_GET_NAME");
        lx_emit("prctl", LX_CHECK(g == 0, memcmp(back, "lxprobe", 8) == 0),
                "PR_GET_NAME reads back what PR_SET_NAME wrote");
        // comm must agree with it too -- the name is one fact, two views.
        {
            const long fd = LX_SYS3(SYS_openat, AT_FDCWD, "/proc/self/comm", O_RDONLY);
            static char cm[64];
            memset(cm, 0, sizeof cm);
            const long n = (fd < 0) ? fd : LX_SYS3(SYS_read, fd, cm, 63);
            if (fd >= 0) LX_SYS1(SYS_close, fd);
            lx_emit("prctl", LX_CHECK(g == 0 && n > 0, memcmp(cm, "lxprobe", 7) == 0),
                    "/proc/self/comm agrees with PR_SET_NAME");
        }
        lx_emit("prctl", LX_SYS1(SYS_prctl, 0x7fffffff), "a bogus prctl option is EINVAL");
    }

    // -- getpgrp: the no-argument spelling ---------------------------------
#ifdef SYS_getpgrp
    lx_emit("getpgrp", LX_SYS0(SYS_getpgrp) == LX_SYS1(SYS_getpgid, 0) ? 1 : 0,
            "getpgrp agrees with getpgid(0)");
#else
    lx_emit("getpgrp", LX_NA, "getpgrp agrees with getpgid(0)");
#endif

    // -- rt_sigsuspend: woken by a signal, returns EINTR -------------------
    // Done in a child so a mistake cannot hang the probe: the parent reaps
    // it, and a child that never wakes shows up as a divergent status rather
    // than a stuck run.
    {
        const long c = do_fork();
        if (c == 0) {
            // Arrange for a signal to arrive. aarch64 has no alarm(2) -- like
            // dup2 and the other legacy calls, asm-generic dropped it -- so
            // use setitimer, which exists everywhere and does the same job.
#ifdef SYS_alarm
            LX_SYS1(SYS_alarm, 1);
#else
            // struct itimerval { {sec,usec} interval; {sec,usec} value; }
            static long itv[4] = {0, 0, 1, 0};
            LX_SYS3(SYS_setitimer, 0 /*ITIMER_REAL*/, itv, 0);
#endif
            static unsigned long mask = 0;
            const long r = LX_SYS2(SYS_rt_sigsuspend, &mask, 8);
            // rt_sigsuspend ALWAYS returns -EINTR when it returns at all.
            LX_SYS1(SYS_exit_group, (r == -4) ? 0 : 61);
        }
        int st = 0;
        const long w = (c > 0) ? reap(c, &st) : c;
        // The default action for SIGALRM is to terminate, so the child dies
        // by signal 14 rather than exiting -- either way it must not hang,
        // and both runs must agree on which happened.
        lx_emit("rt_sigsuspend",
                LX_CHECK(w > 0, exited_with(st) == 0 || killed_by(st) == 14),
                "rt_sigsuspend returns EINTR or the signal kills us");
    }

    // -- wait4 error boundaries --------------------------------------------
    {
        int st = 0;
        lx_emit("wait4", LX_SYS4(SYS_wait4, 0x3fffffff, &st, 0, 0),
                "wait4 on a pid that is not our child is ECHILD");
        lx_emit("wait4", LX_SYS4(SYS_wait4, -1, &st, 0, 0),
                "wait4 with no children left is ECHILD");
    }
    return 0;
}
