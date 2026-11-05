// tests/probes/signals.c
//
// rt_sigaction/rt_sigprocmask/sigaltstack/rt_sigpending and the kill family.
//
// linuxity has to deliver signals itself (the DeliversSignals capability in
// runtime/backend.hpp) and it translates guest pids to host tids on the way,
// so this family is mostly its own code. The disposition TABLE is also
// linuxity's: a guest that sets a handler and reads it back must see what it
// set, not the host's idea.
//
// No handler is ever actually RUN here on purpose. Running one would make the
// trace depend on delivery timing, which is not deterministic between two
// runs; what IS deterministic is the bookkeeping -- what sigaction reports,
// what the mask contains, which errnos the edge cases give.
#include "probe.h"

#include <string.h>

#define SIG_BLOCK   0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2
#define SIGHUP   1
#define SIGKILL  9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGSTOP 19
#define SIGRTMIN 34

// The kernel's struct sigaction (not glibc's): handler, flags, restorer, mask.
struct k_sigaction {
    unsigned long handler;
    unsigned long flags;
    unsigned long restorer;
    unsigned long mask;
};

#define SA_RESTORER 0x04000000

int main(void) {
    const long pid = LX_SYS0(SYS_getpid);

    // -- rt_sigaction: what we set is what we read back --------------------
    {
        struct k_sigaction old;
        memset(&old, 0, sizeof old);
        // Query SIGUSR1's current disposition. A fresh process has SIG_DFL.
        const long q = LX_SYS4(SYS_rt_sigaction, SIGUSR1, 0, &old, 8);
        lx_emit("rt_sigaction", q, "query SIGUSR1");
        lx_emit("rt_sigaction", old.handler == 0 ? 1 : 0,
                "a fresh process has SIG_DFL for SIGUSR1");

        // Set SIG_IGN (1), then read it back.
        struct k_sigaction ign;
        memset(&ign, 0, sizeof ign);
        ign.handler = 1;                     // SIG_IGN
        ign.flags = SA_RESTORER;
        const long s = LX_SYS4(SYS_rt_sigaction, SIGUSR1, &ign, 0, 8);
        lx_emit("rt_sigaction", s, "set SIGUSR1 to SIG_IGN");

        memset(&old, 0, sizeof old);
        LX_SYS4(SYS_rt_sigaction, SIGUSR1, 0, &old, 8);
        lx_emit("rt_sigaction", old.handler == 1 ? 1 : 0,
                "SIGUSR1 reads back as SIG_IGN");

        // An ignored signal sent to ourselves is delivered and discarded --
        // the call must still succeed.
        lx_emit("kill", LX_SYS2(SYS_kill, pid, SIGUSR1),
                "kill self with an ignored signal succeeds");

        // Restore SIG_DFL.
        struct k_sigaction dfl;
        memset(&dfl, 0, sizeof dfl);
        dfl.flags = SA_RESTORER;
        lx_emit("rt_sigaction", LX_SYS4(SYS_rt_sigaction, SIGUSR1, &dfl, 0, 8),
                "restore SIGUSR1 to SIG_DFL");
    }

    // -- SIGKILL and SIGSTOP cannot be caught or ignored -------------------
    {
        struct k_sigaction ign;
        memset(&ign, 0, sizeof ign);
        ign.handler = 1;
        ign.flags = SA_RESTORER;
        lx_emit("rt_sigaction", LX_SYS4(SYS_rt_sigaction, SIGKILL, &ign, 0, 8),
                "catching SIGKILL is EINVAL");
        lx_emit("rt_sigaction", LX_SYS4(SYS_rt_sigaction, SIGSTOP, &ign, 0, 8),
                "catching SIGSTOP is EINVAL");
    }

    // -- signal number bounds ---------------------------------------------
    {
        struct k_sigaction a;
        memset(&a, 0, sizeof a);
        lx_emit("rt_sigaction", LX_SYS4(SYS_rt_sigaction, 0, 0, &a, 8),
                "signal 0 is EINVAL for sigaction");
        lx_emit("rt_sigaction", LX_SYS4(SYS_rt_sigaction, 65, 0, &a, 8),
                "signal 65 is EINVAL");
        lx_emit("rt_sigaction", LX_SYS4(SYS_rt_sigaction, -1, 0, &a, 8),
                "a negative signal is EINVAL");
        // A real-time signal IS valid.
        lx_emit("rt_sigaction", LX_SYS4(SYS_rt_sigaction, SIGRTMIN, 0, &a, 8),
                "SIGRTMIN is a valid signal");
        // A wrong sigsetsize is EINVAL.
        lx_emit("rt_sigaction", LX_SYS4(SYS_rt_sigaction, SIGUSR1, 0, &a, 4),
                "a wrong sigsetsize is EINVAL");
    }

    // -- rt_sigprocmask: the mask round-trips ------------------------------
    {
        unsigned long mask = 0, old = 0;

        // Start from a known state.
        lx_emit("rt_sigprocmask", LX_SYS4(SYS_rt_sigprocmask, SIG_SETMASK,
                                          &mask, &old, 8),
                "clear the signal mask");

        // Block SIGUSR1 and read the mask back.
        mask = 1UL << (SIGUSR1 - 1);
        lx_emit("rt_sigprocmask", LX_SYS4(SYS_rt_sigprocmask, SIG_BLOCK,
                                          &mask, 0, 8),
                "block SIGUSR1");
        old = 0;
        LX_SYS4(SYS_rt_sigprocmask, SIG_BLOCK, 0, &old, 8);
        lx_emit("rt_sigprocmask", (old & (1UL << (SIGUSR1 - 1))) ? 1 : 0,
                "the mask reports SIGUSR1 blocked");

        // A blocked signal sent to ourselves becomes PENDING, not delivered.
        lx_emit("kill", LX_SYS2(SYS_kill, pid, SIGUSR1),
                "kill self with a blocked signal succeeds");
        {
            unsigned long pending = 0;
            lx_emit("rt_sigpending",
                    LX_SYS2(SYS_rt_sigpending, &pending, 8), "query pending");
            lx_emit("rt_sigpending", (pending & (1UL << (SIGUSR1 - 1))) ? 1 : 0,
                    "SIGUSR1 is pending while blocked");
        }

        // Unblocking delivers it -- and SIGUSR1 is SIG_DFL now, which would
        // KILL us. So set it to ignore first.
        {
            struct k_sigaction ign;
            memset(&ign, 0, sizeof ign);
            ign.handler = 1;
            ign.flags = SA_RESTORER;
            LX_SYS4(SYS_rt_sigaction, SIGUSR1, &ign, 0, 8);
        }
        mask = 1UL << (SIGUSR1 - 1);
        lx_emit("rt_sigprocmask", LX_SYS4(SYS_rt_sigprocmask, SIG_UNBLOCK,
                                          &mask, 0, 8),
                "unblock SIGUSR1 (now ignored, so it is discarded)");
        {
            unsigned long pending = 0;
            LX_SYS2(SYS_rt_sigpending, &pending, 8);
            lx_emit("rt_sigpending", (pending & (1UL << (SIGUSR1 - 1))) ? 0 : 1,
                    "SIGUSR1 is no longer pending after unblocking");
        }

        // SIGKILL and SIGSTOP cannot be blocked -- the kernel silently drops
        // them from the mask rather than failing.
        mask = (1UL << (SIGKILL - 1)) | (1UL << (SIGSTOP - 1));
        lx_emit("rt_sigprocmask", LX_SYS4(SYS_rt_sigprocmask, SIG_BLOCK,
                                          &mask, 0, 8),
                "blocking SIGKILL/SIGSTOP succeeds (silently ignored)");
        old = 0;
        LX_SYS4(SYS_rt_sigprocmask, SIG_BLOCK, 0, &old, 8);
        lx_emit("rt_sigprocmask", (old & (1UL << (SIGKILL - 1))) ? 0 : 1,
                "SIGKILL did NOT end up blocked");

        // A bogus `how` is EINVAL.
        lx_emit("rt_sigprocmask", LX_SYS4(SYS_rt_sigprocmask, 99, &mask, 0, 8),
                "a bogus sigprocmask how is EINVAL");
        // A wrong sigsetsize is EINVAL.
        lx_emit("rt_sigprocmask", LX_SYS4(SYS_rt_sigprocmask, SIG_BLOCK,
                                          &mask, 0, 4),
                "a wrong sigsetsize is EINVAL");
    }

    // -- sigaltstack -------------------------------------------------------
    {
        // struct sigaltstack { void* sp; int flags; size_t size; }
        struct { void* sp; int flags; unsigned long size; } ss, oss;
        memset(&oss, 0, sizeof oss);
        lx_emit("sigaltstack", LX_SYS2(SYS_sigaltstack, 0, &oss),
                "query the alt stack");
        // A fresh process has no alt stack: SS_DISABLE (2).
        lx_emit("sigaltstack", (oss.flags & 2) ? 1 : 0,
                "a fresh process has no alt stack");

        // Too small a stack is ENOMEM.
        static char small[128];
        ss.sp = small; ss.flags = 0; ss.size = sizeof small;
        lx_emit("sigaltstack", LX_SYS2(SYS_sigaltstack, &ss, 0),
                "a too-small alt stack is ENOMEM");

        // A reasonable one is accepted, and reads back.
        static char big[64 * 1024];
        ss.sp = big; ss.flags = 0; ss.size = sizeof big;
        lx_emit("sigaltstack", LX_SYS2(SYS_sigaltstack, &ss, 0),
                "a 64K alt stack is accepted");
        memset(&oss, 0, sizeof oss);
        LX_SYS2(SYS_sigaltstack, 0, &oss);
        lx_emit("sigaltstack", oss.size == sizeof big ? 1 : 0,
                "the alt stack size reads back");
    }

    // -- the kill family ---------------------------------------------------
    lx_emit("kill", LX_SYS2(SYS_kill, pid, 0), "kill(self, 0) is a liveness probe");
    lx_emit("kill", LX_SYS2(SYS_kill, pid, 99), "a bogus signal is EINVAL");
    lx_emit("kill", LX_SYS2(SYS_kill, 0x3fffffff, 0), "an absent pid is ESRCH");

    // tgkill needs a matching tgid/tid; tid == pid for the leader.
    lx_emit("tgkill", LX_SYS3(SYS_tgkill, pid, pid, 0),
            "tgkill(self, self, 0) succeeds");
    lx_emit("tgkill", LX_SYS3(SYS_tgkill, pid, pid, 99),
            "tgkill with a bogus signal is EINVAL");
    lx_emit("tgkill", LX_SYS3(SYS_tgkill, -1, pid, 0),
            "tgkill with a negative tgid is EINVAL");
    lx_emit("tkill", LX_SYS2(SYS_tkill, pid, 0), "tkill(self, 0) succeeds");
    lx_emit("tkill", LX_SYS2(SYS_tkill, -1, 0), "tkill with a negative tid is EINVAL");

    return 0;
}
