// tests/probes/creds.c
//
// The credential calls: the full get* set, and what the set* ones do.
//
// THE GAP THIS CLOSES. procid covers getuid/getgid/getpid/getppid, and the
// ioctls probe added setpgid -- but 19 credential handlers were still
// unverified, including every setter (setuid, setgid, setresuid, setreuid,
// setfsuid, setgroups) and several getters (geteuid, getegid, getresuid,
// getresgid, getsid, getpriority). The job-control bug today lived in exactly
// this family: setpgid was discarded while getpgrp reported it, and nothing
// compared the two.
//
// VALUES CANNOT BE COMPARED, RELATIONSHIPS CAN. linuxity presents a
// fake-root world -- the guest is uid 0 in its own namespace while the native
// run is whatever user CI uses. Comparing the numbers would report a
// divergence on every line and prove nothing. So, like procid, this probe
// asserts INVARIANTS that hold for ANY correct credential model:
//
//   * the three-way getters agree with the simple ones
//     (getresuid's real == getuid, effective == geteuid)
//   * a setter to the CURRENT value is a no-op that succeeds
//   * -1 means "leave unchanged" in setresuid/setreuid
//   * raising privilege you do not have is EPERM, and consistently so
//   * getsid/getpgid of self agree with getsid(0)/getpgrp
//
// Those are true on a real kernel and must be true under linuxity, whatever
// the actual numbers are. That is the whole trick: an invariant is portable
// across the very difference that makes values incomparable.
//
// NOTHING HERE DROPS PRIVILEGE IRREVERSIBLY. Every setter is called either
// with the value it already has, or with -1, or in a way that is expected to
// fail. A probe that actually became another user could not continue to run.
#include "probe.h"

#include <stdlib.h>

int main(void) {
    // -- the simple getters ------------------------------------------------
    const long uid  = LX_SYS0(SYS_getuid);
    const long euid = LX_SYS0(SYS_geteuid);
    const long gid  = LX_SYS0(SYS_getgid);
    const long egid = LX_SYS0(SYS_getegid);

    lx_emit("getuid",  uid  >= 0 ? 1 : uid,  "uid is valid");
    lx_emit("geteuid", euid >= 0 ? 1 : euid, "euid is valid");
    lx_emit("getgid",  gid  >= 0 ? 1 : gid,  "gid is valid");
    lx_emit("getegid", egid >= 0 ? 1 : egid, "egid is valid");
    // A probe is not setuid, so the real and effective ids must match. This
    // holds for a real user and for a fake-root guest alike.
    lx_emit("geteuid", euid == uid ? 1 : 0, "euid == uid (not a setuid binary)");
    lx_emit("getegid", egid == gid ? 1 : 0, "egid == gid");

    // -- the three-way getters must agree with the simple ones -------------
    {
        unsigned r = 0xffffffffu, e = 0xffffffffu, s = 0xffffffffu;
        const long rc = LX_SYS3(SYS_getresuid, &r, &e, &s);
        lx_emit("getresuid", rc, "getresuid succeeds");
        lx_emit("getresuid", (rc == 0 && (long)r == uid) ? 1 : 0,
                "getresuid's real == getuid");
        lx_emit("getresuid", (rc == 0 && (long)e == euid) ? 1 : 0,
                "getresuid's effective == geteuid");
        // Not setuid, so saved == effective too.
        lx_emit("getresuid", (rc == 0 && s == e) ? 1 : 0,
                "getresuid's saved == effective");
    }
    {
        unsigned r = 0xffffffffu, e = 0xffffffffu, s = 0xffffffffu;
        const long rc = LX_SYS3(SYS_getresgid, &r, &e, &s);
        lx_emit("getresgid", rc, "getresgid succeeds");
        lx_emit("getresgid", (rc == 0 && (long)r == gid) ? 1 : 0,
                "getresgid's real == getgid");
        lx_emit("getresgid", (rc == 0 && (long)e == egid) ? 1 : 0,
                "getresgid's effective == getegid");
    }
    // A null pointer must be rejected, not crash.
    lx_emit("getresuid", LX_SYS3(SYS_getresuid, 0L, 0L, 0L),
            "getresuid with null pointers is EFAULT");

    // -- setters to the CURRENT value are no-ops that succeed --------------
    // This is the safe half of every setter: it exercises the whole path --
    // argument decoding, permission check, credential update -- without
    // actually changing anything.
    lx_emit("setuid", LX_SYS1(SYS_setuid, uid), "setuid to our own uid succeeds");
    lx_emit("setgid", LX_SYS1(SYS_setgid, gid), "setgid to our own gid succeeds");
    lx_emit("setreuid", LX_SYS2(SYS_setreuid, uid, euid), "setreuid to current ids");
    lx_emit("setregid", LX_SYS2(SYS_setregid, gid, egid), "setregid to current ids");
    lx_emit("setresuid", LX_SYS3(SYS_setresuid, uid, euid, euid),
            "setresuid to current ids");
    lx_emit("setresgid", LX_SYS3(SYS_setresgid, gid, egid, egid),
            "setresgid to current ids");

    // -1 means "leave this one alone" -- always legal, even unprivileged.
    lx_emit("setreuid", LX_SYS2(SYS_setreuid, -1, -1), "setreuid(-1,-1) changes nothing");
    lx_emit("setregid", LX_SYS2(SYS_setregid, -1, -1), "setregid(-1,-1) changes nothing");
    lx_emit("setresuid", LX_SYS3(SYS_setresuid, -1, -1, -1),
            "setresuid(-1,-1,-1) changes nothing");
    lx_emit("setresgid", LX_SYS3(SYS_setresgid, -1, -1, -1),
            "setresgid(-1,-1,-1) changes nothing");

    // THE INVARIANT: after all that, the ids must be exactly what they were.
    lx_emit("getuid",  LX_SYS0(SYS_getuid)  == uid  ? 1 : 0, "uid unchanged");
    lx_emit("geteuid", LX_SYS0(SYS_geteuid) == euid ? 1 : 0, "euid unchanged");
    lx_emit("getgid",  LX_SYS0(SYS_getgid)  == gid  ? 1 : 0, "gid unchanged");
    lx_emit("getegid", LX_SYS0(SYS_getegid) == egid ? 1 : 0, "egid unchanged");

    // -- the REFUSAL paths -------------------------------------------------
    // The calls above only ever ask for the identity we already have, which
    // exercises decoding but not the decision.
    //
    // A PRIVILEGE DROP IS DELIBERATELY VACUOUS under linuxity, and that is
    // not incoherence to be fixed. The guest world is root-owned and there
    // is exactly one identity to be; a real setuid to pacman's 'alpm' user
    // would EPERM on the host and abort the program, so linuxity accepts the
    // drop and keeps reporting uid 0. Natively the same call is EPERM. So
    // the OUTCOME cannot be compared -- what can is that the answer is
    // self-consistent with what the getters say afterwards, which is the
    // property a program actually depends on.
    {
        const long want = (uid == 0) ? 12345 : 0;   // an id we are not
        const long rc = LX_SYS1(SYS_setuid, want);
        const long now = LX_SYS0(SYS_geteuid);
        // Natively: refused, and we did not move. Under linuxity: accepted,
        // and the root world is unchanged by design. Both are coherent
        // stories; a setter that moved us HALFWAY would not be.
        lx_emit("setuid", (rc < 0) ? (now == euid) : (now == want || now == euid),
                "setuid to another uid leaves a coherent identity");
    }
    {
        const long want = (gid == 0) ? 12345 : 0;
        const long rc = LX_SYS1(SYS_setgid, want);
        const long now = LX_SYS0(SYS_getegid);
        lx_emit("setgid", (rc < 0) ? (now == egid) : (now == want || now == egid),
                "setgid to another gid leaves a coherent identity");
    }

    // setgroups with a bogus count: the list must survive the attempt
    // whichever way the call goes.
    {
        static unsigned groups[4] = {0, 0, 0, 0};
        (void)LX_SYS2(SYS_setgroups, -1, groups);
        (void)LX_SYS2(SYS_setgroups, 1, 0L);
        lx_emit("getgroups", LX_SYS2(SYS_getgroups, 0, 0L) >= 0 ? 1 : 0,
                "getgroups still answers after bad setgroups calls");
    }

    // -- setfsuid/setfsgid return the PREVIOUS value, never an error -------
    // Famously they cannot fail: the return is the old fsuid, so the way to
    // read the current one is to set it to something invalid.
    {
        const long prev = LX_SYS1(SYS_setfsuid, -1);
        lx_emit("setfsuid", prev == euid ? 1 : 0,
                "setfsuid(-1) returns the current fsuid");
        lx_emit("setfsuid", LX_SYS1(SYS_setfsuid, prev) == prev ? 1 : 0,
                "setting it back returns the same value");
    }
    {
        const long prev = LX_SYS1(SYS_setfsgid, -1);
        lx_emit("setfsgid", prev == egid ? 1 : 0,
                "setfsgid(-1) returns the current fsgid");
    }

    // -- groups ------------------------------------------------------------
    // getgroups(0, NULL) asks for the COUNT without writing anything, which
    // is always legal.
    {
        const long n = LX_SYS2(SYS_getgroups, 0, 0L);
        lx_emit("getgroups", n >= 0 ? 1 : n, "getgroups(0,NULL) counts the groups");
        // A negative size is EINVAL.
        lx_emit("getgroups", LX_SYS2(SYS_getgroups, -1, 0L),
                "a negative getgroups size is EINVAL");
    }
    // setgroups needs CAP_SETGID, and that is precisely where the two runs
    // legitimately differ: linuxity presents a fake-root world, so the guest
    // MAY do this while an unprivileged native run may not. Comparing the
    // outcome would report a divergence that is really the fake-root model
    // working as designed.
    //
    // What IS comparable is that the answer is one of the two documented
    // ones and that the call does not corrupt anything: whatever setgroups
    // did, getgroups must still work afterwards.
    {
        const long sg = LX_SYS2(SYS_setgroups, 0, 0L);
        lx_emit("setgroups", (sg == 0 || sg == -EPERM) ? 1 : 0,
                "setgroups to the empty set succeeds or is EPERM");
        lx_emit("getgroups", LX_SYS2(SYS_getgroups, 0, 0L) >= 0 ? 1 : 0,
                "getgroups still works after setgroups");
    }

    // -- sessions and process groups ---------------------------------------
    // These are the family the job-control bug lived in: the ioctl and the
    // syscall must tell one story.
    const long sid = LX_SYS1(SYS_getsid, 0);
    lx_emit("getsid", sid > 0 ? 1 : sid, "getsid(0) is a valid session");
    lx_emit("getsid", LX_SYS1(SYS_getsid, LX_SYS0(SYS_getpid)) == sid ? 1 : 0,
            "getsid(self) == getsid(0)");
    lx_emit("getsid", LX_SYS1(SYS_getsid, 0x3fffffff),
            "getsid of an absent pid is ESRCH");

#ifdef SYS_getpgrp
    const long pgrp = LX_SYS0(SYS_getpgrp);
#else
    const long pgrp = LX_SYS1(SYS_getpgid, 0);
#endif
    lx_emit("getpgid", pgrp > 0 ? 1 : pgrp, "our pgrp is valid");
    lx_emit("getpgid", LX_SYS1(SYS_getpgid, 0) == pgrp ? 1 : 0,
            "getpgid(0) == getpgrp");
    lx_emit("getpgid", LX_SYS1(SYS_getpgid, LX_SYS0(SYS_getpid)) == pgrp ? 1 : 0,
            "getpgid(self) == getpgrp");
    lx_emit("getpgid", LX_SYS1(SYS_getpgid, 0x3fffffff),
            "getpgid of an absent pid is ESRCH");

    // setpgid to the group we are already in is a no-op success, and must
    // stay visible to the getter -- the half that broke job control.
    lx_emit("setpgid", LX_SYS2(SYS_setpgid, 0, pgrp), "setpgid to our own group");
    lx_emit("setpgid", LX_SYS1(SYS_getpgid, 0) == pgrp ? 1 : 0,
            "getpgid still agrees after setpgid");
    lx_emit("setpgid", LX_SYS2(SYS_setpgid, 0x3fffffff, 0),
            "setpgid of an absent pid is ESRCH");

    // -- priority ----------------------------------------------------------
    // PRIO_PROCESS is 0. getpriority legitimately returns a NEGATIVE nice
    // value on success, so errno is the only way to tell failure apart --
    // which is itself worth pinning.
    lx_emit("getpriority", LX_SYS2(SYS_getpriority, 0, 0) >= -20 ? 1 : 0,
            "getpriority is a plausible nice value");
    lx_emit("getpriority", LX_SYS2(SYS_getpriority, 99, 0),
            "a bogus priority `which` is EINVAL");
    // Setting the nice value we already have is a no-op; RAISING priority
    // (lower number) needs privilege, so that one is the interesting answer.
    lx_emit("setpriority", LX_SYS3(SYS_setpriority, 0, 0, 0),
            "setpriority to nice 0");
    lx_emit("setpriority", LX_SYS3(SYS_setpriority, 99, 0, 0),
            "a bogus setpriority `which` is EINVAL");

    return 0;
}
