// tests/probes/ioctls.c
//
// ioctl on a pty: termios, window size, and the foreground process group.
//
// THE GAP THIS CLOSES. ioctl is the widest syscall in Linux -- every terminal,
// every tty-aware program -- and had no probe at all. Four real bugs shipped
// through that hole in one day:
//
//   * TCGETS2/TCSETS2 got EACCES on Android, because the shell domain's
//     SELinux ioctl whitelist for devpts predates termios2 while glibc >= 2.42
//     uses only termios2. `tty` said "not a tty" on a working pty.
//   * the fix matched the request zero-extended, so musl's sign-extended
//     0xffffffff802c542a fell through and still failed.
//   * TIOCGPGRP reported the bare pid while getpgrp reported the group
//     setpgid had just set, so bash's job-control loop never converged, it
//     gave up with "no job control", and that turns OFF line editing.
//   * (and the pty itself: ttyname() needs /proc/self/fd to resolve.)
//
// WHY A PTY AND NOT stdin. The probe must behave identically natively and
// under linuxity, but the harness gives it whatever stdin it has -- a pipe in
// CI, a terminal when run by hand -- and tty ioctls answer differently on
// each. So the probe MAKES its own pty. That is deterministic, it is the
// device class the bugs live on (devpts, not ptmx -- they differ under
// SELinux), and it works the same in CI and on a developer's terminal.
//
// WHAT IS COMPARED. Mostly invariants and relationships, not raw values: a
// termios struct contains a baud code and control characters that are allowed
// to differ between hosts, and comparing them would make this probe a test of
// the host's default line discipline. What MUST agree is the structure --
// does the call succeed, does a set stick, do the two spellings of the same
// request behave the same, does tcgetpgrp agree with getpgrp.
#include "probe.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

// Raw request numbers. The TCGETS2 macro needs struct termios2, which is not
// in every libc's headers, and these values are arch-independent on every
// arch linuxity targets.
#define R_TCGETS     0x5401UL
#define R_TCSETS     0x5402UL
#define R_TCSETSW    0x5403UL
#define R_TCGETS2    0x802c542aUL
#define R_TCSETS2    0x402c542bUL
#define R_TCSETSW2   0x402c542cUL
#define R_TIOCGWINSZ 0x5413UL
#define R_TIOCSWINSZ 0x5414UL
#define R_TIOCGPGRP  0x540fUL
#define R_TIOCSCTTY  0x540eUL
#define R_TIOCNOTTY  0x5422UL
#define R_TIOCGSID   0x5429UL
#define R_TIOCSPGRP  0x5410UL
#define R_TIOCGPTN   0x80045430UL
#define R_TIOCSPTLCK 0x40045431UL

// struct termios is 4 flags + c_line + 19 c_cc = 36 bytes; termios2 adds
// c_ispeed/c_ospeed for 44. Hand-rolled so the layout is explicit rather
// than whatever this host's headers happen to say.
#define T_SZ   36
#define T_SZ2  44
#define OFF_LFLAG 12          // c_iflag, c_oflag, c_cflag, c_lflag
#define OFF_CFLAG 8

#define F_ECHO   0x00000008
#define F_ICANON 0x00000002

static unsigned u32_at(const unsigned char* p, int off) {
    unsigned v;
    memcpy(&v, p + off, 4);
    return v;
}
static void set_u32_at(unsigned char* p, int off, unsigned v) {
    memcpy(p + off, &v, 4);
}

// A derived invariant whose PRECONDITION did not hold.
//
// Emitted instead of 0/1 when the call an invariant depends on failed. The
// two runs must emit the same number of steps or every later comparison
// misaligns, so the check cannot simply be skipped -- but it must not report
// "false" either, because that is indistinguishable from a real violation.
//
// This matters on Android: SELinux denies TCGETS2 on a pty slave natively
// while linuxity serves it, so natively the precondition fails and the
// invariant is unanswerable, while under linuxity it holds. Reporting 2 on
// one side and 1 on the other would be a divergence that means nothing. The
// law exempts the EACCES itself; this keeps the derived checks honest by
// saying "not applicable" in the one place that knows why.
#define LX_NA 2
#define LX_CHECK(pre, cond) ((pre) ? ((cond) ? 1 : 0) : LX_NA)

int main(void) {
    // -- open a pty master, unlock it, and open its slave -------------------
    // /dev/ptmx is a different SELinux class from the devpts slave, and the
    // Android bug appeared ONLY on the slave, so both are exercised.
    const long m = LX_SYS3(SYS_openat, AT_FDCWD, "/dev/ptmx", O_RDWR | O_NOCTTY);
    lx_emit("openat", m >= 0 ? 1 : m, "open /dev/ptmx");
    if (m < 0) return 0;          // no pty support: nothing further is meaningful

    int unlock = 0;
    lx_emit("ioctl", LX_SYS3(SYS_ioctl, m, R_TIOCSPTLCK, &unlock),
            "TIOCSPTLCK unlocks the slave");

    unsigned ptn = 0;
    const long gptn = LX_SYS3(SYS_ioctl, m, R_TIOCGPTN, &ptn);
    lx_emit("ioctl", gptn, "TIOCGPTN gets the slave number");

    // Build /dev/pts/N without snprintf: the number itself varies between
    // runs, so it must NOT reach the trace.
    char path[32];
    {
        char d[16];
        int n = 0;
        unsigned v = ptn;
        if (v == 0) d[n++] = '0';
        while (v) { d[n++] = (char)('0' + v % 10); v /= 10; }
        memcpy(path, "/dev/pts/", 9);
        for (int i = 0; i < n; ++i) path[9 + i] = d[n - 1 - i];
        path[9 + n] = 0;
    }

    const long s = LX_SYS3(SYS_openat, AT_FDCWD, path, O_RDWR | O_NOCTTY);
    lx_emit("openat", s >= 0 ? 1 : s, "open the pty slave /dev/pts/N");
    if (s < 0) { LX_SYS1(SYS_close, m); return 0; }

    static unsigned char a[64], b[64], c[64];

    // -- the classic termios pair ------------------------------------------
    memset(a, 0xAA, sizeof a);
    const long g1 = LX_SYS3(SYS_ioctl, s, R_TCGETS, a);
    lx_emit("ioctl", g1, "TCGETS on the pty slave");

    // -- the termios2 pair, which is what modern glibc actually calls -------
    // This is the one that returned EACCES on Android. The VALUE of the
    // struct is not compared (baud and control chars are host policy); what
    // must agree is that the call works at all.
    memset(b, 0xBB, sizeof b);
    const long g2 = LX_SYS3(SYS_ioctl, s, R_TCGETS2, b);
    lx_emit("ioctl", g2, "TCGETS2 on the pty slave");

    // THE INVARIANT that catches the downgrade being wrong: termios2 is
    // termios plus two speed fields, so the leading 36 bytes must be
    // identical. A widen that writes the wrong offset breaks this.
    //
    // Every check from here on is emitted UNCONDITIONALLY, even when the
    // call it depends on failed. The traces are compared step by step, so a
    // probe that skips steps when something fails produces a SHORTER trace
    // and misaligns every later comparison against an unrelated operation.
    // On Android that is live: TCGETS2 is denied by SELinux natively but
    // served by linuxity, so the two runs would drift by eleven steps. A
    // skipped check reports 0, which is a real answer rather than a gap.
    lx_emit("ioctl", LX_CHECK(g1 == 0 && g2 == 0, memcmp(a, b, T_SZ) == 0),
            "TCGETS2's first 36 bytes == TCGETS");

    // The speed fields must be FILLED IN, not left as our poison. A pty
    // always has a baud rate, so poison here means the fixup never ran.
    lx_emit("ioctl", LX_CHECK(g2 == 0, u32_at(b, 36) != 0xBBBBBBBBu),
            "TCGETS2 wrote c_ispeed");
    lx_emit("ioctl", LX_CHECK(g2 == 0, u32_at(b, 40) != 0xBBBBBBBBu),
            "TCGETS2 wrote c_ospeed");
    lx_emit("ioctl", LX_CHECK(g2 == 0, u32_at(b, 36) == u32_at(b, 40)),
            "c_ispeed == c_ospeed on a pty");

    // THE SIGN-EXTENSION CASE. An ioctl request is 32 bits but travels in a
    // 64-bit register, and TCGETS2's direction bit makes it negative as a
    // signed int -- musl sign-extends it, glibc does not. Both spellings must
    // reach the same handler.
    memset(c, 0xCC, sizeof c);
    const long gx = LX_SYS3(SYS_ioctl, s, (long)0xffffffff802c542aUL, c);
    lx_emit("ioctl", gx, "TCGETS2 sign-extended behaves the same");
    lx_emit("ioctl", LX_CHECK(g2 == 0 && gx == 0, memcmp(b, c, T_SZ2) == 0),
            "sign-extended TCGETS2 returns the same struct");

    // -- a set must actually STICK -----------------------------------------
    // Clearing ECHO and reading it back is the whole of `stty -echo`, and a
    // set that silently no-ops looks fine until a shell turns off echo for a
    // password prompt and the password is echoed.
    memcpy(c, b, T_SZ2);
    if (g2 == 0)
        set_u32_at(c, OFF_LFLAG, u32_at(b, OFF_LFLAG) & ~(unsigned)F_ECHO);
    lx_emit("ioctl", LX_SYS3(SYS_ioctl, s, R_TCSETS2, c),
            "TCSETS2 clears ECHO");

    memset(c, 0, sizeof c);
    {
        const long rb = LX_SYS3(SYS_ioctl, s, R_TCGETS2, c);
        lx_emit("ioctl", LX_CHECK(rb == 0, (u32_at(c, OFF_LFLAG) & F_ECHO) == 0),
                "ECHO reads back cleared");
    }

    // TCSETSW2 is the drain-then-set variant `stty` reaches for, and was
    // forwarded raw after the first fix only handled the plain one.
    memcpy(c, b, T_SZ2);
    if (g2 == 0)
        set_u32_at(c, OFF_LFLAG, u32_at(b, OFF_LFLAG) | (unsigned)F_ECHO);
    lx_emit("ioctl", LX_SYS3(SYS_ioctl, s, R_TCSETSW2, c),
            "TCSETSW2 restores ECHO");

    memset(c, 0, sizeof c);
    {
        const long rb = LX_SYS3(SYS_ioctl, s, R_TCGETS2, c);
        lx_emit("ioctl", LX_CHECK(rb == 0, (u32_at(c, OFF_LFLAG) & F_ECHO) != 0),
                "ECHO reads back set");
    }

    // And the classic setter must agree with the new one: after a termios2
    // set, a classic get must see it.
    memset(c, 0, sizeof c);
    {
        const long rb = LX_SYS3(SYS_ioctl, s, R_TCGETS, c);
        lx_emit("ioctl", LX_CHECK(rb == 0 && g2 == 0,
                                  (u32_at(c, OFF_LFLAG) & F_ECHO) != 0),
                "TCGETS sees what TCSETSW2 set");
    }

    // -- window size --------------------------------------------------------
    // struct winsize is 4 x unsigned short. A set must stick here too: this
    // is how every full-screen program learns its geometry.
    {
        unsigned short ws[4] = {0, 0, 0, 0};
        lx_emit("ioctl", LX_SYS3(SYS_ioctl, s, R_TIOCGWINSZ, ws),
                "TIOCGWINSZ on the pty slave");

        unsigned short set[4] = {40, 132, 0, 0};
        const long sw = LX_SYS3(SYS_ioctl, s, R_TIOCSWINSZ, set);
        lx_emit("ioctl", sw, "TIOCSWINSZ sets 40x132");
        unsigned short got[4] = {0, 0, 0, 0};
        const long rb = LX_SYS3(SYS_ioctl, s, R_TIOCGWINSZ, got);
        lx_emit("ioctl", LX_CHECK(sw == 0 && rb == 0, got[0] == 40),
                "winsize rows stuck");
        lx_emit("ioctl", LX_CHECK(sw == 0 && rb == 0, got[1] == 132),
                "winsize cols stuck");
    }

    // -- the foreground process group --------------------------------------
    // THE INVARIANT that catches the job-control bug. A shell loops until
    // tcgetpgrp(tty) == getpgrp(); if those two disagree it concludes it is a
    // background job, gives up on job control, and switches off line editing.
    // They must agree BEFORE and AFTER setpgid -- the bug was that setpgid
    // moved one and not the other.
    {
        int pg = 0;
        const long gp = LX_SYS3(SYS_ioctl, s, R_TIOCGPGRP, &pg);
        lx_emit("ioctl", gp >= 0 ? 1 : gp, "TIOCGPGRP on the pty slave");

#ifdef SYS_getpgrp
        const long mine = LX_SYS0(SYS_getpgrp);
#else
        const long mine = LX_SYS1(SYS_getpgid, 0);
#endif
        lx_emit("ioctl", LX_CHECK(gp == 0, pg == mine),
                "tcgetpgrp == getpgrp (a shell loops until this holds)");

        // Become a group leader, then re-check. This is exactly what bash
        // does in initialize_job_control.
        const long sp = LX_SYS2(SYS_setpgid, 0, 0);
        lx_emit("setpgid", sp, "setpgid(0,0) makes us a group leader");

#ifdef SYS_getpgrp
        const long after = LX_SYS0(SYS_getpgrp);
#else
        const long after = LX_SYS1(SYS_getpgid, 0);
#endif
        int pg2 = 0;
        const long gp2 = LX_SYS3(SYS_ioctl, s, R_TIOCGPGRP, &pg2);
        lx_emit("ioctl", LX_CHECK(sp == 0 && gp2 == 0, pg2 == after),
                "tcgetpgrp == getpgrp AFTER setpgid");
    }

    // -- who OWNS the terminal ---------------------------------------------
    // The session ioctls, which decide whether a shell gets job control at
    // all. These are policy-sensitive: Android's SELinux denies the shell
    // domain TIOCGSID and TIOCNOTTY on a pty that a desktop kernel allows,
    // so the golden pins whatever THIS kernel does and linuxity has to agree
    // with it rather than with an assumption.
    //
    // Order matters. TIOCGSID is asked BEFORE any claim, so the trace
    // records the not-our-terminal answer too, not just the happy path.
    {
        int sid = 0;
        lx_emit("ioctl", LX_SYS3(SYS_ioctl, s, R_TIOCGSID, &sid),
                "TIOCGSID before we own the terminal");

        // A session leader may claim the pty. setsid() fails if we are
        // already a group leader (the setpgid above made us one), so the
        // emitted value pins whichever answer this kernel gives.
        const long sd = LX_SYS0(SYS_setsid);
        lx_emit("setsid", sd, "setsid before claiming a controlling terminal");

        lx_emit("ioctl", LX_SYS3(SYS_ioctl, s, R_TIOCSCTTY, 0),
                "TIOCSCTTY claims the pty as our controlling terminal");

        int sid2 = 0;
        const long gs = LX_SYS3(SYS_ioctl, s, R_TIOCGSID, &sid2);
        lx_emit("ioctl", gs, "TIOCGSID after the claim");

        // Giving it up must stick: the session ioctls go back to refusing.
        lx_emit("ioctl", LX_SYS3(SYS_ioctl, s, R_TIOCNOTTY, 0),
                "TIOCNOTTY releases the controlling terminal");
        int pg3 = 0;
        lx_emit("ioctl", LX_SYS3(SYS_ioctl, s, R_TIOCGPGRP, &pg3),
                "TIOCGPGRP after TIOCNOTTY");
    }

    // -- the error boundaries ----------------------------------------------
    // An unknown request and a non-tty fd must fail the same way on both
    // sides. These pin that linuxity's default arm forwards rather than
    // inventing a success.
    lx_emit("ioctl", LX_SYS3(SYS_ioctl, s, 0xdeadUL, a),
            "an unknown ioctl request fails");

    {
        const long f = LX_SYS3(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY);
        lx_emit("ioctl", f < 0 ? f : LX_SYS3(SYS_ioctl, f, R_TCGETS, a),
                "TCGETS on a non-tty is ENOTTY");
        if (f >= 0) LX_SYS1(SYS_close, f);
    }

    lx_emit("ioctl", LX_SYS3(SYS_ioctl, 9999, R_TCGETS, a),
            "TCGETS on a closed fd is EBADF");

    // The session ioctls must reject a non-tty the same way, not fabricate a
    // success. linuxity answers these from its own bookkeeping, so this is
    // the arm that catches it saying yes to a plain file.
    {
        const long f = LX_SYS3(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY);
        int pg = 0;
        lx_emit("ioctl", f < 0 ? f : LX_SYS3(SYS_ioctl, f, R_TIOCGPGRP, &pg),
                "TIOCGPGRP on a non-tty is ENOTTY");
        lx_emit("ioctl", f < 0 ? f : LX_SYS3(SYS_ioctl, f, R_TIOCNOTTY, 0),
                "TIOCNOTTY on a non-tty is ENOTTY");
        if (f >= 0) LX_SYS1(SYS_close, f);
    }

    LX_SYS1(SYS_close, s);
    LX_SYS1(SYS_close, m);
    return 0;
}
