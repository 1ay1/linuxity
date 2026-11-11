#!/usr/bin/env python3
"""oracle.py -- one command that says whether a Linux environment behaves
like Linux.

It runs every *_torture.py suite beside it, each as its own process with a
deadline, and gives one verdict. The suites together cover the whole
system call surface a program meets:

    process     fork/exec/wait, signals, sessions, job control, /proc/<pid>
    filesystem  files, dirs, names, links, metadata, permissions, locks
    memory      mmap, protection, sharing, mremap, memfd, JIT, limits
    ipc         pipes, SysV shm/sem/msg, POSIX shm/sem/mqueue, eventfd
    sync        threads, futexes, clocks, sleeps, timers, signalfd, asyncio
    net         TCP, UDP, AF_UNIX, fd passing, readiness, DNS, the internet
    tty         ptys, line discipline, termios, SIGWINCH, an interactive bash
    sys         uname, creds, capabilities, rlimits, /proc, /sys, namespaces,
                seccomp, landlock, ptrace
    tools       bash, coreutils, find/grep/sed/awk, tar/gzip/xz, perl,
                sqlite in WAL mode, a parallel build

Run as root, it runs everything twice: as root, then again as an ordinary
user (the first uid >= 1000 in /etc/passwd), because permission rules are
half the kernel. Every check in every suite must also hold on a real Linux
kernel -- the oracle is the kernel's behaviour, not linuxity's.

    python3 oracle.py              # everything
    python3 oracle.py net tty      # just these suites
    python3 oracle.py -v           # every failing check, with tracebacks
    python3 oracle.py --no-user    # as root: skip the unprivileged pass

Exit status 0 means: nothing failed anywhere.
"""
import os
import pwd
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SUITES = [
    ("process", "process_torture.py"),
    ("filesystem", "fs_torture.py"),
    ("memory", "mem_torture.py"),
    ("ipc", "ipc_torture.py"),
    ("sync", "sync_torture.py"),
    ("net", "net_torture.py"),
    ("tty", "tty_torture.py"),
    ("sys", "sys_torture.py"),
    ("tools", "tools_torture.py"),
]
SUMMARY = re.compile(r"(\d+) passed, (\d+) failed, (\d+) skipped of (\d+)")


def ordinary_user():
    for p in sorted(pwd.getpwall(), key=lambda p: p.pw_uid):
        if 1000 <= p.pw_uid < 60000:
            return p
    return pwd.getpwnam("nobody")


def run_suite(script, user=None, verbose=False, deadline=900):
    """(passed, failed, skipped, total, secs, failure lines, note, skip lines)"""
    cmd = [sys.executable, "-X", "utf8", os.path.join(HERE, script)] + (["-v"] if verbose else [])
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

    def drop():
        os.setpgid(0, 0)
        if user:
            os.setgroups([])
            os.setgid(user.pw_gid)
            os.setuid(user.pw_uid)
    if user:
        env.update(HOME=user.pw_dir if os.path.isdir(user.pw_dir) else "/tmp",
                   USER=user.pw_name, LOGNAME=user.pw_name)
    t = time.monotonic()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         env=env, cwd="/tmp", preexec_fn=drop)
    try:
        out, _ = p.communicate(timeout=deadline)
        note = ""
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        note = f"the suite itself timed out after {deadline}s"
    secs = time.monotonic() - t
    text = out.decode(errors="replace")
    m = SUMMARY.findall(text)
    if not m:
        tail = "\n".join(text.strip().splitlines()[-5:])
        return 0, 1, 0, 1, secs, [f"  CRASH {script}: no summary line (exit {p.returncode})\n{tail}"], note, []
    passed, failed, skipped, total = map(int, m[-1])
    keep = ("FAIL",) if not verbose else ("FAIL", "Traceback", "  File", "Error", "    ")
    lines = [l for l in text.splitlines() if l.lstrip().startswith(keep)]
    skips = [l for l in text.splitlines() if l.lstrip().startswith("SKIP")]
    return passed, failed, skipped, total, secs, lines, note, skips


def main(argv):
    verbose = "-v" in argv
    words = [a for a in argv if not a.startswith("-")]
    chosen = [s for s in SUITES if not words or s[0] in words]
    passes = [("root" if os.geteuid() == 0 else pwd.getpwuid(os.getuid()).pw_name, None)]
    if os.geteuid() == 0 and "--no-user" not in argv:
        u = ordinary_user()
        passes.append((f"{u.pw_name} (uid {u.pw_uid})", u))
    print(f"oracle: {len(chosen)} suites x {len(passes)} identities on "
          f"{os.uname().sysname} {os.uname().release} {os.uname().machine}\n", flush=True)
    grand = [0, 0, 0, 0]
    failures, all_skips = [], []
    t0 = time.monotonic()
    for who, user in passes:
        print(f"as {who}:", flush=True)
        for name, script in chosen:
            passed, failed, skipped, total, secs, lines, note, skips = run_suite(script, user, verbose)
            for i, v in enumerate((passed, failed, skipped, total)):
                grand[i] += v
            mark = "ok  " if not failed and not note else "FAIL"
            print(f"  {mark} {name:11} {passed:3}/{total:<3} passed, {failed} failed, "
                  f"{skipped} skipped  {secs:6.1f}s  {note}", flush=True)
            for l in lines:
                failures.append(f"[{who}] {name}: {l.strip()}" if not verbose else l)
            all_skips += [f"[{who}] {name}: {l.strip()}" for l in skips]
        print(flush=True)
    passed, failed, skipped, total = grand
    if all_skips:
        print("skipped (not tested here, and why):")
        for s in all_skips:
            print("  " + re.sub(r"\s+\d+\.\d+s\s+", "  ", s)[:200])
        print()
    if failures:
        print("failures:")
        for f in failures:
            print("  " + (f if verbose else re.sub(r"\s+\d+\.\d+s\s+", "  ", f)[:240]))
        print()
    secs = time.monotonic() - t0
    if failed:
        print(f"ORACLE: FAIL -- {failed} of {total} checks failed ({passed} passed, {skipped} skipped) in {secs:.0f}s")
        return 1
    print(f"ORACLE: PASS -- all {passed} checks behave like Linux ({skipped} skipped) in {secs:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
