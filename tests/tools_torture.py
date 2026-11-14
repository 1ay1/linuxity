#!/usr/bin/env python3
"""tools_torture.py -- real programs doing real work: shells, coreutils,
text tools, archivers, perl, package databases, sqlite, a parallel build.
Each exercises many subsystems at once, the way users do; when the other
suites pass but one of these fails, the bug is in an interaction.
See torture.py for running."""
import sys
sys.dont_write_bytecode = True
import hashlib
import os
import subprocess
import time

from torture import *  # noqa: F401,F403
from torture import check, ok, eq, Skip, main, sh, have, ROOT


def need(*progs):
    missing = [p for p in progs if not have(p)]
    if missing:
        raise Skip(f"not installed here: {' '.join(missing)}")


def run(cmd, timeout=60, **kw):
    rc, out, err = sh(cmd, timeout=timeout, **kw)
    if rc != 0:
        raise AssertionError(f"`{cmd[:80]}` exited {rc}: {err.strip()[-300:]}")
    return out


@check(timeout=90)
def bash_language_features():
    need("bash")
    script = r'''
set -euo pipefail
declare -A m=([a]=1 [b]=2); arr=(x y z)
f() { local v=$1; echo "$((v * 2))"; }
r=$(f 21)
exec 3> fd3.txt; echo three >&3; exec 3>&-
diff <(printf 'a\nb\n') <(printf 'a\nb\n')
trap 'echo trapped' USR1; kill -USR1 $$
read -r first < <(echo "from process substitution")
cat <<EOF > here.txt
${m[b]}:${#arr[@]}:${arr[1]}
EOF
( exit 3 ) || sub=$?
{ false | true; ps=("${PIPESTATUS[@]}"); } || :
for i in {1..200}; do :; done
coproc C { read -r x; echo "co:$x"; }; echo ping >&"${C[1]}"; read -r back <&"${C[0]}"
printf '%s|' "$r" "$(cat fd3.txt)" "$first" "$(cat here.txt)" "$sub" "${ps[*]}" "$back"
'''
    out = run(f"bash -c {sh_quote(script)}")
    eq(out, "trapped\n42|three|from process substitution|2:3:y|3|1 0|co:ping|",
       "bash: arrays, functions, fds, process substitution, traps, coprocs")


def sh_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


@check
def posix_sh_and_many_processes():
    need("dash")
    out = run("dash -c 'i=0; while [ $i -lt 300 ]; do i=$((i+1)); /bin/true; done; echo $i'")
    eq(out.strip(), "300", "300 fork+exec from dash")
    out = run("dash -c 'for i in 1 2 3 4 5 6 7 8; do (sleep 0.2; echo $i) & done; wait' | sort | tr -d '\\n'")
    eq(out, "12345678", "eight background jobs, wait")
    rc, _, _ = sh("dash -c 'exit 7'")
    eq(rc, 7, "exit status")
    rc, out, _ = sh("dash -c 'kill -TERM $$; echo not reached'")
    ok(rc in (-15, 143) and out == "", f"a shell killed by a signal: rc={rc} out={out!r}")


@check(timeout=90)
def coreutils_pipelines():
    need("seq", "sort", "head", "wc", "md5sum", "tr", "cut", "uniq", "tac", "paste")
    eq(run("seq 1 200000 | sort -rn | head -1").strip(), "200000", "seq | sort -rn | head")
    eq(run("seq 1 100000 | wc -l").strip(), "100000", "wc -l")
    data = os.urandom(3 << 20)
    open("blob", "wb").write(data)
    eq(run("md5sum blob").split()[0], hashlib.md5(data).hexdigest(), "md5sum of 3 MiB")
    eq(run("sha256sum blob").split()[0], hashlib.sha256(data).hexdigest(), "sha256sum")
    eq(run("echo 'b a c a b a' | tr ' ' '\\n' | sort | uniq -c | sort -rn | head -1").split(), ["3", "a"], "uniq -c")
    eq(run("printf '1:x\\n2:y\\n' | cut -d: -f2 | tac | paste -sd,").strip(), "y,x", "cut | tac | paste")
    eq(run("date -u -d @0 +%Y-%m-%dT%H:%M:%S").strip(), "1970-01-01T00:00:00", "date -d @0")
    eq(run("expr 6 \\* 7").strip(), "42", "expr")
    ok(int(run("nproc").strip()) == len(os.sched_getaffinity(0)), "nproc")


@check(timeout=90)
def file_tools_preserve_metadata():
    need("cp", "mv", "ln", "stat", "du", "df", "touch", "chmod", "rm", "mkdir")
    run("mkdir -p tree/a/b && echo hi > tree/a/b/f && chmod 751 tree/a/b/f && "
        "touch -d '2001-02-03 04:05:06' tree/a/b/f && ln -s b/f tree/a/link")
    run("cp -a tree copy")
    eq(run("stat -c '%a %Y' copy/a/b/f").strip(), run("stat -c '%a %Y' tree/a/b/f").strip(),
       "cp -a keeps mode and mtime")
    eq(os.readlink("copy/a/link"), "b/f", "cp -a keeps symlinks as symlinks")
    run("mv copy moved && test -f moved/a/b/f && test ! -e copy")
    ok(int(run("du -sk tree").split()[0]) > 0, "du")
    ok("%" in run("df -P ."), "df")
    run("rm -rf tree moved")
    eq(os.listdir("."), [], "rm -rf")


@check(timeout=90)
def find_xargs_grep_sed_awk():
    need("find", "xargs", "grep", "sed", "awk")
    for d in range(10):
        os.makedirs(f"src/d{d}")
        for f in range(20):
            open(f"src/d{d}/f{f}.txt", "w").write(f"line {d} {f}\nTODO fix {d}-{f}\n")
    eq(run("find src -name '*.txt' | wc -l").strip(), "200", "find")
    eq(run("find src -type f -print0 | xargs -0 -P8 -n10 grep -l TODO | wc -l").strip(), "200",
       "xargs -P8 fans out grep")
    eq(run("grep -rc TODO src | awk -F: '{s+=$2} END {print s}'").strip(), "200", "grep -rc | awk")
    run("sed -i 's/TODO/DONE/' src/d3/f7.txt")
    eq(open("src/d3/f7.txt").read(), "line 3 7\nDONE fix 3-7\n", "sed -i")
    eq(run("awk 'BEGIN{for(i=1;i<=100;i++) s+=i; printf \"%d %s\", s, toupper(\"ok\")}'"), "5050 OK", "awk")
    eq(run("grep -E -o '[0-9]+-[0-9]+' src/d9/f19.txt").strip(), "9-19", "grep -E -o")


@check(timeout=120)
def archives_round_trip():
    need("tar", "gzip", "xz")
    os.makedirs("t/sub/deep")
    open("t/sub/deep/data", "wb").write(os.urandom(500_000))
    open("t/text", "w").write("hello\n" * 1000)
    os.chmod("t/text", 0o640)
    os.symlink("sub/deep/data", "t/link")
    os.link("t/text", "t/hard")
    for flag, ext in (("z", "gz"), ("J", "xz"), ("", "tar")):
        run(f"tar -c{flag}f a.{ext} t")
        os.makedirs(f"x{ext}")
        run(f"tar -x{flag}pf a.{ext} -C x{ext}")
        run(f"diff -r t x{ext}/t")
        eq(os.readlink(f"x{ext}/t/link"), "sub/deep/data", f"{ext}: symlink")
        eq(os.stat(f"x{ext}/t/text").st_mode & 0o777, 0o640, f"{ext}: mode")
        eq(os.stat(f"x{ext}/t/text").st_ino, os.stat(f"x{ext}/t/hard").st_ino, f"{ext}: hard link")
    run("gzip -9 -c t/text > text.gz && gzip -t text.gz && zcat text.gz | cmp - t/text")


@check
def perl_and_python_subprocesses():
    need("perl")
    eq(run("perl -e 'my %h=(a=>1,b=>2); print join(\",\", map {\"$_=$h{$_}\"} sort keys %h), \"\\n\"'").strip(),
       "a=1,b=2", "perl")
    eq(run("perl -MPOSIX -e 'print floor(7.9), \" \", getppid() > 0 ? \"ok\" : \"no\"'"), "7 ok", "perl POSIX")
    big = os.urandom(8 << 20)
    p = subprocess.run([sys.executable, "-c", "import sys; d=sys.stdin.buffer.read(); sys.stdout.buffer.write(d[::-1])"],
                       input=big, capture_output=True, timeout=60)
    eq(p.stdout == big[::-1], True, "8 MiB through a child's stdin and stdout")
    procs = [subprocess.Popen([sys.executable, "-c", f"print({i}*{i})"], stdout=subprocess.PIPE) for i in range(30)]
    eq([int(p.communicate()[0]) for p in procs], [i * i for i in range(30)], "30 concurrent pythons")


@check(timeout=90)
def sqlite_wal_across_processes():
    import sqlite3
    db = sqlite3.connect("t.db")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE t (k INTEGER PRIMARY KEY, v TEXT)")
    db.commit()
    code = ("import sqlite3,sys; d=sqlite3.connect('t.db', timeout=30); "
            "[ (d.execute('INSERT INTO t(v) VALUES (?)', (sys.argv[1],)), d.commit()) for _ in range(200) ]")
    procs = [subprocess.Popen([sys.executable, "-c", code, f"w{i}"]) for i in range(4)]
    for p in procs:
        eq(p.wait(60), 0, "writer")
    eq(db.execute("SELECT count(*) FROM t").fetchone()[0], 800, "800 rows from 4 concurrent writers")
    eq(db.execute("PRAGMA integrity_check").fetchone()[0], "ok", "integrity_check")
    ok(os.path.exists("t.db-wal") and os.path.exists("t.db-shm"), "WAL and its shared-memory index")


@check
def system_tools_see_the_system():
    need("ps", "getent", "id")
    out = run("ps -eo pid,comm")
    ok(str(os.getpid()) in out.split(), "ps lists us")
    eq(run("getent passwd root").split(":")[0], "root", "getent passwd")
    eq(run("id -u").strip(), str(os.getuid()), "id -u")
    if have("top"):
        ok("load average" in run("top -b -n1 | head -5"), "top -b")
    if have("dpkg"):
        ok(int(run("dpkg -l | grep -c '^ii'").strip()) > 50, "dpkg's database")
    if have("apt-cache"):
        ok("Installed:" in run("apt-cache policy bash"), "apt-cache policy")
    if have("locale"):
        ok("C.utf8" in run("locale -a") or "C.UTF-8" in run("locale -a"), "locale -a")


@check(timeout=120)
def parallel_build_like_make():
    need("sh", "cat", "xargs")
    os.makedirs("objs")
    for i in range(64):
        open(f"s{i}.c", "w").write(f"unit {i}\n" * 500)
    t = time.monotonic()
    run("ls s*.c | xargs -P8 -I{} sh -c 'sleep 0.05; sha1sum {} > objs/{}.o'")
    run("cat objs/*.o | sort > linked")
    eq(len(open("linked").read().splitlines()), 64, "64 objects linked")
    ok(time.monotonic() - t < 60, f"in {time.monotonic() - t:.1f}s")
    if have("make"):
        open("Makefile", "w").write("all: $(patsubst %.c,%.out,$(wildcard s*.c))\n%.out: %.c\n\tcp $< $@\n")
        run("make -j8 -s")
        eq(len([f for f in os.listdir(".") if f.endswith(".out")]), 64, "make -j8")


@check(timeout=60)
def a_session_dbus_bus_is_there():
    # A Linux login session has a D-Bus session bus at $XDG_RUNTIME_DIR/bus
    # (systemd's dbus.socket). GTK's accessibility bridge, Firefox, portals
    # and notifications all reach for it; without one every GTK app warned
    # "Failed to create DBus proxy for org.a11y.Bus". linuxity starts the
    # guest's own dbus-daemon on first use, socket-activated.
    if not have("dbus-send"):
        raise Skip("no dbus-send in this image")
    addr = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")
    if not addr:
        raise Skip("no session bus in this session (no XDG_RUNTIME_DIR or dbus-daemon)")
    rt = os.environ.get("XDG_RUNTIME_DIR", "")
    ok(addr == f"unix:path={rt}/bus", f"the bus is at $XDG_RUNTIME_DIR/bus ({addr})")
    st = os.stat(rt)
    eq((st.st_uid, st.st_mode & 0o777), (os.getuid(), 0o700), "XDG_RUNTIME_DIR is ours, 0700")
    rc, out, err = sh("dbus-send --session --print-reply --dest=org.freedesktop.DBus / org.freedesktop.DBus.GetId", timeout=20)
    eq(rc, 0, f"the bus answers: {err.strip()}")
    if os.path.exists("/usr/share/dbus-1/services/org.a11y.Bus.service"):
        rc, out, err = sh("dbus-send --session --print-reply --dest=org.a11y.Bus /org/a11y/bus org.a11y.Bus.GetAddress", timeout=20)
        eq(rc, 0, f"D-Bus activation works (org.a11y.Bus): {err.strip()}")


if __name__ == "__main__":
    sys.exit(main("real programs"))
