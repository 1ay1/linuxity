"""findutils, grep, sed, awk, tar and xargs over a real tree."""
import os

from lxt import check, eq, need_cmd, sh, test


def make_tree():
    for d in ("t/a/x", "t/b", "t/c/deep/er"):
        os.makedirs(d, exist_ok=True)
    for p, body in (("t/a/x/one.txt", "alpha\n"), ("t/b/two.txt", "beta\ngamma\n"),
                    ("t/c/deep/er/three.log", "delta\n"), ("t/c/space name.txt", "eps\n")):
        with open(p, "w") as f:
            f.write(body)
    os.symlink("../b/two.txt", "t/a/link.txt")


@test
def find_queries():
    """find by name, type, depth, size, newer and with -exec / -print0."""
    need_cmd("find", "xargs", "sort")
    make_tree()
    eq(sh("find t -name '*.txt' -type f | sort").stdout.split("\n")[:-1],
       ["t/a/x/one.txt", "t/b/two.txt", "t/c/space name.txt"], "-name -type f")
    eq(sh("find t -type l").stdout, "t/a/link.txt\n", "-type l")
    eq(sh("find t -mindepth 3 -maxdepth 3 -type d | sort").stdout, "t/c/deep/er\n", "-mindepth/-maxdepth")
    eq(sh("find t -name '*.log' -exec cat {} +").stdout, "delta\n", "-exec +")
    eq(sh("find t -name '*.txt' -type f -print0 | xargs -0 cat | sort").stdout.split(),
       ["alpha", "beta", "eps", "gamma"], "-print0 | xargs -0")
    sh("touch -d '2000-01-01' t/b/two.txt", check_rc=0)
    eq(sh("find t -type f -newer t/b/two.txt -name '*.txt' | sort").stdout.split("\n")[:-1],
       ["t/a/x/one.txt", "t/c/space name.txt"], "-newer")
    eq(sh("find -L t -name link.txt -type f").stdout, "t/a/link.txt\n", "-L follows links")
    return "name, type, depth, exec, print0, newer, -L"


@test
def grep_sed_awk():
    """grep -r/-c/-l, sed -i and s///g, awk fields and sums."""
    need_cmd("grep", "sed", "awk")
    make_tree()
    # files containing an 'a' (grep -r skips the symlink unless -R)
    eq(sh("grep -rl a t | sort").stdout.split("\n")[:-1],
       ["t/a/x/one.txt", "t/b/two.txt", "t/c/deep/er/three.log"], "grep -rl")
    eq(sh("grep -Rl a t | sort").stdout.split("\n")[:-1],
       ["t/a/link.txt", "t/a/x/one.txt", "t/b/two.txt", "t/c/deep/er/three.log"], "grep -Rl")
    eq(sh("grep -c a t/b/two.txt").stdout, "2\n", "grep -c")
    eq(sh("grep -E '^(alpha|delta)$' -rh t | sort").stdout, "alpha\ndelta\n", "grep -E -h")
    sh("sed -i 's/a/A/g' t/b/two.txt", check_rc=0)
    with open("t/b/two.txt") as f:
        eq(f.read(), "betA\ngAmmA\n", "sed -i s///g")
    eq(sh("seq 1 100 | awk '{s+=$1} END {print s}'").stdout, "5050\n", "awk sum")
    eq(sh("echo 'a:b:c' | awk -F: '{print $3 $1}'").stdout, "ca\n", "awk -F")
    return "grep -rl/-c/-E, sed -i, awk"


@test
def tar_roundtrip():
    """tar czf / xzf keeps contents, modes, mtimes and symlinks."""
    need_cmd("tar", "gzip")
    make_tree()
    os.chmod("t/a/x/one.txt", 0o751)
    sh("tar czf t.tgz t && mkdir out && tar xzf t.tgz -C out", check_rc=0)
    for p in ("a/x/one.txt", "b/two.txt", "c/space name.txt"):
        a, b = os.stat(f"t/{p}"), os.stat(f"out/t/{p}")
        eq((b.st_mode, b.st_size, int(b.st_mtime)), (a.st_mode, a.st_size, int(a.st_mtime)), p)
    eq(os.readlink("out/t/a/link.txt"), "../b/two.txt", "symlink in the archive")
    eq(sh("tar tzf t.tgz | wc -l").stdout.strip(), str(len(sh("find t").stdout.split("\n")) - 1), "entry count")
    return "contents, modes, mtimes, symlinks"


@test
def parallel_xargs():
    """xargs -P runs jobs concurrently and collects every result."""
    need_cmd("xargs", "seq", "sort")
    r = sh("seq 1 64 | xargs -P 8 -I{} sh -c 'echo $(({} * {}))' | sort -n | tail -n1", timeout=60)
    eq(r.stdout, "4096\n", "xargs -P 8")
    return "64 jobs, 8 at a time"
