"""coreutils: the everyday commands produce the bytes they should."""
import hashlib
import os

from lxt import check, eq, need_cmd, sh, test


@test
def text_pipeline():
    """seq, sort, uniq, head, tail, wc, tr, cut, paste agree with Python."""
    need_cmd("seq", "sort", "uniq", "head", "tail", "wc", "tr", "cut", "paste")
    eq(sh("seq 1 200000 | sort -rn | head -n1").stdout, "200000\n", "seq|sort|head")
    eq(sh("seq 10 | tail -n3 | paste -sd,").stdout, "8,9,10\n", "tail|paste")
    eq(sh("printf 'b\\na\\nb\\nc\\na\\n' | sort | uniq -c | tr -s ' ' | cut -d' ' -f2,3").stdout,
       "2 a\n2 b\n1 c\n", "sort|uniq -c|cut")
    eq(sh("printf 'one two\\nthree\\n' | wc -lwc").stdout.split(), ["2", "3", "14"], "wc")
    eq(sh("echo Hello | tr a-z A-Z").stdout, "HELLO\n", "tr")
    return "9 tools"


@test
def hashing_and_bytes():
    """sha256sum/md5sum/base64/od over 5 MB match Python."""
    need_cmd("yes", "head", "sha256sum", "md5sum", "base64", "od", "cmp")
    data = (b"crazy\n" * 1000000)[:5000000]
    eq(sh("yes crazy | head -c 5000000 | sha256sum").stdout.split()[0], hashlib.sha256(data).hexdigest(), "sha256sum")
    with open("blob", "wb") as f:
        f.write(bytes(range(256)) * 10)
    eq(sh("md5sum blob").stdout.split()[0], hashlib.md5(bytes(range(256)) * 10).hexdigest(), "md5sum")
    eq(sh("base64 -w0 blob | base64 -d | cmp - blob && echo same").stdout, "same\n", "base64 round trip")
    eq(sh("head -c 4 blob | od -An -tx1").stdout.split(), ["00", "01", "02", "03"], "od")
    return "sha256 of 5 MB, md5, base64, od"


@test
def file_commands():
    """cp -a, mv, ln, rm -r, mkdir -p, touch -d, stat -c, chmod, du, df."""
    need_cmd("cp", "mv", "ln", "rm", "mkdir", "touch", "stat", "chmod", "du", "df", "ls")
    sh("mkdir -p a/b/c && echo data > a/b/c/f && chmod 640 a/b/c/f && ln -s c/f a/b/link && "
       "touch -d '2001-02-03 04:05:06' a/b/c/f", check_rc=0)
    sh("cp -a a copy", check_rc=0)
    eq(sh("stat -c '%a %s %Y' copy/b/c/f").stdout, sh("stat -c '%a %s %Y' a/b/c/f").stdout, "cp -a keeps mode, size, mtime")
    eq(sh("readlink copy/b/link").stdout, "c/f\n", "cp -a keeps the symlink")
    sh("mv copy moved && rm -r a", check_rc=0)
    eq(sh("cat moved/b/link").stdout, "data\n", "mv then read through the link")
    check(not os.path.exists("a"), "rm -r")
    eq(sh("ls moved/b").stdout.split(), ["c", "link"], "ls")
    check(sh("du -sk moved").stdout.split()[0].isdigit(), "du")
    eq(sh("df -P . | tail -n1 | awk '{print NF}'").stdout.strip(), "6", "df -P")
    return "cp -a, mv, ln, rm, stat, touch -d, du, df"


@test
def dates_and_ids():
    """date, id, whoami, uname, env, nproc look like Linux."""
    need_cmd("date", "id", "uname", "env", "nproc")
    eq(sh("date -u -d @0 +%Y-%m-%dT%H:%M:%S").stdout, "1970-01-01T00:00:00\n", "date -d @0")
    eq(sh("id -u").stdout.strip(), str(os.getuid()), "id -u")
    eq(sh("uname -s").stdout, "Linux\n", "uname -s")
    eq(sh("uname -r").stdout.strip(), os.uname().release, "uname -r")
    eq(sh("nproc").stdout.strip(), str(len(os.sched_getaffinity(0))), "nproc")
    eq(sh("FOO=bar env | grep ^FOO=").stdout, "FOO=bar\n", "env")
    return "date, id, uname, nproc, env"
