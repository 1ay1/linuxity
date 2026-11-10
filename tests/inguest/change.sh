#!/bin/bash
# change.sh LINUXITY ROOT: the in-guest handler must notice changes made while a
# process is running: chmod, chown, rm of a lower file, rename, a new link,
# chdir. One long-lived guest probes, changes, probes again.
set -u
L=$1; R=$2
d=$(mktemp -d)
cat > "$d/t.c" <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static int fails;
// the same call site every time, so it is patched after the first few
static int probe(const char* p, struct stat* st) { return lstat(p, st); }
static void warm(const char* p) { struct stat st; for (int i = 0; i < 10; i++) probe(p, &st); }
static void want(const char* what, const char* p, int ok, unsigned mode, unsigned uid, unsigned nlink) {
    struct stat st; memset(&st, 0, sizeof st);
    int r = probe(p, &st);
    int good = ok ? (r == 0 && (!mode || (st.st_mode & 07777) == mode) && st.st_uid == uid &&
                     (!nlink || st.st_nlink == nlink))
                  : (r != 0 && errno == ENOENT);
    if (!good) { fails++; printf("FAIL %s %s: r=%d e=%d mode=%o uid=%u nlink=%lu\n", what, p, r, r ? errno : 0,
                                 st.st_mode & 07777, st.st_uid, (unsigned long)st.st_nlink); }
}
int main(void) {
    setvbuf(stdout, 0, _IOLBF, 0);
    system("rm -rf /tmp/c; mkdir -p /tmp/c/d; echo a > /tmp/c/f; echo b > /tmp/c/g; echo h > /tmp/c/h");
    warm("/tmp/c/f"); warm("/tmp/c/g"); warm("/usr/bin/bash"); warm("/tmp/c/h"); warm("f");
    want("start", "/tmp/c/f", 1, 0644, 0, 1);
    if (chmod("/tmp/c/f", 0600)) perror("chmod");
    want("after chmod", "/tmp/c/f", 1, 0600, 0, 1);
    if (chown("/tmp/c/f", 123, 45)) perror("chown");
    want("after chown", "/tmp/c/f", 1, 0600, 123, 1);
    if (rename("/tmp/c/g", "/tmp/c/g2")) perror("rename");
    want("renamed away", "/tmp/c/g", 0, 0, 0, 0);
    want("renamed to", "/tmp/c/g2", 1, 0644, 0, 1);
    if (link("/tmp/c/h", "/tmp/c/h2")) perror("link");
    want("after link", "/tmp/c/h", 1, 0644, 0, 2);
    want("the link", "/tmp/c/h2", 1, 0644, 0, 2);
    // a lower-layer file removed in the overlay (whiteout)
    if (unlink("/usr/bin/bash")) perror("unlink");
    want("whited out", "/usr/bin/bash", 0, 0, 0, 0);
    // relative paths follow chdir
    if (chdir("/tmp/c")) perror("chdir");
    want("relative after chdir", "f", 1, 0600, 123, 1);
    if (chdir("/tmp/c/d")) perror("chdir2");
    want("relative in new dir", "f", 0, 0, 0, 0);
    // fork: the child sees the same answers, and its chdir is its own
    pid_t c = fork();
    if (c == 0) {
        want("child relative", "f", 0, 0, 0, 0);
        if (chdir("/tmp/c")) perror("child chdir");
        want("child after chdir", "f", 1, 0600, 123, 1);
        _exit(fails);
    }
    int st; waitpid(c, &st, 0);
    if (WEXITSTATUS(st)) { fails++; printf("FAIL child\n"); }
    want("parent unaffected", "f", 0, 0, 0, 0);
    // a warm directory swapped for a symlink to /etc: names under it must
    // resolve in the guest's /etc, never the host's
    system("mkdir -p /tmp/c/sw; echo s > /tmp/c/sw/x");
    warm("/tmp/c/sw/x"); warm("/tmp/c/sw/passwd");
    if (rename("/tmp/c/sw", "/tmp/c/sw.old")) perror("rename sw");
    if (symlink("/etc", "/tmp/c/sw")) perror("symlink");
    want("under swapped dir", "/tmp/c/sw/x", 0, 0, 0, 0);
    struct stat a, b;
    memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    int ra = probe("/tmp/c/sw/passwd", &a), rb = probe("/etc/passwd", &b);
    if (ra != rb || a.st_size != b.st_size || a.st_ino != b.st_ino) {
        fails++;
        printf("FAIL swapped dir resolves outside the guest: %d/%ld vs %d/%ld\n", ra, (long)a.st_size, rb, (long)b.st_size);
    }
    // fds: an fd number reused for another file, a dup2 over a warm fd, a
    // chmod seen through fstat. (A dirfd whose dir was renamed away resolves
    // by its old name in the dispatcher too; diff-style agreement is
    // what the in-guest handler owes there, and the blob checks the parent's
    // inode so it never answers from the wrong dir by itself.)
    {
        system("mkdir -p /tmp/c/fa; echo 1 > /tmp/c/fa/one; echo 22 > /tmp/c/fa/two");
        struct stat s;
        for (int k = 0; k < 6; k++) {
            int fd = open(k % 2 ? "/tmp/c/fa/two" : "/tmp/c/fa/one", O_RDONLY);
            for (int j = 0; j < 4; j++) fstat(fd, &s);
            if (s.st_size != (k % 2 ? 3 : 2)) { fails++; printf("FAIL fd reuse round %d size %ld\n", k, (long)s.st_size); }
            close(fd);
        }
        int a = open("/tmp/c/fa/one", O_RDONLY), b = open("/tmp/c/fa/two", O_RDONLY);
        for (int j = 0; j < 4; j++) fstat(a, &s);
        dup2(b, a);
        fstat(a, &s);
        if (s.st_size != 3) { fails++; printf("FAIL fstat after dup2 size %ld\n", (long)s.st_size); }
        chmod("/tmp/c/fa/two", 0640);
        fstat(a, &s);
        if ((s.st_mode & 0777) != 0640) { fails++; printf("FAIL fstat after chmod mode %o\n", s.st_mode & 0777); }
        int d = open("/tmp/c/fa", O_RDONLY | O_DIRECTORY);
        for (int j = 0; j < 4; j++) fstatat(d, "one", &s, AT_SYMLINK_NOFOLLOW);
        if (s.st_size != 2) { fails++; printf("FAIL fstatat dirfd size %ld\n", (long)s.st_size); }
        close(a); close(b); close(d);
    }
    printf(fails ? "change: %d failures\n" : "change: all good\n", fails);
    return fails != 0;
}
EOF
cc -O1 -o "$d/t" "$d/t.c" -include sys/wait.h || exit 2
u=$(mktemp -d)
rc=0
for trap in "" 1; do
    LINUXITY_TEST_ALL_TRAP=$trap LINUXITY_PROFILE=1 "$L" --quiet --root "$R" --persist "$u" --bind "$d:/fpc" /fpc/t 2>"$d/err" || rc=1
    grep 'linuxity in-guest' "$d/err"
    rm -rf "$u"; mkdir -p "$u"
done
LINUXITY_FORCE_LINK_EMULATION=1 LINUXITY_PROFILE=1 "$L" --quiet --root "$R" --persist "$u" --bind "$d:/fpc" /fpc/t 2>"$d/err" || rc=1
grep 'linuxity in-guest' "$d/err"
rm -rf "$d" "$u"
exit $rc
