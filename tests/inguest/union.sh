#!/bin/bash
# union.sh LINUXITY ROOT: merged (upper + lower) directory listings served
# in the guest must read exactly like the supervisor's: same names, order,
# d_ino, d_type and cookies, through small buffers, rewinds, seeks to saved
# cookies, a dup or fork mid-listing, and an exec-free handover.
set -u
L=$1; R=$2
d=$(mktemp -d)
cat > "$d/t.c" <<'EOF'
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
struct ld { unsigned long ino; long off; unsigned short reclen; unsigned char type; char name[]; };
static void dump(const char* tag, int fd, int bufsz, int max) {
    char buf[65536];
    int n, k = 0;
    while ((n = syscall(SYS_getdents64, fd, buf, bufsz)) > 0) {
        for (int at = 0; at < n;) {
            struct ld* e = (struct ld*)(buf + at);
            printf("%s %s %lu %d %ld\n", tag, e->name, e->ino, e->type, e->off);
            at += e->reclen;
            if (max && ++k >= max) return;
        }
    }
    printf("%s end %d %d\n", tag, n, n < 0 ? errno : 0);
}
int main(int argc, char** argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    for (int a = 1; a < argc; a++) {
        const char* p = argv[a];
        // warm the site so the listing is served in the guest
        for (int w = 0; w < 12; w++) { DIR* x = opendir(p); if (x) { while (readdir(x)); closedir(x); } }
        int fd = open(p, O_RDONLY | O_DIRECTORY);
        if (fd < 0) { printf("open %s: %d\n", p, errno); continue; }
        printf("== %s\n", p);
        dump("big", fd, 65536, 0);
        lseek(fd, 0, SEEK_SET);
        dump("tiny", fd, 64, 0);          /* one or two entries a call */
        int r = syscall(SYS_getdents64, fd, (char[16]){0}, 16);
        printf("toosmall %d %d\n", r, r < 0 ? errno : 0);
        lseek(fd, 0, SEEK_SET);
        dump("part", fd, 200, 7);
        long here = lseek(fd, 0, SEEK_CUR);
        printf("tell %ld\n", here);
        dump("rest", fd, 300, 5);
        printf("seek %ld\n", lseek(fd, here, SEEK_SET));
        dump("again", fd, 300, 5);
        printf("back %ld\n", lseek(fd, -40, SEEK_CUR));
        dump("cur", fd, 300, 3);
        int d2 = dup(fd);
        dump("dup", d2, 400, 4);
        close(d2);
        pid_t c = fork();
        if (c == 0) { dump("child", fd, 4096, 6); _exit(0); }
        waitpid(c, 0, 0);
        dump("parent", fd, 4096, 0);
        close(fd);
    }
    return 0;
}
EOF
cc -O1 -o "$d/t" "$d/t.c" || exit 2
u=$(mktemp -d)
setup='mkdir -p /usr/share/fpu-a/sub; touch /usr/share/fpu-a/new1 /usr/share/fpu-a/new2; rm -f /usr/share/doc/README 2>/dev/null; true'
dirs="/usr/include /usr/share /usr/share/fpu-a /usr/bin /etc /var/lib/pacman/local /usr/lib"
run() {
    "$L" --quiet --root "$R" --persist "$u" --bind "$d:/fpu" /fpu/t $dirs 2>&1
}
# the files only one layer has, made once so both runs see the same inodes
LINUXITY_TEST_ALL_TRAP=1 "$L" --quiet --root "$R" --persist "$u" /bin/sh -c "$setup" >/dev/null 2>&1
run > "$d/on"
LINUXITY_TEST_ALL_TRAP=1 run > "$d/off"
rc=0
if cmp -s "$d/off" "$d/on"; then
    echo "union: $(grep -c . "$d/on") lines match"
else
    echo "union: listings differ (< all trapped, > in-guest):"
    diff "$d/off" "$d/on" | head -20
    rc=1
fi
LINUXITY_PROFILE=1 "$L" --quiet --root "$R" --persist "$u" --bind "$d:/fpu" /fpu/t /usr/include 2>&1 >/dev/null | grep 'linuxity in-guest'
rm -rf "$d" "$u"
exit $rc
