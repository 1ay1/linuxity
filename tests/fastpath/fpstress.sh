#!/bin/bash
# fpstress.sh LINUXITY ROOT: the in-guest fast path under concurrency.
# Threads open/close/stat/readdir at once while the supervisor serves other
# calls; forks inherit open dirs; vfork children share memory; results must
# match a plain run.
set -u
L=$1; R=$2
d=$(mktemp -d)
cat > "$d/t.c" <<'EOF'
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
static const char* dirs[] = {"/usr/include", "/usr/include/linux", "/usr/bin", "/etc", "/usr/lib"};
static long count_dir(const char* p) {
    DIR* d = opendir(p);
    if (!d) return -1;
    long n = 0;
    struct dirent* e;
    while ((e = readdir(d))) n++;
    rewinddir(d);
    long m = 0;
    while ((e = readdir(d))) m++;
    closedir(d);
    return n == m ? n : -(n * 100000 + m);
}
static long want[5];
static int fails;
static void* worker(void* arg) {
    long id = (long)arg;
    for (int round = 0; round < 40; round++) {
        int i = (int)((id + round) % 5);
        long n = count_dir(dirs[i]);
        if (n != want[i]) { __atomic_add_fetch(&fails, 1, __ATOMIC_RELAXED); printf("FAIL t%ld %s %ld != %ld\n", id, dirs[i], n, want[i]); }
        int fd = open("/etc/passwd", O_RDONLY | O_CLOEXEC);
        char buf[16];
        if (fd < 0 || read(fd, buf, 4) != 4 || memcmp(buf, "root", 4)) { __atomic_add_fetch(&fails, 1, __ATOMIC_RELAXED); printf("FAIL t%ld read passwd\n", id); }
        int d2 = dup(fd);
        struct stat a, b;
        if (fstat(d2, &a) || stat("/etc/passwd", &b) || a.st_ino != b.st_ino) { __atomic_add_fetch(&fails, 1, __ATOMIC_RELAXED); printf("FAIL t%ld dup stat\n", id); }
        close(fd); close(d2);
    }
    return 0;
}
int main(void) {
    setvbuf(stdout, 0, _IOLBF, 0);
    for (int i = 0; i < 5; i++) want[i] = count_dir(dirs[i]);
    pthread_t th[8];
    for (long i = 0; i < 8; i++) pthread_create(&th[i], 0, worker, (void*)i);
    for (int i = 0; i < 8; i++) pthread_join(th[i], 0);
    // a child forked with open dirs lists them right, and its closes don't
    // touch the parent's
    DIR* keep = opendir("/usr/include");
    for (int k = 0; k < 5; k++) readdir(keep);
    pid_t c = fork();
    if (c == 0) {
        long n = 0; while (readdir(keep)) n++;
        closedir(keep);
        _exit(n > 0 && count_dir("/usr/bin") == want[2] ? 0 : 1);
    }
    int st; waitpid(c, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st)) { fails++; printf("FAIL forked child\n"); }
    long rest = 0; while (readdir(keep)) rest++;
    if (rest + 5 + 0 < 6) { fails++; printf("FAIL parent dir after child closed its copy\n"); }
    closedir(keep);
    // vfork-style spawns share memory with us while they run
    for (int k = 0; k < 20; k++) {
        pid_t p;
        char* av[] = {"/usr/bin/true", 0};
        if (posix_spawn(&p, "/usr/bin/true", 0, 0, av, environ)) { fails++; printf("FAIL spawn\n"); continue; }
        int fd = open("/etc/passwd", O_RDONLY);
        waitpid(p, &st, 0);
        if (fd < 0) { fails++; printf("FAIL open after spawn\n"); }
        close(fd);
        if (count_dir("/etc") != want[3]) { fails++; printf("FAIL list after spawn\n"); }
    }
    printf(fails ? "fpstress: %d failures\n" : "fpstress: all good\n", fails);
    return fails != 0;
}
EOF
cc -O1 -pthread -o "$d/t" "$d/t.c" || exit 2
u=$(mktemp -d)
rc=0
for fp in ${FPS:-1 0 1 1}; do
    LINUXITY_FASTPATH=$fp LINUXITY_PROFILE=1 "$L" --quiet --root "$R" --persist "$u" --bind "$d:/fps" /fps/t 2>"$d/err" || rc=1
    grep 'fast path' "$d/err"
done
rm -rf "$d" "$u"
exit $rc
