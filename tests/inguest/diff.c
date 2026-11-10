// Prints what stat/lstat/statx/readlink/xattr return for a list of paths,
// each call made from the SAME site many times so the in-guest handler kicks in.
// Run it with the in-guest handler on and off and diff the output.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static void one(const char* p) {
    struct stat st;
    struct statx sx;
    char buf[512];
    int r;
    for (int rep = 0; rep < 6; rep++) {
        memset(&st, 0xaa, sizeof st);
        r = stat(p, &st);
        if (rep == 5) printf("stat %s = %d e=%d mode=%o uid=%u gid=%u nlink=%lu size=%ld ino=%lu\n", p, r, r ? errno : 0,
                             st.st_mode, st.st_uid, st.st_gid, (unsigned long)st.st_nlink, (long)st.st_size, (unsigned long)st.st_ino);
    }
    for (int rep = 0; rep < 6; rep++) {
        memset(&st, 0xaa, sizeof st);
        r = lstat(p, &st);
        if (rep == 5) printf("lstat %s = %d e=%d mode=%o uid=%u nlink=%lu size=%ld\n", p, r, r ? errno : 0,
                             st.st_mode, st.st_uid, (unsigned long)st.st_nlink, (long)st.st_size);
    }
    for (int rep = 0; rep < 6; rep++) {
        memset(&sx, 0xaa, sizeof sx);
        r = statx(AT_FDCWD, p, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS | STATX_MNT_ID, &sx);
        if (rep == 5) printf("statx %s = %d e=%d mask=%x mode=%o uid=%u mnt=%llu attr=%llx/%llx btime=%lld\n", p, r, r ? errno : 0,
                             sx.stx_mask, sx.stx_mode, sx.stx_uid, (unsigned long long)sx.stx_mnt_id,
                             (unsigned long long)sx.stx_attributes, (unsigned long long)sx.stx_attributes_mask,
                             (long long)sx.stx_btime.tv_sec);
    }
    for (int rep = 0; rep < 6; rep++) {
        memset(buf, 0, sizeof buf);
        r = (int)readlink(p, buf, sizeof buf - 1);
        if (rep == 5) printf("readlink %s = %d e=%d '%s'\n", p, r, r < 0 ? errno : 0, r > 0 ? buf : "");
    }
    for (int rep = 0; rep < 6; rep++) {
        memset(buf, 0, sizeof buf);
        r = (int)llistxattr(p, buf, sizeof buf);
        if (rep == 5) printf("llistxattr %s = %d e=%d\n", p, r, r < 0 ? errno : 0);
    }
    for (int rep = 0; rep < 6; rep++) {
        r = (int)lgetxattr(p, "user.nope", buf, sizeof buf);
        if (rep == 5) printf("lgetxattr %s = %d e=%d\n", p, r, r < 0 ? errno : 0);
    }
    for (int rep = 0; rep < 6; rep++) {
        r = access(p, F_OK);
        int r2 = access(p, X_OK);
        if (rep == 5) printf("access %s = %d e=%d x=%d\n", p, r, r ? errno : 0, r2);
    }
    for (int rep = 0; rep < 6; rep++) {
        int fd = open(p, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
        int e1 = fd < 0 ? errno : 0;
        struct stat fs; memset(&fs, 0, sizeof fs);
        if (fd >= 0) { fstat(fd, &fs); close(fd); }
        if (rep == 5) printf("open %s = %d e=%d mode=%o size=%ld\n", p, fd >= 0, e1, fs.st_mode, (long)fs.st_size);
    }
}

int main(int argc, char** argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--cd") == 0 && i + 1 < argc) { if (chdir(argv[++i])) perror("chdir"); continue; }
        one(argv[i]);
    }
    return 0;
}
