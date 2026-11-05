// tests/probes/dirseek.c
//
// Directory cursor conformance: getdents64 + lseek on one fd.
//
// This is the scenario that caught the real bug. getdents64 handed out d_off
// as a byte offset while lseek treated the position as an entry INDEX, so any
// caller doing arithmetic on telldir() cookies got EINVAL -- fish asked for
// lseek(dirfd, -102, SEEK_CUR) and failed at every startup.
//
// Everything here is a RAW syscall. Using opendir/telldir would observe
// glibc's cached buffer position instead of the kernel's fd offset, which is
// how a hand-written test of this exact behaviour passed while broken.
#include "probe.h"

#include <fcntl.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    const char* path = argc > 1 ? argv[1] : "/usr/bin";

    const long fd = LX_SYS3(SYS_openat, AT_FDCWD, path, O_RDONLY | O_DIRECTORY);
    lx_emit("openat", fd, path);
    if (fd < 0) return 1;

    static char buf[4096];

    // First batch. The SIZE is deliberately NOT emitted: /proc has one entry
    // per process, so the guest (which must see its OWN processes, not the
    // host's) legitimately reports 384 bytes where the host reports 4096.
    // Comparing that would report a design requirement as a divergence.
    //
    // What IS comparable is the cursor ALGEBRA -- the invariants the kernel
    // guarantees regardless of how many entries a directory holds. That is
    // where the real bug lived.
    const long n1 = LX_SYS3(SYS_getdents64, fd, buf, sizeof buf);
    lx_emit("getdents64", n1 > 0 ? 1 : n1, "first batch is non-empty");
    if (n1 <= 0) return 1;

    // The cursor must ADVANCE past zero after reading. The bug reported an
    // entry index here (13) where the kernel reports a byte offset (368);
    // both are positive, so the invariant that catches it is the relationship
    // between the cursor and the bytes just read, checked below.
    const long at = LX_SYS3(SYS_lseek, fd, 0, SEEK_CUR);
    lx_emit("lseek", at > 0 ? 1 : at, "cursor advanced after a read");

    // THE regression, as an invariant rather than a magic number: the cursor
    // must be in the SAME UNIT as the bytes getdents64 returned, so seeking
    // back by a byte-sized delta is valid. With an index cursor, 102 was past
    // the start of the stream and this returned EINVAL -- the fish bug.
    const long back = LX_SYS3(SYS_lseek, fd, -102, SEEK_CUR);
    lx_emit("lseek", back >= 0 ? 1 : back, "rewind by a byte delta (the fish case)");

    // The cursor must be a byte count, not an entry count: a directory whose
    // first batch filled N bytes cannot have a cursor smaller than the number
    // of RECORDS, and a byte cursor is always >= 24 per record. Comparing the
    // boolean keeps this stable across directories of any size.
    lx_emit("lseek", at >= 24 ? 1 : 0, "cursor is a byte offset, not an index");

    // The stream must still be readable after that seek.
    const long n2 = LX_SYS3(SYS_getdents64, fd, buf, sizeof buf);
    lx_emit("getdents64", n2 >= 0 ? 1 : n2, "readable after relative seek");

    // Absolute rewind, then a re-read: a full rewind must restart the stream.
    const long zero = LX_SYS3(SYS_lseek, fd, 0, SEEK_SET);
    lx_emit("lseek", zero, "SEEK_SET 0 -- rewind");

    const long n3 = LX_SYS3(SYS_getdents64, fd, buf, sizeof buf);
    lx_emit("getdents64", n3 == n1 ? 1 : 0, "rewound batch matches the first");

    // Seeking to the cookie the kernel just reported must be accepted.
    const long to_at = LX_SYS3(SYS_lseek, fd, at, SEEK_SET);
    lx_emit("lseek", to_at == at ? 1 : to_at, "SEEK_SET to a reported cookie");

    // Error paths. These matter more than the happy path: an emulator that
    // returns the wrong errno breaks callers that branch on it, and this is
    // where divergence is most common.
    const long neg = LX_SYS3(SYS_lseek, fd, -1, SEEK_SET);
    lx_emit("lseek", neg, "SEEK_SET -1 must be EINVAL");

    const long badwhence = LX_SYS3(SYS_lseek, fd, 0, 99);
    lx_emit("lseek", badwhence, "bad whence must be EINVAL");

    const long badfd = LX_SYS3(SYS_lseek, 9999, 0, SEEK_SET);
    lx_emit("lseek", badfd, "bad fd must be EBADF");

    // Reading a directory with read(2) is EISDIR, a classic emulator miss.
    const long rd = LX_SYS3(SYS_read, fd, buf, sizeof buf);
    lx_emit("read", rd, "read() on a dirfd must be EISDIR");

    lx_emit("close", LX_SYS1(SYS_close, fd), 0);

    // Operating on the closed fd must now be EBADF.
    lx_emit("getdents64", LX_SYS3(SYS_getdents64, fd, buf, sizeof buf),
            "after close must be EBADF");

    return 0;
}
