// tests/probes/rwio.c
//
// read/write/pread/pwrite/readv/writev/lseek on regular files, plus the
// boundaries that callers actually branch on.
//
// These are the most-executed syscalls in any workload, and most of them are
// FORWARDED on Linux -- which is exactly why this probe matters: it proves the
// forwarding path does not corrupt offsets, short reads, or errnos, and it
// pins the behaviour before anyone decides to intercept one of them.
//
// Everything happens in a file this probe creates, so the trace is independent
// of the host's filesystem contents.
#include "probe.h"

#include <fcntl.h>
#include <sys/uio.h>
#include <string.h>

#define PATH "/tmp/lx-rwio-probe.dat"

int main(void) {
    // -- create, write, and verify the offset bookkeeping -----------------
    const long fd = LX_SYS4(SYS_openat, AT_FDCWD, PATH,
                            O_RDWR | O_CREAT | O_TRUNC, 0644);
    lx_emit("openat", fd < 0 ? fd : 1, "create the scratch file");
    if (fd < 0) return 1;

    const char* msg = "0123456789abcdef";          // 16 bytes
    const long w = LX_SYS3(SYS_write, fd, msg, 16);
    lx_emit("write", w, "write 16 bytes");

    // The offset must now be exactly 16.
    lx_emit("lseek", LX_SYS3(SYS_lseek, fd, 0, SEEK_CUR), "offset after write");

    // SEEK_END on a 16-byte file is 16; SEEK_SET 0 rewinds.
    lx_emit("lseek", LX_SYS3(SYS_lseek, fd, 0, SEEK_END), "SEEK_END is the size");
    lx_emit("lseek", LX_SYS3(SYS_lseek, fd, 0, SEEK_SET), "SEEK_SET 0 rewinds");

    // Seeking PAST the end is legal and does not extend the file.
    lx_emit("lseek", LX_SYS3(SYS_lseek, fd, 100, SEEK_SET), "seek past EOF is legal");
    lx_emit("read", LX_SYS3(SYS_read, fd, (char[16]){0}, 16), "read past EOF is 0");
    lx_emit("lseek", LX_SYS3(SYS_lseek, fd, 0, SEEK_SET), "rewind again");

    // -- read: full, short, and zero --------------------------------------
    {
        char buf[32];
        memset(buf, 0, sizeof buf);
        const long r = LX_SYS3(SYS_read, fd, buf, 8);
        lx_emit("read", r, "read 8 of 16");
        // The CONTENT matters here -- it is deterministic, unlike a directory.
        lx_emit_buf("read", r < 0 ? r : 1, 1, buf, 8, "first 8 bytes");

        // Asking for more than remains must short-read, not fail.
        const long r2 = LX_SYS3(SYS_read, fd, buf, 32);
        lx_emit("read", r2, "read 32 with only 8 left short-reads to 8");

        // At EOF, read returns 0.
        lx_emit("read", LX_SYS3(SYS_read, fd, buf, 8), "read at EOF is 0");

        // A zero-length read is 0, not an error.
        lx_emit("read", LX_SYS3(SYS_read, fd, buf, 0), "zero-length read is 0");
    }

    // -- pread/pwrite do NOT move the file offset --------------------------
    {
        lx_emit("lseek", LX_SYS3(SYS_lseek, fd, 4, SEEK_SET), "park the offset at 4");

        char buf[8];
        const long pr = LX_SYS4(SYS_pread64, fd, buf, 4, 12);
        lx_emit("pread64", pr, "pread 4 at offset 12");
        lx_emit_buf("pread64", pr < 0 ? pr : 1, 1, buf, 4, "bytes at offset 12");

        // THE invariant: the offset must still be 4.
        lx_emit("lseek", LX_SYS3(SYS_lseek, fd, 0, SEEK_CUR),
                "pread left the offset alone");

        const long pw = LX_SYS4(SYS_pwrite64, fd, "ZZZZ", 4, 0);
        lx_emit("pwrite64", pw, "pwrite 4 at offset 0");
        lx_emit("lseek", LX_SYS3(SYS_lseek, fd, 0, SEEK_CUR),
                "pwrite left the offset alone");

        // And the write landed where asked.
        const long back = LX_SYS4(SYS_pread64, fd, buf, 4, 0);
        lx_emit("pread64", back < 0 ? back : 1, "read back offset 0");
        lx_emit_buf("pread64", 1, 1, buf, 4, "pwrite landed at offset 0");

        // A negative pread offset is EINVAL.
        lx_emit("pread64", LX_SYS4(SYS_pread64, fd, buf, 4, -1),
                "negative pread offset is EINVAL");
        // ...and so is a negative pwrite offset. pwrite also must not
        // extend a file backwards or move the offset, which the read-back
        // above checks for the success case.
        lx_emit("pwrite64", LX_SYS4(SYS_pwrite64, fd, "Q", 1, -1),
                "negative pwrite offset is EINVAL");
        lx_emit("pwrite64", LX_SYS4(SYS_pwrite64, 9999, "Q", 1, 0),
                "pwrite on a closed fd is EBADF");
    }

    // -- readv / writev ----------------------------------------------------
    {
        lx_emit("lseek", LX_SYS3(SYS_lseek, fd, 0, SEEK_SET), "rewind for readv");

        char a[4], b[6];
        struct iovec iov[2] = {{a, sizeof a}, {b, sizeof b}};
        const long rv = LX_SYS3(SYS_readv, fd, iov, 2);
        lx_emit("readv", rv, "readv fills both buffers");
        lx_emit_buf("readv", rv < 0 ? rv : 1, 1, a, sizeof a, "readv first iov");
        lx_emit_buf("readv", rv < 0 ? rv : 1, 1, b, sizeof b, "readv second iov");

        // A zero-count readv is 0.
        lx_emit("readv", LX_SYS3(SYS_readv, fd, iov, 0), "readv with 0 iovs is 0");

        // writev appends at the current offset.
        struct iovec out[2] = {{(void*)"XY", 2}, {(void*)"Z", 1}};
        lx_emit("lseek", LX_SYS3(SYS_lseek, fd, 0, SEEK_END), "seek to end");
        const long wv = LX_SYS3(SYS_writev, fd, out, 2);
        lx_emit("writev", wv, "writev 2+1 bytes");
        lx_emit("lseek", LX_SYS3(SYS_lseek, fd, 0, SEEK_CUR), "offset advanced by 3");

        // READ THEM BACK. A writev that reports 3 but scattered the bytes
        // wrong, or coalesced the iovs in the wrong order, looks identical
        // from the return value alone -- and ordering across iovs is the
        // one thing writev exists to get right.
        {
            char back[3] = {0, 0, 0};
            const long off = LX_SYS3(SYS_lseek, fd, -3, SEEK_CUR);
            const long rb = (off < 0) ? off : LX_SYS3(SYS_read, fd, back, 3);
            lx_emit_buf("writev", rb < 0 ? rb : 1, 1, back, 3,
                        "the iovs landed in order");
        }

        // A zero-count writev writes nothing and is not an error.
        lx_emit("writev", LX_SYS3(SYS_writev, fd, out, 0), "writev with 0 iovs is 0");
        // A negative count is EINVAL, and a bad fd is EBADF -- the two ways
        // a caller gets this wrong.
        lx_emit("writev", LX_SYS3(SYS_writev, fd, out, -1),
                "writev with a negative count is EINVAL");
        lx_emit("writev", LX_SYS3(SYS_writev, 9999, out, 2),
                "writev on a closed fd is EBADF");
        lx_emit("readv", LX_SYS3(SYS_readv, 9999, iov, 2),
                "readv on a closed fd is EBADF");
    }

    // -- the error boundaries ---------------------------------------------
    lx_emit("read", LX_SYS3(SYS_read, 9999, (char[4]){0}, 4), "read bad fd is EBADF");
    lx_emit("write", LX_SYS3(SYS_write, 9999, "x", 1), "write bad fd is EBADF");

    // Reading from a write-only fd is EBADF (not EACCES).
    {
        const long wo = LX_SYS4(SYS_openat, AT_FDCWD, PATH, O_WRONLY, 0);
        lx_emit("openat", wo < 0 ? wo : 1, "reopen write-only");
        if (wo >= 0) {
            lx_emit("read", LX_SYS3(SYS_read, wo, (char[4]){0}, 4),
                    "read from a write-only fd is EBADF");
            lx_emit("close", LX_SYS1(SYS_close, wo), "close write-only");
        }
    }

    // Writing to a read-only fd is EBADF.
    {
        const long ro = LX_SYS4(SYS_openat, AT_FDCWD, PATH, O_RDONLY, 0);
        lx_emit("openat", ro < 0 ? ro : 1, "reopen read-only");
        if (ro >= 0) {
            lx_emit("write", LX_SYS3(SYS_write, ro, "x", 1),
                    "write to a read-only fd is EBADF");
            lx_emit("close", LX_SYS1(SYS_close, ro), "close read-only");
        }
    }

    // O_APPEND ignores the offset and always writes at the end.
    {
        const long ap = LX_SYS4(SYS_openat, AT_FDCWD, PATH, O_WRONLY | O_APPEND, 0);
        lx_emit("openat", ap < 0 ? ap : 1, "reopen O_APPEND");
        if (ap >= 0) {
            lx_emit("lseek", LX_SYS3(SYS_lseek, ap, 0, SEEK_SET),
                    "seek to 0 on an O_APPEND fd");
            lx_emit("write", LX_SYS3(SYS_write, ap, "!", 1),
                    "O_APPEND write goes to the end anyway");
            lx_emit("lseek", LX_SYS3(SYS_lseek, ap, 0, SEEK_CUR),
                    "offset is at the new end, not 1");
            lx_emit("close", LX_SYS1(SYS_close, ap), "close O_APPEND");
        }
    }

    // -- ftruncate and the resulting size ---------------------------------
    lx_emit("ftruncate", LX_SYS2(SYS_ftruncate, fd, 4), "truncate to 4");
    lx_emit("lseek", LX_SYS3(SYS_lseek, fd, 0, SEEK_END), "size is now 4");
    lx_emit("ftruncate", LX_SYS2(SYS_ftruncate, fd, -1),
            "negative ftruncate is EINVAL");
    lx_emit("ftruncate", LX_SYS2(SYS_ftruncate, 9999, 0),
            "ftruncate bad fd is EBADF");

    lx_emit("close", LX_SYS1(SYS_close, fd), "close the scratch file");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, PATH, 0), "unlink it");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, PATH, 0),
            "unlink again is ENOENT");

    return 0;
}
