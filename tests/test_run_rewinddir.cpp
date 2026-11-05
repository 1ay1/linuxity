// rewinddir()/seekdir() over an overlay-union directory.
//
// A merged directory's entries live in linuxity's OWN dir_stream, not in the
// backing host fd: the host fd sees only the upper layer. So rewinddir(3) --
// which is an lseek(fd, 0, SEEK_SET) on the dirfd -- must reset OUR cursor.
//
// It didn't. lseek was missing from the seccomp trapped set, so it ran
// natively in the guest and never reached the dispatcher's (already written)
// Sysno::lseek handler. The host lseek rewound a directory holding only the
// upper's entries while our cursor stayed at EOF, so the second readdir pass
// returned ZERO entries.
//
// That broke every rewinddir-driven walk. Concretely: libalpm rewinds
// /var/lib/pacman/local before loading the package cache, so `pacman -Q`
// reported 0 packages on a database with 139 of them.
#include "guest_harness.hpp"

#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/linux/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/stat.h>

using namespace lx;

// Counts entries, rewinds, counts again, and requires the two passes to
// agree. The directory is a UNION: some names exist only in the read-only
// lower, some only in the upper, so a correct rewind has to replay the merged
// listing rather than whatever the host fd holds.
static const char* kSrc =
    "#include <stdio.h>\n"
    "#include <string.h>\n"
    "#include <dirent.h>\n"
    "#include <errno.h>\n"
    "#include <sys/types.h>\n"
    "#include <unistd.h>\n"
    "static int count(DIR* d){\n"
    "  int n = 0; struct dirent* e;\n"
    "  while ((e = readdir(d))) {\n"
    "    if (!strcmp(e->d_name, \".\") || !strcmp(e->d_name, \"..\")) continue;\n"
    "    n++;\n"
    "  }\n"
    "  return n;\n"
    "}\n"
    "int main(void){\n"
    "  DIR* d = opendir(\"/db\");\n"
    "  if (!d) return 1;\n"
    "  int p1 = count(d);\n"
    "  if (p1 != 4) return 10 + p1;        /* 2 lower + 2 upper, merged */\n"
    "  rewinddir(d);\n"
    "  int p2 = count(d);\n"
    "  if (p2 != p1) return 20 + p2;       /* the bug: p2 was 0 */\n"
    // A THIRD pass, to prove the cursor is genuinely reusable and the first
    // rewind didn't just get lucky.
    "  rewinddir(d);\n"
    "  int p3 = count(d);\n"
    "  if (p3 != p1) return 40 + p3;\n"
    "  closedir(d);\n"
    // seekdir to a saved position must also land where it was told. This is
    // the same lseek path with a non-zero offset.
    "  DIR* d2 = opendir(\"/db\");\n"
    "  if (!d2) return 2;\n"
    "  struct dirent* e = readdir(d2);\n"
    "  if (!e) return 3;\n"
    "  long after_first = telldir(d2);\n"
    "  while (readdir(d2)) {}\n"
    "  seekdir(d2, after_first);\n"
    "  struct dirent* again = readdir(d2);\n"
    "  if (!again) return 4;              /* seekdir left us at EOF */\n"
    "  closedir(d2);\n"
    // Callers do arithmetic on telldir() cookies -- fish seeks by
    // `saved - current` -- so cookies and lseek must share one unit. With
    // d_off an entry index and lseek counting bytes, that difference
    // underflowed and lseek returned EINVAL.
    "  DIR* d3 = opendir(\"/db\");\n"
    "  if (!d3) return 5;\n"
    "  if (!readdir(d3)) return 5;\n"
    "  long c1 = telldir(d3);\n"
    "  if (!readdir(d3)) return 5;\n"
    "  long c2 = telldir(d3);\n"
    "  if (c2 <= c1) return 8;            /* cookies must advance */\n"
    // The cookies must be BYTE offsets, not entry indices: a 4-entry dir
    // yields indices 1..4 but byte offsets in the hundreds. Checking the
    // magnitude is what distinguishes the two, and it's the reason fish's
    // lseek(dirfd, -102, SEEK_CUR) used to return EINVAL -- with indices,
    // 102 was past the start of the stream.
    "  if (c2 < 24) return 10;            /* a dirent record is >= 24 bytes */\n"
    "  errno = 0;\n"
    // Seek back over a whole record by its byte length. With an index
    // cursor this underflowed to EINVAL.
    "  if (lseek(dirfd(d3), c1 - c2, SEEK_CUR) == -1) return 9;\n"
    // And the absolute form fish actually used.
    "  errno = 0;\n"
    "  if (lseek(dirfd(d3), c2, SEEK_SET) != c2) return 11;\n"
    "  closedir(d3);\n"
    "  return 99;\n}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_rewinddir: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    // /db is a union: two entries in the pristine lower, two in the upper.
    // Neither layer alone has all four, so a rewind that replays the host fd
    // instead of our stream produces the wrong count (or zero).
    const auto tree = lxtest::make_tree("rewind", /*overlay=*/true,
        "mkdir -p /tmp/lx_rewind_root/db /tmp/lx_rewind_upper/db"
        " && touch /tmp/lx_rewind_root/db/lower_a /tmp/lx_rewind_root/db/lower_b"
        " && touch /tmp/lx_rewind_upper/db/upper_a /tmp/lx_rewind_upper/db/upper_b");
    if (!lxtest::compile_guest("run_rewinddir", tree, kSrc)) return 0;

    auto r = lxtest::run_guest(tree);
    lxtest::remove_tree(tree);

    if (!r) { std::puts("run_rewinddir: skipped (ptrace unavailable)"); return 0; }
    const int code = *r;
    // Exit-code encoding: 99 = pass. 1-4 = setup failures. 10+N / 20+N / 40+N
    // carry the entry count each pass saw, so a failure says WHAT it counted.
    if (code >= 10 && code < 20) {
        std::printf("run_rewinddir: FAIL first pass saw %d entries, expected 4 "
                    "(the overlay union is not merging)\n", code - 10);
        return 1;
    }
    if (code >= 20 && code < 40) {
        std::printf("run_rewinddir: FAIL after rewinddir the second pass saw "
                    "%d entries, expected 4. lseek on a dir fd is not "
                    "resetting our dir_stream -- check that 8 (lseek) is in "
                    "kTrappedX86_64 (runtime/linux/seccomp_filter.hpp); if it "
                    "is not trapped, the dispatcher's Sysno::lseek case is "
                    "unreachable and `pacman -Q` reports nothing.\n",
                    code - 20);
        return 1;
    }
    if (code >= 40 && code < 60) {
        std::printf("run_rewinddir: FAIL the third pass saw %d entries -- the "
                    "cursor is not reusable across rewinds\n", code - 40);
        return 1;
    }
    if (code == 4) {
        std::puts("run_rewinddir: FAIL seekdir() to a saved telldir() position "
                  "left the stream at EOF (non-zero lseek offset ignored)");
        return 1;
    }
    if (code == 8) {
        std::puts("run_rewinddir: FAIL telldir() cookies did not advance between "
                  "entries -- d_off must be a growing byte offset");
        return 1;
    }
    if (code == 9) {
        std::puts("run_rewinddir: FAIL lseek(dirfd, c1 - c2, SEEK_CUR) returned "
                  "EINVAL. telldir() cookies and lseek disagree on units: d_off "
                  "is bytes, so the dir cursor must count bytes too, not "
                  "entries. This is the fish 'lseek: Invalid argument' bug.");
        return 1;
    }
    if (code == 10) {
        std::puts("run_rewinddir: FAIL telldir() cookies are too small to be "
                  "byte offsets -- d_off is still an entry index, so any "
                  "caller doing arithmetic on cookies hits EINVAL");
        return 1;
    }
    if (code == 11) {
        std::puts("run_rewinddir: FAIL lseek(dirfd, cookie, SEEK_SET) did not "
                  "return the cookie it was given");
        return 1;
    }
    if (code != 99) {
        std::printf("run_rewinddir: FAIL guest exit=%d (expected 99)\n", code);
        return 1;
    }
    std::puts("run_rewinddir: rewinddir/seekdir reset the merged dir cursor; "
              "three passes over a lower+upper union all see 4 entries, and "
              "seeking by a telldir() cookie difference works, exit=99");
    return 0;
#endif
}
