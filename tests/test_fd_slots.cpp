// The shared fd-slot table (runtime/shared/fd_slots.hpp).
//
// This is the half of FdTable that darwin and windows had line-for-line
// identical. It is pure bookkeeping -- no host calls -- so it is testable on
// any host, which is the point: the fd-number logic is where the bugs live
// (an off-by-one in the lowest-free scan shows up as a guest reading the
// wrong file, long after the mistake).
#include "linuxity/runtime/shared/fd_slots.hpp"

#include <cstdio>
#include <memory>
#include <string>

using namespace lx;
using namespace lx::runtime;

// Stand-ins for the backends' HostFd / WinFd and their per-slot extras.
struct FakeFile {
    int handle;
    explicit FakeFile(int h) : handle{h} {}
};
struct FakeExtra {
    bool append{false};
    std::string path;
};

using Table = FdSlots<FakeFile, FakeExtra>;

static int failures = 0;
static void check(bool cond, const char* what) {
    if (!cond) { std::fprintf(stderr, "FAIL: %s\n", what); ++failures; }
}

static std::shared_ptr<FakeFile> mk(int h) {
    return std::make_shared<FakeFile>(h);
}

int main() {
    // -- lowest free fd, which POSIX REQUIRES ------------------------------
    // Programs depend on it: a shell builds pipelines assuming 0/1/2 then the
    // next free numbers. Handing out a higher fd when a lower one is free
    // breaks that silently.
    //
    // Note how 0/1/2 get reserved: by installing REAL entries, not by
    // resizing. An empty slot is still free, so the scan would hand out fd 0
    // and a guest's open() would return 1 -- writing its data into stdout.
    // My first version of this resized instead, and this test caught it.
    {
        Table t;
        for (int i = 0; i < 3; ++i) (void)t.install(mk(i), false);
        check(t.size() == 3, "0/1/2 occupied");
        const int a = t.install(mk(100), false);
        const int b = t.install(mk(101), false);
        check(a == 3, "first open gets fd 3, not 0");
        check(b == 4, "then 4");

        // Free the lower one; the next install MUST reuse it.
        check(t.close(a) == 0, "close(3)");
        const int c = t.install(mk(102), false);
        check(c == 3, "the freed LOWEST slot is reused, not appended");

        // And a hole in the middle is filled before growing.
        const int d = t.install(mk(103), false);
        check(d == 5, "no hole left, so grow");
        check(t.close(4) == 0, "close(4) to make a hole");
        check(t.install(mk(104), false) == 4, "the hole is filled first");
    }

    // -- close ------------------------------------------------------------
    {
        Table t;
        const int g = t.install(mk(7), false);
        check(t.valid(g), "installed fd is valid");
        check(t.close(g) == 0, "close succeeds");
        check(!t.valid(g), "and the slot is actually cleared");
        // Double close, and closing something never opened, are both EBADF.
        check(t.close(g) == -static_cast<int>(Errno::ebadf), "double close is EBADF");
        check(t.close(999) == -static_cast<int>(Errno::ebadf), "unknown fd is EBADF");
        check(t.close(-1) == -static_cast<int>(Errno::ebadf), "negative fd is EBADF");
    }

    // -- dup shares the FILE, not a copy ----------------------------------
    // Both fds must see one file offset; that shared offset is the whole
    // point of dup. Copying the File instead of the pointer would give each
    // fd its own position, and `cmd >> log` from two fds would overwrite.
    {
        Table t;
        const int a = t.install(mk(42), false);
        const int b = t.dup(a, false);
        check(b > a, "dup returns a new fd number");
        check(t.at(a)->file == t.at(b)->file, "dup SHARES the underlying file");
        check(t.at(a)->file.use_count() == 2, "...by reference, not by copy");
        // Closing one must not disturb the other.
        check(t.close(a) == 0, "close the original");
        check(t.valid(b), "the dup survives");
        check(t.at(b)->file->handle == 42, "and still points at the same host fd");
    }

    // -- dup and the extra payload ----------------------------------------
    // Windows tracks append mode and the guest path per slot; a dup that
    // dropped the path binding would make an *at call through the new fd
    // resolve against the wrong directory (the `rm -rf` class of bug).
    //
    // But Extra is NOT copied implicitly: Windows' holds a
    // unique_ptr<DirCursor>, so an implicit copy wouldn't even compile -- and
    // a SHARED cursor would be wrong anyway, since two fds reading one
    // directory would consume each other's entries. So the caller states what
    // the new slot gets, and that is what this checks.
    {
        Table t;
        const int a = t.install(mk(1), false, FakeExtra{true, "/var/lib"});
        const int b = t.dup(a, false, t.at(a)->extra);   // explicit carry-over
        check(t.at(b)->extra.append, "dup can carry the append flag");
        check(t.at(b)->extra.path == "/var/lib", "dup can carry the path binding");
        // ...and the default is a FRESH Extra, not the source's.
        const int c = t.dup(a, false);
        check(!t.at(c)->extra.append && t.at(c)->extra.path.empty(),
              "dup without an explicit Extra gets a fresh one");
        // The file is still shared either way -- that part is not optional.
        check(t.at(a)->file == t.at(c)->file, "dup always shares the file");
    }

    // -- a move-only Extra must work --------------------------------------
    // This is Windows' real shape (unique_ptr<DirCursor>). An earlier version
    // of dup() copied Extra and simply failed to instantiate here; the
    // compiler caught it, which is why the signature takes Extra by value.
    {
        struct MoveOnlyExtra { std::unique_ptr<int> cursor; };
        FdSlots<FakeFile, MoveOnlyExtra> mt;
        const int g = mt.install(mk(1), false, MoveOnlyExtra{std::make_unique<int>(7)});
        check(g == 0, "install with a move-only Extra");
        check(mt.at(g)->extra.cursor && *mt.at(g)->extra.cursor == 7,
              "...and it arrives intact");
        const int d = mt.dup(g, false, MoveOnlyExtra{std::make_unique<int>(9)});
        check(d == 1 && *mt.at(d)->extra.cursor == 9,
              "dup with a fresh move-only Extra");
        check(mt.at(g)->file == mt.at(d)->file, "the file is still shared");
    }

    // -- dup2/dup3 onto a FIXED target ------------------------------------
    {
        Table t;
        const int a = t.install(mk(10), false);
        const int b = t.install(mk(11), false);
        check(t.dup_to(a, b, false) == b, "dup2 returns the target");
        check(t.at(b)->file->handle == 10, "the target now aliases the source");
        check(t.at(a)->file == t.at(b)->file, "...sharing the file");

        // dup2(fd, fd) is a documented NO-OP and must not clear cloexec.
        t.set_cloexec(a, true);
        check(t.dup_to(a, a, false) == a, "dup2(fd,fd) returns fd");
        check(t.cloexec(a), "dup2(fd,fd) must NOT clear the cloexec bit");

        // A bad source is EBADF, and must not have touched the target.
        check(t.dup_to(500, b, false) == -static_cast<int>(Errno::ebadf),
              "dup2 from an unknown fd is EBADF");
        check(t.at(b)->file->handle == 10, "...and the target is untouched");

        // dup2 can target a fd beyond the current table, growing it.
        check(t.dup_to(a, 64, false) == 64, "dup2 to a high fd grows the table");
        check(t.valid(64), "and that fd is usable");
    }

    // -- cloexec ----------------------------------------------------------
    {
        Table t;
        const int keep = t.install(mk(1), /*cloexec=*/false);
        const int drop = t.install(mk(2), /*cloexec=*/true);
        check(!t.cloexec(keep) && t.cloexec(drop), "cloexec bit is per slot");
        t.set_cloexec(keep, true);
        check(t.cloexec(keep), "set_cloexec works");
        t.set_cloexec(keep, false);
        check(!t.cloexec(keep), "...and clears");

        // execve drops exactly the cloexec descriptors. Missing this leaks
        // fds into the new image, which is a sandbox concern when the leaked
        // fd points outside the guest root.
        t.on_exec();
        check(t.valid(keep), "a non-cloexec fd survives exec");
        check(!t.valid(drop), "a cloexec fd is dropped by exec");

        // Asking about an unknown or closed fd is false, not a crash.
        check(!t.cloexec(999), "cloexec(unknown) is false");
        check(!t.cloexec(-1), "cloexec(negative) is false");
        t.set_cloexec(999, true);   // must not grow the table or crash
        check(t.size() < 999u, "set_cloexec on an unknown fd is a no-op");
    }

    // -- the cap ----------------------------------------------------------
    {
        Table t;
        int last = 0;
        for (int i = 0; i < Table::kMaxFds; ++i) last = t.install(mk(i), false);
        check(last == Table::kMaxFds - 1, "fills exactly to the cap");
        check(t.install(mk(0), false) == -static_cast<int>(Errno::emfile),
              "one past the cap is EMFILE, not a silent overwrite");
        // Freeing one makes room again.
        check(t.close(5) == 0, "free a slot");
        check(t.install(mk(0), false) == 5, "and the cap lifts by exactly one");
    }

    if (failures == 0) std::puts("fd_slots: all checks passed");
    return failures == 0 ? 0 : 1;
}
