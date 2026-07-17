// Exercises the real VFS end-to-end: a tmpfs root, a second tmpfs mounted
// at /proc, file creation, write/read round-trips, path resolution across a
// mount boundary, and the errno paths. This is "install a rootfs and use it"
// in miniature — no host, no OS, pure runtime.
#include "linuxity/vfs/vfs.hpp"
#include "linuxity/vfs/tmpfs.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string_view>

using namespace lx;
using namespace lx::vfs;

static std::span<const std::byte> bytes(std::string_view s) {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

int main() {
    // A root filesystem mounted at "/", plus a separate tmpfs at "/proc" to
    // prove longest-prefix mount resolution.
    Vfs fs{Tmpfs{}};
    fs.mount("/proc", Tmpfs{});

    // Create + open + write a file in the root fs.
    auto fd = fs.open("/hello", OFlags::creat | OFlags::rdwr, mode(0644));
    assert(fd.has_value());

    const char* msg = "native speed, no VM\n";
    auto w = fs.write(*fd, bytes(msg));
    assert(w.has_value() && *w == std::strlen(msg));
    assert(fs.close(*fd).has_value());

    // Reopen and read it back — data persists in the inode.
    auto fd2 = fs.open("/hello", OFlags::rdonly, mode(0));
    assert(fd2.has_value());
    std::byte buf[64]{};
    auto r = fs.read(*fd2, std::span<std::byte>{buf, sizeof buf});
    assert(r.has_value() && *r == std::strlen(msg));
    assert(std::memcmp(buf, msg, *r) == 0);

    // stat reports the right size and type.
    auto st = fs.stat("/hello");
    assert(st.has_value());
    assert(st->type == FileType::regular);
    assert(st->size == std::strlen(msg));

    // A file created under /proc lands in the OTHER backend (mount crossing).
    auto pf = fs.open("/proc/version", OFlags::creat | OFlags::rdwr, mode(0444));
    assert(pf.has_value());
    (void)fs.write(*pf, bytes("Linux version 6.x linuxity\n"));

    // It exists under /proc but NOT under / (separate inode spaces).
    assert(fs.stat("/proc/version").has_value());
    assert(!fs.stat("/version").has_value());
    assert(fs.stat("/version").error() == Errno::enoent);

    // Missing path -> ENOENT; bad fd -> EBADF.
    assert(fs.open("/nope", OFlags::rdonly, mode(0)).error() == Errno::enoent);
    assert(fs.read(Fd{999}, std::span<std::byte>{buf}).error() == Errno::ebadf);

    std::puts("vfs: mount/create/write/read/stat round-trips passed");
    return 0;
}
