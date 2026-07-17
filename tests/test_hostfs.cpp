// HostFs end-to-end: build a real host directory tree, mount it as the guest
// root via HostFs, and read it back through the VFS — exactly the "extract a
// rootfs tarball and mount it at /" flow, in miniature. Zero deps; the tree
// is created with plain POSIX and torn down after.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/vfs/hostfs.hpp"
#include "linuxity/vfs/tmpfs.hpp"
#include "linuxity/vfs/vfs.hpp"

#include <sys/stat.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

using namespace lx;
using namespace lx::vfs;

static_assert(FileSystem<HostFs<host::PosixHost>>,
              "HostFs must model the FileSystem concept");

int main() {
    // -- Build a throwaway "rootfs" on the host. --------------------------
    char tmpl[] = "/tmp/linuxity_rootfs_XXXXXX";
    char* base = ::mkdtemp(tmpl);
    assert(base);
    std::string root = base;
    ::mkdir((root + "/etc").c_str(), 0755);
    ::mkdir((root + "/bin").c_str(), 0755);
    { std::ofstream(root + "/etc/os-release") << "NAME=linuxity-guest\n"; }
    { std::ofstream(root + "/bin/hello") << "#!/bin/sh\necho hi\n"; }

    // -- Mount it as the guest root, with tmpfs over /tmp. ----------------
    host::PosixHost hw;
    Vfs fs{HostFs<host::PosixHost>{hw, root}};
    fs.mount("/tmp", Tmpfs{});

    // Read a real file from the host-backed root through the guest VFS.
    auto fd = fs.open("/etc/os-release", OFlags::rdonly, mode(0));
    assert(fd.has_value());
    std::byte buf[128]{};
    auto n = fs.read(*fd, std::span<std::byte>{buf, sizeof buf});
    assert(n.has_value() && *n > 0);
    assert(std::memcmp(buf, "NAME=linuxity-guest", 19) == 0);

    // stat crosses directories and reports type/size from the real file.
    auto st = fs.stat("/bin/hello");
    assert(st.has_value());
    assert(st->type == FileType::regular);
    assert(st->size > 0);

    // A directory stats as a directory.
    auto dst = fs.stat("/etc");
    assert(dst.has_value() && dst->type == FileType::directory);

    // The host-backed root is read-only: creating there yields EROFS...
    auto ro = fs.open("/etc/newfile", OFlags::creat | OFlags::rdwr, mode(0644));
    assert(!ro.has_value() && ro.error() == Errno::erofs);

    // ...but the tmpfs mounted at /tmp is writable.
    auto w = fs.open("/tmp/scratch", OFlags::creat | OFlags::rdwr, mode(0644));
    assert(w.has_value());

    // Missing path -> ENOENT.
    assert(fs.stat("/nonexistent").error() == Errno::enoent);

    // -- Clean up the host tree. ------------------------------------------
    ::remove((root + "/etc/os-release").c_str());
    ::remove((root + "/bin/hello").c_str());
    ::rmdir((root + "/etc").c_str());
    ::rmdir((root + "/bin").c_str());
    ::rmdir(root.c_str());

    std::puts("hostfs: real rootfs directory mounted and read through the VFS");
    return 0;
}
