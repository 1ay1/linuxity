// The filesystem namespace: mount table, path normalization, realm
// classification, and the synthesized /proc — all host-free and
// deterministic. Proves that "the guest lives in linuxity's virtual tree"
// is decided entirely in the type-checked namespace, before any ptrace or
// real syscall is involved.
#include "linuxity/kernel/file_namespace.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cassert>
#include <cstdio>
#include <string>

using namespace lx;
using kernel::Realm2;

static std::string bytes_to_string(const std::vector<std::byte>& b) {
    std::string s(b.size(), '\0');
    for (std::size_t i = 0; i < b.size(); ++i) s[i] = static_cast<char>(b[i]);
    return s;
}

int main() {
    // -- Lexical path normalization (pure). -------------------------------
    using FN = kernel::FileNamespace;
    assert(FN::normalize("/a/b/../c") == "/a/c");
    assert(FN::normalize("/a/./b//c/") == "/a/b/c");
    assert(FN::normalize("/../../x") == "/x");
    assert(FN::normalize("/") == "/");
    assert(FN::normalize("///") == "/");

    // -- Mount table + longest-prefix classification. ---------------------
    FN f;
    f.mount_host("/", "/tmp/lxroot");
    f.mount_virtual("/proc",
        vfs::make_procfs(1, "6.6.0-linuxity", "linuxity"));

    // A rootfs path translates to base + rel (host-backed realm).
    {
        auto pc = f.classify(f.absolutize("/etc/os-release"));
        assert(pc.realm == Realm2::host_backed);
        assert(pc.host_path == "/tmp/lxroot/etc/os-release");
    }
    // A /proc path is virtual (longest-prefix beats the "/" host mount).
    {
        auto pc = f.classify(f.absolutize("/proc/version"));
        assert(pc.realm == Realm2::virtual_file);
        assert(pc.host_path.empty());
    }
    // "/procX" is NOT under the /proc mount (component boundary respected).
    {
        auto pc = f.classify(f.absolutize("/procX/y"));
        assert(pc.realm == Realm2::host_backed);
        assert(pc.host_path == "/tmp/lxroot/procX/y");
    }

    // -- cwd + relative resolution. ---------------------------------------
    f.set_cwd("/usr/lib");
    assert(f.absolutize("libc.so.6") == "/usr/lib/libc.so.6");
    assert(f.absolutize("../bin/sh") == "/usr/bin/sh");
    // dirfd-relative (openat with a bound dirfd path).
    assert(f.absolutize("passwd", "/etc") == "/etc/passwd");

    // -- Synthesized /proc reports linuxity's world, not the host's. ------
    {
        auto vf = f.produce("/proc/version");
        assert(vf.has_value());
        std::string s = bytes_to_string(vf->bytes);
        assert(s.find("6.6.0-linuxity") != std::string::npos);
        assert(s.find("linuxity") != std::string::npos);
    }
    {
        // /proc/self resolves to /proc/<pid> and reports Pid 1, Uid 0.
        auto vf = f.produce("/proc/self/status");
        assert(vf.has_value());
        std::string s = bytes_to_string(vf->bytes);
        assert(s.find("Pid:\t1") != std::string::npos);
        assert(s.find("Uid:\t0") != std::string::npos);
    }
    {
        auto vf = f.produce("/proc/mounts");
        assert(vf.has_value());
        std::string s = bytes_to_string(vf->bytes);
        assert(s.find("rootfs / rootfs") != std::string::npos);
    }
    {
        // An unknown /proc entry is a clean ENOENT, not a crash.
        auto vf = f.produce("/proc/does-not-exist");
        assert(!vf.has_value() && vf.error() == Errno::enoent);
    }

    // -- Guest fd table binds a real fd back to its guest path. -----------
    f.bind_fd(7, "/etc/hosts");
    assert(f.path_of_fd(7) == "/etc/hosts");
    f.unbind_fd(7);
    assert(f.path_of_fd(7).empty());

    std::puts("file_namespace: mount table, normalization, realm "
              "classification, and synthesized /proc all correct");
    return 0;
}
