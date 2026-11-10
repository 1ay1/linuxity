// The filesystem namespace: mount table, path normalization, realm
// classification, and the synthesized /proc — all host-free and
// deterministic. Proves that "the guest lives in linuxity's virtual tree"
// is decided entirely in the type-checked namespace, before any ptrace or
// real syscall is involved.
#include "linuxity/kernel/file_namespace.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

using namespace lx;
using kernel::Realm2;

static std::string bytes_to_string(const std::vector<std::byte>& b) {
    std::string s(b.size(), '\0');
    for (std::size_t i = 0; i < b.size(); ++i) s[i] = static_cast<char>(b[i]);
    return s;
}

// A deliberately naive reference normalizer: stage every surviving component
// in a vector, pop one on "..", then join. Obviously correct and obviously
// slower than what FileNamespace actually ships (which builds the result
// in place, with no per-call heap allocation).
//
// This exists because an in-place ".." is easy to get subtly wrong: an early
// version of the fast path truncated the output to rfind('/') + 1, keeping
// the separator, so "/a/b/../c" became "/a//c" and a LATER ".." then popped
// only that empty component instead of a real one -- i.e. "a/b/../.." stayed
// inside "/a" rather than reaching "/". That is a sandbox-escape-shaped bug
// in a path canonicalizer, and no hand-written case list caught it. The
// exhaustive comparison below did, immediately.
static std::string reference_normalize(std::string_view p) {
    std::vector<std::string_view> stack;
    std::size_t i = 0;
    while (i < p.size()) {
        while (i < p.size() && p[i] == '/') ++i;
        std::size_t j = i;
        while (j < p.size() && p[j] != '/') ++j;
        if (j > i) {
            const std::string_view comp = p.substr(i, j - i);
            if (comp == ".") {
                // skip
            } else if (comp == "..") {
                if (!stack.empty()) stack.pop_back();
            } else {
                stack.push_back(comp);
            }
        }
        i = j;
    }
    std::string out = "/";
    for (std::size_t k = 0; k < stack.size(); ++k) {
        out += stack[k];
        if (k + 1 < stack.size()) out += '/';
    }
    return out;
}

int main() {
    // -- Lexical path normalization (pure). -------------------------------
    using FN = kernel::FileNamespace;
    assert(FN::normalize("/a/b/../c") == "/a/c");
    assert(FN::normalize("/a/./b//c/") == "/a/b/c");
    assert(FN::normalize("/../../x") == "/x");
    assert(FN::normalize("/") == "/");
    assert(FN::normalize("///") == "/");
    // ".." must not be satisfied by an empty component left behind by a
    // previous ".." -- these pin the exact bug the differential check below
    // found, so a regression fails here with a readable case.
    assert(FN::normalize("/a/b/../c") == "/a/c");       // no "/a//c"
    assert(FN::normalize("/a/b/../..") == "/");         // reaches the root
    assert(FN::normalize("/a/b/../../c") == "/c");
    assert(FN::normalize("/a/..") == "/");
    assert(FN::normalize("/a/../..") == "/");           // clamps at the root
    assert(FN::normalize("/...") == "/...");            // not a ".."
    assert(FN::normalize("/..a/a..") == "/..a/a..");

    // Exhaustive differential check against the naive reference above: every
    // path of up to 5 components drawn from an alphabet chosen to stress the
    // parser (".." and "." themselves, empty components, names that merely
    // START with dots, and multi-char names), each tried with and without a
    // trailing slash and with and without a leading one. ~265k paths. Pure
    // and fast, so it runs as part of the normal suite rather than a fuzzer.
    {
        const char* alpha[] = {"a", "bb", "..", ".", "", "/",
                               "...", "..a", "a.."};
        std::vector<std::string> cur{"", "/"};
        long checked = 0;
        for (int depth = 0; depth < 5; ++depth) {
            std::vector<std::string> next;
            for (const auto& s : cur) {
                for (const char* comp : alpha) {
                    const std::string with_slash = s + comp + "/";
                    const std::string bare = s + comp;
                    for (const std::string* v : {&with_slash, &bare}) {
                        ++checked;
                        if (FN::normalize(*v) != reference_normalize(*v)) {
                            std::fprintf(stderr,
                                "normalize mismatch: %s -> %s, expected %s\n",
                                v->c_str(), FN::normalize(*v).c_str(),
                                reference_normalize(*v).c_str());
                            return 1;
                        }
                    }
                    next.push_back(with_slash);
                }
            }
            cur = std::move(next);
        }
        assert(checked > 200000);
    }

    // -- Mount table + longest-prefix classification. ---------------------
    // classify() resolves through the real host directories (a missing
    // parent is ENOENT, as in a kernel walk), so the rootfs must exist: a
    // private one, not whatever a previous run left in /tmp/lxroot.
    const std::string root = "/tmp/lx-fn-root-" + std::to_string(::getpid());
    (void)std::system(("mkdir -p " + root + "/etc " + root + "/procX").c_str());
    FN f;
    f.mount_host("/", root);
    kernel::ProcessTable procs;
    static const kernel::MachineSpec mach;
    f.mount_virtual("/proc", vfs::make_procfs(procs, mach));

    // A rootfs path translates to base + rel (host-backed realm).
    {
        auto pc = f.classify(f.absolutize("/etc/os-release"));
        assert(pc.realm == Realm2::host_backed);
        assert(pc.host_path == root + "/etc/os-release");
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
        assert(pc.host_path == root + "/procX/y");
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
        // the root is a REAL filesystem (the one the rootfs lives on), never
        // the initramfs placeholder "rootfs" -- tools read that as no root
        assert(s.find(" / ") != std::string::npos);
        assert(s.find(" / rootfs ") == std::string::npos);
    }
    {
        // System-wide /proc/stat + /proc/meminfo (htop / free / top read these).
        auto st = f.produce("/proc/stat");
        assert(st.has_value());
        std::string s = bytes_to_string(st->bytes);
        assert(s.find("cpu ") != std::string::npos);
        assert(s.find("btime ") != std::string::npos);

        auto mi = f.produce("/proc/meminfo");
        assert(mi.has_value());
        // the host's live file on Linux, synthesized elsewhere
        assert(mi->redirect_host == "/proc/meminfo" ||
               bytes_to_string(mi->bytes).find("MemTotal:") != std::string::npos);

        auto ci = f.produce("/proc/cpuinfo");
        assert(ci.has_value());
        assert(bytes_to_string(ci->bytes).find("processor") != std::string::npos);
    }
    {
        // On arm64, /proc/cpuinfo's "Features" must be whatever the machine
        // spec says -- never a baked-in list. The guest runs NATIVELY, so a
        // feature advertised here that the real CPU lacks makes libgcrypt
        // pick an instruction path that SIGILLs: `gpg --import` died exactly
        // that way on a Snapdragon, because the list was hardcoded from an
        // Apple M-series chip and promised sha3/sha512.
        kernel::ProcessTable p;
        kernel::ProcInfo init;
        init.pid = 1;
        init.cmdline = "/init";
        p.upsert(init);

        // static: make_procfs keeps a reference to the spec.
        static kernel::MachineSpec m;
        m.machine_arch = "aarch64";
        m.ncpu = 1;
        m.cpu_features = "fp asimd aes pmull sha1 sha2 crc32";
        m.cpu_implementer = "0x51";
        m.cpu_architecture = "8";

        FN g;
        g.mount_virtual("/proc", vfs::make_procfs(p, m));
        auto ci = g.produce("/proc/cpuinfo");
        assert(ci.has_value());
        const std::string s = bytes_to_string(ci->bytes);
        assert(s.find("Features\t: fp asimd aes pmull sha1 sha2 crc32\n")
               != std::string::npos);
        assert(s.find("CPU implementer\t: 0x51") != std::string::npos);
        // The feature the old hardcoded list invented must NOT appear.
        assert(s.find("sha3") == std::string::npos &&
               "cpuinfo must not advertise a feature the host never reported");
        assert(s.find("sha512") == std::string::npos);
    }
    {
        // /proc is an ENUMERABLE directory: it lists every pid + the
        // well-known files (this backs getdents64 on /proc).
        auto d = f.produce("/proc");
        assert(d.has_value() && d->is_dir);
        bool has_pid1 = false, has_stat = false, has_meminfo = false;
        for (const auto& e : d->entries) {
            if (e.name == "1") has_pid1 = true;
            if (e.name == "stat") has_stat = true;
            if (e.name == "meminfo") has_meminfo = true;
        }
        assert(has_pid1 && has_stat && has_meminfo);
    }
    {
        // The per-process /proc/<pid> directory enumerates its files.
        auto d = f.produce("/proc/1");
        assert(d.has_value() && d->is_dir);
        bool has_stat = false, has_status = false, has_cmdline = false;
        for (const auto& e : d->entries) {
            if (e.name == "stat") has_stat = true;
            if (e.name == "status") has_status = true;
            if (e.name == "cmdline") has_cmdline = true;
        }
        assert(has_stat && has_status && has_cmdline);

        auto stat1 = f.produce("/proc/1/stat");
        assert(stat1.has_value());
        // /proc/1/stat starts with "1 (comm) R ..."
        assert(bytes_to_string(stat1->bytes).starts_with("1 ("));
    }

    // -- Guest fd table binds a real fd back to its guest path. -----------
    f.bind_fd(7, "/etc/hosts");
    assert(f.path_of_fd(7) == "/etc/hosts");
    f.unbind_fd(7);
    assert(f.path_of_fd(7).empty());

    // -- Virtual-directory fd stream (backs getdents64). ------------------
    f.bind_dir(9, {{"a", false}, {"b", true}});
    assert(f.is_virtual_dir_fd(9));
    {
        auto* ds = f.dir_stream(9);
        assert(ds && ds->entries.size() == 2 && ds->pos == 0);
    }
    f.unbind_fd(9);
    assert(!f.is_virtual_dir_fd(9));

    // -- Overlay (copy-up upper over read-only lower). --------------------
    {
        std::string lower = "/tmp/lx_fns_lower";
        std::string upper = "/tmp/lx_fns_upper";
        std::system(("rm -rf " + lower + " " + upper +
                     " && mkdir -p " + lower + "/etc " + upper).c_str());
        { std::FILE* lf = std::fopen((lower + "/etc/conf").c_str(), "w");
          std::fputs("pristine\n", lf); std::fclose(lf); }

        FN ov;
        ov.mount_host("/", lower, upper);

        // A READ of an un-copied file resolves to the lower (pristine).
        {
            auto pc = ov.classify("/etc/conf", /*for_write=*/false);
            assert(pc.realm == Realm2::host_backed);
            assert(pc.host_path == lower + "/etc/conf");
        }
        // A WRITE copies it up: the target is now in the upper, and the copy
        // carries the lower's bytes; the lower stays untouched.
        {
            auto pc = ov.classify("/etc/conf", /*for_write=*/true);
            assert(pc.realm == Realm2::host_backed);
            assert(pc.host_path == upper + "/etc/conf");
            std::FILE* uf = std::fopen(pc.host_path.c_str(), "r");
            assert(uf);
            char b[32] = {}; std::fread(b, 1, sizeof b - 1, uf); std::fclose(uf);
            assert(std::string(b) == "pristine\n");   // copied up
        }
        // After copy-up, a READ resolves to the upper.
        {
            auto pc = ov.classify("/etc/conf", false);
            assert(pc.host_path == upper + "/etc/conf");
        }
        // The pristine lower is never mutated.
        {
            std::FILE* lf = std::fopen((lower + "/etc/conf").c_str(), "r");
            assert(lf);
            char b[32] = {}; std::fread(b, 1, sizeof b - 1, lf); std::fclose(lf);
            assert(std::string(b) == "pristine\n");
        }
        std::system(("rm -rf " + lower + " " + upper).c_str());
    }

    // -- Rootfs symlink re-rooting. A distro is full of ABSOLUTE symlinks
    //    whose targets must resolve INSIDE the rootfs, not the host root.
    {
        std::string base = "/tmp/lx_fns_slroot";
        std::system(("rm -rf " + base +
                     " && mkdir -p " + base + "/bin " + base + "/usr/bin").c_str());
        // /bin/real is the actual file; /bin/sh -> /bin/real (absolute, guest);
        // /bin/link2 -> real (relative). And /usr/bin/env -> /bin/real.
        { std::FILE* rf = std::fopen((base + "/bin/real").c_str(), "w");
          std::fputs("X\n", rf); std::fclose(rf); }
        std::system(("ln -sf /bin/real " + base + "/bin/sh").c_str());
        std::system(("ln -sf real "      + base + "/bin/link2").c_str());
        std::system(("ln -sf /bin/real " + base + "/usr/bin/env").c_str());

        FN sf;
        sf.mount_host("/", base);
        // follow=true (default): the symlink resolves to the real host file.
        {
            auto pc = sf.classify("/bin/sh");
            assert(pc.realm == Realm2::host_backed);
            assert(pc.host_path == base + "/bin/real");   // re-rooted, not /bin/real
        }
        {
            auto pc = sf.classify("/bin/link2");           // relative symlink
            assert(pc.host_path == base + "/bin/real");
        }
        {
            auto pc = sf.classify("/usr/bin/env");         // absolute, cross-dir
            assert(pc.host_path == base + "/bin/real");
        }
        // follow=false (lstat/readlink): the LINK path is kept, not the target.
        {
            auto pc = sf.classify("/bin/sh", /*for_write=*/false, /*follow=*/false);
            assert(pc.host_path == base + "/bin/sh");
        }
        std::system(("rm -rf " + base).c_str());
    }

    // -- Cross-mount symlink: a rootfs link into the virtual /proc. --------
    // /etc/mtab -> /proc/self/mounts is the canonical case: following it must
    // land in the VIRTUAL realm (so open injects the synthesized mount table),
    // NOT fabricate a nonexistent <rootfs>/proc/self/mounts host path.
    {
        std::string base = "/tmp/lx_fnx_root";
        std::system(("rm -rf " + base + " && mkdir -p " + base + "/etc").c_str());
        std::system(("ln -sf ../proc/self/mounts " + base + "/etc/mtab").c_str());

        FN xf;
        xf.mount_host("/", base);
        kernel::ProcessTable xprocs;
        static const kernel::MachineSpec xmach;
        xf.mount_virtual("/proc", vfs::make_procfs(xprocs, xmach));

        // follow=true: the link resolves across the mount boundary into /proc.
        auto pc = xf.classify("/etc/mtab");
        assert(pc.realm == Realm2::virtual_file);
        assert(pc.virtual_path == "/proc/self/mounts");   // resolved target
        // And producing THAT path yields the synthesized mount table bytes.
        auto vf = xf.produce(pc.virtual_path);
        assert(vf.has_value());
        assert(bytes_to_string(vf->bytes).find(" / ") != std::string::npos);

        // follow=false (lstat): the LINK node itself is kept, host-backed.
        auto lc = xf.classify("/etc/mtab", false, false);
        assert(lc.realm == Realm2::host_backed);
        assert(lc.host_path == base + "/etc/mtab");
        std::system(("rm -rf " + base).c_str());
    }

    // The ROOT itself must classify to a usable host path. mount_host used to
    // strip the trailing slash unconditionally, reducing a host_base of "/"
    // to "" -- and join_host("", "") is "", so classify("/") handed the
    // dispatcher an empty path and stat("/") returned ENOENT. Deeper paths
    // accidentally worked (join_host("", "usr") == "/usr"), so only the root
    // was broken, which was enough to make `rm -r` fail: it stats "/" on the
    // way up. Found by the differential harness against the host kernel.
    {
        kernel::FileNamespace rf;
        rf.mount_host("/", "/");
        for (const char* p : {"/", "/.", "//"}) {
            const auto rc = rf.classify(
                kernel::FileNamespace::normalize(p), false, false);
            assert(rc.realm == Realm2::host_backed);
            assert(rc.host_path == "/");   // not ""
        }
        // And a path below the root still resolves, without a doubled slash.
        const auto uc = rf.classify("/usr", false, false);
        assert(uc.realm == Realm2::host_backed);
        assert(uc.host_path == "/usr");
    }

    // Relative host paths handed to mount_host come out ABSOLUTE, resolved
    // against the supervisor's cwd. A relative upper like `--persist
    // ./arch-upper` used to be stored as-is, and the host path classify()
    // hands out is spliced into the guest's registers for a REDIRECT -- where
    // the kernel resolves it against the GUEST's dirfd. rm -rf (fts unlinks
    // relative to an open dirfd) then removed nothing and failed ENOTEMPTY.
    // Found on Android, where --root/--persist are naturally relative.
    {
        kernel::FileNamespace rf;
        rf.set_host_cwd("/data/local/tmp");
        rf.mount_host("/", "./arch", "./arch-upper");
        const auto rc = rf.classify("/var/lib/x", /*for_write=*/true, false);
        assert(rc.realm == Realm2::host_backed);
        assert(!rc.host_path.empty() && rc.host_path.front() == '/');
        assert(rc.host_path.rfind("/data/local/tmp/arch-upper/", 0) == 0);

        // An already-absolute path is untouched apart from normalization.
        kernel::FileNamespace af;
        af.set_host_cwd("/elsewhere");
        af.mount_host("/", "/srv/root//", "/srv/up/");
        const auto ac = af.classify("/f", true, false);
        assert(ac.host_path.rfind("/srv/up/", 0) == 0);

        // `..` in a relative path resolves lexically, not by escaping.
        assert(rf.absolute_host("../x") == "/data/local/x");
        assert(rf.absolute_host("").empty());
    }

    std::puts("file_namespace: mount table, normalization, realm "
              "classification, synthesized /proc, cross-mount symlinks, "
              "root-mount host paths, relative mount paths, and copy-up "
              "overlay correct");
    (void)std::system(("rm -rf " + root).c_str());
    return 0;
}
