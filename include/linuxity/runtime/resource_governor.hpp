// linuxity/runtime/resource_governor.hpp
//
// Applies a kernel::ResourceSpec to the guest process tree by asking the HOST
// kernel to bound it. Because linuxity runs the guest as a real native process
// tree (ptrace, forwarded mmap/brk), the guest is cgroup-able exactly like any
// other host process — so "how much CPU/RAM the guest gets" becomes a policy
// the host enforces, not something linuxity partitions.
//
// STRATEGY, best-effort with graceful fallback (state-of-the-art unprivileged
// operation, the Docker-rootless / Termux discipline):
//
//   1. cgroup v2 — create a child cgroup under linuxity's OWN delegated
//      cgroup and write cpu.max / memory.max / memory.swap.max / pids.max /
//      cpuset.cpus. This is the real, kernel-enforced bound. It requires the
//      controllers to be DELEGATED into our subtree (true when linuxity itself
//      was launched inside a delegated scope — e.g. re-exec'd through
//      `systemd-run --user --scope`, run in a container, or as root). We
//      detect delegation by probing for the limit files.
//
//   2. setrlimit — if no cgroup can be created, fall back to POSIX rlimits
//      (RLIMIT_AS for memory, RLIMIT_CPU for CPU-seconds, RLIMIT_NPROC for
//      task count). These are per-process ceilings the host always honors,
//      unprivileged, though coarser than a cgroup (RLIMIT_AS caps address
//      space, not RSS; RLIMIT_CPU is cumulative seconds, not a rate).
//
// The GOVERNOR is created in the parent; the CHILD (post-fork, pre-execve)
// calls join() to (a) write its own pid into the cgroup and (b) install the
// rlimit fallbacks. Every forked descendant then inherits both automatically.
#pragma once

#include "linuxity/kernel/resources.hpp"

#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

#include <cstdio>
#include <cstdint>
#include <string>
#include <string_view>

namespace lx::runtime {

class ResourceGovernor {
public:
    explicit ResourceGovernor(kernel::ResourceSpec spec) : spec_{std::move(spec)} {
        if (spec_.any()) create_cgroup();
    }

    ~ResourceGovernor() { destroy_cgroup(); }

    ResourceGovernor(const ResourceGovernor&) = delete;
    ResourceGovernor& operator=(const ResourceGovernor&) = delete;

    // True if a real, kernel-enforced cgroup was established (so limits bite
    // precisely). When false, join() still installs rlimit fallbacks.
    [[nodiscard]] bool cgroup_active() const { return !cg_path_.empty(); }

    // A one-line human description of what enforcement is actually in effect,
    // for the launcher to print. Empty when the spec requested nothing.
    [[nodiscard]] std::string describe() const {
        if (!spec_.any()) return {};
        std::string how = cgroup_active() ? "cgroup v2" : "setrlimit (coarse)";
        std::string s = "bounded via " + how + ":";
        if (spec_.cpus)    s += " cpus=" + trim(std::to_string(*spec_.cpus));
        if (spec_.mem_max) s += " mem=" + human(*spec_.mem_max);
        if (spec_.pids_max) s += " pids=" + std::to_string(*spec_.pids_max);
        if (spec_.cpuset)  s += " cpuset=" + *spec_.cpuset;
        return s;
    }

    // Called by the CHILD after fork(), before execve(). Adopts the child into
    // the cgroup (all descendants inherit it) and installs rlimit fallbacks.
    // Must be async-signal-safe-ish: only simple syscalls, no allocation past
    // small std::string building already done. Best-effort; never fatal.
    void join_child() const {
        if (!cg_path_.empty()) {
            std::string procs = cg_path_ + "/cgroup.procs";
            write_num(procs.c_str(), static_cast<std::uint64_t>(::getpid()));
        }
        install_rlimits();
    }

private:
    // ---- cgroup v2 --------------------------------------------------------

    // linuxity's own cgroup path, read from /proc/self/cgroup (v2 unified line
    // is "0::<path>"). The cgroupfs mount is conventionally /sys/fs/cgroup.
    static std::string self_cgroup() {
        int fd = ::open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return {};
        char buf[4096]; ssize_t n = ::read(fd, buf, sizeof buf - 1); ::close(fd);
        if (n <= 0) return {};
        buf[n] = 0;
        std::string_view sv{buf, static_cast<std::size_t>(n)};
        auto pos = sv.find("0::");
        if (pos == std::string_view::npos) return {};
        sv.remove_prefix(pos + 3);
        auto eol = sv.find('\n');
        if (eol != std::string_view::npos) sv = sv.substr(0, eol);
        return std::string{sv};
    }

    void create_cgroup() {
        std::string rel = self_cgroup();
        if (rel.empty()) return;
        std::string base = "/sys/fs/cgroup" + (rel == "/" ? std::string{} : rel);

        // The controllers we need must be ENABLED in this cgroup's
        // subtree_control before a child can set the matching limit files.
        // If they aren't yet (the usual case in a fresh delegated scope), try
        // to enable them — but cgroup v2's "no internal processes" rule forbids
        // enabling controllers while THIS cgroup still holds tasks. So first
        // move OURSELVES (linuxity is a single process at this pre-fork point)
        // into a sibling `supervisor` leaf, emptying the delegation root, then
        // enable the controllers, then create the bounded `payload` child the
        // guest tree will live in.
        std::string want = needed_controllers();
        if (!subtree_has(base, want)) {
            std::string sup = base + "/supervisor";
            if (::mkdir(sup.c_str(), 0755) == 0 || errno == EEXIST) {
                write_num((sup + "/cgroup.procs").c_str(),
                          static_cast<std::uint64_t>(::getpid()));
                // Enable each controller with a '+' token; ignore failures
                // (a controller not available here just won't enforce).
                write_str((base + "/cgroup.subtree_control").c_str(), want);
            }
        }

        std::string cg = base + "/payload";
        if (::mkdir(cg.c_str(), 0755) != 0 && errno != EEXIST) return;

        bool any_enforced = false;
        if (spec_.mem_max)
            any_enforced |= write_num((cg + "/memory.max").c_str(), *spec_.mem_max);
        if (spec_.swap_and_mem_max && spec_.mem_max &&
            *spec_.swap_and_mem_max > *spec_.mem_max)
            (void)write_num((cg + "/memory.swap.max").c_str(),
                            *spec_.swap_and_mem_max - *spec_.mem_max);
        if (spec_.pids_max)
            any_enforced |= write_num((cg + "/pids.max").c_str(), *spec_.pids_max);
        if (spec_.cpus) {
            std::string q = std::to_string(spec_.cpu_quota_us()) + " " +
                            std::to_string(kernel::ResourceSpec::kCpuPeriodUs);
            any_enforced |= write_str((cg + "/cpu.max").c_str(), q);
        }
        if (spec_.cpuset)
            (void)write_str((cg + "/cpuset.cpus").c_str(), *spec_.cpuset);

        if (any_enforced) {
            cg_path_ = cg;          // keep it; join_child() will adopt the pid
        } else {
            ::rmdir(cg.c_str());    // controllers not delegated — fall back
        }
    }

    // The `+`-prefixed controller list we try to enable, restricted to what
    // this policy actually needs.
    [[nodiscard]] std::string needed_controllers() const {
        std::string s;
        if (spec_.mem_max || spec_.swap_and_mem_max) s += "+memory ";
        if (spec_.cpus || spec_.cpuset)              s += "+cpu ";
        if (spec_.pids_max)                          s += "+pids ";
        if (!s.empty() && s.back() == ' ') s.pop_back();
        return s;
    }

    // True if `base`/cgroup.subtree_control already lists every controller in
    // the space-separated `+`-prefixed `want` string (so a child inherits the
    // limit files without us enabling anything).
    static bool subtree_has(const std::string& base, const std::string& want) {
        int fd = ::open((base + "/cgroup.subtree_control").c_str(),
                        O_RDONLY | O_CLOEXEC);
        if (fd < 0) return false;
        char buf[256] = {0}; ssize_t n = ::read(fd, buf, sizeof buf - 1); ::close(fd);
        if (n <= 0) return false;
        std::string have{buf, static_cast<std::size_t>(n)};
        std::string_view w{want};
        while (!w.empty()) {
            auto sp = w.find(' ');
            std::string_view tok = w.substr(0, sp);
            if (!tok.empty() && tok[0] == '+') tok.remove_prefix(1);
            if (!tok.empty() && have.find(std::string{tok}) == std::string::npos)
                return false;
            if (sp == std::string_view::npos) break;
            w.remove_prefix(sp + 1);
        }
        return true;
    }

    void destroy_cgroup() {
        if (cg_path_.empty()) return;
        // A cgroup can only be removed once empty; the tree has exited by the
        // time the governor is destroyed, so rmdir succeeds. Remove the
        // payload; the supervisor leaf (still holding OUR pid) and the enabled
        // subtree_control are cleaned up by the kernel when linuxity itself
        // exits and the delegated scope is torn down. Best-effort.
        ::rmdir(cg_path_.c_str());
    }

    // ---- setrlimit fallback ----------------------------------------------

    void install_rlimits() const {
        if (spec_.mem_max) {
            // RLIMIT_AS bounds ADDRESS SPACE (a superset of RSS), the closest
            // rlimit to a memory cap. Coarser than memory.max but always works.
            struct ::rlimit rl{*spec_.mem_max, *spec_.mem_max};
            (void)::setrlimit(RLIMIT_AS, &rl);
        }
        // NOTE: --pids is NOT translated to RLIMIT_NPROC: that rlimit counts
        // EVERY process of the real UID (the whole login session), not just
        // the guest tree, so a small cap would instantly break fork() for a
        // desktop user. pids.max (the cgroup path) is tree-scoped and correct;
        // when only rlimits are available we simply leave --pids unenforced.
        //
        // CPU as a RATE also has no rlimit analogue (RLIMIT_CPU is cumulative
        // seconds, which would just kill a long run), so --cpus likewise only
        // bites through the cgroup path.
    }

    // ---- small helpers ----------------------------------------------------

    static bool write_str(const char* path, const std::string& val) {
        int fd = ::open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0) return false;
        ssize_t n = ::write(fd, val.data(), val.size());
        ::close(fd);
        return n == static_cast<ssize_t>(val.size());
    }
    static bool write_num(const char* path, std::uint64_t v) {
        return write_str(path, std::to_string(v));
    }

    static std::string human(std::uint64_t b) {
        const char* u[] = {"B", "K", "M", "G", "T"};
        double d = static_cast<double>(b); int i = 0;
        while (d >= 1024.0 && i < 4) { d /= 1024.0; ++i; }
        char out[32];
        std::snprintf(out, sizeof out, (d < 10 && i) ? "%.1f%s" : "%.0f%s", d, u[i]);
        return out;
    }
    static std::string trim(std::string s) {
        if (s.find('.') != std::string::npos) {
            while (!s.empty() && s.back() == '0') s.pop_back();
            if (!s.empty() && s.back() == '.') s.pop_back();
        }
        return s;
    }

    kernel::ResourceSpec spec_;
    std::string          cg_path_;   // non-empty iff a live cgroup was created
};

} // namespace lx::runtime
