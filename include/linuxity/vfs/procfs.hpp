// linuxity/vfs/procfs.hpp
//
// A comprehensive synthesized /proc — the virtual window onto linuxity's
// world. Every file is produced on demand from linuxity's own state (its
// process table, its uname identity), never the host's. This is what makes a
// process monitor (ps / top / htop) show linuxity's world: pid 1 is init, the
// process list is exactly the guests we run, and the numbers are ours.
//
// The producer maps an absolute /proc path to bytes (for reads) or to a
// directory-entry list (for getdents enumeration). It covers the system-wide
// files programs poll early (/proc/stat, /proc/meminfo, /proc/cpuinfo,
// /proc/uptime, /proc/loadavg, /proc/mounts, /proc/filesystems, ...) and the
// per-process tree (/proc/<pid>/{stat,statm,status,cmdline,comm,...}) that a
// process monitor walks.
#pragma once

#include "linuxity/kernel/file_namespace.hpp"
#include "linuxity/kernel/process_table.hpp"

#include <string>
#include <string_view>

namespace lx::vfs {

namespace detail {

inline kernel::VirtualFile text_file(std::string s) {
    kernel::VirtualFile vf;
    vf.bytes.resize(s.size());
    for (std::size_t i = 0; i < s.size(); ++i)
        vf.bytes[i] = static_cast<std::byte>(s[i]);
    return vf;
}

inline kernel::VirtualFile dir_file(std::vector<kernel::VirtualDirent> e) {
    kernel::VirtualFile vf; vf.is_dir = true; vf.entries = std::move(e);
    return vf;
}

// Split "/proc/123/stat" -> ("123", "stat"); returns pid=-1 if not /proc/<pid>.
inline std::pair<long, std::string> split_pid(std::string_view abs) {
    std::string_view rest = abs.substr(std::string_view{"/proc"}.size());
    while (rest.starts_with('/')) rest.remove_prefix(1);
    if (rest.empty()) return {-1, {}};
    std::size_t slash = rest.find('/');
    std::string_view head = rest.substr(0, slash);
    for (char c : head) if (c < '0' || c > '9') return {-1, {}};
    long pid = 0; for (char c : head) pid = pid * 10 + (c - '0');
    std::string tail = slash == std::string_view::npos ? std::string{}
                        : std::string{rest.substr(slash + 1)};
    return {pid, tail};
}

} // namespace detail

// Build a /proc producer bound to linuxity's process table + identity. The
// table is captured by reference; it is owned by the kernel and updated live
// as the runtime traces the guest tree.
[[nodiscard]] inline kernel::FileNamespace::Producer
make_procfs(const kernel::ProcessTable& procs, std::string release,
            std::string nodename, long ncpu = 1) {
    if (ncpu < 1) ncpu = 1;
    return [&procs, release = std::move(release), nodename = std::move(nodename), ncpu]
           (std::string_view abs) -> Result<kernel::VirtualFile> {
        using detail::text_file; using detail::dir_file;
        const long nproc = static_cast<long>(procs.count());

        // ---- /proc/self -> /proc/<pid 1> canonicalization ---------------
        std::string p{abs};
        // Our "self" is always pid 1 (the traced root / init).
        if (p == "/proc/self" || p.starts_with("/proc/self/"))
            p = "/proc/1" + p.substr(std::string_view{"/proc/self"}.size());

        // ---- /proc root: enumerate every pid + the well-known files -----
        if (abs == "/proc") {
            std::vector<kernel::VirtualDirent> e;
            for (std::int32_t pid : procs.pids())
                e.push_back({std::to_string(pid), true});
            for (const char* f : {"stat","meminfo","cpuinfo","uptime","loadavg",
                                  "version","cmdline","filesystems","mounts",
                                  "self","sys"})
                e.push_back({f, std::string_view{f} == "sys"});
            return ok(dir_file(std::move(e)));
        }

        // ---- system-wide files ------------------------------------------
        if (abs == "/proc/version")
            return ok(text_file("Linux version " + release + " (linuxity@" +
                                nodename + ") (linuxity portable Linux ABI) #1\n"));
        if (abs == "/proc/cmdline")
            return ok(text_file("BOOT_IMAGE=/boot/linuxity root=linuxity ro\n"));
        if (abs == "/proc/cpuinfo") {
            std::string s;
            for (long c = 0; c < ncpu; ++c) {
                s += "processor\t: " + std::to_string(c) + "\n";
                s += "vendor_id\t: LinuxityVirtual\n"
                     "cpu family\t: 6\nmodel\t\t: 1\nmodel name\t: linuxity native CPU\n"
                     "cpu MHz\t\t: 3000.000\ncache size\t: 8192 KB\n";
                s += "physical id\t: 0\nsiblings\t: " + std::to_string(ncpu) +
                     "\ncore id\t\t: " + std::to_string(c) +
                     "\ncpu cores\t: " + std::to_string(ncpu) + "\n";
                s += "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep\n"
                     "bogomips\t: 6000.00\n\n";
            }
            return ok(text_file(std::move(s)));
        }
        if (abs == "/proc/meminfo") {
            return ok(text_file(
                "MemTotal:        2097152 kB\nMemFree:         1048576 kB\n"
                "MemAvailable:    1572864 kB\nBuffers:           32768 kB\n"
                "Cached:           524288 kB\nSwapCached:            0 kB\n"
                "Active:           786432 kB\nInactive:         262144 kB\n"
                "SwapTotal:             0 kB\nSwapFree:              0 kB\n"
                "Dirty:                 0 kB\nWriteback:             0 kB\n"
                "Shmem:             16384 kB\nSlab:              65536 kB\n"));
        }
        if (abs == "/proc/stat") {
            // System-wide CPU + process counters. htop/top/btop read this
            // first; the aggregate `cpu` line plus one `cpuN` per logical CPU.
            std::string s;
            s += "cpu  " + std::to_string(1000 * ncpu) + " 0 " +
                 std::to_string(500 * ncpu) + " " +
                 std::to_string(100000 * ncpu) + " " +
                 std::to_string(200 * ncpu) + " 0 " +
                 std::to_string(50 * ncpu) + " 0 0 0\n";
            for (long c = 0; c < ncpu; ++c)
                s += "cpu" + std::to_string(c) +
                     " 1000 0 500 100000 200 0 50 0 0 0\n";
            s += "intr 0\nctxt 12345\n";
            s += "btime 1700000000\n";
            s += "processes " + std::to_string(nproc + 10) + "\n";
            s += "procs_running 1\nprocs_blocked 0\n";
            return ok(text_file(std::move(s)));
        }
        if (abs == "/proc/uptime")   return ok(text_file("1000.00 990.00\n"));
        if (abs == "/proc/loadavg")
            return ok(text_file("0.00 0.01 0.05 1/" + std::to_string(nproc) + " 1\n"));
        if (abs == "/proc/filesystems")
            return ok(text_file("nodev\tproc\nnodev\tsysfs\nnodev\ttmpfs\n\text4\n"));
        if (abs == "/proc/mounts" || abs == "/proc/1/mounts")
            return ok(text_file(
                "rootfs / rootfs rw 0 0\nproc /proc proc rw,nosuid,nodev,noexec 0 0\n"
                "sysfs /sys sysfs rw,nosuid,nodev,noexec 0 0\n"
                "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"));
        if (abs == "/proc/sys" || abs == "/proc/sys/kernel")
            return ok(dir_file({}));
        if (abs == "/proc/sys/kernel/osrelease") return ok(text_file(release + "\n"));
        if (abs == "/proc/sys/kernel/hostname")  return ok(text_file(nodename + "\n"));
        if (abs == "/proc/sys/kernel/pid_max")   return ok(text_file("32768\n"));

        // ---- per-process /proc/<pid>/* ----------------------------------
        auto [pid, tail] = detail::split_pid(p);
        if (pid >= 0) {
            const kernel::ProcInfo* pi = procs.find(static_cast<std::int32_t>(pid));
            if (!pi) return err<kernel::VirtualFile>(Errno::enoent);
            const auto& I = *pi;

            if (tail.empty())     // the /proc/<pid> directory itself
                return ok(dir_file({
                    {"stat",false},{"statm",false},{"status",false},
                    {"cmdline",false},{"comm",false},{"cwd",true},
                    {"exe",false},{"root",true},{"fd",true},{"maps",false},
                    {"io",false},{"oom_score",false},{"task",true},
                }));

            // ---- /proc/<pid>/task : the thread group -------------------
            // We model one main thread whose tid == pid. htop/top enumerate
            // processes THROUGH this directory, so it must exist and its
            // per-thread files mirror the process's own.
            if (tail == "task")
                return ok(dir_file({{std::to_string(I.pid), true}}));
            if (tail.starts_with("task/")) {
                std::string_view rest = std::string_view{tail}.substr(5);
                std::size_t slash = rest.find('/');
                std::string_view tid = rest.substr(0, slash);
                // Only the main thread (tid == pid) exists.
                if (tid != std::to_string(I.pid))
                    return err<kernel::VirtualFile>(Errno::enoent);
                if (slash == std::string_view::npos)  // /proc/<pid>/task/<tid>
                    return ok(dir_file({
                        {"stat",false},{"statm",false},{"status",false},
                        {"cmdline",false},{"comm",false},{"maps",false},
                        {"io",false},{"children",false},
                    }));
                // Re-target the file lookup at the thread's own file, which is
                // identical to the process's (single-thread model).
                tail = std::string{rest.substr(slash + 1)};
            }

            if (tail == "comm")   return ok(text_file(I.comm + "\n"));
            if (tail == "cmdline") {
                std::string cl = I.cmdline; cl.push_back('\0');  // NUL-terminated
                return ok(text_file(std::move(cl)));
            }
            if (tail == "stat") {
                // The single-line /proc/<pid>/stat (fields per proc(5)).
                std::string s;
                s += std::to_string(I.pid);
                s += " (" + I.comm + ") ";
                s += I.state; s += ' ';
                s += std::to_string(I.ppid) + " ";      // ppid
                s += std::to_string(I.pid) + " ";       // pgrp
                s += std::to_string(I.pid) + " ";       // session
                s += "0 -1 ";                           // tty_nr, tpgid
                s += "4194304 ";                        // flags
                s += "0 0 0 0 ";                        // minflt cminflt majflt cmajflt
                s += "100 20 0 0 ";                     // utime stime cutime cstime
                s += "20 0 ";                           // priority nice
                s += "1 0 ";                            // num_threads itrealvalue
                s += "1000 ";                           // starttime
                s += std::to_string(I.vsize_bytes) + " ";           // vsize
                s += std::to_string(I.rss_pages) + " ";             // rss (pages)
                s += "18446744073709551615 ";           // rsslim
                s += "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";  // rest, zeroed
                return ok(text_file(std::move(s)));
            }
            if (tail == "statm") {
                std::uint64_t sz = I.vsize_bytes / 4096;
                std::string s = std::to_string(sz) + " " +
                                std::to_string(I.rss_pages) + " " +
                                std::to_string(I.rss_pages / 4) + " 1 0 " +
                                std::to_string(I.rss_pages) + " 0\n";
                return ok(text_file(std::move(s)));
            }
            if (tail == "status") {
                std::string s;
                s += "Name:\t" + I.comm + "\n";
                s += "State:\t"; s += I.state;
                s += (I.state=='R' ? " (running)\n" : " (sleeping)\n");
                s += "Tgid:\t" + std::to_string(I.pid) + "\n";
                s += "Pid:\t" + std::to_string(I.pid) + "\n";
                s += "PPid:\t" + std::to_string(I.ppid) + "\n";
                s += "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n";
                s += "Threads:\t1\n";
                s += "VmSize:\t" + std::to_string(I.vsize_bytes/1024) + " kB\n";
                s += "VmRSS:\t"  + std::to_string(I.rss_pages*4) + " kB\n";
                return ok(text_file(std::move(s)));
            }
            if (tail == "io")
                return ok(text_file("rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\n"
                                    "read_bytes: 0\nwrite_bytes: 0\n"));
            if (tail == "children") return ok(text_file(""));
            if (tail == "oom_score") return ok(text_file("0\n"));
            if (tail == "maps")      return ok(text_file(""));
            if (tail == "fd")        return ok(dir_file({{"0",false},{"1",false},{"2",false}}));
            if (tail == "cwd" || tail == "root") return ok(dir_file({}));
            return err<kernel::VirtualFile>(Errno::enoent);
        }

        return err<kernel::VirtualFile>(Errno::enoent);
    };
}

} // namespace lx::vfs
