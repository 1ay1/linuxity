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

#include "linuxity/host/entropy.hpp"
#include "linuxity/kernel/file_namespace.hpp"
#include "linuxity/kernel/machine.hpp"
#include "linuxity/kernel/process_table.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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

// Build a /proc producer bound to linuxity's process table + machine spec.
// The spec (kernel/machine.hpp) is the SINGLE source of truth for ncpu, RAM,
// frequency, identity and uptime; /proc reads only from it, so it can never
// drift from /sys or the sysinfo(2)/sched_getaffinity(2) syscalls. Both the
// table and the spec are captured by reference (owned by the kernel).
[[nodiscard]] inline kernel::FileNamespace::Producer
make_procfs(const kernel::ProcessTable& procs, const kernel::MachineSpec& mach) {
    return [&procs, &mach](std::string_view abs) -> Result<kernel::VirtualFile> {
        using detail::text_file; using detail::dir_file;
        const long  nproc   = static_cast<long>(procs.count());
        const long  ncpu    = mach.ncpu < 1 ? 1 : mach.ncpu;
        const auto& release = mach.release;
        const auto& nodename= mach.nodename;

        // ---- /proc/self/fd/N -> the guest's REAL host fd ----------------
        // /dev/stdout, /dev/stdin and any dup-via-path go through here. The
        // guest is a genuine host process, so the host kernel's own
        // /proc/self/fd/N (resolved in the guest's context) IS the guest's
        // fd N. Redirect to that literal host path so a write to /dev/stdout
        // reaches the real fd 1. (Enumerating the fd DIRECTORY is left to the
        // native host procfs via the same redirect.)
        {
            std::string q{abs};
            if (q == "/proc/self/fd" || q.starts_with("/proc/self/fd/") ||
                q == "/proc/thread-self/fd" || q.starts_with("/proc/thread-self/fd/")) {
                kernel::VirtualFile vf; vf.redirect_host = std::move(q);
                return ok(std::move(vf));
            }
        }

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
            for (const char* f : {"stat","meminfo","vmstat","cpuinfo","uptime","loadavg",
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
            char mhz[32];
            std::snprintf(mhz, sizeof mhz, "%.3f", mach.cpu_mhz());
            std::string s;
            if (mach.machine_arch == "aarch64") {
                // The arm64 kernel's format (arch/arm64/kernel/cpuinfo.c):
                // no vendor_id/model name/MHz, but Features + the MIDR
                // fields lscpu decodes. We add a "model name" line too: Asahi
                // and several distros carry it, and fetch tools (screenfetch,
                // fastfetch) show it.
                //
                // Features comes from the MachineSpec, which main.cpp fills
                // from the host -- the guest executes on the real CPU, so
                // claiming a feature it lacks makes libgcrypt choose an
                // instruction path that SIGILLs.
                for (long c = 0; c < ncpu; ++c) {
                    s += "processor\t: " + std::to_string(c) + "\n";
                    s += "model name\t: " + mach.cpu_model + "\n";
                    s += "BogoMIPS\t: 48.00\n"
                         "Features\t: " + mach.cpu_features + "\n"
                         "CPU implementer\t: " + mach.cpu_implementer + "\n"
                         "CPU architecture: " + mach.cpu_architecture + "\n"
                         "CPU variant\t: 0x0\nCPU part\t: 0x" + mach.cpu_part + "\n"
                         "CPU revision\t: 0\n\n";
                }
                return ok(text_file(std::move(s)));
            }
            for (long c = 0; c < ncpu; ++c) {
                s += "processor\t: " + std::to_string(c) + "\n";
                s += "vendor_id\t: LinuxityVirtual\n"
                     "cpu family\t: 6\nmodel\t\t: 1\nmodel name\t: " + mach.cpu_model + "\n";
                s += "cpu MHz\t\t: " + std::string{mhz} + "\ncache size\t: 8192 KB\n";
                s += "physical id\t: 0\nsiblings\t: " + std::to_string(ncpu) +
                     "\ncore id\t\t: " + std::to_string(c) +
                     "\ncpu cores\t: " + std::to_string(ncpu) + "\n";
                s += "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep\n"
                     "bogomips\t: 6000.00\n\n";
            }
            return ok(text_file(std::move(s)));
        }
        if (abs == "/proc/meminfo") {
            // The kernel's own format is `"%-15s %8lu kB\n"` -- label padded
            // LEFT to 15 columns, value RIGHT-aligned in 8. This file used
            // hardcoded runs of spaces instead, which happened to look right
            // for one magnitude of number and drifted for any other.
            //
            // That is not cosmetic. procps-ng parses meminfo by matching a
            // field name and then reading the value, and `ps -eo %mem` died
            // with SIGFPE ("Signal 8 (FPE) caught by ps") because it could
            // not recover MemTotal and divided by zero. `free` and `top` read
            // the same file. Matching the kernel byte-for-byte is the only
            // version that is safe against every consumer's parser.
            auto row = [](const char* label, std::uint64_t bytes) {
                char line[64];
                std::snprintf(line, sizeof line, "%-15s %8llu kB\n", label,
                              static_cast<unsigned long long>(bytes >> 10));
                return std::string{line};
            };
            std::string s;
            s += row("MemTotal:",     mach.mem_total);
            s += row("MemFree:",      mach.mem_free());
            s += row("MemAvailable:", mach.mem_available());
            s += row("Buffers:",      mach.mem_buffers());
            s += row("Cached:",       mach.mem_cached());
            s += row("SwapCached:",   0);
            s += row("Active:",       mach.mem_cached());
            s += row("Inactive:",     mach.mem_buffers());
            s += row("SwapTotal:",    mach.swap_total);
            s += row("SwapFree:",     mach.swap_total);
            s += row("Dirty:",        0);
            s += row("Writeback:",    0);
            s += row("AnonPages:",    mach.mem_total - mach.mem_free());
            s += row("Mapped:",       mach.mem_cached());
            s += row("Shmem:",        16384ull << 10);
            // SReclaimable is read by `free` to split cache from slab; without
            // it the cache column reads low.
            s += row("Slab:",          65536ull << 10);
            s += row("SReclaimable:",  32768ull << 10);
            s += row("SUnreclaim:",    32768ull << 10);
            return ok(text_file(std::move(s)));
        }
        if (abs == "/proc/vmstat") {
            // Virtual-memory event counters, one `name value` pair per line.
            //
            // It did not exist at all, and libproc2's vmstat reader fails
            // outright on a missing FILE ("vmstat: Unable to create vmstat
            // structure") while tolerating any field it doesn't recognise --
            // it looks each name up in a hash table and skips misses. So the
            // file must exist and be well-formed; the field list only has to
            // cover what consumers actually read.
            //
            // vmstat(8) reads pgpgin/pgpgout (block I/O) and pswpin/pswpout
            // (swap). There is no swap and linuxity does no paging of its own,
            // so the swap counters are truthfully 0. nr_free_pages is derived
            // from the same MemFree that /proc/meminfo reports, so the two
            // files cannot disagree.
            const std::uint64_t page = 4096;
            std::string s;
            auto row = [&](const char* name, std::uint64_t v) {
                s += name; s += ' '; s += std::to_string(v); s += '\n';
            };
            row("nr_free_pages", mach.mem_free() / page);
            row("nr_inactive_anon", 0);
            row("nr_active_anon", (mach.mem_total - mach.mem_free()) / page);
            row("nr_inactive_file", mach.mem_buffers() / page);
            row("nr_active_file", mach.mem_cached() / page);
            row("nr_dirty", 0);
            row("nr_writeback", 0);
            row("pgpgin", 0);
            row("pgpgout", 0);
            row("pswpin", 0);
            row("pswpout", 0);
            row("pgfault", 0);
            row("pgmajfault", 0);
            return ok(text_file(std::move(s)));
        }
        if (abs == "/proc/stat") {
            // System-wide CPU + process counters. htop/top/btop read this
            // first, then AGAIN a second later, and compute each core's CPU%
            // from the delta. So the jiffies must ADVANCE with real time:
            // derive them from linuxity's virtual uptime (HZ = 100). Each core
            // spends a small, gently per-core-varied slice busy and the rest
            // idle, so a monitor renders a live, plausible — not frozen — load.
            constexpr long kHz = 100;
            const double up = mach.uptime_seconds();
            const long total = static_cast<long>(up * kHz);
            auto core_line = [&](long c) {
                // A steady baseline load per core (2%..~14%), phase-shifted by
                // core index so the gauges differ; the rest is idle.
                long busy_pct = 2 + (c * 3) % 12;
                long busy = total * busy_pct / 100;
                long user = busy * 2 / 3, sys = busy - user;
                long idle = total - busy;
                if (idle < 0) idle = 0;
                return std::to_string(user) + " 0 " + std::to_string(sys) + " " +
                       std::to_string(idle) + " 0 0 0 0 0 0";
            };
            // Aggregate = sum across cores.
            long auser = 0, asys = 0, aidle = 0;
            for (long c = 0; c < ncpu; ++c) {
                long busy_pct = 2 + (c * 3) % 12;
                long busy = total * busy_pct / 100;
                auser += busy * 2 / 3; asys += busy - busy * 2 / 3;
                aidle += total - busy;
            }
            std::string s;
            s += "cpu  " + std::to_string(auser) + " 0 " + std::to_string(asys) +
                 " " + std::to_string(aidle) + " 0 0 0 0 0 0\n";
            for (long c = 0; c < ncpu; ++c)
                s += "cpu" + std::to_string(c) + " " + core_line(c) + "\n";
            s += "intr " + std::to_string(total * 20) + "\n";
            s += "ctxt " + std::to_string(total * 8) + "\n";
            s += "btime " + std::to_string(mach.boot_epoch()) + "\n";
            s += "processes " + std::to_string(nproc + 10) + "\n";
            s += "procs_running 1\nprocs_blocked 0\n";
            return ok(text_file(std::move(s)));
        }
        if (abs == "/proc/uptime") {
            const double up = mach.uptime_seconds();
            // idle time = uptime * ncpu * (mostly idle); a plausible ratio.
            char buf[64];
            std::snprintf(buf, sizeof buf, "%.2f %.2f\n", up,
                          up * static_cast<double>(ncpu) * 0.9);
            return ok(text_file(std::string{buf}));
        }
        if (abs == "/proc/loadavg")
            return ok(text_file("0.00 0.01 0.05 1/" + std::to_string(nproc) + " 1\n"));
        if (abs == "/proc/filesystems")
            return ok(text_file("nodev\tproc\nnodev\tsysfs\nnodev\ttmpfs\n\text4\n"));
        // The mount table. /etc/mtab -> /proc/self/mounts, and pacman/df read
        // it to determine filesystem mount points before checking free space,
        // so /proc/mounts AND every per-pid /proc/<pid>/mounts must yield it.
        //
        // This matched only /proc/1/{mounts,mountinfo,mountstats}, which
        // worked solely because /proc/self used to canonicalize to /proc/1
        // for EVERY process. Once self binds to the real caller, pid 13
        // reading /proc/self/mounts asks for /proc/13/mounts, and that hit
        // ENOENT -- breaking df, pacman's space check and /etc/mtab at once.
        // All guest tasks share one mount namespace, so the table is the same
        // for any pid; match the shape rather than the number.
        const auto per_pid = [&](std::string_view leaf) {
            if (!p.starts_with("/proc/") || !p.ends_with(leaf)) return false;
            const std::string_view mid{p.data() + 6, p.size() - 6 - leaf.size()};
            return !mid.empty() &&
                   mid.find_first_not_of("0123456789") == std::string_view::npos;
        };
        const bool mountinfo = per_pid("/mountinfo");
        if (p == "/proc/mounts" || per_pid("/mounts") || mountinfo ||
            per_pid("/mountstats")) {
            if (mountinfo)
                return ok(text_file(
                    "1 1 0:1 / / rw - rootfs rootfs rw\n"
                    "2 1 0:2 / /proc rw,nosuid,nodev,noexec - proc proc rw\n"
                    "3 1 0:3 / /sys rw,nosuid,nodev,noexec - sysfs sysfs rw\n"
                    "4 1 0:4 / /dev rw,nosuid - devtmpfs devtmpfs rw\n"
                    "5 1 0:5 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw\n"));
            return ok(text_file(
                "rootfs / rootfs rw 0 0\nproc /proc proc rw,nosuid,nodev,noexec 0 0\n"
                "sysfs /sys sysfs rw,nosuid,nodev,noexec 0 0\n"
                "devtmpfs /dev devtmpfs rw,nosuid 0 0\n"
                "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"));
        }
        if (abs == "/proc/sys" || abs == "/proc/sys/kernel")
            return ok(dir_file({{"kernel",true},{"osrelease",false},{"hostname",false},
                                {"pid_max",false},{"random",true}}));
        if (abs == "/proc/sys/kernel/osrelease") return ok(text_file(release + "\n"));
        if (abs == "/proc/sys/kernel/hostname")  return ok(text_file(nodename + "\n"));
        if (abs == "/proc/sys/kernel/pid_max")   return ok(text_file("32768\n"));
        // random/: login profiles, systemd tools and Python's uuid read these.
        // uuid is a fresh v4 per read; boot_id is fixed for this boot.
        if (abs == "/proc/sys/kernel/random")
            return ok(dir_file({{"uuid",false},{"boot_id",false},{"entropy_avail",false},
                                {"poolsize",false}}));
        if (abs == "/proc/sys/kernel/random/uuid" || abs == "/proc/sys/kernel/random/boot_id") {
            std::uint8_t b[16];
            static std::uint8_t boot[16];
            // host::random_bytes, not arc4random_buf: this is a PORTABLE
            // header, and arc4random_buf is BSD/glibc-only -- mingw has no
            // such symbol, so this file could not compile on Windows at all.
            static const bool seeded = [] {
                return host::random_bytes(boot, sizeof boot);
            }();
            (void)seeded;
            if (abs.ends_with("uuid")) {
                if (!host::random_bytes(b, sizeof b))
                    return err<kernel::VirtualFile>(Errno::eio);
            } else {
                std::memcpy(b, boot, sizeof b);
            }
            b[6] = static_cast<std::uint8_t>((b[6] & 0x0f) | 0x40);   // version 4
            b[8] = static_cast<std::uint8_t>((b[8] & 0x3f) | 0x80);   // RFC 4122 variant
            char s[40];
            std::snprintf(s, sizeof s, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
                          b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
            return ok(text_file(s));
        }
        if (abs == "/proc/sys/kernel/random/entropy_avail") return ok(text_file("256\n"));
        if (abs == "/proc/sys/kernel/random/poolsize")      return ok(text_file("256\n"));

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
                // utime/stime advance with virtual uptime so a monitor shows a
                // live per-process CPU% and a growing TIME+ column. A small
                // fraction of elapsed jiffies is attributed to this task.
                {
                    long up_j = static_cast<long>(mach.uptime_seconds() * 100);
                    long ut = up_j / 20, st = up_j / 40;   // ~5% user, ~2.5% sys
                    s += std::to_string(ut) + " " + std::to_string(st) + " 0 0 ";
                }
                s += "20 0 ";                           // priority nice
                s += "1 0 ";                            // num_threads itrealvalue
                s += "100 ";                            // starttime (jiffies)
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
            if (tail == "cwd" || tail == "root" || tail == "exe") {
                // Symlinks whose targets only the dispatcher knows (it has
                // the live task and the backend's exe table). Mark them so
                // classify() reports virtual_file instead of absent, and
                // let syscall.hpp substitute the real target.
                kernel::VirtualFile vf;
                vf.symlink_target = "(proc-link)";
                return ok(std::move(vf));
            }
            return err<kernel::VirtualFile>(Errno::enoent);
        }

        return err<kernel::VirtualFile>(Errno::enoent);
    };
}

} // namespace lx::vfs
