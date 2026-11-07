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
#include <set>
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

// The host's own copy of a /proc or /sys file, or "" when it hides it.
inline std::string host_file(const char* path) {
    std::string out;
    if (std::FILE* f = std::fopen(path, "re")) {
        char buf[8192];
        for (std::size_t n; (n = std::fread(buf, 1, sizeof buf, f)) > 0;) {
            out.append(buf, n);
            if (out.size() > (8u << 20)) break;
        }
        std::fclose(f);
    }
    return out;
}

// A virtual node that reads the host's live file, when the host lets us.
inline std::optional<kernel::VirtualFile> host_redirect(const char* path) {
    if (::access(path, R_OK) != 0) return std::nullopt;
    kernel::VirtualFile vf;
    vf.redirect_host = path;
    return vf;
}

// The run state of a guest process as the host scheduler sees it ('R', 'S',
// 'D', ...), or `fallback` when its host task can't be read.
inline char host_state(const kernel::ProcessTable& procs, std::int32_t pid, char fallback) {
    const int h = procs.host_of(pid);
    if (h <= 0) return fallback;
    const std::string s = host_file(("/proc/" + std::to_string(h) + "/stat").c_str());
    const auto rp = s.rfind(')');
    if (rp == std::string::npos || rp + 2 >= s.size()) return fallback;
    // 't' is a ptrace stop: a real stop if we recorded one, else the task is
    // waiting while linuxity serves its syscall, which on Linux is running
    if (s[rp + 2] == 't') return fallback == 'T' ? 'T' : 'R';
    return s[rp + 2];
}

// Guest processes running and blocked in disk sleep, for /proc/stat and
// loadavg. The reader itself is always running.
inline std::pair<int, int> run_counts(const kernel::ProcessTable& procs) {
    int running = 0, blocked = 0;
    for (const std::int32_t pid : procs.pids()) {
        const auto* pi = procs.find(pid);
        if (!pi) continue;
        const char st = host_state(procs, pid, pi->state);
        running += st == 'R';
        blocked += st == 'D';
    }
    return {running < 1 ? 1 : running, blocked};
}

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
            auto host_dir = [&](std::string_view d) {
                return q == d || (q.starts_with(d) && q.size() > d.size() && q[d.size()] == '/');
            };
            if (host_dir("/proc/self/fd") || host_dir("/proc/thread-self/fd") ||
                host_dir("/proc/self/fdinfo") || host_dir("/proc/thread-self/fdinfo") ||
                host_dir("/proc/self/ns")) {
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
                                  "interrupts","softirqs","swaps","partitions",
                                  "diskstats","devices","modules","misc",
                                  "kallsyms","kmsg","self","sys"})
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
            // The guest runs natively on the host's CPUs, so the host's own
            // jiffies, intr and ctxt are the true answer. Only the process
            // counts are the guest's own.
            const auto [running, blocked] = run_counts(procs);
            const std::string tail = "processes " + std::to_string(procs.last_pid()) +
                                     "\nprocs_running " + std::to_string(running) +
                                     "\nprocs_blocked " + std::to_string(blocked) + "\n";
            if (const std::string h = host_file("/proc/stat"); !h.empty()) {
                std::string s;
                std::size_t at = 0;
                while (at < h.size()) {
                    std::size_t nl = h.find('\n', at);
                    if (nl == std::string::npos) nl = h.size();
                    const std::string_view line{h.data() + at, nl - at};
                    // only the CPUs this machine has (cpuN with N < ncpu)
                    bool other_cpu = false;
                    if (line.starts_with("cpu") && line.size() > 3 && line[3] >= '0' && line[3] <= '9')
                        other_cpu = std::atol(std::string{line.substr(3, line.find(' ') - 3)}.c_str()) >= ncpu;
                    if (!line.starts_with("processes ") && !line.starts_with("procs_") &&
                        !line.empty() && !other_cpu) {
                        s.append(line);
                        s.push_back('\n');
                    }
                    at = nl + 1;
                }
                return ok(text_file(s + tail));
            }
            // The host hides it: counters that at least advance with time.
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
            s += tail;
            return ok(text_file(std::move(s)));
        }
        if (abs == "/proc/uptime") {
            if (std::string h = host_file("/proc/uptime"); !h.empty()) return ok(text_file(std::move(h)));
            const double up = mach.uptime_seconds();
            // idle time = uptime * ncpu * (mostly idle); a plausible ratio.
            char buf[64];
            std::snprintf(buf, sizeof buf, "%.2f %.2f\n", up,
                          up * static_cast<double>(ncpu) * 0.9);
            return ok(text_file(std::string{buf}));
        }
        if (abs == "/proc/loadavg") {
            // The load is the host's: the guest's work runs on its CPUs.
            // Runnable/total and the last pid are the guest's own.
            const int running = run_counts(procs).first;
            std::string avg = "0.00 0.01 0.05";
            if (const std::string h = host_file("/proc/loadavg"); !h.empty()) {
                // first three fields
                std::size_t at = 0;
                for (int i = 0; i < 3 && at != std::string::npos; ++i) at = h.find(' ', at + 1);
                if (at != std::string::npos) avg = h.substr(0, at);
            }
            return ok(text_file(avg + " " + std::to_string(running) + "/" + std::to_string(nproc) +
                                " " + std::to_string(procs.last_pid()) + "\n"));
        }
        // Hardware the guest really runs on: the host's own files, live.
        for (const char* f : {"/proc/interrupts", "/proc/softirqs", "/proc/modules",
                              "/proc/kallsyms", "/proc/pressure/cpu",
                              "/proc/pressure/memory", "/proc/pressure/io"})
            if (abs == f)
                if (auto vf = host_redirect(f)) return ok(std::move(*vf));
        // the host hides its symbols: no symbols, like kptr_restrict on a
        // locked-down kernel, but the file is there
        if (abs == "/proc/kallsyms") return ok(text_file(""));
        // the host hides its log: open is EPERM, as for a process without
        // CAP_SYSLOG (syscall.hpp refuses it); the file itself exists
        if (abs == "/proc/kmsg") {
            if (auto vf = host_redirect("/proc/kmsg")) return ok(std::move(*vf));
            return ok(text_file(""));
        }
        // Interrupt counters, per CPU, in the kernel's layout (show_interrupts
        // and show_softirqs). They grow with uptime, like /proc/stat's intr.
        if (abs == "/proc/interrupts" || abs == "/proc/softirqs") {
            const auto ticks = static_cast<std::uint64_t>(mach.uptime_seconds() * 100);
            const bool arm = mach.machine_arch == "aarch64";
            const bool soft = abs == "/proc/softirqs";
            std::string s(soft ? 20 : 11, ' ');
            char cell[32];
            for (long c = 0; c < ncpu; ++c) {
                std::snprintf(cell, sizeof cell, "CPU%-8ld", c);
                s += cell;
            }
            s += '\n';
            struct Row { const char* name; std::uint64_t per_100; const char* desc; };
            std::vector<Row> rows;
            if (soft)
                rows = {{"HI", 0, ""}, {"TIMER", 100, ""}, {"NET_TX", 1, ""},
                        {"NET_RX", 4, ""}, {"BLOCK", 2, ""}, {"IRQ_POLL", 0, ""},
                        {"TASKLET", 1, ""}, {"SCHED", 40, ""}, {"HRTIMER", 0, ""},
                        {"RCU", 30, ""}};
            else if (arm)
                rows = {{"11", 100, "    GICv3  27 Level     arch_timer"},
                        {"IPI0", 30, "      Rescheduling interrupts"},
                        {"IPI1", 10, "      Function call interrupts"},
                        {"IPI2", 0, "      CPU stop interrupts"},
                        {"IPI3", 0, "      CPU stop NMIs"},
                        {"IPI4", 0, "      Timer broadcast interrupts"},
                        {"IPI5", 2, "      IRQ work interrupts"},
                        {"IPI6", 0, "      CPU backtrace interrupts"},
                        {"IPI7", 0, "      KGDB roundup interrupts"}};
            else
                rows = {{"0", 0, "  IO-APIC    2-edge      timer"},
                        {"1", 0, "  IO-APIC    1-edge      i8042"},
                        {"8", 0, "  IO-APIC    8-edge      rtc0"},
                        {"9", 0, "  IO-APIC    9-fasteoi   acpi"},
                        {"NMI", 0, "  Non-maskable interrupts"},
                        {"LOC", 100, "  Local timer interrupts"},
                        {"RES", 30, "  Rescheduling interrupts"},
                        {"CAL", 10, "  Function call interrupts"},
                        {"TLB", 5, "  TLB shootdowns"}};
            for (const Row& r : rows) {
                std::snprintf(cell, sizeof cell, soft ? "%12s:" : "%3s: ", r.name);
                s += cell;
                for (long c = 0; c < ncpu; ++c) {
                    // spread a little per CPU so the columns aren't identical
                    const std::uint64_t v = ticks * r.per_100 / 100 * (90 + static_cast<std::uint64_t>(c * 7 % 20)) / 100;
                    std::snprintf(cell, sizeof cell, soft ? " %10llu" : "%10llu ",
                                  static_cast<unsigned long long>(v));
                    s += cell;
                }
                s += r.desc;
                s += '\n';
            }
            if (!soft) s += arm ? "Err:          0\n" : "ERR:          0\nMIS:          0\n";
            return ok(text_file(std::move(s)));
        }
        if (abs == "/proc/swaps")
            return ok(text_file("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"));
        // No block devices: the guest's root is a directory, not a disk.
        if (abs == "/proc/partitions")
            return ok(text_file("major minor  #blocks  name\n\n"));
        if (abs == "/proc/diskstats")
            return ok(text_file(""));
        if (abs == "/proc/devices")
            return ok(text_file("Character devices:\n  1 mem\n  4 /dev/vc/0\n  4 tty\n"
                                "  5 /dev/tty\n  5 /dev/console\n  5 /dev/ptmx\n"
                                " 10 misc\n136 pts\n\nBlock devices:\n"));
        if (abs == "/proc/modules")
            return ok(text_file(""));
        if (abs == "/proc/misc")
            return ok(text_file("183 hw_random\n229 fuse\n"));
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
        // /proc/sys: the knobs programs read. Machine facts are ours; the
        // limits come from the host, since its kernel enforces them, and
        // fall back to the kernel's defaults when the host hides them.
        {
            struct Knob { const char* path; const char* fallback; bool from_host; };
            static constexpr Knob kKnobs[] = {
                {"/proc/sys/kernel/ostype", "Linux", false},
                {"/proc/sys/kernel/threads-max", "126000", true},
                {"/proc/sys/kernel/ngroups_max", "65536", false},
                {"/proc/sys/kernel/cap_last_cap", "40", true},
                {"/proc/sys/kernel/randomize_va_space", "2", true},
                {"/proc/sys/kernel/shmmax", "18446744073692774399", true},
                {"/proc/sys/kernel/shmall", "18446744073692774399", true},
                {"/proc/sys/kernel/shmmni", "4096", true},
                {"/proc/sys/kernel/sem", "32000\t1024000000\t500\t32000", true},
                {"/proc/sys/kernel/msgmax", "8192", true},
                {"/proc/sys/kernel/msgmnb", "16384", true},
                {"/proc/sys/kernel/msgmni", "32000", true},
                {"/proc/sys/kernel/core_pattern", "core", false},
                {"/proc/sys/kernel/yama/ptrace_scope", "1", true},
                {"/proc/sys/fs/file-max", "9223372036854775807", true},
                {"/proc/sys/fs/nr_open", "1048576", true},
                {"/proc/sys/fs/pipe-max-size", "1048576", true},
                {"/proc/sys/fs/inotify/max_user_watches", "65536", true},
                {"/proc/sys/fs/inotify/max_user_instances", "128", true},
                {"/proc/sys/fs/inotify/max_queued_events", "16384", true},
                {"/proc/sys/vm/overcommit_memory", "0", true},
                {"/proc/sys/vm/max_map_count", "65530", true},
                {"/proc/sys/vm/swappiness", "60", true},
                {"/proc/sys/vm/overcommit_ratio", "50", true},
                {"/proc/sys/vm/dirty_ratio", "20", true},
                {"/proc/sys/vm/dirty_background_ratio", "10", true},
                {"/proc/sys/vm/vfs_cache_pressure", "100", true},
                {"/proc/sys/vm/min_free_kbytes", "67584", true},
                {"/proc/sys/vm/page-cluster", "3", true},
                // write-only: root's read is EACCES (see syscall.hpp)
                {"/proc/sys/vm/drop_caches", "", false},
                {"/proc/sys/net/core/somaxconn", "4096", true},
                {"/proc/sys/net/ipv4/ip_local_port_range", "32768\t60999", true},
                {"/proc/sys/net/ipv4/tcp_fin_timeout", "60", true},
            };
            for (const Knob& k : kKnobs) {
                if (abs != k.path) continue;
                std::string v;
                if (k.from_host) {
                    if (std::FILE* f = std::fopen(k.path, "re")) {
                        char buf[256];
                        const std::size_t n = std::fread(buf, 1, sizeof buf, f);
                        std::fclose(f);
                        v.assign(buf, n);
                    }
                }
                if (v.empty() && *k.fallback) v = std::string{k.fallback} + "\n";
                return ok(text_file(std::move(v)));
            }
            auto dir_of = [&](std::string_view d) {
                std::vector<kernel::VirtualDirent> e;
                std::set<std::string> seen;
                const std::string pre = std::string{d} + "/";
                for (const Knob& k : kKnobs) {
                    std::string_view p{k.path};
                    if (!p.starts_with(pre)) continue;
                    p.remove_prefix(pre.size());
                    const std::size_t s = p.find('/');
                    std::string name{p.substr(0, s)};
                    if (seen.insert(name).second) e.push_back({name, s != std::string_view::npos});
                }
                return e;
            };
            for (const char* d : {"/proc/sys", "/proc/sys/kernel", "/proc/sys/fs", "/proc/sys/vm",
                                  "/proc/sys/net", "/proc/sys/net/core", "/proc/sys/net/ipv4",
                                  "/proc/sys/fs/inotify", "/proc/sys/kernel/yama"}) {
                if (abs != d) continue;
                auto e = dir_of(d);
                if (abs == "/proc/sys/kernel")
                    for (const char* n : {"osrelease", "hostname", "pid_max"})
                        e.push_back({n, false});
                if (abs == "/proc/sys/kernel") e.push_back({"random", true});
                return ok(dir_file(std::move(e)));
            }
        }
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
            std::int32_t self_tid = static_cast<std::int32_t>(pid);   // names the thread
            // /proc/<tid> of a non-main thread is unlisted but resolves, like Linux
            if (!pi)
                if (const auto tg = procs.thread_group_of(self_tid)) pi = procs.find(tg);
            if (!pi) return err<kernel::VirtualFile>(Errno::enoent);
            const auto& I = *pi;

            if (tail.empty())     // the /proc/<pid> directory itself
                return ok(dir_file({
                    {"stat",false},{"statm",false},{"status",false},
                    {"cmdline",false},{"comm",false},{"cwd",true},
                    {"exe",false},{"root",true},{"fd",true},{"maps",false},
                    {"io",false},{"oom_score",false},{"task",true},
                    {"environ",false},{"fdinfo",true},{"mountinfo",false},
                    {"mounts",false},{"limits",false},{"ns",true},
                }));

            // ---- /proc/<pid>/task : the thread group -------------------
            // htop/top enumerate processes THROUGH this directory. Each
            // thread's files mirror the process's own.
            if (tail == "task") {
                std::vector<kernel::VirtualDirent> ents{{std::to_string(I.pid), true}};
                for (auto t : I.threads) ents.push_back({std::to_string(t), true});
                return ok(dir_file(std::move(ents)));
            }
            if (tail.starts_with("task/")) {
                std::string_view rest = std::string_view{tail}.substr(5);
                std::size_t slash = rest.find('/');
                std::string_view tid = rest.substr(0, slash);
                const bool known = tid == std::to_string(I.pid) ||
                    std::any_of(I.threads.begin(), I.threads.end(),
                                [&](std::int32_t t) { return tid == std::to_string(t); });
                if (!known)
                    return err<kernel::VirtualFile>(Errno::enoent);
                if (slash == std::string_view::npos)  // /proc/<pid>/task/<tid>
                    return ok(dir_file({
                        {"stat",false},{"statm",false},{"status",false},
                        {"cmdline",false},{"comm",false},{"maps",false},
                        {"io",false},{"children",false},
                    }));
                // Re-target the file lookup at the thread's own file, which
                // mirrors the process's but names the thread. Parse tid
                // first: it views into tail.
                self_tid = static_cast<std::int32_t>(std::atol(std::string{tid}.c_str()));
                tail = std::string{rest.substr(slash + 1)};
            }

            // The host task's own /proc, for facts only the host kernel keeps.
            const int host = procs.host_of(self_tid);
            auto host_file = [&](const char* leaf) {
                std::string out;
                if (host <= 0) return out;
                const std::string p = "/proc/" + std::to_string(host) + "/" + leaf;
                if (std::FILE* f = std::fopen(p.c_str(), "re")) {
                    char buf[8192];
                    while (std::size_t n = std::fread(buf, 1, sizeof buf, f)) out.append(buf, n);
                    std::fclose(f);
                }
                return out;
            };
            // One "Key:\tvalue" line of the host task's status, or "".
            auto host_status = [&, cache = std::string{}](std::string_view key) mutable {
                if (cache.empty()) cache = host_file("status");
                std::size_t at = 0;
                while (at < cache.size()) {
                    const std::size_t nl = std::min(cache.find('\n', at), cache.size());
                    std::string_view line{cache.data() + at, nl - at};
                    if (line.starts_with(key) && line.size() > key.size() && line[key.size()] == ':')
                        return std::string{line.substr(key.size() + 1)};
                    at = nl + 1;
                }
                return std::string{};
            };
            // The host task's stat fields after "(comm)", 0-based from state.
            auto host_stat = [&]() {
                std::vector<std::string> f;
                const std::string s = host_file("stat");
                const std::size_t rp = s.rfind(')');
                if (rp == std::string::npos) return f;
                std::size_t at = rp + 2;
                while (at < s.size()) {
                    const std::size_t sp = std::min(s.find(' ', at), s.size());
                    f.emplace_back(s.substr(at, sp - at));
                    at = sp + 1;
                }
                return f;
            };

            const std::string& comm = kernel::ProcessTable::comm_of(I, self_tid);
            const char state = host_state(procs, self_tid, I.state);
            if (tail == "comm")   return ok(text_file(comm + "\n"));
            if (tail == "cmdline") {
                std::string cl = I.cmdline; cl.push_back('\0');  // NUL-terminated
                return ok(text_file(std::move(cl)));
            }
            if (tail == "stat") {
                // The single-line /proc/<pid>/stat (fields per proc(5)). Ids
                // and names are ours; times and memory are the task's own.
                const auto hs = host_stat();
                auto hf = [&](std::size_t i, const char* dflt) {
                    // proc(5) numbers from 1 (pid); hs[0] is field 3 (state)
                    return i - 3 < hs.size() ? hs[i - 3] : std::string{dflt};
                };
                std::string s;
                s += std::to_string(self_tid);
                s += " (" + comm + ") ";
                s += state; s += ' ';
                s += std::to_string(I.ppid) + " ";      // ppid
                // From the process table, not the pid: answering pid made
                // `ps -o pgid` show every task as its own group leader.
                s += std::to_string(procs.pgid_of(I.pid)) + " ";  // pgrp
                s += std::to_string(procs.sid_of(I.pid)) + " ";   // session
                s += "0 -1 ";                           // tty_nr, tpgid
                s += hf(9, "4194304") + " ";            // flags
                for (std::size_t i = 10; i <= 17; ++i)   // faults, utime stime cutime cstime
                    s += hf(i, "0") + " ";
                s += std::to_string(20 + I.nice) + " " + std::to_string(I.nice) + " ";  // priority nice
                s += std::to_string(1 + I.threads.size()) + " 0 ";  // num_threads itrealvalue
                s += hf(22, "100") + " ";               // starttime
                s += hf(23, std::to_string(I.vsize_bytes).c_str()) + " ";
                s += hf(24, std::to_string(I.rss_pages).c_str()) + " ";
                s += hf(25, "18446744073709551615");
                for (std::size_t i = 26; i <= 52; ++i)  // the rest, as the task has them
                    s += " " + hf(i, "0");
                s += "\n";
                return ok(text_file(std::move(s)));
            }
            if (tail == "environ") {
                // The task's real initial environment, as the kernel keeps it.
                std::string env = host_file("environ");
                return ok(text_file(std::move(env)));
            }
            if (tail == "limits") {
                // the task's real rlimits; the host enforces them
                std::string l = host_file("limits");
                if (l.empty()) return err<kernel::VirtualFile>(Errno::enoent);
                return ok(text_file(std::move(l)));
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
                s += "Name:\t" + comm + "\n";
                s += "State:\t"; s += state;
                switch (state) {
                    case 'R': s += " (running)\n"; break;
                    case 'T': s += " (stopped)\n"; break;
                    case 'Z': s += " (zombie)\n"; break;
                    case 'D': s += " (disk sleep)\n"; break;
                    default:  s += " (sleeping)\n"; break;
                }
                s += "Tgid:\t" + std::to_string(I.pid) + "\n";
                s += "Pid:\t" + std::to_string(self_tid) + "\n";
                s += "PPid:\t" + std::to_string(I.ppid) + "\n";
                s += "TracerPid:\t0\n";
                auto ids = [](const std::array<std::uint32_t, 4>& v) {
                    return std::to_string(v[0]) + "\t" + std::to_string(v[1]) + "\t" +
                           std::to_string(v[2]) + "\t" + std::to_string(v[3]) + "\n";
                };
                s += "Uid:\t" + ids(I.uids);
                s += "Gid:\t" + ids(I.gids);
                s += "FDSize:\t" + (host_status("FDSize").empty() ? std::string{"\t64"} : host_status("FDSize")) + "\n";
                s += "Groups:\t";
                {
                    const auto g = procs.groups_of(I.pid);
                    for (std::size_t i = 0; i < g.size(); ++i)
                        s += std::to_string(g[i]) + " ";
                }
                s += "\n";
                s += "NStgid:\t" + std::to_string(I.pid) + "\n";
                s += "NSpid:\t" + std::to_string(self_tid) + "\n";
                s += "NSpgid:\t" + std::to_string(procs.pgid_of(I.pid)) + "\n";
                s += "NSsid:\t" + std::to_string(procs.sid_of(I.pid)) + "\n";
                // memory, as the task really uses it
                for (const char* k : {"VmPeak", "VmSize", "VmLck", "VmPin", "VmHWM", "VmRSS",
                                      "RssAnon", "RssFile", "RssShmem", "VmData", "VmStk",
                                      "VmExe", "VmLib", "VmPTE", "VmSwap"}) {
                    std::string v = host_status(k);
                    if (v.empty()) {
                        if (std::string_view{k} == "VmSize") v = "\t" + std::to_string(I.vsize_bytes / 1024) + " kB";
                        else if (std::string_view{k} == "VmRSS") v = "\t" + std::to_string(I.rss_pages * 4) + " kB";
                        else continue;
                    }
                    s += std::string{k} + ":" + v + "\n";
                }
                s += "Threads:\t" + std::to_string(1 + I.threads.size()) + "\n";
                // signal state, which only the kernel holds
                for (const char* k : {"SigQ", "SigPnd", "ShdPnd", "SigBlk", "SigIgn", "SigCgt"}) {
                    std::string v = host_status(k);
                    s += std::string{k} + ":" + (v.empty() ? std::string{"\t0000000000000000"} : v) + "\n";
                }
                char caps[160];
                std::snprintf(caps, sizeof caps,
                              "CapInh:\t%016llx\nCapPrm:\t%016llx\nCapEff:\t%016llx\n"
                              "CapBnd:\t%016llx\nCapAmb:\t%016llx\n",
                              static_cast<unsigned long long>(I.cap_inh),
                              static_cast<unsigned long long>(I.cap_prm),
                              static_cast<unsigned long long>(I.cap_eff),
                              static_cast<unsigned long long>(I.cap_bnd),
                              static_cast<unsigned long long>(I.cap_amb));
                s += caps;
                s += std::string{"NoNewPrivs:\t"} + (I.no_new_privs ? "1" : "0") + "\n";
                s += "Seccomp:\t0\nSeccomp_filters:\t0\n";
                for (const char* k : {"Cpus_allowed", "Cpus_allowed_list", "Mems_allowed",
                                      "Mems_allowed_list", "voluntary_ctxt_switches",
                                      "nonvoluntary_ctxt_switches"}) {
                    std::string v = host_status(k);
                    if (!v.empty()) s += std::string{k} + ":" + v + "\n";
                }
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
