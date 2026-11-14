// linuxity/runtime/darwin/procinfo.hpp
//
// The per-process /proc facts only a kernel keeps, for a host with no /proc.
//
// On Linux the portable procfs reads them straight from the host task's own
// /proc/<pid> (stat, status, io, environ, fd/...): the guest is a real host
// process and the host kernel is the authority. macOS has no /proc at all, so
// those reads came back empty and procfs fell back to placeholders: an rss of
// 1 MiB, utime that never moved, no /proc/self/fd, an environ with no PATH.
//
// This file answers the same questions in LINUX'S FORMAT, so procfs parses
// them exactly as it parses a host file (ProcessTable::host_fact):
//
//   * for THIS process -- what the backend itself tracks: the guest fd table,
//     the threads, the initial environment, read/write counters, signal
//     dispositions and pending set, the guest's own address space;
//   * for any process in the tree -- what Darwin will say about another host
//     process of the same user (proc_pidinfo): run state, CPU times, memory,
//     thread count, start time.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include "linuxity/runtime/darwin/darwin.hpp"
#include "linuxity/runtime/darwin/proc.hpp"
#include "linuxity/runtime/darwin/signal.hpp"
#include "linuxity/runtime/darwin/task.hpp"

#include <fcntl.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

namespace lx::runtime::procinfo {

inline constexpr std::uint64_t kHz = 100;   // USER_HZ: what stat's times count in

// Mach absolute time (what proc_taskinfo's CPU times are in on Apple
// Silicon) -> clock ticks.
[[nodiscard]] inline std::uint64_t mach_to_ticks(std::uint64_t t) noexcept {
    static const mach_timebase_info_data_t tb = [] {
        mach_timebase_info_data_t i{};
        ::mach_timebase_info(&i);
        if (i.denom == 0) i = {1, 1};
        return i;
    }();
    const long double ns = static_cast<long double>(t) * tb.numer / tb.denom;
    return static_cast<std::uint64_t>(ns / (1'000'000'000.0L / kHz));
}

// What Darwin knows about one host process.
struct HostTask {
    char state{'S'};
    std::uint64_t utime{}, stime{};          // ticks
    std::uint64_t rss{}, peak_rss{};         // bytes
    std::uint64_t threads{1};
    std::uint64_t start_ticks{};             // since boot
    std::uint64_t minflt{}, majflt{};
    std::uint64_t vol_cs{}, invol_cs{};
    int nice{};
};

[[nodiscard]] inline std::uint64_t boot_seconds() noexcept {
    static const std::uint64_t b = [] {
        ::timeval tv{};
        std::size_t len = sizeof tv;
        int mib[2] = {CTL_KERN, KERN_BOOTTIME};
        return ::sysctl(mib, 2, &tv, &len, nullptr, 0) == 0 ? static_cast<std::uint64_t>(tv.tv_sec) : 0;
    }();
    return b;
}

[[nodiscard]] inline std::optional<HostTask> host_task(pid_t pid) {
    HostTask t;
    ::proc_taskinfo ti{};
    if (::proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, sizeof ti) != sizeof ti) {
        // A ZOMBIE has no task left (TASKINFO fails), but it is still a
        // process, and `ps`, `wait_until(state == Z)` and every supervisor
        // ask exactly then. proc_pidinfo answers nothing for one at all, so
        // ask sysctl's process record; without it /proc fell back to 'S'
        // and a dead child looked alive.
        struct ::kinfo_proc kp{};
        std::size_t len = sizeof kp;
        int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
        if (::sysctl(mib, 4, &kp, &len, nullptr, 0) != 0 || len == 0 || kp.kp_proc.p_stat != SZOMB)
            return std::nullopt;
        t.state = 'Z';
        t.threads = 1;
        return t;
    }
    t.utime = mach_to_ticks(ti.pti_total_user);
    t.stime = mach_to_ticks(ti.pti_total_system);
    t.rss = ti.pti_resident_size;
    t.threads = ti.pti_threadnum > 0 ? static_cast<std::uint64_t>(ti.pti_threadnum) : 1;
    t.minflt = static_cast<std::uint64_t>(ti.pti_faults > ti.pti_pageins ? ti.pti_faults - ti.pti_pageins : 0);
    t.majflt = static_cast<std::uint64_t>(ti.pti_pageins);
    t.invol_cs = static_cast<std::uint64_t>(ti.pti_csw);
    ::rusage_info_v2 ru{};
    if (::proc_pid_rusage(pid, RUSAGE_INFO_V2, reinterpret_cast<rusage_info_t*>(&ru)) == 0)
        t.peak_rss = ru.ri_phys_footprint > t.rss ? ru.ri_phys_footprint : t.rss;
    else
        t.peak_rss = t.rss;
    ::proc_bsdinfo bi{};
    if (::proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof bi) == sizeof bi) {
        switch (bi.pbi_status) {
            case SSTOP: t.state = 'T'; break;
            case SZOMB: t.state = 'Z'; break;
            case SIDL:  t.state = 'R'; break;
            default:    t.state = 'S'; break;        // Darwin says SRUN for sleepers too
        }
        t.nice = bi.pbi_nice;
        const std::uint64_t boot = boot_seconds();
        if (bi.pbi_start_tvsec >= boot)
            t.start_ticks = (bi.pbi_start_tvsec - boot) * kHz + bi.pbi_start_tvusec / (1'000'000 / kHz);
    }
    if (pid == ::getpid()) t.state = 'R';                // the reader is running
    return t;
}

// This process's guest: the facts the backend tracks itself.
struct Self {
    ProcessState& proc;
    std::int32_t pid;     // its guest pid
};

[[nodiscard]] inline std::uint64_t guest_vsize(ProcessState& p) {
    return p.with_space([](AddressSpace& s) {
        std::uint64_t n = 0;
        for (const Vma& v : s.vmas()) n += v.end - v.begin;
        return n;
    });
}

[[nodiscard]] inline std::string hex16(std::uint64_t v) {
    char b[20];
    std::snprintf(b, sizeof b, "%016llx", static_cast<unsigned long long>(v));
    return b;
}

// /proc/<pid>/maps for this process: the guest's VMAs, with the names its
// images, files and stack were mapped under.
[[nodiscard]] inline std::string maps(ProcessState& p) {
    struct Row { std::uint64_t b, e; GuestProt prot; bool anon; };
    std::vector<Row> rows = p.with_space([](AddressSpace& s) {
        std::vector<Row> r;
        for (const Vma& v : s.vmas()) r.push_back({v.begin, v.end, v.prot, v.anonymous});
        return r;
    });
    std::vector<ProcessState::NamedRange> names = p.with_names([](auto& v) { return v; });
    std::string out;
    char line[160];
    for (const Row& r : rows) {
        // a VMA may be named in pieces (an image's segments): split on names
        std::uint64_t at = r.b;
        while (at < r.e) {
            const ProcessState::NamedRange* hit = nullptr;
            std::uint64_t next = r.e;
            for (const auto& n : names) {
                if (n.begin <= at && n.end > at) { hit = &n; break; }
                if (n.begin > at && n.begin < next) next = n.begin;
            }
            const std::uint64_t end = hit ? std::min(hit->end, r.e) : next;
            const auto has = [&](GuestProt f) { return runtime::has(r.prot, f); };
            const std::uint64_t off = hit ? hit->off + (at - hit->begin) : 0;
            std::snprintf(line, sizeof line, "%08llx-%08llx %c%c%c%c %08llx 00:00 0",
                          static_cast<unsigned long long>(at), static_cast<unsigned long long>(end),
                          has(GuestProt::read) ? 'r' : '-', has(GuestProt::write) ? 'w' : '-',
                          has(GuestProt::exec) ? 'x' : '-', hit && hit->shared ? 's' : 'p',
                          static_cast<unsigned long long>(off));
            out += line;
            if (hit && !hit->name.empty()) {
                out.append(std::max<std::size_t>(1, 73 - std::strlen(line)), ' ');
                out += hit->name;
            }
            out += '\n';
            at = end;
        }
    }
    return out;
}

// What another guest process published about itself (PidSpace): the host
// task's numbers count linuxity, not the program. 0 = not published.
struct Peer {
    std::uint32_t threads{0};
    std::uint64_t vsize{0};
    // the guest's resident bytes (asked only for the leaves that show it;
    // 0 = unknown, use the host task's count)
    std::function<std::uint64_t()> resident{};
};

// Leaves about a process's own address space and image, which only its own
// linuxity can answer (another process asks it through memsvc).
[[nodiscard]] inline bool is_own_fact(std::string_view leaf) noexcept {
    return leaf == "maps" || leaf == "smaps" || leaf == "smaps_rollup" || leaf == "auxv" ||
           leaf == "environ";
}

// One fact, Linux-formatted, or nullopt for "not known here".
[[nodiscard]] inline std::optional<std::string>
fact(std::string_view leaf, pid_t host, const Self* self, std::optional<int> nice = std::nullopt,
     Peer peer = {}) {
    const auto ht = host > 0 ? host_task(host) : std::nullopt;
    // The GUEST's size and threads: its own mappings and vCPU threads, never
    // the host task's (linuxity's timer/service threads made every python
    // fork() warn "this process is multi-threaded"; ps showed RSS == VSZ).
    // Resident memory is the host's count, which includes linuxity's own;
    // capped at the size, since nothing is resident that isn't mapped.
    struct Sizes { std::uint64_t vs, rss, nth; };
    auto sizes = [&]() -> Sizes {
        const std::uint64_t vs = self ? guest_vsize(self->proc)
                               : peer.vsize ? peer.vsize : (ht ? ht->rss : 0);
        // Both counts over-count: the host task's includes linuxity itself,
        // and mincore still calls MADV_FREE'd guest pages resident until the
        // host reclaims them. The smaller is the closer.
        // (never asked of a stopped or dead process: it can't answer)
        const bool can_answer = ht && ht->state != 'T' && ht->state != 'Z';
        const std::uint64_t res_guest = peer.resident && can_answer ? peer.resident() : 0;
        const std::uint64_t host_rss = ht ? (res_guest ? std::min(res_guest, ht->rss) : ht->rss) : 0;
        const std::uint64_t rss = std::min(host_rss, vs ? vs : host_rss);
        const std::uint64_t nth = self ? std::max<std::size_t>(1, self->proc.thread_count())
                                : peer.threads ? peer.threads : 1;
        return {vs, rss, nth};
    };
    if (leaf == "stat") {
        // after "pid (comm) ": state ppid pgrp session tty tpgid flags minflt
        // cminflt majflt cmajflt utime stime cutime cstime prio nice nthreads
        // itreal starttime vsize rss rsslim ... (procfs keeps its own ids)
        if (!ht) return std::nullopt;
        const auto [vs, rss, nth] = sizes();
        const int nv = nice.value_or(ht->nice);
        char b[512];
        std::snprintf(b, sizeof b,
            "0 (x) %c 0 0 0 0 -1 4194304 %llu 0 %llu 0 %llu %llu 0 0 %d %d %llu 0 %llu %llu %llu "
            "18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            ht->state, static_cast<unsigned long long>(ht->minflt), static_cast<unsigned long long>(ht->majflt),
            static_cast<unsigned long long>(ht->utime), static_cast<unsigned long long>(ht->stime),
            20 + nv, nv, static_cast<unsigned long long>(nth),
            static_cast<unsigned long long>(ht->start_ticks), static_cast<unsigned long long>(vs),
            static_cast<unsigned long long>(rss / 4096));
        return std::string{b};
    }
    if (leaf == "statm") {
        if (!ht) return std::nullopt;
        const auto [vs, rss, nth] = sizes();
        const std::uint64_t res = rss / 4096;
        const std::uint64_t size = vs / 4096;
        char b[128];
        std::snprintf(b, sizeof b, "%llu %llu 0 0 0 %llu 0\n", static_cast<unsigned long long>(size),
                      static_cast<unsigned long long>(res), static_cast<unsigned long long>(res));
        return std::string{b};
    }
    if (leaf == "status") {
        if (!ht) return std::nullopt;
        std::string s;
        auto kb = [&](const char* k, std::uint64_t bytes) {
            s += k; s += ":\t"; s += std::to_string(bytes / 1024); s += " kB\n";
        };
        const auto [vs, rss, nth] = sizes();
        kb("VmPeak", vs); kb("VmSize", vs);
        kb("VmLck", self ? self->proc.locked_bytes() : 0);
        kb("VmHWM", std::min(ht->peak_rss, vs ? vs : ht->peak_rss)); kb("VmRSS", rss);
        kb("RssAnon", rss); kb("RssFile", 0); kb("RssShmem", 0);
        s += "Threads:\t" + std::to_string(nth) + "\n";
        if (self) {
            std::uint64_t ign = 0, cgt = 0;
            self->proc.with_signals([&](SignalDispositions& d) {
                for (int sg = 1; sg <= 64; ++sg) {
                    const auto a = d.get(sg);
                    if (a.handler == 1) ign |= sigbit(sg);
                    else if (a.handler > 1) cgt |= sigbit(sg);
                }
                return 0;
            });
            s += "SigQ:\t0/63432\n";
            s += "SigPnd:\t" + hex16(0) + "\n";
            s += "ShdPnd:\t" + hex16(g_pending.bits.load(std::memory_order_relaxed)) + "\n";
            s += "SigBlk:\t" + hex16(self->proc.leader_sigmask.load(std::memory_order_relaxed)) + "\n";
            s += "SigIgn:\t" + hex16(ign) + "\n";
            s += "SigCgt:\t" + hex16(cgt) + "\n";
        }
        s += "voluntary_ctxt_switches:\t" + std::to_string(ht->vol_cs) + "\n";
        s += "nonvoluntary_ctxt_switches:\t" + std::to_string(ht->invol_cs) + "\n";
        return s;
    }
    if (!self) return std::nullopt;
    ProcessState& p = self->proc;
    if (leaf == "io") {
        auto n = [](const std::atomic<std::uint64_t>& a) { return std::to_string(a.load(std::memory_order_relaxed)); };
        return "rchar: " + n(p.rchar) + "\nwchar: " + n(p.wchar) + "\nsyscr: " + n(p.syscr) +
               "\nsyscw: " + n(p.syscw) + "\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n";
    }
    if (leaf == "environ") return p.environ();
    if (leaf == "auxv") return p.auxv();
    if (leaf == "cmdline") { auto c = p.cmdline(); if (c.empty()) return std::nullopt; return c; }
    if (leaf == "limits") {
        // fs/proc/base.c's proc_pid_limits, column for column
        static constexpr struct { const char* name; const char* unit; } kRows[16] = {
            {"Max cpu time", "seconds"}, {"Max file size", "bytes"}, {"Max data size", "bytes"},
            {"Max stack size", "bytes"}, {"Max core file size", "bytes"}, {"Max resident set", "bytes"},
            {"Max processes", "processes"}, {"Max open files", "files"}, {"Max locked memory", "bytes"},
            {"Max address space", "bytes"}, {"Max file locks", "locks"}, {"Max pending signals", "signals"},
            {"Max msgqueue size", "bytes"}, {"Max nice priority", ""}, {"Max realtime priority", ""},
            {"Max realtime timeout", "us"}};
        char b[128];
        std::snprintf(b, sizeof b, "%-25s %-20s %-20s %-10s\n", "Limit", "Soft Limit", "Hard Limit", "Units");
        std::string s = b;
        auto v = [](std::uint64_t x) {
            return x == ProcessState::kInf ? std::string{"unlimited"} : std::to_string(x);
        };
        for (int i = 0; i < 16; ++i) {
            const auto& r = p.rlimits[static_cast<std::size_t>(i)];
            std::snprintf(b, sizeof b, "%-25s %-20s %-20s %-10s\n", kRows[i].name,
                          v(r.cur).c_str(), v(r.max).c_str(), kRows[i].unit);
            s += b;
        }
        return s;
    }
    if (leaf == "maps") return maps(p);
    if (leaf == "smaps" || leaf == "smaps_rollup") {
        // Each mapping's line, then its page accounting. Residency per
        // mapping isn't tracked; Rss is the process total, attributed to
        // the rollup (what tools sum), and the per-range fields are the
        // range's size where Linux would show at most that.
        const std::string m = maps(p);
        auto field = [](std::string& s, const char* name, std::uint64_t kb) {
            char b[64];
            std::snprintf(b, sizeof b, "%-16s%8llu kB\n", name, static_cast<unsigned long long>(kb));
            s += b;
        };
        const std::uint64_t rss = ht ? sizes().rss / 1024 : 0;
        if (leaf == "smaps_rollup") {
            std::string s = "00400000-ffffffffff601000 ---p 00000000 00:00 0                  [rollup]\n";
            field(s, "Rss:", rss); field(s, "Pss:", rss); field(s, "Pss_Anon:", rss);
            for (const char* f : {"Shared_Clean:", "Shared_Dirty:", "Private_Clean:"}) field(s, f, 0);
            field(s, "Private_Dirty:", rss); field(s, "Referenced:", rss); field(s, "Anonymous:", rss);
            for (const char* f : {"LazyFree:", "AnonHugePages:", "Swap:", "SwapPss:", "Locked:"}) field(s, f, 0);
            return s;
        }
        std::string s;
        for (std::size_t at = 0; at < m.size();) {
            const std::size_t nl = std::min(m.find('\n', at), m.size());
            const std::string line = m.substr(at, nl - at);
            at = nl + 1;
            unsigned long long lo = 0, hi = 0;
            if (std::sscanf(line.c_str(), "%llx-%llx", &lo, &hi) != 2) continue;
            s += line + "\n";
            const std::uint64_t kb = (hi - lo) / 1024;
            field(s, "Size:", kb);
            field(s, "KernelPageSize:", 4);
            field(s, "MMUPageSize:", 4);
            for (const char* f : {"Rss:", "Pss:", "Shared_Clean:", "Shared_Dirty:", "Private_Clean:",
                                  "Private_Dirty:", "Referenced:", "Anonymous:", "LazyFree:",
                                  "AnonHugePages:", "Swap:", "SwapPss:", "Locked:"})
                field(s, f, 0);
            s += "VmFlags: rd wr mr mw me ac\n";
        }
        return s;
    }
    if (leaf == "task") {
        // The leader is always a member while the process lives (Linux keeps
        // a dead leader's entry as a zombie until the group exits). The
        // thread table can lack it briefly: a sibling thread's exit runs
        // under the same lock that a leader's (re)registration takes.
        std::string s = std::to_string(self->pid) + "\n";
        for (const auto t : p.thread_ids())
            if (t != self->pid) s += std::to_string(t) + "\n";
        return s;
    }
    if (leaf == "fd") {
        return p.with_fds([](const FdTable& t) {
            std::string s;
            for (int g = 0; g < FdTable::kMaxFds; ++g)
                if (t.host(g)) s += std::to_string(g) + "\n";
            return s;
        });
    }
    if (leaf.starts_with("fdinfo/")) {
        int g = -1;
        if (std::sscanf(std::string{leaf.substr(7)}.c_str(), "%d", &g) != 1) return std::nullopt;
        const auto [h, cx] = p.with_fds([g](const FdTable& t) {
            return std::pair{t.host(g).value_or(-1), t.cloexec(g)};
        });
        if (h < 0) return std::nullopt;
        const off_t pos = ::lseek(h, 0, SEEK_CUR);
        const int fl = ::fcntl(h, F_GETFL);
        struct ::stat st{};
        (void)::fstat(h, &st);
        std::uint64_t lf = fl < 0 ? 0 : static_cast<std::uint64_t>(darwin::open_flags_to_linux(fl));
        if (cx) lf |= 02000000;                                   // O_CLOEXEC
        if (fl >= 0 && (fl & O_NONBLOCK) == 0) lf &= ~std::uint64_t{04000};
        char b[160];
        std::snprintf(b, sizeof b, "pos:\t%lld\nflags:\t0%llo\nmnt_id:\t1\nino:\t%llu\n",
                      static_cast<long long>(pos < 0 ? 0 : pos), static_cast<unsigned long long>(lf),
                      static_cast<unsigned long long>(st.st_ino));
        return std::string{b};
    }
    return std::nullopt;
}

} // namespace lx::runtime::procinfo

#endif // __APPLE__ && __aarch64__
