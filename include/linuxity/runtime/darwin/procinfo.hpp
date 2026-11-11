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
            std::snprintf(line, sizeof line, "%08llx-%08llx %c%c%c%c %08llx 00:00 0",
                          static_cast<unsigned long long>(at), static_cast<unsigned long long>(end),
                          has(GuestProt::read) ? 'r' : '-', has(GuestProt::write) ? 'w' : '-',
                          has(GuestProt::exec) ? 'x' : '-', 'p', 0ull);
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

// One fact, Linux-formatted, or nullopt for "not known here".
[[nodiscard]] inline std::optional<std::string>
fact(std::string_view leaf, pid_t host, const Self* self, std::optional<int> nice = std::nullopt) {
    const auto ht = host > 0 ? host_task(host) : std::nullopt;
    if (leaf == "stat") {
        // after "pid (comm) ": state ppid pgrp session tty tpgid flags minflt
        // cminflt majflt cmajflt utime stime cutime cstime prio nice nthreads
        // itreal starttime vsize rss rsslim ... (procfs keeps its own ids)
        if (!ht) return std::nullopt;
        const int nv = nice.value_or(ht->nice);
        const std::uint64_t vs = self ? guest_vsize(self->proc) : ht->rss;
        char b[512];
        std::snprintf(b, sizeof b,
            "0 (x) %c 0 0 0 0 -1 4194304 %llu 0 %llu 0 %llu %llu 0 0 %d %d %llu 0 %llu %llu %llu "
            "18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            ht->state, static_cast<unsigned long long>(ht->minflt), static_cast<unsigned long long>(ht->majflt),
            static_cast<unsigned long long>(ht->utime), static_cast<unsigned long long>(ht->stime),
            20 + nv, nv, static_cast<unsigned long long>(ht->threads),
            static_cast<unsigned long long>(ht->start_ticks), static_cast<unsigned long long>(vs),
            static_cast<unsigned long long>(ht->rss / 4096));
        return std::string{b};
    }
    if (leaf == "statm") {
        if (!ht) return std::nullopt;
        const std::uint64_t res = ht->rss / 4096;
        const std::uint64_t size = std::max(res, self ? guest_vsize(self->proc) / 4096 : res);
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
        const std::uint64_t vs = std::max(ht->rss, self ? guest_vsize(self->proc) : ht->rss);
        kb("VmPeak", vs); kb("VmSize", vs);
        kb("VmLck", self ? self->proc.locked_bytes() : 0);
        kb("VmHWM", ht->peak_rss); kb("VmRSS", ht->rss);
        kb("RssAnon", ht->rss); kb("RssFile", 0); kb("RssShmem", 0);
        s += "Threads:\t" + std::to_string(self ? std::max<std::size_t>(1, self->proc.thread_count())
                                                : ht->threads) + "\n";
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
    if (leaf == "maps") return maps(p);
    if (leaf == "task") {
        std::string s;
        for (const auto t : p.thread_ids()) s += std::to_string(t) + "\n";
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
