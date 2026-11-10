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

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#if !defined(_WIN32)
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

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

namespace detail {
// The kernel's auxv for host task `h`, with the entries a debugger uses
// (AT_PHDR, AT_PHNUM, AT_ENTRY, AT_BASE) put back the way a direct exec
// sets them when linuxity started the program as `ld.so prog`: then the
// kernel's copy describes the loader, and AT_BASE is 0.
inline std::string fixed_auxv(int h) {
    std::string raw;
#if !defined(_WIN32)
    if (std::FILE* f = std::fopen(("/proc/" + std::to_string(h) + "/auxv").c_str(), "re")) {
        char buf[1024];
        for (std::size_t n; (n = std::fread(buf, 1, sizeof buf, f)) > 0;) raw.append(buf, n);
        std::fclose(f);
    }
    if (raw.size() % 16) return raw;
    auto get = [&](std::uint64_t key) -> std::uint64_t {
        for (std::size_t i = 0; i + 16 <= raw.size(); i += 16) {
            std::uint64_t k, v;
            std::memcpy(&k, raw.data() + i, 8);
            std::memcpy(&v, raw.data() + i + 8, 8);
            if (k == key) return v;
        }
        return 0;
    };
    auto set = [&](std::uint64_t key, std::uint64_t val) {
        for (std::size_t i = 0; i + 16 <= raw.size(); i += 16) {
            std::uint64_t k;
            std::memcpy(&k, raw.data() + i, 8);
            if (k == key) { std::memcpy(raw.data() + i + 8, &val, 8); return; }
        }
    };
    if (get(7 /*AT_BASE*/) != 0) return raw;   // a direct exec: already right
    // the program's file and lowest mapping (ld.so has mapped it by now)
    char exe[4096];
    const ::ssize_t n = ::readlink(("/proc/" + std::to_string(h) + "/exe").c_str(), exe, sizeof exe - 1);
    if (n <= 0) return raw;
    exe[n] = '\0';
    const std::string ldso = exe;   // the kernel ran the loader
    std::string prog;
    std::uint64_t prog_lo = 0, ld_lo = 0;
    if (std::FILE* m = std::fopen(("/proc/" + std::to_string(h) + "/maps").c_str(), "re")) {
        char line[4352];
        while (std::fgets(line, sizeof line, m)) {
            unsigned long lo, hi, off;
            char perms[8], path[4096] = {0};
            if (std::sscanf(line, "%lx-%lx %7s %lx %*s %*s %4095[^\n]", &lo, &hi, perms, &off, path) < 4) continue;
            std::string p = path;
            while (!p.empty() && p.front() == ' ') p.erase(0, 1);
            if (p.empty() || p[0] != '/' || off != 0) continue;
            if (p == ldso) { if (!ld_lo) ld_lo = lo; continue; }
            if (prog.empty() && !p.ends_with(".so") && p.find(".so.") == std::string::npos) {
                prog = p;
                prog_lo = lo;
            }
        }
        std::fclose(m);
    }
    if (prog.empty() || !prog_lo) return raw;   // not mapped yet
    // the program's ELF header: phoff, phnum, entry, and its first PT_LOAD
    std::FILE* f = std::fopen(prog.c_str(), "rb");
    if (!f) return raw;
    unsigned char eh[64];
    const bool got = std::fread(eh, 1, sizeof eh, f) == sizeof eh;
    std::uint64_t entry = 0, phoff = 0, first_vaddr = 0;
    std::uint16_t phnum = 0, etype = 0;
    if (got) {
        std::memcpy(&etype, eh + 16, 2);
        std::memcpy(&entry, eh + 24, 8);
        std::memcpy(&phoff, eh + 32, 8);
        std::memcpy(&phnum, eh + 56, 2);
        for (std::uint16_t i = 0; i < phnum; ++i) {
            unsigned char ph[56];
            if (std::fseek(f, static_cast<long>(phoff + 56u * i), SEEK_SET) != 0 ||
                std::fread(ph, 1, sizeof ph, f) != sizeof ph) break;
            std::uint32_t type;
            std::memcpy(&type, ph, 4);
            if (type == 1 /*PT_LOAD*/) { std::memcpy(&first_vaddr, ph + 16, 8); break; }
        }
    }
    std::fclose(f);
    if (!got) return raw;
    // a PIE (ET_DYN) is loaded at prog_lo - its first vaddr; a fixed one at 0
    const std::uint64_t bias = etype == 3 ? prog_lo - (first_vaddr & ~0xfffull) : 0;
    set(3 /*AT_PHDR*/, bias + first_vaddr + phoff);
    set(5 /*AT_PHNUM*/, phnum);
    set(9 /*AT_ENTRY*/, bias + entry);
    set(7 /*AT_BASE*/, ld_lo);
#else
    (void)h;
#endif
    return raw;
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
#if defined(_WIN32)
    (void)path;
    return std::nullopt;
#else
    if (::access(path, R_OK) != 0) return std::nullopt;
    kernel::VirtualFile vf;
    vf.redirect_host = path;
    return vf;
#endif
}

// The guest's mount table, as the host's mounts look through the directories
// the guest sees: its root and each --bind. For each view the deepest host
// mount holding the directory sits at the view's guest path (with the
// bind's subdir in the root field, as the kernel shows a bind mount), and
// every host mount below the directory appears at its guest path. The
// trees linuxity serves itself (/proc, /sys, /dev, /tmp) are left out, the
// caller lists its own. Paths are matched, not st_dev: a btrfs subvolume's
// st_dev is not its mount's.
struct GuestMount { std::string majmin, root, guest, opts, fstype, source; };
inline std::vector<GuestMount>
guest_mounts(const std::vector<std::pair<std::string, std::string>>& views) {
    std::vector<GuestMount> out;
#if !defined(_WIN32)
    struct Host { std::string majmin, root, mnt, opts, fstype, source; };
    std::vector<Host> host;
    const std::string mi = host_file("/proc/self/mountinfo");
    for (std::size_t at = 0; at < mi.size();) {
        std::size_t nl = mi.find('\n', at);
        if (nl == std::string::npos) nl = mi.size();
        const std::string line = mi.substr(at, nl - at);
        at = nl + 1;
        // id parent maj:min root mountpoint opts [optional...] - fstype source superopts
        char majmin[32] = {}, root[4096] = {}, mnt[4096] = {}, opts[512] = {};
        if (std::sscanf(line.c_str(), "%*s %*s %31s %4095s %4095s %511s",
                        majmin, root, mnt, opts) != 4)
            continue;
        const auto dash = line.find(" - ");
        if (dash == std::string::npos) continue;
        char fs[64] = {}, src[1024] = {};
        if (std::sscanf(line.c_str() + dash + 3, "%63s %1023s", fs, src) != 2) continue;
        host.push_back({majmin, root, mnt, opts, fs, src});
    }
    const auto under = [](std::string_view p, std::string_view dir) {
        return dir == "/" || p == dir ||
               (p.starts_with(dir) && p.size() > dir.size() && p[dir.size()] == '/');
    };
    const auto ours = [&](std::string_view g) {
        for (const std::string_view v : {"/proc", "/sys", "/dev", "/tmp"})
            if (under(g, v)) return true;
        return false;
    };
    for (const auto& [g, h] : views) {
        // the mount holding the view's directory
        const Host* base = nullptr;
        for (const Host& e : host)
            if (under(h, e.mnt) && (!base || e.mnt.size() >= base->mnt.size())) base = &e;
        if (base) {
            std::string sub = base->mnt == "/" ? (h == "/" ? "" : h)
                                                : h.substr(base->mnt.size());
            std::string root = base->root == "/" ? (sub.empty() ? "/" : sub)
                                                  : base->root + sub;
            out.push_back({base->majmin, std::move(root), g, base->opts, base->fstype,
                           base->source});
        }
        // mounts below it
        for (const Host& e : host) {
            if (e.mnt == h || !under(e.mnt, h)) continue;
            const std::string rel = e.mnt.substr(h == "/" ? 0 : h.size());
            const std::string gp = g == "/" ? rel : g + rel;
            if (ours(gp)) continue;
            out.push_back({e.majmin, e.root, gp, e.opts, e.fstype, e.source});
        }
    }
#endif
    return out;
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

// /proc/net/<rest> (rest may be empty): the host's network, which the guest
// shares. Socket tables are rewritten so the host uid running linuxity
// reads as the guest's root, like the rest of its identity.
// Android's /proc/net/wireless has only its header (the vendor driver skips
// wireless extensions), but `cmd wifi status` gives the shell user the link's
// RSSI. Build the kernel's line for wlan0 from it, as cfg80211 would: quality
// is rssi+110 clamped to 0..70. Cached two seconds; empty when not connected.
inline std::string android_wireless_line() {
    static std::string cache;
    static std::chrono::steady_clock::time_point at{};
    static const bool have = ::access("/system/bin/cmd", X_OK) == 0;
    if (!have) return {};
    const auto now = std::chrono::steady_clock::now();
    if (at.time_since_epoch().count() && now - at < std::chrono::seconds(2)) return cache;
    at = now;
    cache.clear();
    if (std::FILE* p = ::popen("/system/bin/cmd wifi status 2>/dev/null", "re")) {
        char line[2048];
        while (std::fgets(line, sizeof line, p))
            if (const char* r = std::strstr(line, "RSSI: "); r && std::strstr(line, "WifiInfo:")) {
                const int rssi = std::atoi(r + 6);
                if (rssi < 0 && rssi > -127) {
                    const int q = std::clamp(rssi, -110, -40) + 110;
                    char out[160];
                    std::snprintf(out, sizeof out, "%6s: %04x  %3d.  %4d.  %4d  %6d %6d %6d %6d %6d   %6d\n",
                                  "wlan0", 0, q, rssi, -256, 0, 0, 0, 0, 0, 0);
                    cache = out;
                }
            }
        ::pclose(p);
    }
    return cache;
}

inline std::optional<Result<kernel::VirtualFile>> net_view(std::string_view rest, int host_pid = 0) {
#if defined(_WIN32)
    (void)rest;
    (void)host_pid;
    return std::nullopt;
#else
    // a task in a real network namespace of its own reads that one
    const std::string base = host_pid > 0 ? "/proc/" + std::to_string(host_pid) + "/net" : "/proc/net";
    const std::string host = rest.empty() ? base : base + "/" + std::string{rest};
    if (rest.empty()) {
        DIR* d = ::opendir(host.c_str());
        if (!d) return std::nullopt;
        std::vector<kernel::VirtualDirent> e;
        while (const dirent* de = ::readdir(d))
            if (de->d_name[0] != '.') e.push_back({de->d_name, de->d_type == DT_DIR});
        ::closedir(d);
        return ok(detail::dir_file(std::move(e)));
    }
    static constexpr std::string_view kSockTables[] = {
        "tcp", "tcp6", "udp", "udp6", "raw", "raw6", "icmp", "icmp6", "udplite", "udplite6"};
    bool table = false;
    for (const auto t : kSockTables) table |= rest == t;
    if (!table) {
        if (rest == "wireless") {
            std::string h = host_file(host.c_str());
            // the header alone: no interface reports; ask Android's service
            if (std::count(h.begin(), h.end(), '\n') <= 2)
                if (const std::string l = android_wireless_line(); !l.empty())
                    return ok(detail::text_file(h + l));
        }
        if (auto vf = host_redirect(host.c_str())) return ok(std::move(*vf));
        return std::nullopt;
    }
    const std::string h = host_file(host.c_str());
    if (h.empty() && ::access(host.c_str(), R_OK) != 0) return std::nullopt;
    // the uid is the 8th field; keep its column width so the layout holds
    const std::string me = std::to_string(::getuid());
    std::string out;
    std::size_t at = 0;
    bool header = true;
    while (at < h.size()) {
        std::size_t nl = h.find('\n', at);
        if (nl == std::string::npos) nl = h.size();
        std::string line = h.substr(at, nl - at);
        at = nl + 1;
        if (!header) {
            std::size_t p = 0;
            for (int field = 0; field < 7 && p != std::string::npos; ++field) {
                p = line.find_first_not_of(' ', p);
                p = p == std::string::npos ? p : line.find(' ', p);
            }
            if (p != std::string::npos) {
                const std::size_t b = line.find_first_not_of(' ', p);
                const std::size_t e = b == std::string::npos ? b : line.find(' ', b);
                if (b != std::string::npos && line.compare(b, e - b, me) == 0) {
                    std::string repl = "0";
                    repl.insert(0, (e - b) - 1, ' ');
                    line.replace(b, e - b, repl);
                }
            }
        }
        header = false;
        out += line;
        out += '\n';
    }
    return ok(detail::text_file(std::move(out)));
#endif
}

// /proc/sysvipc/{msg,sem,shm}, byte for byte like ipc/{msg,sem,shm}.c: a
// header always, then one row per object in the reader's IPC namespace.
// ids go through the reader's user namespace, pids through its pid one.
inline std::string sysvipc_text(const kernel::ProcessTable& procs, std::string_view which) {
    const auto set = procs.ns_of(procs.reader());
    const auto ipc_ns = set[kernel::NsKind::ipc];
    const auto user_ns = set[kernel::NsKind::user];
    auto uid = [&](std::uint32_t v) { return user_ns ? procs.ns().to_ns(user_ns, v, false) : v; };
    auto gid = [&](std::uint32_t v) { return user_ns ? procs.ns().to_ns(user_ns, v, true) : v; };
    auto pid = [&](std::int32_t v) { return static_cast<unsigned>(v > 0 ? procs.view_pid(v) : 0); };
    const kernel::IpcSpace* sp = procs.ipc().find_space(ipc_ns);
    std::string s;
    char row[512];
    if (which == "msg") {
        s = "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n";
        if (sp)
            for (const auto& [id, q] : sp->msq) {
                std::snprintf(row, sizeof row,
                    "%10d %10d  %4o  %10lu %10lu %5u %5u %5u %5u %5u %5u %10llu %10llu %10llu\n",
                    q.perm.key, id, q.perm.mode & 0777, static_cast<unsigned long>(q.cbytes),
                    static_cast<unsigned long>(q.msgs.size()), pid(q.lspid), pid(q.lrpid),
                    uid(q.perm.uid), gid(q.perm.gid), uid(q.perm.cuid), gid(q.perm.cgid),
                    static_cast<unsigned long long>(q.stime), static_cast<unsigned long long>(q.rtime),
                    static_cast<unsigned long long>(q.ctime));
                s += row;
            }
    } else if (which == "sem") {
        s = "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n";
        if (sp)
            for (const auto& [id, m] : sp->sem) {
                std::snprintf(row, sizeof row, "%10d %10d  %4o %10u %5u %5u %5u %5u %10llu %10llu\n",
                    m.perm.key, id, m.perm.mode & 0777, static_cast<unsigned>(m.sems.size()),
                    uid(m.perm.uid), gid(m.perm.gid), uid(m.perm.cuid), gid(m.perm.cgid),
                    static_cast<unsigned long long>(m.otime), static_cast<unsigned long long>(m.ctime));
                s += row;
            }
    } else {
        s = "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n";
        if (sp)
            for (const auto& [id, g] : sp->shm) {
                // rss: the pages actually backing the segment's file
                unsigned long rss = 0;
#if !defined(_WIN32)
                struct ::stat st{};
                if (!g.file.empty() && ::stat(g.file.c_str(), &st) == 0)
                    rss = static_cast<unsigned long>(st.st_blocks) * 512;
#endif
                // the mode shows SHM_DEST/SHM_LOCKED like the kernel's
                std::snprintf(row, sizeof row,
                    "%10d %10d  %4o %21lu %5u %5u  %5lu %5u %5u %5u %5u %10llu %10llu %10llu %21lu %21lu\n",
                    g.perm.key, id, g.perm.mode & 07777, static_cast<unsigned long>(g.size),
                    pid(g.cpid), pid(g.lpid), static_cast<unsigned long>(g.nattch),
                    uid(g.perm.uid), gid(g.perm.gid), uid(g.perm.cuid), gid(g.perm.cgid),
                    static_cast<unsigned long long>(g.atime), static_cast<unsigned long long>(g.dtime),
                    static_cast<unsigned long long>(g.ctime), rss, 0ul);
                s += row;
            }
    }
    return s;
}

// The host's /proc/sysvipc file, re-printed with the kernel's formats after
// mapping its host pids to guest pids (0 when not one of ours) and the host
// uid running linuxity to the guest's root, through the reader's user ns.
inline std::string sysvipc_from_host(const kernel::ProcessTable& procs, const std::string& h,
                                     std::string_view which) {
    const auto set = procs.ns_of(procs.reader());
    const auto user_ns = set[kernel::NsKind::user];
#if defined(_WIN32)
    const unsigned long me = 0;
#else
    const unsigned long me = ::getuid(), mygid = ::getgid();
#endif
    auto id = [&](unsigned long v, bool gid) -> unsigned long {
#if !defined(_WIN32)
        if (v == (gid ? mygid : me)) v = 0;
#endif
        return user_ns ? procs.ns().to_ns(user_ns, static_cast<std::uint32_t>(v), gid) : v;
    };
    auto pid = [&](unsigned long host) -> unsigned long {
        const auto g = procs.guest_of(static_cast<int>(host));
        return g > 0 ? static_cast<unsigned long>(procs.view_pid(g)) : 0;
    };
    std::string out;
    std::size_t at = 0;
    bool first = true;
    char row[512];
    while (at < h.size()) {
        std::size_t nl = h.find('\n', at);
        if (nl == std::string::npos) nl = h.size();
        const std::string line = h.substr(at, nl - at);
        at = nl + 1;
        if (first) { out += line + "\n"; first = false; continue; }
        long long k = 0, i = 0;
        unsigned long long v[16]{};
        unsigned mode = 0;
        if (which == "msg" &&
            std::sscanf(line.c_str(), "%lld %lld %o %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                        &k, &i, &mode, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9], &v[10]) == 14) {
            std::snprintf(row, sizeof row, "%10lld %10lld  %4o  %10llu %10llu %5lu %5lu %5lu %5lu %5lu %5lu %10llu %10llu %10llu\n",
                          k, i, mode, v[0], v[1], pid(v[2]), pid(v[3]), id(v[4], false), id(v[5], true),
                          id(v[6], false), id(v[7], true), v[8], v[9], v[10]);
            out += row;
        } else if (which == "sem" &&
                   std::sscanf(line.c_str(), "%lld %lld %o %llu %llu %llu %llu %llu %llu %llu",
                               &k, &i, &mode, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6]) == 10) {
            std::snprintf(row, sizeof row, "%10lld %10lld  %4o %10llu %5lu %5lu %5lu %5lu %10llu %10llu\n",
                          k, i, mode, v[0], id(v[1], false), id(v[2], true), id(v[3], false), id(v[4], true),
                          v[5], v[6]);
            out += row;
        } else if (which == "shm" &&
                   std::sscanf(line.c_str(), "%lld %lld %o %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                               &k, &i, &mode, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9],
                               &v[10], &v[11], &v[12]) == 16) {
            std::snprintf(row, sizeof row,
                          "%10lld %10lld  %4o %21llu %5lu %5lu  %5llu %5lu %5lu %5lu %5lu %10llu %10llu %10llu %21llu %21llu\n",
                          k, i, mode, v[0], pid(v[1]), pid(v[2]), v[3], id(v[4], false), id(v[5], true),
                          id(v[6], false), id(v[7], true), v[8], v[9], v[10], v[11], v[12]);
            out += row;
        }
    }
    return out;
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

        // ---- /proc/sysvipc: the IPC objects the syscalls see ------------
        if (abs == "/proc/sysvipc")
            return ok(dir_file({{"msg",false},{"sem",false},{"shm",false}}));
        if (abs == "/proc/sysvipc/msg" || abs == "/proc/sysvipc/sem" || abs == "/proc/sysvipc/shm") {
            // where the host has SysV IPC the syscalls go to it, so this does
            // too, with its host pids and uids shown as the guest's. A guest's
            // own IPC namespace is linuxity's.
            const bool own_ipc_ns = procs.ns_of(procs.reader())[kernel::NsKind::ipc] != 0;
            if (procs.ipc().host_backed() && !own_ipc_ns)
                if (std::string h = host_file(std::string{abs}.c_str()); !h.empty())
                    return ok(text_file(sysvipc_from_host(procs, h, abs.substr(14))));
            return ok(text_file(sysvipc_text(procs, abs.substr(14))));
        }

        // ---- /proc/net: the host's network, which the guest shares ------
        if (abs == "/proc/net" || abs.starts_with("/proc/net/"))
            if (auto r = net_view(abs.size() > 10 ? abs.substr(10) : std::string_view{},
                                  procs.net_isolated(procs.reader()) ? procs.host_of(procs.reader()) : 0))
                return std::move(*r);

        // ---- /proc/self -> /proc/<pid 1> canonicalization ---------------
        std::string p{abs};
        // Our "self" is always pid 1 (the traced root / init).
        if (p == "/proc/self" || p.starts_with("/proc/self/"))
            p = "/proc/" + std::to_string(procs.init_pid()) +
                p.substr(std::string_view{"/proc/self"}.size());

        // ---- --host-pids: a host process that isn't ours is the host's own
        //      /proc entry, read-only as the kernel lets us read it
        if (procs.host_pids() && procs.reader_pid_ns() == 0) {
            const auto [hp, rest] = detail::split_pid(p);
            if (hp > 0 && !procs.has(static_cast<std::int32_t>(hp)) &&
                !procs.thread_group_of(static_cast<std::int32_t>(hp))) {
                const std::string h = "/proc/" + std::to_string(hp);
                if (::access(h.c_str(), F_OK) != 0) return err<kernel::VirtualFile>(Errno::enoent);
                kernel::VirtualFile vf;
                vf.redirect_host = std::string{p};
                return ok(std::move(vf));
            }
        }

        // ---- /proc root: enumerate every pid + the well-known files -----
        if (abs == "/proc") {
            std::vector<kernel::VirtualDirent> e;
            // only the pids the reader's pid namespace can see, by its numbers
            for (std::int32_t pid : procs.pids())
                if (const auto v = procs.view_pid(pid); v > 0)
                    if (!procs.host_pids() || pid == procs.init_pid() ||
                        ::access(("/proc/" + std::to_string(pid)).c_str(), F_OK) == 0)
                        e.push_back({std::to_string(v), true});
            if (procs.host_pids() && procs.reader_pid_ns() == 0)
                if (DIR* d = ::opendir("/proc")) {
                    while (const dirent* de = ::readdir(d)) {
                        char* end = nullptr;
                        const long v = std::strtol(de->d_name, &end, 10);
                        if (v > 0 && *end == '\0' && !procs.has(static_cast<std::int32_t>(v)))
                            e.push_back({de->d_name, true});
                    }
                    ::closedir(d);
                }
            for (const char* f : {"stat","meminfo","vmstat","cpuinfo","uptime","loadavg",
                                  "version","cmdline","filesystems","mounts",
                                  "interrupts","softirqs","swaps","partitions",
                                  "diskstats","devices","modules","misc",
                                  "kallsyms","kmsg","self","sys","net","sysvipc"})
                e.push_back({f, std::string_view{f} == "sys" || std::string_view{f} == "net" ||
                                std::string_view{f} == "sysvipc"});
            for (const char* d : {"pressure", "driver"})
                if ((mach.host_hw || d[0] == 'p') &&
                    ::access((std::string{"/proc/"} + d).c_str(), F_OK) == 0)
                    e.push_back({d, true});
            return ok(dir_file(std::move(e)));
        }
        // PSI: the host's own files. A file the host lists but hides (Android
        // shows io and refuses cpu and memory) still redirects, so the open
        // fails with the host's EACCES rather than a made-up ENOENT.
        if (abs == "/proc/pressure" || abs.starts_with("/proc/pressure/")) {
            std::vector<kernel::VirtualDirent> e;
            bool listed = false;
            if (DIR* d = ::opendir("/proc/pressure")) {
                listed = true;
                while (const dirent* de = ::readdir(d))
                    if (de->d_name[0] != '.') e.push_back({de->d_name, false});
                ::closedir(d);
            }
            if (!listed) return err<kernel::VirtualFile>(Errno::enoent);
            if (abs == "/proc/pressure") return ok(dir_file(std::move(e)));
            const std::string_view leaf = abs.substr(15);
            for (const auto& x : e)
                if (x.name == leaf) {
                    kernel::VirtualFile vf;
                    vf.redirect_host = std::string{abs};
                    return ok(std::move(vf));
                }
            return err<kernel::VirtualFile>(Errno::enoent);
        }

        // ---- system-wide files ------------------------------------------
        if (abs == "/proc/version")
            return ok(text_file("Linux version " + release + " (linuxity@" +
                                nodename + ") (linuxity portable Linux ABI) #1\n"));
        if (abs == "/proc/cmdline")
            return ok(text_file("BOOT_IMAGE=/boot/linuxity root=linuxity ro\n"));
        if (abs == "/proc/cpuinfo") {
            // The real CPU when the guest sees all of it; a --cpus limit needs
            // the synthesized file so the processor count agrees.
            if (mach.host_hw && ncpu == ::sysconf(_SC_NPROCESSORS_ONLN))
                if (auto vf = host_redirect("/proc/cpuinfo")) return ok(std::move(*vf));
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
        // The guest's memory is the host's: its live accounting, every field.
        if (abs == "/proc/meminfo" || abs == "/proc/vmstat" || abs == "/proc/zoneinfo" ||
            abs == "/proc/buddyinfo" || abs == "/proc/pagetypeinfo")
            if (auto vf = host_redirect(std::string{abs}.c_str())) return ok(std::move(*vf));
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
                              "/proc/kallsyms"})
            if (abs == f)
                if (auto vf = host_redirect(f)) return ok(std::move(*vf));
        // the host hides its symbols: no symbols, like kptr_restrict on a
        // locked-down kernel, but the file is there
        if (abs == "/proc/kallsyms") return ok(text_file(""));
        // the guest's own log (syscall.hpp serves the opens); stat shows the
        // host's node when it has one
        if (abs == "/proc/kmsg") {
#if !defined(_WIN32)
            struct ::stat kst{};
            if (::stat("/proc/kmsg", &kst) == 0) {
                kernel::VirtualFile vf;
                vf.redirect_host = "/proc/kmsg";
                return ok(std::move(vf));
            }
#endif
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
        if (mach.host_hw) {
            for (const char* f : {"/proc/swaps", "/proc/partitions", "/proc/diskstats",
                                  "/proc/devices", "/proc/misc", "/proc/filesystems"})
                if (abs == f)
                    if (auto vf = host_redirect(f)) return ok(std::move(*vf));
            // GPU drivers publish here (nvidia-smi reads /proc/driver/nvidia)
            if (abs == "/proc/driver" || abs.starts_with("/proc/driver/"))
                if (auto vf = host_redirect(std::string{abs}.c_str())) return ok(std::move(*vf));
        }
        if (abs == "/proc/swaps") {
            // The host hid its table (Android) but meminfo says swap exists:
            // one zram line that agrees with meminfo, which is what Android
            // swaps to, so tools reading this file don't call swap disabled.
            std::string s = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
            const auto total = kernel::MachineSpec::host_meminfo_kb("SwapTotal:");
            const auto freek = kernel::MachineSpec::host_meminfo_kb("SwapFree:");
            if (mach.host_hw && total && *total) {
                const auto used = *total - std::min(*total, freek.value_or(*total));
                char line[160];
                std::snprintf(line, sizeof line, "%-40s%-16s%-16llu%-16llu%d\n", "/dev/block/zram0",
                              "partition", static_cast<unsigned long long>(*total),
                              static_cast<unsigned long long>(used), -2);
                s += line;
            }
            return ok(text_file(std::move(s)));
        }
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
            std::vector<std::pair<std::string, std::string>> views{{"/", mach.root_host}};
            for (const auto& b : mach.binds) views.push_back(b);
            const auto gm = mach.host_hw ? guest_mounts(views) : std::vector<GuestMount>{};
            if (!gm.empty() && gm.front().guest == "/") {
                // the root first, then ours, then the rest in host order
                struct V { const char* mnt; const char* fs; const char* opts; };
                static constexpr V kOurs[] = {
                    {"/proc", "proc", "rw,nosuid,nodev,noexec"},
                    {"/sys", "sysfs", "rw,nosuid,nodev,noexec"},
                    {"/dev", "devtmpfs", "rw,nosuid"},
                    {"/tmp", "tmpfs", "rw,nosuid,nodev"}};
                std::string s;
                int id = 21, minor = 2;
                auto add = [&](const std::string& majmin, const std::string& root,
                               const std::string& mnt, const std::string& opts,
                               const std::string& fs, const std::string& src) {
                    if (mountinfo)
                        s += std::to_string(id) + " " + (id == 21 ? "1" : "21") + " " + majmin +
                             " " + root + " " + mnt + " " + opts + " - " + fs + " " + src +
                             " " + opts + "\n";
                    else
                        s += src + " " + mnt + " " + fs + " " + opts + " 0 0\n";
                    ++id;
                };
                const GuestMount& r = gm.front();
                add(r.majmin, r.root, r.guest, r.opts, r.fstype, r.source);
                for (const V& v : kOurs)
                    add("0:" + std::to_string(minor++), "/", v.mnt, v.opts, v.fs, v.fs);
                for (std::size_t i = 1; i < gm.size(); ++i)
                    add(gm[i].majmin, gm[i].root, gm[i].guest, gm[i].opts, gm[i].fstype,
                        gm[i].source);
                return ok(text_file(std::move(s)));
            }
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
                {"/proc/sys/kernel/perf_event_paranoid", "2", true},
                {"/proc/sys/kernel/perf_event_max_sample_rate", "100000", true},
                {"/proc/sys/kernel/kptr_restrict", "1", true},
                // the guest's own ring buffer (/dev/kmsg) is readable by root
                {"/proc/sys/kernel/dmesg_restrict", "0", false},
                {"/proc/sys/kernel/printk", "4\t4\t1\t7", true},
                {"/proc/sys/kernel/panic", "0", true},
                {"/proc/sys/kernel/pid_max", "4194304", true},
                {"/proc/sys/kernel/sched_autogroup_enabled", "1", true},
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
        if (abs == "/proc/sys/kernel/hostname" || abs == "/proc/sys/kernel/domainname") {
            // the reader's UTS namespace; the initial one is the machine
            const auto uid = procs.ns_of(procs.reader())[kernel::NsKind::uts];
            const auto& names = procs.ns().uts(uid);
            const bool dom = abs.ends_with("domainname");
            const std::string v = uid ? (dom ? names.second : names.first)
                                      : (dom ? std::string{"(none)"} : nodename);
            return ok(text_file(v + "\n"));
        }
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
            // the number in the path is the reader's (its pid namespace's)
            if (const auto pns = procs.reader_pid_ns(); pns) {
                const auto g = procs.pid_from(pns, static_cast<std::int32_t>(pid));
                if (g <= 0) return err<kernel::VirtualFile>(Errno::enoent);
                pid = g;
            }
            const kernel::ProcInfo* pi = procs.find(static_cast<std::int32_t>(pid));
            std::int32_t self_tid = static_cast<std::int32_t>(pid);   // names the thread
            // /proc/<tid> of a non-main thread is unlisted but resolves, like Linux
            if (!pi)
                if (const auto tg = procs.thread_group_of(self_tid)) pi = procs.find(tg);
            if (!pi) return err<kernel::VirtualFile>(Errno::enoent);
            // With host pids the guest and host share numbers, and a reaped
            // task's record can outlive the waitpid that reaped it by a beat.
            // The host is the truth: no host task, no entry. Kernel threads
            // and zombies the host still shows are its answer too.
            if (procs.host_pids() && self_tid != procs.init_pid() &&
                ::access(("/proc/" + std::to_string(self_tid)).c_str(), F_OK) != 0)
                return err<kernel::VirtualFile>(Errno::enoent);
            const auto& I = *pi;

            if (tail.empty())     // the /proc/<pid> directory itself
                return ok(dir_file({
                    {"stat",false},{"statm",false},{"status",false},
                    {"cmdline",false},{"comm",false},{"cwd",true},
                    {"exe",false},{"root",true},{"fd",true},{"maps",false},
                    {"io",false},{"oom_score",false},{"task",true},
                    {"environ",false},{"fdinfo",true},{"mountinfo",false},
                    {"mounts",false},{"limits",false},{"ns",true},{"net",true},
                    {"smaps",false},{"smaps_rollup",false},{"oom_score_adj",false},
                    {"oom_adj",false},{"wchan",false},{"sched",false},{"schedstat",false},
                    {"cgroup",false},{"children",false},{"autogroup",false},
                    {"personality",false},{"timerslack_ns",false},{"coredump_filter",false},
                    {"loginuid",false},{"sessionid",false},{"syscall",false},{"stack",false},
                    {"uid_map",false},{"gid_map",false},{"setgroups",false},
                    {"mem",false},{"auxv",false},
                }));
            // the process's network namespace
            if (tail == "net" || tail.starts_with("net/"))
                if (auto r = net_view(tail.size() > 4 ? std::string_view{tail}.substr(4) : std::string_view{},
                                      procs.net_isolated(self_tid) ? procs.host_of(self_tid) : 0))
                    return std::move(*r);
            // ---- namespaces: the process's own (syscall.hpp sends a process
            // still in all the initial ones to the host's real links) ------
            if (tail == "ns" || tail.starts_with("ns/")) {
                const auto& reg = procs.ns();
                const auto& s = I.ns;
                auto id_of = [&](std::string_view n) -> std::uint64_t {
                    const auto leaf = kernel::parse_ns_leaf(n);
                    if (!leaf) return 0;
                    const auto kd = leaf->kind;
                    if (!leaf->for_children) return reg.resolve(s, kd);
                    const auto c = kd == kernel::NsKind::pid ? s.pid_for_children
                                 : kd == kernel::NsKind::time ? s.time_for_children : 0;
                    return c ? c : reg.resolve(s, kd);
                };
                if (tail == "ns") {
                    std::vector<kernel::VirtualDirent> e;
                    for (const auto n : kernel::kNsName) e.push_back({std::string{n}, false});
                    e.push_back({"pid_for_children", false});
                    e.push_back({"time_for_children", false});
                    return ok(dir_file(std::move(e)));
                }
                std::string n = tail.substr(3);
                const auto id = id_of(n);
                if (!id) return err<kernel::VirtualFile>(Errno::enoent);
                if (n.ends_with("_for_children")) n.resize(n.size() - 13);
                kernel::VirtualFile vf;
                vf.symlink_target = n + ":[" + std::to_string(id) + "]";
                return ok(std::move(vf));
            }
            if (tail == "uid_map" || tail == "gid_map") {
                const auto un = I.ns[kernel::NsKind::user];
                return ok(text_file(procs.ns().map_text(un, tail == "gid_map")));
            }
            if (tail == "setgroups") {
                const auto un = I.ns[kernel::NsKind::user];
                const auto* u = procs.ns().user_ns(un);
                return ok(text_file(!u || u->setgroups_allowed ? "allow\n" : "deny\n"));
            }

            // ---- /proc/<pid>/task : the thread group -------------------
            // htop/top enumerate processes THROUGH this directory. Each
            // thread's files mirror the process's own.
            if (tail == "task") {
                std::vector<kernel::VirtualDirent> ents{{std::to_string(procs.view_pid(I.pid)), true}};
                for (auto t : I.threads)
                    if (const auto v = procs.view_pid(t); v > 0)
                        if (!procs.host_pids() ||
                            ::access(("/proc/" + std::to_string(I.pid) + "/task/" +
                                      std::to_string(t)).c_str(), F_OK) == 0)
                            ents.push_back({std::to_string(v), true});
                return ok(dir_file(std::move(ents)));
            }
            if (tail.starts_with("task/")) {
                std::string_view rest = std::string_view{tail}.substr(5);
                std::size_t slash = rest.find('/');
                std::string_view tid = rest.substr(0, slash);
                // the reader's number for the thread -> its global tid
                std::int32_t global_tid = 0;
                if (tid == std::to_string(procs.view_pid(I.pid))) global_tid = I.pid;
                for (const auto t : I.threads)
                    if (tid == std::to_string(procs.view_pid(t))) global_tid = t;
                if (!global_tid)
                    return err<kernel::VirtualFile>(Errno::enoent);
                if (slash == std::string_view::npos)  // /proc/<pid>/task/<tid>
                    return ok(dir_file({
                        {"stat",false},{"statm",false},{"status",false},
                        {"cmdline",false},{"comm",false},{"maps",false},
                        {"io",false},{"children",false},
                    }));
                // Re-target the file lookup at the thread's own file, which
                // mirrors the process's but names the thread.
                self_tid = global_tid;
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
            // its real memory: the host task's file
            if (tail == "mem") {
                const int h = procs.host_of(self_tid);
                if (h <= 0) return err<kernel::VirtualFile>(Errno::enoent);
                kernel::VirtualFile vf;
                vf.redirect_host = "/proc/" + std::to_string(h) + "/" + tail;
                return ok(std::move(vf));
            }
            // auxv as a direct exec shows it, even when linuxity started the
            // program through its loader (debuggers find the program by it)
            if (tail == "auxv") {
                const int h = procs.host_of(self_tid);
                if (h <= 0) return err<kernel::VirtualFile>(Errno::enoent);
                return ok(text_file(detail::fixed_auxv(h)));
            }
            const char state = procs.tracer_of(self_tid).second ? 't' : host_state(procs, self_tid, I.state);
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
                s += std::to_string(procs.view_pid(self_tid));
                s += " (" + comm + ") ";
                s += state; s += ' ';
                s += std::to_string(procs.view_pid(I.ppid)) + " ";      // ppid
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
            // Per-task facts only the host kernel keeps (memory, oom, wait
            // channel, scheduler stats): the host task's own files, live, and
            // writable where the kernel allows (oom_score_adj).
            static constexpr std::string_view kHostLeaves[] = {
                "statm", "smaps", "smaps_rollup", "oom_score", "oom_score_adj",
                "oom_adj", "wchan", "schedstat", "autogroup", "personality",
                "timerslack_ns", "coredump_filter", "loginuid", "sessionid",
                "syscall", "stack"};
            if (host > 0)
                for (const auto l : kHostLeaves)
                    if (tail == l) {
                        std::string hp = "/proc/" + std::to_string(host) + "/" + std::string{l};
                        if (::access(hp.c_str(), F_OK) != 0) break;
                        kernel::VirtualFile vf;
                        vf.redirect_host = std::move(hp);
                        return ok(std::move(vf));
                    }
            // sched names the task by its host pid; show the guest's
            if (tail == "sched") {
                std::string s = host_file("sched");
                if (s.empty()) return err<kernel::VirtualFile>(Errno::enoent);
                const std::string hp = "(" + std::to_string(host) + ",";
                if (const auto at = s.find(hp); at != std::string::npos && at < s.find('\n'))
                    s.replace(0, at + hp.size(),
                              comm + " (" + std::to_string(procs.view_pid(self_tid)) + ",");
                return ok(text_file(std::move(s)));
            }
            // the guest's cgroup root, which /sys/fs/cgroup describes
            if (tail == "cgroup") return ok(text_file("0::/\n"));
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
                    case 't': s += " (tracing stop)\n"; break;
                    case 'T': s += " (stopped)\n"; break;
                    case 'Z': s += " (zombie)\n"; break;
                    case 'D': s += " (disk sleep)\n"; break;
                    default:  s += " (sleeping)\n"; break;
                }
                s += "Tgid:\t" + std::to_string(procs.view_pid(I.pid)) + "\n";
                s += "Pid:\t" + std::to_string(procs.view_pid(self_tid)) + "\n";
                s += "PPid:\t" + std::to_string(procs.view_pid(I.ppid)) + "\n";
                s += "TracerPid:\t" + std::to_string(procs.view_pid(procs.tracer_of(self_tid).first)) + "\n";
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
                // one number per pid namespace from the reader's down
                auto ns_chain = [&](std::int32_t g) {
                    std::string out = std::to_string(procs.view_pid(g));
                    const auto own = kernel::ProcessTable::pid_ns(I.ns);
                    if (own && own != procs.reader_pid_ns())
                        if (const auto l = procs.pid_in(own, g); l > 0) out += "\t" + std::to_string(l);
                    return out;
                };
                s += "NStgid:\t" + ns_chain(I.pid) + "\n";
                s += "NSpid:\t" + ns_chain(self_tid) + "\n";
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
            if (tail == "io") {
                if (std::string h = host_file("io"); !h.empty()) return ok(text_file(std::move(h)));
                return ok(text_file("rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\n"
                                    "read_bytes: 0\nwrite_bytes: 0\n"));
            }
            if (tail == "children") {
                std::string s;
                for (const std::int32_t c : procs.pids())
                    if (const auto* ci = procs.find(c); ci && ci->ppid == I.pid && ci->pid == c)
                        s += std::to_string(procs.view_pid(c)) + " ";
                return ok(text_file(std::move(s)));
            }
            if (tail == "oom_score") return ok(text_file("0\n"));
            if (tail == "maps")      return ok(text_file(""));
            if (tail == "fd") {
                // the host task's real fd numbers; links resolve through the
                // dispatcher (own fds) or the fd/N arm below (sockets, pipes)
                std::vector<kernel::VirtualDirent> e;
                if (host > 0)
                    if (DIR* d = ::opendir(("/proc/" + std::to_string(host) + "/fd").c_str())) {
                        while (const dirent* de = ::readdir(d))
                            if (de->d_name[0] != '.')
                                e.push_back({de->d_name, kernel::DType::symlink});
                        ::closedir(d);
                    }
                if (e.empty()) e = {{"0",false},{"1",false},{"2",false}};
                return ok(dir_file(std::move(e)));
            }
            if (tail.starts_with("fd/") && host > 0) {
                // A socket or pipe has no path; its link text is the host's.
                char tgt[256];
                const std::string l = "/proc/" + std::to_string(host) + "/" + tail;
                const ::ssize_t n = ::readlink(l.c_str(), tgt, sizeof tgt - 1);
                if (n > 0 && tgt[0] != '/') {
                    kernel::VirtualFile vf;
                    vf.symlink_target.assign(tgt, static_cast<std::size_t>(n));
                    return ok(std::move(vf));
                }
            }
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
