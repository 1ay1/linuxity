// linuxity/vfs/sysfs.hpp
//
// A synthesized /sys — linuxity's virtual view of the machine's hardware
// topology. Like procfs.hpp, every node is produced on demand from
// linuxity's own model of the world, NEVER the host's real sysfs. This is
// what lets a hardware monitor (btop / lm-sensors / lscpu) discover CPUs,
// temperatures, block devices and power state that belong to linuxity's
// virtual machine, not the box it happens to run on.
//
// The tree we synthesize (the subset real tools actually walk):
//
//   /sys/devices/system/cpu/            online, present, possible, N cpuN/
//     cpu/cpufreq/policyN/              scaling_cur/min/max_freq, cpuinfo_*
//     cpuN/topology/                    core_id, physical_package_id, *_siblings
//   /sys/devices/system/node/node0/     cpulist, meminfo
//   /sys/devices/virtual/hwmon/hwmon0/  name, tempN_input/label/max/crit
//   /sys/class/hwmon/hwmon0 -> ...      (symlink target flattened as a dir)
//   /sys/class/power_supply/            (empty: a server has no battery)
//   /sys/block/vda/                     stat, size, queue/, device/
//   /sys/class/net/lo/                  (loopback only)
//   /sys/fs/cgroup/                     cgroup2 stub
//
// Values are steady + plausible so tools render a coherent machine: one
// virtual socket with `Ncpu` cores, a single hwmon reporting a mild CPU temp,
// and one virtual block device.
//
// With MachineSpec::host_hw the host's own /sys is shown wherever the host
// lets us read it (sensors, battery, disks, GPU, network), and the tree above
// fills the gaps. The cpu, node, memory, cgroup and kernel subtrees stay ours
// so they agree with ncpu and the resource limits.
#pragma once

#include "linuxity/kernel/file_namespace.hpp"
#include "linuxity/kernel/machine.hpp"

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace lx::vfs {

namespace sysfs_detail {

using kernel::VirtualFile;
using kernel::VirtualDirent;
using kernel::DType;

inline VirtualFile text(std::string s) {
    VirtualFile vf;
    vf.bytes.resize(s.size());
    for (std::size_t i = 0; i < s.size(); ++i)
        vf.bytes[i] = static_cast<std::byte>(s[i]);
    return vf;
}
inline VirtualFile dir(std::vector<VirtualDirent> e) {
    VirtualFile vf; vf.is_dir = true; vf.entries = std::move(e); return vf;
}

// "cpu0" -> 0 ; returns -1 if `s` isn't "cpu"<digits>.
inline long index_after(std::string_view s, std::string_view prefix) {
    if (!s.starts_with(prefix)) return -1;
    s.remove_prefix(prefix.size());
    if (s.empty()) return -1;
    long n = 0;
    for (char c : s) { if (c < '0' || c > '9') return -1; n = n * 10 + (c - '0'); }
    return n;
}

// CPU caches. The host's /sys tree when it has one; an attribute it omits
// (Android exposes only level/type) comes from the core's published specs,
// keyed by the MIDR part number in /proc/cpuinfo.
struct CoreCache { unsigned l1d_kb, l1i_kb, l1_ways, l2_kb, l2_ways; };
inline CoreCache core_cache(long cpu) {
    unsigned part = 0;
    if (std::FILE* f = std::fopen("/proc/cpuinfo", "re")) {
        char line[256];
        long cur = -1;
        while (std::fgets(line, sizeof line, f)) {
            long n;
            unsigned p;
            if (std::sscanf(line, "processor : %ld", &n) == 1) cur = n;
            else if (cur == cpu && std::sscanf(line, "CPU part : %x", &p) == 1) { part = p; break; }
        }
        std::fclose(f);
    }
    switch (part) {
        case 0xd05: return {32, 32, 4, 128, 4};     // Cortex-A55
        case 0xd0b: return {64, 64, 4, 256, 8};     // Cortex-A76
        case 0xd0d: return {64, 64, 4, 512, 8};     // Cortex-A77
        case 0xd41: return {64, 64, 4, 512, 8};     // Cortex-A78
        case 0xd44: return {64, 64, 4, 1024, 8};    // Cortex-X1
        case 0xd46: return {64, 64, 4, 512, 8};     // Cortex-A510
        case 0xd47: return {64, 64, 4, 512, 8};     // Cortex-A710
        case 0xd48: return {64, 64, 4, 1024, 8};    // Cortex-X2
        case 0xd03: return {32, 32, 4, 512, 16};    // Cortex-A53
        default:    return {32, 32, 4, 512, 8};
    }
}
inline std::string read_text(const std::string& p) {
    std::string out;
    if (std::FILE* f = std::fopen(p.c_str(), "re")) {
        char buf[512];
        for (std::size_t n; (n = std::fread(buf, 1, sizeof buf, f)) > 0;) out.append(buf, n);
        std::fclose(f);
    }
    return out;
}
inline Result<VirtualFile> cpu_cache(long cpu, std::string_view rel, long ncpu) {
    while (!rel.empty() && rel.front() == '/') rel.remove_prefix(1);
    const std::string base = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/cache";
    const std::string hp = rel.empty() ? base : base + "/" + std::string{rel};
    static constexpr std::string_view kAttrs[] = {
        "coherency_line_size", "id", "level", "number_of_sets", "physical_line_partition",
        "shared_cpu_list", "shared_cpu_map", "size", "type", "uevent", "ways_of_associativity"};
    auto text = [](std::string s) { VirtualFile vf; vf.bytes.assign(reinterpret_cast<const std::byte*>(s.data()), reinterpret_cast<const std::byte*>(s.data() + s.size())); return vf; };
    auto dir_of = [](std::vector<VirtualDirent> e) { VirtualFile vf; vf.is_dir = true; vf.entries = std::move(e); return vf; };
    // the indexes the host has; on a host with no cache tree, L1d and L1i
    std::vector<std::string> idx;
    if (DIR* d = ::opendir(base.c_str())) {
        while (const dirent* de = ::readdir(d))
            if (std::string_view{de->d_name}.starts_with("index")) idx.emplace_back(de->d_name);
        ::closedir(d);
    }
    if (idx.empty()) idx = {"index0", "index1"};
    std::sort(idx.begin(), idx.end());
    if (rel.empty()) {
        std::vector<VirtualDirent> e;
        for (const auto& i : idx) e.push_back({i, true});
        e.push_back({"uevent", false});
        return ok(dir_of(std::move(e)));
    }
    if (rel == "uevent") return ok(text(""));
    const auto slash = rel.find('/');
    const std::string ix{rel.substr(0, slash)};
    if (std::find(idx.begin(), idx.end(), ix) == idx.end()) return err<VirtualFile>(Errno::enoent);
    if (slash == std::string_view::npos) {
        std::vector<VirtualDirent> e;
        for (const auto a : kAttrs) e.push_back({std::string{a}, false});
        return ok(dir_of(std::move(e)));
    }
    const std::string_view attr = rel.substr(slash + 1);
    if (std::find(std::begin(kAttrs), std::end(kAttrs), attr) == std::end(kAttrs))
        return err<VirtualFile>(Errno::enoent);
    // the host's value when it gives one
    if (::access(hp.c_str(), R_OK) == 0) {
        VirtualFile vf;
        vf.redirect_host = hp;
        return ok(std::move(vf));
    }
    // otherwise from the core's specs, for this index's level and type
    const std::string idir = base + "/" + ix;
    std::string type = read_text(idir + "/type");
    while (!type.empty() && type.back() == '\n') type.pop_back();
    long level = std::atol(read_text(idir + "/level").c_str());
    const long n = std::atol(ix.c_str() + 5);
    if (type.empty()) type = n == 0 ? "Data" : n == 1 ? "Instruction" : "Unified";
    if (level <= 0) level = n <= 1 ? 1 : n;
    const auto cc = core_cache(cpu);
    const unsigned kb = level == 1 ? (type == "Instruction" ? cc.l1i_kb : cc.l1d_kb) : cc.l2_kb;
    const unsigned ways = level == 1 ? cc.l1_ways : cc.l2_ways;
    const unsigned line = 64;
    const std::string me = std::to_string(cpu);
    if (attr == "level") return ok(text(std::to_string(level) + "\n"));
    if (attr == "type") return ok(text(type + "\n"));
    if (attr == "size") return ok(text(std::to_string(kb) + "K\n"));
    if (attr == "ways_of_associativity") return ok(text(std::to_string(ways) + "\n"));
    if (attr == "coherency_line_size") return ok(text(std::to_string(line) + "\n"));
    if (attr == "number_of_sets") return ok(text(std::to_string(kb * 1024 / (ways * line)) + "\n"));
    if (attr == "physical_line_partition") return ok(text("1\n"));
    if (attr == "id") return ok(text(me + "\n"));
    if (attr == "shared_cpu_list") return ok(text(me + "\n"));
    if (attr == "shared_cpu_map") {
        std::string out;
        for (long w = (ncpu + 31) / 32 - 1; w >= 0; --w) {
            unsigned v = 0;
            if (cpu / 32 == w) v = 1u << (cpu % 32);
            char buf[16];
            std::snprintf(buf, sizeof buf, "%08x", v);
            out += buf;
            if (w) out += ',';
        }
        return ok(text(out + "\n"));
    }
    return ok(text(""));
}

} // namespace sysfs_detail

namespace sysfs_detail {

// Can the guest use the host's node at this path? A directory must list and a
// file must open: Android shows /sys/class/thermal but SELinux refuses it, and
// then the synthesized node is the better answer.
inline bool host_node_ok(const std::string& p) {
    struct ::stat st{};
    if (::stat(p.c_str(), &st) != 0) return false;
    if (S_ISDIR(st.st_mode)) {
        // opening isn't enough: Android lets an app open /sys/class/net but
        // not list it, so read an entry to be sure the guest can too
        DIR* d = ::opendir(p.c_str());
        if (!d) return false;
        errno = 0;
        const bool listed = ::readdir(d) != nullptr || errno == 0;
        ::closedir(d);
        return listed && ::access(p.c_str(), R_OK | X_OK) == 0;
    }
    return ::access(p.c_str(), R_OK) == 0 || ::access(p.c_str(), W_OK) == 0;
}

// Add the host directory's entries to `e`, the host's winning on a clash.
inline void host_entries(const std::string& p, std::vector<VirtualDirent>& e) {
    DIR* d = ::opendir(p.c_str());
    if (!d) return;
    while (const dirent* de = ::readdir(d)) {
        const std::string_view n{de->d_name};
        if (n == "." || n == "..") continue;
        const DType t = de->d_type == DT_DIR ? DType::dir
                      : de->d_type == DT_LNK ? DType::symlink : DType::regular;
        std::erase_if(e, [&](const VirtualDirent& x) { return x.name == n; });
        e.push_back({std::string{n}, t});
    }
    ::closedir(d);
}

inline long read_long(const char* p) {
    std::FILE* f = std::fopen(p, "re");
    if (!f) return -1;
    long v = -1;
    if (std::fscanf(f, "%ld", &v) != 1) v = -1;
    std::fclose(f);
    return v;
}

// How busy the host's CPUs have been, smoothed over ~20 s (0..1).
inline double smoothed_load() {
    using clk = std::chrono::steady_clock;
    static std::mutex mu;
    static unsigned long long last_busy = 0, last_total = 0;
    static clk::time_point last_at{};
    static double ema = 0.0;
    std::lock_guard lk{mu};
    std::FILE* f = std::fopen("/proc/stat", "re");
    if (!f) return ema;
    unsigned long long v[8]{};
    const int n = std::fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                              &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]);
    std::fclose(f);
    if (n < 4) return ema;
    unsigned long long total = 0;
    for (const auto x : v) total += x;
    const unsigned long long busy = total - v[3] - v[4];   // minus idle and iowait
    const auto now = clk::now();
    if (last_total && total > last_total) {
        const double dt = std::chrono::duration<double>(now - last_at).count();
        const double util = static_cast<double>(busy - last_busy) / static_cast<double>(total - last_total);
        const double a = 1.0 - std::exp(-dt / 20.0);
        ema += a * (util - ema);
    }
    if (!last_total || std::chrono::duration<double>(now - last_at).count() > 0.25) {
        last_busy = busy; last_total = total; last_at = now;
    }
    return ema;
}

// CPU temperature in millidegrees C (see the producer for the sources).
inline long cpu_temp_mc() {
    if (const long t = read_long("/sys/class/thermal/thermal_zone0/temp"); t > 0) return t;
    if (const long b = read_long("/sys/class/power_supply/battery/temp"); b > 0)
        return b * 100 + static_cast<long>(smoothed_load() * 40000.0) + 3000;
    return 42000;
}

// Android hides /sys/class/thermal from apps and adb, but its thermal HAL
// answers `dumpsys thermalservice` for the shell user: every zone (skin, TPU,
// battery, modem...) and its throttling thresholds. Read it at most once a
// second; empty off Android or when the service refuses.
struct HalZone { std::string name; long mc; long hot_mc; };
inline std::vector<HalZone> android_zones() {
    static std::vector<HalZone> cache;
    static std::chrono::steady_clock::time_point at{};
    static const bool have = ::access("/system/bin/dumpsys", X_OK) == 0;
    if (!have) return {};
    const auto now = std::chrono::steady_clock::now();
    if (at.time_since_epoch().count() && now - at < std::chrono::seconds(1)) return cache;
    at = now;
    std::vector<HalZone> z;
    std::map<std::string, long> hot;
    if (std::FILE* p = ::popen("/system/bin/dumpsys thermalservice 2>/dev/null", "re")) {
        char line[512];
        bool cur = false;
        while (std::fgets(line, sizeof line, p)) {
            const std::string_view l{line};
            if (l.starts_with("Current temperatures from HAL")) { cur = true; continue; }
            if (cur && !l.starts_with("\t")) cur = false;
            char name[128] = {};
            double v = 0;
            if (cur && std::sscanf(line, " Temperature{mValue=%lf, mType=%*d, mName=%127[^,]", &v, name) == 2) {
                // a HAL reports an unwired sensor as a nonsense value
                if (v > -40 && v < 150 && v != 0.0)
                    z.push_back({name, static_cast<long>(v * 1000.0), 0});
                continue;
            }
            // first finite hot throttling threshold, the "high" mark
            if (std::sscanf(line, " TemperatureThreshold{mType=%*d, mName=%127[^,]", name) == 1) {
                const char* h = std::strstr(line, "mHotThrottlingThresholds=[");
                if (!h) continue;
                h += 26;
                while (*h && *h != ']') {
                    char* e = nullptr;
                    const double t = std::strtod(h, &e);
                    if (e == h) { while (*h && *h != ',' && *h != ']') ++h; }
                    else { if (t == t) { hot[name] = static_cast<long>(t * 1000.0); break; } h = e; }
                    if (*h == ',') ++h;
                    while (*h == ' ') ++h;
                }
            }
        }
        ::pclose(p);
    }
    for (auto& x : z)
        if (auto it = hot.find(x.name); it != hot.end()) x.hot_mc = it->second;
    cache = std::move(z);
    return cache;
}

} // namespace sysfs_detail

// Build a /sys producer describing linuxity's virtual machine. It reads the
// SAME MachineSpec (kernel/machine.hpp) as /proc and the syscalls, so the CPU
// count, topology and reported frequency can never disagree between /sys and
// /proc. One physical package, `ncpu` cores, no SMT.
[[nodiscard]] inline kernel::FileNamespace::Producer
make_sysfs(const kernel::MachineSpec& mach) {
    auto synth = [&mach](std::string_view abs) -> Result<kernel::VirtualFile> {
        using namespace sysfs_detail;
        const long ncpu = mach.ncpu < 1 ? 1 : mach.ncpu;
        const long khz  = mach.cpu_khz();

        auto D = [](std::initializer_list<VirtualDirent> e) {
            return ok(dir(std::vector<VirtualDirent>(e)));
        };
        auto T = [](std::string s) { return ok(text(std::move(s))); };

        // Helper: "0-3" style cpu range list for `ncpu`.
        std::string cpu_range = mach.cpu_range();
        // the host's cpufreq policy layout applies when the guest has every cpu
        auto host_policies = [&] {
            return mach.host_hw && ncpu == ::sysconf(_SC_NPROCESSORS_ONLN) &&
                   host_node_ok("/sys/devices/system/cpu/cpufreq");
        };

        // ================= /sys root =====================================
        if (abs == "/sys")
            return D({{"devices",true},{"class",true},{"block",true},
                     {"bus",true},{"fs",true},{"kernel",true},{"module",true},
                     {"firmware",true},{"dev",true},{"power",true}});

        // ================= /sys/devices ==================================
        if (abs == "/sys/devices")
            return D({{"system",true},{"virtual",true},{"platform",true}});
        if (abs == "/sys/devices/system")
            return D({{"cpu",true},{"node",true},{"memory",true},{"clocksource",true}});

        // ---- clocksource: the host's if it shows it, else the arch's own
        // names (the guest's clock IS the host's counter) -----------------
        if (abs == "/sys/devices/system/clocksource")
            return D({{"clocksource0",true}});
        if (abs == "/sys/devices/system/clocksource/clocksource0")
            return D({{"available_clocksource",false},{"current_clocksource",false},
                      {"unbind_clocksource",false},{"uevent",false}});
        if (abs == "/sys/devices/system/clocksource/clocksource0/current_clocksource" ||
            abs == "/sys/devices/system/clocksource/clocksource0/available_clocksource") {
            std::string h;
            if (std::FILE* f = std::fopen(std::string{abs}.c_str(), "re")) {
                char buf[256];
                if (std::fgets(buf, sizeof buf, f)) h = buf;
                std::fclose(f);
            }
            if (!h.empty()) return T(std::move(h));
            const bool arm = mach.machine_arch == "aarch64";
            const bool cur = abs.ends_with("current_clocksource");
            return T(arm ? "arch_sys_counter\n" : cur ? "tsc\n" : "tsc hpet acpi_pm \n");
        }
        if (abs == "/sys/devices/system/clocksource/clocksource0/unbind_clocksource" ||
            abs == "/sys/devices/system/clocksource/clocksource0/uevent")
            return T("");

        // ---- CPU topology -----------------------------------------------
        if (abs == "/sys/devices/system/cpu") {
            std::vector<VirtualDirent> e;
            for (long i = 0; i < ncpu; ++i)
                e.push_back({"cpu" + std::to_string(i), true});
            for (const char* f : {"online","present","possible","offline",
                                  "kernel_max","cpufreq"})
                e.push_back({f, std::string_view{f} == "cpufreq"});
            return ok(dir(std::move(e)));
        }
        if (abs == "/sys/devices/system/cpu/online" ||
            abs == "/sys/devices/system/cpu/present" ||
            abs == "/sys/devices/system/cpu/possible")
            return T(cpu_range + "\n");
        if (abs == "/sys/devices/system/cpu/offline")     return T("\n");
        if (abs == "/sys/devices/system/cpu/kernel_max")  return T(std::to_string(ncpu - 1) + "\n");

        // /sys/devices/system/cpu/cpufreq/policyN/*
        if (abs == "/sys/devices/system/cpu/cpufreq") {
            std::vector<VirtualDirent> e;
            // the host's policies (one per cluster on big.LITTLE) when the
            // guest has every cpu; fastfetch sums related_cpus over them
            if (host_policies())
                host_entries("/sys/devices/system/cpu/cpufreq", e);
            if (e.empty())
                for (long i = 0; i < ncpu; ++i)
                    e.push_back({"policy" + std::to_string(i), true});
            return ok(dir(std::move(e)));
        }
        // per-cpu dir: /sys/devices/system/cpu/cpuN and its subtree, plus
        // the cpufreq/policyN subtree (btop reads scaling_cur_freq there).
        {
            std::string_view rest = abs;
            const std::string base = "/sys/devices/system/cpu/";
            if (rest.starts_with(base)) {
                rest.remove_prefix(base.size());
                // Strip a leading "cpufreq/" so policyN resolves either as
                // .../cpu/cpufreq/policyN or (rarely) .../cpu/policyN.
                if (rest.starts_with("cpufreq/")) rest.remove_prefix(8);
                std::string_view head = rest.substr(0, rest.find('/'));
                std::string_view tail = rest.size() > head.size()
                                        ? rest.substr(head.size() + 1) : std::string_view{};
                long cpu = index_after(head, "cpu");
                long pol = index_after(head, "policy");
                // a policy the host doesn't have doesn't exist
                if (pol >= 0 && host_policies() &&
                    ::access(("/sys/devices/system/cpu/cpufreq/" + std::string{head}).c_str(),
                             F_OK) != 0)
                    return err<kernel::VirtualFile>(Errno::enoent);

                if (cpu >= 0 && cpu < ncpu) {
                    // Kernel cpumask format: comma-separated 32-bit hex words,
                    // most significant first. lscpu parses these and asserts
                    // on a malformed one ("print_cpuset: Assertion `set'").
                    auto mask = [&](auto&& in) {
                        std::string out;
                        const long words = (ncpu + 31) / 32;
                        for (long w = words - 1; w >= 0; --w) {
                            std::uint32_t v = 0;
                            for (long b = 0; b < 32; ++b)
                                if (in(w * 32 + b)) v |= 1u << b;
                            char buf[16];
                            std::snprintf(buf, sizeof buf, "%08x", v);
                            out += buf;
                            if (w) out += ',';
                        }
                        return out + "\n";
                    };
                    const auto self = [&](long c) { return c == cpu; };
                    const auto all  = [&](long c) { return c < ncpu; };
                    const std::string one = std::to_string(cpu) + "\n";
                    // ---- cache/indexN: the host's own cache description,
                    // with any attribute the host leaves out filled from the
                    // core's published L1/L2 sizes (sysfs_detail::core_cache)
                    if (tail == "cache" || tail.starts_with("cache/"))
                        return sysfs_detail::cpu_cache(cpu, tail.substr(5), ncpu);
                    if (tail.empty())
                        return D({{"topology",true},{"cache",true},
                                 {"cpufreq",true},{"online",false}});
                    if (tail == "online") return T("1\n");
                    // The real SMT and cluster layout, when the guest sees
                    // every host CPU (a --cpus limit keeps the flat one).
                    if (mach.host_hw && ncpu == ::sysconf(_SC_NPROCESSORS_ONLN) &&
                        tail.starts_with("topology")) {
                        const std::string hp = "/sys/devices/system/cpu/cpu" +
                                               std::to_string(cpu) + "/" + std::string{tail};
                        if (host_node_ok(hp)) {
                            if (tail == "topology") {
                                std::vector<VirtualDirent> e;
                                host_entries(hp, e);
                                return ok(dir(std::move(e)));
                            }
                            VirtualFile vf;
                            vf.redirect_host = hp;
                            return ok(std::move(vf));
                        }
                    }
                    if (tail == "topology")
                        return D({{"core_id",false},{"physical_package_id",false},
                                 {"cluster_id",false},{"die_id",false},
                                 {"core_cpus",false},{"core_cpus_list",false},
                                 {"thread_siblings",false},{"thread_siblings_list",false},
                                 {"core_siblings",false},{"core_siblings_list",false},
                                 {"package_cpus",false},{"package_cpus_list",false},
                                 {"cluster_cpus",false},{"cluster_cpus_list",false},
                                 {"die_cpus",false},{"die_cpus_list",false}});
                    if (tail == "topology/core_id")             return T(one);
                    if (tail == "topology/physical_package_id" ||
                        tail == "topology/cluster_id" || tail == "topology/die_id")
                        return T("0\n");
                    // One thread per core (Apple Silicon has no SMT).
                    if (tail == "topology/core_cpus_list" ||
                        tail == "topology/thread_siblings_list") return T(one);
                    if (tail == "topology/core_cpus" ||
                        tail == "topology/thread_siblings")      return T(mask(self));
                    if (tail == "topology/core_siblings_list" || tail == "topology/package_cpus_list" ||
                        tail == "topology/cluster_cpus_list"  || tail == "topology/die_cpus_list")
                        return T(cpu_range + "\n");
                    if (tail == "topology/core_siblings" || tail == "topology/package_cpus" ||
                        tail == "topology/cluster_cpus"  || tail == "topology/die_cpus")
                        return T(mask(all));
                    // cpuN/cpufreq is the same policy as cpufreq/policyN.
                    if (tail == "cpufreq" || tail.starts_with("cpufreq/")) {
                        pol = cpu;
                        tail = tail == "cpufreq" ? std::string_view{} : tail.substr(8);
                    }
                }
                if (pol >= 0 && pol < ncpu) {
                    // The guest runs on the host's cores, so their real,
                    // moving clock is the honest answer when it's readable.
                    const std::string hdir = "/sys/devices/system/cpu/cpu" + std::to_string(pol) + "/cpufreq";
                    if (tail.empty()) {
                        if (DIR* d = ::opendir(hdir.c_str())) {
                            std::vector<VirtualDirent> e;
                            while (const dirent* de = ::readdir(d))
                                if (de->d_name[0] != '.')
                                    e.push_back({de->d_name, de->d_type == DT_DIR});
                            ::closedir(d);
                            if (!e.empty()) return ok(dir(std::move(e)));
                        }
                    } else if (tail.find('/') == std::string_view::npos) {
                        std::string hp = hdir + "/" + std::string{tail};
                        // cpuinfo_cur_freq is root-only on most hosts; the
                        // scaling one is the same clock
                        if (tail == "cpuinfo_cur_freq" && ::access(hp.c_str(), R_OK) != 0)
                            hp = hdir + "/scaling_cur_freq";
                        if (::access(hp.c_str(), R_OK) == 0) {
                            VirtualFile vf;
                            vf.redirect_host = std::move(hp);
                            return ok(std::move(vf));
                        }
                    }
                    if (tail.empty())
                        return D({{"scaling_cur_freq",false},{"scaling_min_freq",false},
                                 {"scaling_max_freq",false},{"cpuinfo_cur_freq",false},
                                 {"cpuinfo_min_freq",false},{"cpuinfo_max_freq",false},
                                 {"scaling_governor",false},{"scaling_driver",false},
                                 {"affected_cpus",false},{"related_cpus",false}});
                    if (tail == "scaling_cur_freq" || tail == "cpuinfo_cur_freq")
                        return T(std::to_string(khz) + "\n");
                    if (tail == "scaling_max_freq" || tail == "cpuinfo_max_freq")
                        return T(std::to_string(khz) + "\n");
                    if (tail == "scaling_min_freq" || tail == "cpuinfo_min_freq")
                        return T(std::to_string(khz / 4) + "\n");
                    if (tail == "scaling_governor") return T("performance\n");
                    if (tail == "scaling_driver")   return T("linuxity-cpufreq\n");
                    if (tail == "affected_cpus")    return T(std::to_string(pol) + "\n");
                    if (tail == "related_cpus")     return T(std::to_string(pol) + "\n");
                }
            }
        }

        // ---- NUMA node 0 ------------------------------------------------
        if (abs == "/sys/devices/system/node")
            return D({{"node0",true},{"online",false},{"possible",false}});
        if (abs == "/sys/devices/system/node/online" ||
            abs == "/sys/devices/system/node/possible") return T("0\n");
        if (abs == "/sys/devices/system/node/node0")
            return D({{"cpulist",false},{"cpumap",false},{"meminfo",false},
                     {"distance",false}});
        if (abs == "/sys/devices/system/node/node0/cpulist") return T(cpu_range + "\n");
        if (abs == "/sys/devices/system/node/node0/cpumap") {
            // Hex cpumask (32-bit words, MSW first). lscpu reads it into the
            // NUMA map and asserts on NULL when it is missing.
            std::string out;
            const long words = (ncpu + 31) / 32;
            for (long w = words - 1; w >= 0; --w) {
                std::uint32_t v = 0;
                for (long b = 0; b < 32 && w * 32 + b < ncpu; ++b) v |= 1u << b;
                char buf[16];
                std::snprintf(buf, sizeof buf, "%08x", v);
                out += buf;
                if (w) out += ',';
            }
            return T(out + "\n");
        }
        if (abs == "/sys/devices/system/node/node0/distance") return T("10\n");
        if (abs == "/sys/devices/system/node/node0/meminfo")
            return T("Node 0 MemTotal:       " + std::to_string(mach.mem_total_kb()) + " kB\n"
                     "Node 0 MemFree:        " + std::to_string(mach.mem_free() >> 10) + " kB\n");

        // ---- memory block size (btop reads this for hotplug memory) ------
        if (abs == "/sys/devices/system/memory")
            return D({{"block_size_bytes",false}});
        if (abs == "/sys/devices/system/memory/block_size_bytes")
            return T("8000000\n");

        // ================= hwmon (temperatures) ==========================
        // One virtual hwmon exposing a CPU package temperature.
        if (abs == "/sys/devices/virtual")
            return D({{"hwmon",true},{"net",true}});
        // Android's thermal HAL (see android_zones): its real sensors as a
        // second hwmon, temps labelled by zone, so `sensors` and monitors show
        // skin, TPU, battery and modem temperatures. Only with host hardware.
        const auto hal = mach.host_hw ? sysfs_detail::android_zones()
                                      : std::vector<sysfs_detail::HalZone>{};
        auto hal_index = [&](std::string_view t, std::string_view pre, std::string_view post) -> long {
            if (!t.starts_with(pre) || !t.ends_with(post)) return -1;
            const std::string_view n = t.substr(pre.size(), t.size() - pre.size() - post.size());
            long i = 0;
            for (char c : n) { if (c < '0' || c > '9') return -1; i = i * 10 + (c - '0'); }
            return n.empty() || i < 1 || i > static_cast<long>(hal.size()) ? -1 : i - 1;
        };
        for (std::string_view base : {"/sys/devices/virtual/hwmon/hwmon1", "/sys/class/hwmon/hwmon1"}) {
            if (hal.empty() || !(abs == base || abs.starts_with(std::string{base} + "/"))) continue;
            if (abs == base) {
                std::vector<VirtualDirent> e{{"name", false}, {"uevent", false}};
                for (std::size_t i = 1; i <= hal.size(); ++i)
                    for (const char* s : {"_input", "_label", "_max"})
                        e.push_back({"temp" + std::to_string(i) + s, false});
                return ok(dir(std::move(e)));
            }
            const std::string_view t = abs.substr(base.size() + 1);
            if (t == "name")   return T("android_thermal\n");
            if (t == "uevent") return T("");
            if (const long i = hal_index(t, "temp", "_input"); i >= 0)
                return T(std::to_string(hal[static_cast<std::size_t>(i)].mc) + "\n");
            if (const long i = hal_index(t, "temp", "_label"); i >= 0)
                return T(hal[static_cast<std::size_t>(i)].name + "\n");
            if (const long i = hal_index(t, "temp", "_max"); i >= 0 &&
                hal[static_cast<std::size_t>(i)].hot_mc > 0)
                return T(std::to_string(hal[static_cast<std::size_t>(i)].hot_mc) + "\n");
            return err<kernel::VirtualFile>(Errno::enoent);
        }
        if (!hal.empty() && abs.starts_with("/sys/class/thermal/thermal_zone")) {
            const std::string_view t = abs.substr(31);
            const auto slash = t.find('/');
            if (const long i = hal_index(t.substr(0, slash), "", ""); i >= 0) {
                const auto& z = hal[static_cast<std::size_t>(i)];
                if (slash == std::string_view::npos)
                    return D({{"type", false}, {"temp", false}, {"mode", false}});
                const std::string_view leaf = t.substr(slash + 1);
                if (leaf == "type") return T(z.name + "\n");
                if (leaf == "temp") return T(std::to_string(z.mc) + "\n");
                if (leaf == "mode") return T("enabled\n");
                return err<kernel::VirtualFile>(Errno::enoent);
            }
        }
        if (abs == "/sys/devices/virtual/hwmon")
            return hal.empty() ? D({{"hwmon0",true}}) : D({{"hwmon0",true},{"hwmon1",true}});
        if (abs == "/sys/devices/virtual/hwmon/hwmon0" ||
            abs == "/sys/class/hwmon/hwmon0")
            return D({{"name",false},{"temp1_input",false},{"temp1_label",false},
                     {"temp1_max",false},{"temp1_crit",false},
                     {"temp2_input",false},{"temp2_label",false},
                     {"uevent",false}});
        // The host's temperature in millidegrees, read live: its CPU thermal
        // zone when it shows it. Android hides the zones from apps but not
        // the battery sensor, which trails the CPU by minutes, so there the
        // die is estimated from it plus how busy the cores really are,
        // smoothed like silicon heating and cooling. 42 C with neither.
        auto host_temp = [] { return sysfs_detail::cpu_temp_mc(); };
        auto temp_text = [&](long off) { return T(std::to_string(host_temp() + off) + "\n"); };
        {
            // Serve the leaf files under either the class-symlink flattening
            // or the real device path (btop opens whichever it resolved).
            auto hw_leaf = [&](std::string_view t) -> Result<kernel::VirtualFile> {
                if (t == "name")        return T("linuxity_cpu\n");
                if (t == "temp1_label") return T("Package id 0\n");
                if (t == "temp1_input") return temp_text(0);
                if (t == "temp1_max")   return T("95000\n");
                if (t == "temp1_crit")  return T("100000\n");
                if (t == "temp2_label") return T("Core 0\n");
                if (t == "temp2_input") return temp_text(-2000);
                if (t == "uevent")      return T("");
                return err<kernel::VirtualFile>(Errno::enoent);
            };
            for (std::string_view pfx : {"/sys/devices/virtual/hwmon/hwmon0/",
                                         "/sys/class/hwmon/hwmon0/"}) {
                if (abs.starts_with(pfx)) return hw_leaf(abs.substr(pfx.size()));
            }
        }

        // ================= /sys/class ====================================
        if (abs == "/sys/class")
            return D({{"hwmon",true},{"power_supply",true},{"net",true},
                     {"block",true},{"thermal",true},{"drm",true},
                     {"backlight",true}});
        if (abs == "/sys/class/hwmon")
            return hal.empty() ? D({{"hwmon0",true}}) : D({{"hwmon0",true},{"hwmon1",true}});
        if (abs == "/sys/class/power_supply") return D({});     // no battery
        if (abs == "/sys/class/backlight")    return D({});
        if (abs == "/sys/class/drm")          return D({});
        if (abs == "/sys/class/thermal") {
            std::vector<VirtualDirent> e{{"thermal_zone0", true}};
            for (std::size_t i = 1; i <= hal.size(); ++i)
                e.push_back({"thermal_zone" + std::to_string(i), true});
            return ok(dir(std::move(e)));
        }
        if (abs == "/sys/class/thermal/thermal_zone0")
            return D({{"type",false},{"temp",false},{"policy",false},{"mode",false},
                      {"trip_point_0_temp",false},{"trip_point_0_type",false},
                      {"trip_point_1_temp",false},{"trip_point_1_type",false}});
        if (abs == "/sys/class/thermal/thermal_zone0/mode") return T("enabled\n");
        if (abs == "/sys/class/thermal/thermal_zone0/trip_point_0_temp") return T("85000\n");
        if (abs == "/sys/class/thermal/thermal_zone0/trip_point_0_type") return T("passive\n");
        if (abs == "/sys/class/thermal/thermal_zone0/trip_point_1_temp") return T("105000\n");
        if (abs == "/sys/class/thermal/thermal_zone0/trip_point_1_type") return T("critical\n");
        if (abs == "/sys/class/thermal/thermal_zone0/type") return T("cpu-thermal\n");
        if (abs == "/sys/class/thermal/thermal_zone0/temp") return temp_text(0);
        if (abs == "/sys/class/thermal/thermal_zone0/policy") return T("step_wise\n");

        // ---- net (loopback only, so a container-y guest is coherent) ----
        if (abs == "/sys/class/net" || abs == "/sys/devices/virtual/net")
            return D({{"lo",true}});
        if (abs == "/sys/class/net/lo" || abs == "/sys/devices/virtual/net/lo")
            return D({{"address",false},{"mtu",false},{"operstate",false},
                     {"statistics",true},{"flags",false},{"type",false}});
        if (abs.ends_with("/net/lo/address"))   return T("00:00:00:00:00:00\n");
        if (abs.ends_with("/net/lo/mtu"))       return T("65536\n");
        if (abs.ends_with("/net/lo/operstate")) return T("unknown\n");
        if (abs.ends_with("/net/lo/flags"))     return T("0x9\n");
        if (abs.ends_with("/net/lo/type"))      return T("772\n");
        if (abs.ends_with("/net/lo/statistics"))
            return D({{"rx_bytes",false},{"tx_bytes",false},
                     {"rx_packets",false},{"tx_packets",false}});
        if (abs.find("/net/lo/statistics/") != std::string_view::npos) return T("0\n");

        // ================= /sys/block (one virtual disk) =================
        if (abs == "/sys/block" || abs == "/sys/class/block")
            return D({{"vda",true}});
        if (abs == "/sys/block/vda")
            return D({{"stat",false},{"size",false},{"ro",false},
                     {"removable",false},{"queue",true},{"device",true},
                     {"dev",false},{"vda1",true}});
        if (abs == "/sys/block/vda/stat")
            // 15 fields: reads-completed .. ; steady, nonzero so tools chart it.
            return T("   1000        0    64000     2000"
                     "     500        0    32000     1000"
                     "       0     3000     3000        0"
                     "        0        0        0        0        0\n");
        if (abs == "/sys/block/vda/size")      return T("41943040\n");  // 20 GiB / 512
        if (abs == "/sys/block/vda/ro")        return T("0\n");
        if (abs == "/sys/block/vda/removable") return T("0\n");
        if (abs == "/sys/block/vda/dev")       return T("254:0\n");
        if (abs == "/sys/block/vda/queue")
            return D({{"rotational",false},{"logical_block_size",false},
                     {"physical_block_size",false},{"scheduler",false}});
        if (abs == "/sys/block/vda/queue/rotational")          return T("0\n");
        if (abs == "/sys/block/vda/queue/logical_block_size")  return T("512\n");
        if (abs == "/sys/block/vda/queue/physical_block_size") return T("512\n");
        if (abs == "/sys/block/vda/queue/scheduler")           return T("[none] mq-deadline\n");
        if (abs == "/sys/block/vda/device")    return D({{"model",false},{"vendor",false}});
        if (abs == "/sys/block/vda/device/model")  return T("linuxity-disk\n");
        if (abs == "/sys/block/vda/device/vendor") return T("linuxity\n");
        if (abs == "/sys/block/vda/vda1")
            return D({{"stat",false},{"size",false},{"partition",false},{"dev",false}});
        if (abs == "/sys/block/vda/vda1/stat")
            return T("    900        0    58000     1800"
                     "     450        0    28000      900"
                     "       0     2700     2700        0"
                     "        0        0        0        0        0\n");
        if (abs == "/sys/block/vda/vda1/size")      return T("41940992\n");
        if (abs == "/sys/block/vda/vda1/partition") return T("1\n");
        if (abs == "/sys/block/vda/vda1/dev")       return T("254:1\n");

        // ================= /sys/fs (cgroup v2 stub) ======================
        if (abs == "/sys/fs")
            return D({{"cgroup",true},{"ext4",true},{"tmpfs",true}});
        if (abs == "/sys/fs/cgroup")
            return D({{"cgroup.controllers",false},{"cgroup.procs",false},
                     {"cpu.stat",false},{"memory.current",false},
                     {"memory.max",false},{"cpuset.cpus.effective",false}});
        if (abs == "/sys/fs/cgroup/cgroup.controllers") return T("cpu memory pids\n");
        if (abs == "/sys/fs/cgroup/cgroup.procs")        return T("1\n");
        if (abs == "/sys/fs/cgroup/cpu.stat")
            return T("usage_usec 0\nuser_usec 0\nsystem_usec 0\n");
        if (abs == "/sys/fs/cgroup/memory.current")      return T("16777216\n");
        if (abs == "/sys/fs/cgroup/memory.max")          return T("max\n");
        if (abs == "/sys/fs/cgroup/cpuset.cpus.effective") return T(cpu_range + "\n");

        // ================= /sys/module, /sys/kernel stubs ================
        if (abs == "/sys/module")   return D({});
        if (abs == "/sys/bus")      return D({});
        if (abs == "/sys/firmware") return D({});
        if (abs == "/sys/dev")      return D({{"block",true},{"char",true}});
        if (abs == "/sys/dev/block") return D({{"254:0",true}});
        if (abs == "/sys/power")    return D({{"state",false}});
        if (abs == "/sys/power/state") return T("freeze mem disk\n");
        if (abs == "/sys/kernel")
            return D({{"mm",true},{"debug",true},{"tracing",true},{"security",true}});
        // debugfs and tracefs mount points. Nothing is mounted on them, as on
        // a kernel booted without them mounted; their contents are kernel
        // internals no guest can be given.
        if (abs == "/sys/kernel/debug" || abs == "/sys/kernel/tracing" ||
            abs == "/sys/kernel/security" || abs == "/sys/kernel/mm")
            return D({});

        return err<kernel::VirtualFile>(Errno::enoent);
    };
    return [&mach, synth](std::string_view abs) -> Result<kernel::VirtualFile> {
        using namespace sysfs_detail;
        if (!mach.host_hw) return synth(abs);
        const std::string hp{abs};
        // Trees we own: they must agree with ncpu and the resource limits. The
        // host fills in only what we don't synthesize.
        for (const std::string_view own : {"/sys/devices/system/cpu", "/sys/devices/system/node",
                                           "/sys/devices/system/memory", "/sys/fs/cgroup",
                                           "/sys/kernel"})
            if (abs == own || (abs.starts_with(own) && abs[own.size()] == '/')) {
                auto r = synth(abs);
                if (r || r.error() != Errno::enoent) return r;
                if (host_node_ok(hp)) { VirtualFile vf; vf.redirect_host = hp; return ok(std::move(vf)); }
                return r;
            }
        // Top-level dirs list both, so a synthesized fallback child shows up.
        for (const std::string_view top : {"/sys", "/sys/class", "/sys/devices",
                                           "/sys/devices/system", "/sys/devices/virtual"})
            if (abs == top) {
                auto r = synth(abs);
                std::vector<VirtualDirent> e = r && r->is_dir ? r->entries : std::vector<VirtualDirent>{};
                host_entries(hp, e);
                return ok(dir(std::move(e)));
            }
        if (host_node_ok(hp)) {
            VirtualFile vf;
            vf.redirect_host = hp;
            return ok(std::move(vf));
        }
        // Below a device the host shows, its answer is final: falling back
        // made a fake hwmon0/temp1_label appear next to the real hwmon0. Not
        // for /sys/class/<x> itself, where our fallback fills a hidden class.
        {
            const std::string parent = hp.substr(0, hp.rfind('/'));
            const auto depth = std::count(parent.begin(), parent.end(), '/');
            if (depth >= 3 && host_node_ok(parent)) {
                struct ::stat st{};
                if (::stat(parent.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                    // a file there that we may not read (RAPL energy_uj is
                    // root-only) still opens on the host, which says EACCES
                    if (::lstat(hp.c_str(), &st) == 0) {
                        VirtualFile vf;
                        vf.redirect_host = hp;
                        return ok(std::move(vf));
                    }
                    return err<VirtualFile>(errno == EACCES ? Errno::eacces : Errno::enoent);
                }
            }
        }
        return synth(abs);
    };
}

} // namespace lx::vfs
