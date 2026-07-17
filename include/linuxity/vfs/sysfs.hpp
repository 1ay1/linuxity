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
#pragma once

#include "linuxity/kernel/file_namespace.hpp"
#include "linuxity/kernel/machine.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace lx::vfs {

namespace sysfs_detail {

using kernel::VirtualFile;
using kernel::VirtualDirent;

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

} // namespace sysfs_detail

// Build a /sys producer describing linuxity's virtual machine. It reads the
// SAME MachineSpec (kernel/machine.hpp) as /proc and the syscalls, so the CPU
// count, topology and reported frequency can never disagree between /sys and
// /proc. One physical package, `ncpu` cores, no SMT.
[[nodiscard]] inline kernel::FileNamespace::Producer
make_sysfs(const kernel::MachineSpec& mach) {
    return [&mach](std::string_view abs) -> Result<kernel::VirtualFile> {
        using namespace sysfs_detail;
        const long ncpu = mach.ncpu < 1 ? 1 : mach.ncpu;
        const long khz  = mach.cpu_khz();

        auto D = [](std::initializer_list<VirtualDirent> e) {
            return ok(dir(std::vector<VirtualDirent>(e)));
        };
        auto T = [](std::string s) { return ok(text(std::move(s))); };

        // Helper: "0-3" style cpu range list for `ncpu`.
        std::string cpu_range = mach.cpu_range();

        // ================= /sys root =====================================
        if (abs == "/sys")
            return D({{"devices",true},{"class",true},{"block",true},
                     {"bus",true},{"fs",true},{"kernel",true},{"module",true},
                     {"firmware",true},{"dev",true},{"power",true}});

        // ================= /sys/devices ==================================
        if (abs == "/sys/devices")
            return D({{"system",true},{"virtual",true},{"platform",true}});
        if (abs == "/sys/devices/system")
            return D({{"cpu",true},{"node",true},{"memory",true}});

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

                if (cpu >= 0 && cpu < ncpu) {
                    if (tail.empty())
                        return D({{"topology",true},{"cache",true},
                                 {"cpufreq",true},{"online",false}});
                    if (tail == "online") return T(cpu == 0 ? "1\n" : "1\n");
                    if (tail == "topology")
                        return D({{"core_id",false},{"physical_package_id",false},
                                 {"core_siblings_list",false},{"thread_siblings_list",false},
                                 {"core_siblings",false},{"thread_siblings",false}});
                    if (tail == "topology/core_id")             return T(std::to_string(cpu) + "\n");
                    if (tail == "topology/physical_package_id") return T("0\n");
                    if (tail == "topology/core_siblings_list")  return T(cpu_range + "\n");
                    if (tail == "topology/thread_siblings_list")return T(std::to_string(cpu) + "\n");
                    if (tail == "topology/core_siblings")       return T("1\n");
                    if (tail == "topology/thread_siblings")     return T("1\n");
                }
                if (pol >= 0 && pol < ncpu) {
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
        if (abs == "/sys/devices/system/node/node0/distance") return T("10\n");
        if (abs == "/sys/devices/system/node/node0/meminfo")
            return T("Node 0 MemTotal:        2097152 kB\n"
                     "Node 0 MemFree:         1048576 kB\n");

        // ---- memory block size (btop reads this for hotplug memory) ------
        if (abs == "/sys/devices/system/memory")
            return D({{"block_size_bytes",false}});
        if (abs == "/sys/devices/system/memory/block_size_bytes")
            return T("8000000\n");

        // ================= hwmon (temperatures) ==========================
        // One virtual hwmon exposing a CPU package temperature.
        if (abs == "/sys/devices/virtual")
            return D({{"hwmon",true},{"net",true}});
        if (abs == "/sys/devices/virtual/hwmon")
            return D({{"hwmon0",true}});
        if (abs == "/sys/devices/virtual/hwmon/hwmon0" ||
            abs == "/sys/class/hwmon/hwmon0")
            return D({{"name",false},{"temp1_input",false},{"temp1_label",false},
                     {"temp1_max",false},{"temp1_crit",false},
                     {"temp2_input",false},{"temp2_label",false},
                     {"uevent",false}});
        {
            // Serve the leaf files under either the class-symlink flattening
            // or the real device path (btop opens whichever it resolved).
            auto hw_leaf = [&](std::string_view t) -> Result<kernel::VirtualFile> {
                if (t == "name")        return T("linuxity_cpu\n");
                if (t == "temp1_label") return T("Package id 0\n");
                if (t == "temp1_input") return T("42000\n");   // 42.0 °C
                if (t == "temp1_max")   return T("95000\n");
                if (t == "temp1_crit")  return T("100000\n");
                if (t == "temp2_label") return T("Core 0\n");
                if (t == "temp2_input") return T("40000\n");
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
        if (abs == "/sys/class/hwmon")        return D({{"hwmon0",true}});
        if (abs == "/sys/class/power_supply") return D({});     // no battery
        if (abs == "/sys/class/backlight")    return D({});
        if (abs == "/sys/class/drm")          return D({});
        if (abs == "/sys/class/thermal")
            return D({{"thermal_zone0",true}});
        if (abs == "/sys/class/thermal/thermal_zone0")
            return D({{"type",false},{"temp",false},{"policy",false}});
        if (abs == "/sys/class/thermal/thermal_zone0/type") return T("cpu-thermal\n");
        if (abs == "/sys/class/thermal/thermal_zone0/temp") return T("42000\n");
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
            return D({{"mm",true},{"debug",true},{"security",true}});

        return err<kernel::VirtualFile>(Errno::enoent);
    };
}

} // namespace lx::vfs
