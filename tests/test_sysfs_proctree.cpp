// The synthesized /sys and the per-process /proc/<pid>/task tree — both
// host-free and deterministic. Proves that a hardware/process monitor's view
// of linuxity is decided entirely by the producers, before any ptrace or real
// syscall: CPU topology, cpufreq, hwmon temperatures, and the thread group
// directory that htop/top enumerate through.
#include "linuxity/kernel/process_table.hpp"
#include "linuxity/vfs/procfs.hpp"
#include "linuxity/vfs/sysfs.hpp"

#include <cassert>
#include <cstdio>
#include <string>

using namespace lx;

static std::string str(const std::vector<std::byte>& b) {
    std::string s(b.size(), '\0');
    for (std::size_t i = 0; i < b.size(); ++i) s[i] = static_cast<char>(b[i]);
    return s;
}

// Does a virtual directory list an entry with the given name?
static bool has_entry(const kernel::VirtualFile& d, std::string_view name) {
    for (const auto& e : d.entries) if (e.name == name) return true;
    return false;
}

int main() {
    // ================= /sys synthesis (4-CPU virtual machine) ============
    auto sysfs = vfs::make_sysfs(/*ncpu=*/4, /*khz=*/2400000);

    // Root and the top-level topology directories enumerate.
    {
        auto root = sysfs("/sys");
        assert(root && root->is_dir);
        assert(has_entry(*root, "devices") && has_entry(*root, "class") &&
               has_entry(*root, "block"));
    }
    // CPU set: online range reflects ncpu; cpuN dirs enumerate.
    {
        auto online = sysfs("/sys/devices/system/cpu/online");
        assert(online && str(online->bytes) == "0-3\n");
        auto cpudir = sysfs("/sys/devices/system/cpu");
        assert(cpudir && cpudir->is_dir);
        assert(has_entry(*cpudir, "cpu0") && has_entry(*cpudir, "cpu3"));
        assert(!has_entry(*cpudir, "cpu4"));   // only 4 CPUs
    }
    // cpufreq: the policyN subtree (the exact path btop reads).
    {
        auto pol = sysfs("/sys/devices/system/cpu/cpufreq");
        assert(pol && pol->is_dir && has_entry(*pol, "policy0"));
        auto cur = sysfs("/sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq");
        assert(cur && str(cur->bytes) == "2400000\n");
        auto gov = sysfs("/sys/devices/system/cpu/cpufreq/policy2/scaling_governor");
        assert(gov && str(gov->bytes) == "performance\n");
    }
    // Per-CPU topology.
    {
        auto core = sysfs("/sys/devices/system/cpu/cpu2/topology/core_id");
        assert(core && str(core->bytes) == "2\n");
    }
    // hwmon temperature, via both the device path and the class-symlink view.
    {
        auto t1 = sysfs("/sys/class/hwmon/hwmon0/temp1_input");
        assert(t1 && str(t1->bytes) == "42000\n");
        auto nm = sysfs("/sys/devices/virtual/hwmon/hwmon0/name");
        assert(nm && str(nm->bytes) == "linuxity_cpu\n");
    }
    // One virtual block device with a plausible stat line.
    {
        auto blk = sysfs("/sys/block");
        assert(blk && blk->is_dir && has_entry(*blk, "vda"));
        auto st = sysfs("/sys/block/vda/stat");
        assert(st && !st->bytes.empty());
        auto rot = sysfs("/sys/block/vda/queue/rotational");
        assert(rot && str(rot->bytes) == "0\n");   // SSD-like
    }
    // No battery on a server: power_supply is an empty (but present) dir.
    {
        auto ps = sysfs("/sys/class/power_supply");
        assert(ps && ps->is_dir && ps->entries.empty());
    }
    // Unknown nodes are absent (ENOENT), not silently empty.
    {
        auto bad = sysfs("/sys/does/not/exist");
        assert(!bad);
    }

    // ================= /proc/<pid>/task thread group =====================
    kernel::ProcessTable procs;
    kernel::ProcInfo child;
    child.pid = 7; child.ppid = 1; child.comm = "sleep";
    child.cmdline = "sleep 10";
    procs.upsert(child);

    auto procfs = vfs::make_procfs(procs, "6.6.0-linuxity", "linuxity", 4);

    // /proc enumerates the live pids (1 = init, 7 = the child).
    {
        auto root = procfs("/proc");
        assert(root && root->is_dir);
        assert(has_entry(*root, "1") && has_entry(*root, "7"));
    }
    // /proc/7 lists its files including the task/ directory.
    {
        auto d = procfs("/proc/7");
        assert(d && d->is_dir && has_entry(*d, "task") && has_entry(*d, "stat"));
    }
    // /proc/7/task lists exactly the main thread (tid == pid).
    {
        auto d = procfs("/proc/7/task");
        assert(d && d->is_dir && has_entry(*d, "7"));
        assert(d->entries.size() == 1);
    }
    // /proc/7/task/7 lists the thread's own files.
    {
        auto d = procfs("/proc/7/task/7");
        assert(d && d->is_dir && has_entry(*d, "stat") && has_entry(*d, "comm"));
    }
    // The thread's stat/comm mirror the process's (single-thread model).
    {
        auto comm = procfs("/proc/7/task/7/comm");
        assert(comm && str(comm->bytes) == "sleep\n");
        auto stat = procfs("/proc/7/task/7/stat");
        assert(stat && str(stat->bytes).find("(sleep)") != std::string::npos);
    }
    // A non-existent thread (tid != pid) is ENOENT.
    {
        auto bad = procfs("/proc/7/task/999/stat");
        assert(!bad);
    }
    // The per-CPU count flows through to /proc/stat (aggregate + N cpuN lines).
    {
        auto stat = procfs("/proc/stat");
        assert(stat);
        std::string s = str(stat->bytes);
        assert(s.find("cpu0 ") != std::string::npos);
        assert(s.find("cpu3 ") != std::string::npos);
        assert(s.find("cpu4 ") == std::string::npos);
    }

    std::puts("test_sysfs_proctree: OK");
    return 0;
}
