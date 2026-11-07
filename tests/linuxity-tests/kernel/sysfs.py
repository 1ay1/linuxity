"""/sys: devices, cpus and kernel knobs, as tools read them."""
import os

from lxt import check, eq, test


def cpulist(s):
    out = set()
    for part in s.strip().split(","):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        out.update(range(int(lo), int(hi or lo) + 1))
    return out


def read(p):
    with open(p) as f:
        return f.read()


@test
def cpu_topology():
    """/sys/devices/system/cpu agrees with the cpu count and affinity."""
    base = "/sys/devices/system/cpu"
    online = cpulist(read(f"{base}/online"))
    eq(len(online), os.cpu_count(), "cpus in online")
    check(online <= cpulist(read(f"{base}/possible")), "online is not within possible")
    check(online <= cpulist(read(f"{base}/present")), "online is not within present")
    check(set(os.sched_getaffinity(0)) <= online, "affinity names an offline cpu")
    dirs = {int(d[3:]) for d in os.listdir(base) if d.startswith("cpu") and d[3:].isdigit()}
    check(online <= dirs, f"cpuN dirs {sorted(dirs)} miss online cpus")
    return f"{len(online)} online: {read(f'{base}/online').strip()}"


@test
def standard_tree():
    """The top-level /sys directories tools expect exist."""
    for d in ("/sys/devices", "/sys/class", "/sys/kernel", "/sys/bus", "/sys/fs"):
        check(os.path.isdir(d), f"{d} missing")
    check(os.path.isdir("/sys/class/net"), "/sys/class/net missing")
    check("lo" in os.listdir("/sys/class/net"), "/sys/class/net lacks lo")
    with open("/proc/mounts") as f:
        check(any(l.split()[1] == "/sys" and l.split()[2] == "sysfs" for l in f), "/sys isn't mounted as sysfs")
    return "devices, class, kernel, bus, fs, class/net/lo"


@test
def kernel_knobs():
    """/proc/sys values read back as numbers within their kernel ranges."""
    def num(p):
        return int(read(p).split()[0])

    check(num("/proc/sys/kernel/pid_max") >= 32768, "pid_max")
    check(num("/proc/sys/fs/file-max") > 1000, "file-max")
    check(num("/proc/sys/kernel/threads-max") > 100, "threads-max")
    check(0 <= num("/proc/sys/vm/overcommit_memory") <= 2, "overcommit_memory")
    check(num("/proc/sys/vm/max_map_count") > 1000, "max_map_count")
    ngroups = num("/proc/sys/kernel/ngroups_max")
    check(ngroups >= 65536, f"ngroups_max {ngroups}")
    lo, hi = (int(x) for x in read("/proc/sys/net/ipv4/ip_local_port_range").split())
    check(1024 <= lo < hi <= 65535, f"ip_local_port_range {lo} {hi}")
    return "pid_max, file-max, threads-max, vm, ngroups_max, port range"
