// linuxity/kernel/process_table.hpp
//
// The virtual process model — the source of truth /proc reflects.
//
// Real Linux exposes every task through /proc/<pid>/*. Those numbers come
// from the scheduler and the task_struct, not from the host. linuxity owns
// its own PID space (pid 1 = our init), so /proc must be generated from OUR
// process table, not the host's. This is that table: a map of virtual pid ->
// the facts /proc needs (name, state, parent, cmdline, rough memory).
//
// The runtime feeds it as it traces the guest tree (a task appears on
// fork/clone, updates its comm on exec, disappears on exit). Because /proc is
// synthesized from here, `ps`, `htop`, `top`, and anything that walks /proc
// sees linuxity's world: pid 1 is init, uids are root, and the process list
// is exactly the guests we run — never the host's processes.
#pragma once

#include "linuxity/abi/types.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace lx::kernel {

// The per-process facts /proc needs. A deliberately small, total record —
// extends naturally as more /proc fields are synthesized.
struct ProcInfo {
    std::int32_t pid{1};
    std::int32_t ppid{0};
    std::string  comm{"linuxity"};   // short name (/proc/<pid>/comm, stat)
    std::string  cmdline{"linuxity"};// full argv, NUL-joined for /proc/.../cmdline
    char         state{'R'};         // R/S/D/Z/T (running by default)
    std::uint64_t rss_pages{256};    // resident pages (statm, stat)
    std::uint64_t vsize_bytes{16u << 20}; // virtual size
    std::uint32_t uid{0};
    std::uint32_t gid{0};
};

// The virtual process table. Ordered by pid so /proc enumerates numerically.
class ProcessTable {
public:
    ProcessTable() {
        // pid 1 is our init, always present.
        procs_.emplace(1, ProcInfo{});
    }

    void upsert(const ProcInfo& p) { procs_[p.pid] = p; }
    void set_comm(std::int32_t pid, std::string comm) {
        auto& p = procs_[pid]; p.pid = pid; p.comm = comm;
        if (p.cmdline.empty()) p.cmdline = std::move(comm);
    }
    void add(std::int32_t pid, std::int32_t ppid) {
        ProcInfo p; p.pid = pid; p.ppid = ppid; procs_[pid] = p;
    }
    void remove(std::int32_t pid) { if (pid != 1) procs_.erase(pid); }

    [[nodiscard]] bool has(std::int32_t pid) const { return procs_.count(pid) != 0; }
    [[nodiscard]] const ProcInfo* find(std::int32_t pid) const {
        auto it = procs_.find(pid);
        return it == procs_.end() ? nullptr : &it->second;
    }

    [[nodiscard]] std::vector<std::int32_t> pids() const {
        std::vector<std::int32_t> out;
        out.reserve(procs_.size());
        for (const auto& [pid, _] : procs_) out.push_back(pid);
        return out;
    }
    [[nodiscard]] std::size_t count() const noexcept { return procs_.size(); }

private:
    std::map<std::int32_t, ProcInfo> procs_;
};

} // namespace lx::kernel
