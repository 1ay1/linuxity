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

#include <algorithm>
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
    std::string  exe{};              // guest path of the image (/proc/<pid>/exe)
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

    [[nodiscard]] bool has(std::int32_t pid) const { return find(pid) != nullptr; }
    [[nodiscard]] const ProcInfo* find(std::int32_t pid) const {
        auto it = procs_.find(pid);
        if (it != procs_.end()) {
            // Our own record may be a fork-time snapshot (pid 1 is seeded
            // as "linuxity" before the shell even execs). The live table
            // knows what each pid runs NOW; refresh the identity from it.
            if (live_ && live_->alive(pid)) {
                ProcInfo p = it->second;
                const ProcInfo l = live_->info(pid);
                if (!l.exe.empty() && l.exe != p.exe) {
                    p.comm = l.comm; p.cmdline = l.cmdline; p.exe = l.exe;
                }
                if (l.ppid) p.ppid = l.ppid;
                return &(scratch_[pid] = std::move(p));
            }
            return &it->second;
        }
        // Not in OUR copy, but alive somewhere in the tree? On the HVF
        // backend every guest process is a separate host process with its
        // own copy of this table, frozen at fork: a child shell saw only
        // pid 1, so /proc/<its own pid> and /proc/<parent> were ENOENT
        // ("realpath: /proc/2/exe: No such file" from screenfetch under
        // fish). The backend's shared pid table is the authority on who is
        // alive; synthesize a record from it.
        if (live_ && live_->alive(pid)) {
            ProcInfo p = live_->info(pid);
            p.pid = pid;
            return &(scratch_[pid] = std::move(p));
        }
        return nullptr;
    }

    [[nodiscard]] std::vector<std::int32_t> pids() const {
        std::vector<std::int32_t> out;
        out.reserve(procs_.size());
        for (const auto& [pid, _] : procs_) out.push_back(pid);
        if (live_) {
            for (std::int32_t p : live_->pids())
                if (!procs_.count(p)) out.push_back(p);
            std::sort(out.begin(), out.end());
        }
        return out;
    }
    [[nodiscard]] std::size_t count() const { return pids().size(); }

    // A cross-process view of the pid namespace, provided by the backend.
    struct LiveSource {
        virtual ~LiveSource() = default;
        [[nodiscard]] virtual bool alive(std::int32_t pid) const = 0;
        [[nodiscard]] virtual std::vector<std::int32_t> pids() const = 0;
        [[nodiscard]] virtual ProcInfo info(std::int32_t pid) const = 0;
    };
    void set_live_source(const LiveSource* s) noexcept { live_ = s; }

private:
    std::map<std::int32_t, ProcInfo> procs_;
    const LiveSource* live_{nullptr};
    mutable std::map<std::int32_t, ProcInfo> scratch_;
};

} // namespace lx::kernel
