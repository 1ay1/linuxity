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
#include "linuxity/kernel/namespaces.hpp"
#include "linuxity/kernel/sysv_ipc.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>
#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace lx::kernel {

// The per-process facts /proc needs. A deliberately small, total record —
// extends naturally as more /proc fields are synthesized.
struct ProcInfo {
    std::int32_t pid{1};
    std::int32_t ppid{0};
    // Process GROUP. 0 means "not set yet, so it is my own pid" -- resolved
    // through ProcessTable::pgid_of rather than stored eagerly, because a
    // fork-time snapshot does not always know the parent's group yet.
    //
    // This has to live WITH the process: a single scalar for "the caller's
    // group" cannot answer getpgid(other_pid), and answering `pid` for every
    // other pid made each task look like its own leader. A shell then saw
    // the two halves of a pipeline land in DIFFERENT groups, and fish's
    // tty_handoff assertion ("Job should not have fish's pgroup") fired
    // whenever the numbering happened to collide.
    std::int32_t pgid{0};
    // SESSION id, same shape: 0 = inherit from the parent, so a fork stays in
    // its parent's session until setsid. getsid(pid) used to answer pid for
    // every pid, i.e. every task its own session leader -- wrong the same way
    // pgid was, and a job-control shell checks both.
    std::int32_t sid{0};
    // The CONTROLLING TERMINAL, as the pty slave number the session leader
    // claimed with TIOCSCTTY (-1 = none). Sessions own a ctty, not processes,
    // so this is only ever read through ctty_of, which walks to the session.
    std::int32_t ctty{-1};
    std::string  comm{"linuxity"};   // short name (/proc/<pid>/comm, stat)
    std::string  cmdline{"linuxity"};// full argv, NUL-joined for /proc/.../cmdline
    char         state{'R'};         // R/S/D/Z/T (running by default)
    std::uint64_t rss_pages{256};    // resident pages (statm, stat)
    std::uint64_t vsize_bytes{16u << 20}; // virtual size
    std::uint32_t uid{0};
    std::uint32_t gid{0};
    std::string  exe{};              // guest path of the image (/proc/<pid>/exe)
    std::vector<std::int32_t> threads{}; // guest tids besides the main thread
    // names of non-main threads that set one; comm is the main thread's
    std::vector<std::pair<std::int32_t, std::string>> thread_comms{};
    // setgroups(2) list; inherited across fork, root's [0] until set
    std::vector<std::uint32_t> groups{};
    bool groups_set{false};
    // Credentials: real, effective, saved, filesystem. Copied at fork.
    std::array<std::uint32_t, 4> uids{0, 0, 0, 0};
    std::array<std::uint32_t, 4> gids{0, 0, 0, 0};
    // Capability sets (bit n = capability n), moved by the kernel's rules
    // on setuid and exec. kAllCaps until something drops them.
    std::uint64_t cap_eff{kAllCaps}, cap_prm{kAllCaps}, cap_inh{0},
                  cap_bnd{kAllCaps}, cap_amb{0};
    bool keepcaps{false};
    bool no_new_privs{false};
    std::int32_t nice{0};
    // set on a spawn record that carries the parent's credentials
    bool creds_given{false};
    // created by the task's own first syscall, before its spawn event
    bool live_seen{false};
    // owner ids of a set-user/group-ID file the pending execve runs
    std::uint32_t exec_setuid{0xffffffffu}, exec_setgid{0xffffffffu};
    // the namespaces it is in (copied at fork, changed by unshare/setns)
    NsSet ns{};

    static constexpr std::uint64_t kAllCaps = (std::uint64_t{1} << 41) - 1;   // 0..40
};

// The virtual process table. Ordered by pid so /proc enumerates numerically.
class ProcessTable {
public:
    ProcessTable() {
        // pid 1 is our init, always present. It is spawned by linuxity like
        // any child, so natively it inherits linuxity's group and session --
        // it is NOT a leader. Seeding it as its own leader made its first
        // setsid() EPERM, which any daemon or shell bootstrap trips on. The
        // inherited id sits far above any guest pid so it never collides.
        ProcInfo init;
        init.pgid = kInheritedPgid;
        init.sid  = kInheritedPgid;
        procs_.emplace(1, init);
    }
    // Stands in for the host group/session pid 1 was born into.
    static constexpr std::int32_t kInheritedPgid = 0x7fff0000;

    // The guest's init. 1 in linuxity's own pid space; with host pids it is
    // the root task's real pid, known only once the trap has started it.
    [[nodiscard]] std::int32_t init_pid() const { return init_pid_; }
    // Guest pids are host pids (docker's --pid=host): no translation, and
    // processes outside the guest are visible and signalable.
    [[nodiscard]] bool host_pids() const { return host_pids_; }
    void set_host_pids(bool on) { host_pids_ = on; }
    // Move init's record (seeded at 1 before the root existed) to its pid.
    // With host pids nothing needs hiding: init's parent is linuxity, and
    // the group and session it inherited are the real host ones.
    void rekey_init(std::int32_t pid) {
        if (pid <= 0 || pid == init_pid_) return;
        if (auto n = procs_.extract(init_pid_)) {
            n.key() = pid;
            n.mapped().pid = pid;
#if !defined(_WIN32)
            if (host_pids_) {
                n.mapped().ppid = static_cast<std::int32_t>(::getpid());
                if (n.mapped().pgid == kInheritedPgid) n.mapped().pgid = ::getpgrp();
                if (n.mapped().sid == kInheritedPgid) n.mapped().sid = ::getsid(0);
            }
#endif
            for (auto& [_, p] : procs_) if (p.ppid == init_pid_) p.ppid = pid;
            procs_.insert(std::move(n));
        }
        init_pid_ = pid;
        note_pid(pid);
    }

    // Replace a process's identity (comm, argv, exe, ...). Group and session
    // are KEPT unless the new record sets them: they are job-control state,
    // not identity, and main.cpp re-upserting pid 1 at exec time used to
    // wipe the seed above and make the first guest process its own leader.
    void upsert(const ProcInfo& p) {
        note_pid(p.pid);
        auto& cur = procs_[p.pid];
        const std::int32_t pg = p.pgid ? p.pgid : cur.pgid;
        const std::int32_t sd = p.sid ? p.sid : cur.sid;
        auto threads = std::move(cur.threads);   // reaped one by one, not by exec
        auto groups = std::move(cur.groups);     // exec keeps credentials
        const bool groups_set = cur.groups_set;
        const auto uids = cur.uids, gids = cur.gids;
        const ProcInfo old = cur;
        const bool had_creds = cur.pid != 0;
        cur = p;
        cur.pgid = pg;
        cur.sid = sd;
        if (cur.threads.empty()) cur.threads = std::move(threads);
        if (!cur.groups_set) { cur.groups = std::move(groups); cur.groups_set = groups_set; }
        if (had_creds && !p.creds_given) {
            cur.uids = uids; cur.gids = gids;
            cur.cap_eff = old.cap_eff; cur.cap_prm = old.cap_prm; cur.cap_inh = old.cap_inh;
            cur.cap_bnd = old.cap_bnd; cur.cap_amb = old.cap_amb;
            cur.keepcaps = old.keepcaps; cur.no_new_privs = old.no_new_privs; cur.nice = old.nice;
        }
        cur.creds_given = false;
    }
    void add_thread(std::int32_t pid, std::int32_t tid) {
        note_pid(tid);
        auto it = procs_.find(pid);
        if (it == procs_.end() || tid == pid) return;
        // a thread shares its process's pid namespaces and takes a number there
        for (std::uint64_t ns = it->second.ns.id[static_cast<int>(NsKind::pid)]; ns;) {
            auto& p = pidns_[ns];
            if (!p.local_of.count(tid)) {
                const auto n = p.next++;
                p.local_of[tid] = n;
                p.global_of[n] = tid;
            }
            ns = p.parent;
        }
        auto& t = it->second.threads;
        if (std::find(t.begin(), t.end(), tid) == t.end()) t.push_back(tid);
    }
    void drop_thread(std::int32_t tid) {
        // a non-main thread's number goes with it; a process keeps its own
        // until it's waited for (see retire_ns_pid)
        if (thread_group_of(tid)) drop_ns_pid(tid);
        for (auto& [_, p] : procs_) {
            std::erase(p.threads, tid);
            std::erase_if(p.thread_comms, [&](const auto& e) { return e.first == tid; });
        }
    }
    // A process exited. Its namespace numbers stay, so its parent can still
    // wait for it by them, as for a zombie. Guest pids are never reused
    // (next_gpid_ only grows), so the entry can't collide with a later one.
    void retire_ns_pid(std::int32_t) {}
    // the process a non-main thread belongs to, or 0
    [[nodiscard]] std::int32_t thread_group_of(std::int32_t tid) const {
        for (const auto& [pid, p] : procs_)
            if (std::find(p.threads.begin(), p.threads.end(), tid) != p.threads.end())
                return pid;
        return 0;
    }
    void set_comm(std::int32_t pid, std::string comm) {
        auto& p = procs_[pid]; p.pid = pid; p.comm = comm;
        if (p.cmdline.empty()) p.cmdline = std::move(comm);
    }
    // PR_SET_NAME / a comm write: names one thread, not the process
    void set_thread_comm(std::int32_t pid, std::int32_t tid, std::string comm) {
        if (tid == pid || tid <= 0) return set_comm(pid, std::move(comm));
        auto& tc = procs_[pid].thread_comms;
        for (auto& [t, c] : tc)
            if (t == tid) { c = std::move(comm); return; }
        tc.emplace_back(tid, std::move(comm));
    }
    // a thread's name: its own if it set one, else the process's
    [[nodiscard]] static const std::string& comm_of(const ProcInfo& p, std::int32_t tid) {
        for (const auto& [t, c] : p.thread_comms)
            if (t == tid) return c;
        return p.comm;
    }
    void add(std::int32_t pid, std::int32_t ppid) {
        ProcInfo p; p.pid = pid; p.ppid = ppid;
        // A child INHERITS its parent's process group -- it does not start a
        // group of its own. Getting this wrong is what made a fresh child
        // report getpgid(child) == child instead of the parent's group.
        p.pgid = pgid_of(ppid);
        procs_[pid] = p;
        note_pid(pid);
    }

    // Guest ids are handed out in order, so the highest one seen counts every
    // fork and thread since start: /proc/stat's processes, loadavg's last pid.
    void note_pid(std::int32_t id) { if (id > last_pid_) last_pid_ = id; }
    [[nodiscard]] std::int32_t last_pid() const { return last_pid_; }

    // The process group of `pid`, resolving the "0 means my own pid" default.
    // An unknown pid answers its own number, which is what a flat model would
    // have said and keeps callers from having to special-case it.
    [[nodiscard]] std::int32_t pgid_of(std::int32_t pid) const {
        if (pid <= 0) return pid;
        const ProcInfo* p = find(pid);
        if (p == nullptr) return pid;
        // Walk up until a pid with a recorded group. A link that's gone (an
        // ancestor already reaped) or unknown can't have been ours to make
        // a group from, so the chain ends at init's. Answering the missing
        // pid's own number made a dead parent's pid look like our group --
        // and our session, so setpgid said EPERM to a non-leader.
        for (int hops = 0; p != nullptr && hops < 4096; ++hops) {
            if (p->pgid) return p->pgid;
            if (p->ppid == 0 || p->ppid == p->pid) break;
            p = find(p->ppid);
        }
        const ProcInfo* in = find(init_pid_);
        return pid == init_pid_ ? pid : (in && in->pgid ? in->pgid : init_pid_);
    }
    [[nodiscard]] std::int32_t sid_of(std::int32_t pid) const {
        if (pid <= 0) return pid;
        const ProcInfo* p = find(pid);
        if (p == nullptr) return pid;
        for (int hops = 0; p != nullptr && hops < 4096; ++hops) {
            if (p->sid) return p->sid;
            if (p->ppid == 0 || p->ppid == p->pid) break;
            p = find(p->ppid);
        }
        const ProcInfo* in = find(init_pid_);
        return pid == init_pid_ ? pid : (in && in->sid ? in->sid : init_pid_);
    }
    // setsid(): a new session AND a new group, both led by the caller.
    void set_sid(std::int32_t pid) {
        auto& p = procs_[pid];
        if (p.pid == 0) p.pid = pid;
        p.sid = pid;
        p.pgid = pid;
        // A new session starts with NO controlling terminal, even though the
        // caller had one a moment ago -- that is the whole point of setsid,
        // and it is why a daemon calls it.
        p.ctty = -1;
    }

    // The controlling terminal of `pid`'s SESSION, or -1 for none.
    //
    // Stored on the session leader, because that is who claims it, but every
    // member of the session shares it -- so resolve by walking to the leader
    // rather than reading the caller's own field.
    [[nodiscard]] std::int32_t ctty_of(std::int32_t pid) const {
        if (pid <= 0) return -1;
        // The session leader owns it, when there is a recorded session.
        const std::int32_t leader = sid_of(pid);
        if (const ProcInfo* l = find(leader); l != nullptr && l->ctty >= 0)
            return l->ctty;
        // Otherwise walk up the tree. A ctty is INHERITED across fork and
        // exec, exactly like pgid, and this is the common case rather than
        // the exception: linuxity seeds pid 1 from the terminal it was
        // launched on, and the shell the user actually typed at is pid 2.
        // Resolving only through sid_of missed that -- sid_of(2) is 2, which
        // has no ctty of its own, so bash saw ENOTTY on its own terminal and
        // printed "no job control in this shell".
        //
        // Only within the session, though. A setsid() child starts with no
        // ctty, and walking on into its parent found the parent's, so a
        // pty.fork() child's TIOCSCTTY was EPERM whenever its parent sat on
        // a terminal.
        const std::int32_t sess = leader;
        for (const ProcInfo* p = find(pid); p != nullptr; ) {
            if (sid_of(p->pid) != sess) break;
            if (p->ctty >= 0) return p->ctty;
            if (p->ppid == 0 || p->ppid == p->pid) break;
            p = find(p->ppid);
        }
        return -1;
    }

    // TIOCSCTTY: make pty slave `n` the ctty of `pid`'s session.
    void set_ctty(std::int32_t pid, std::int32_t n) {
        const std::int32_t leader = sid_of(pid);
        // the inherited session's leader is outside the guest; recording the
        // tty on it made a fake process at that pid show up in /proc
        if (leader != kInheritedPgid) {
            auto& l = procs_[leader];
            if (l.pid == 0) l.pid = leader;
            l.ctty = n;
        }
        // Record it on the caller too, so a caller that is not (yet) the
        // leader still sees its own claim.
        auto& p = procs_[pid];
        if (p.pid == 0) p.pid = pid;
        p.ctty = n;
    }

    // TIOCNOTTY: drop the ctty for the whole session.
    void clear_ctty(std::int32_t pid) {
        const std::int32_t leader = sid_of(pid);
        for (auto& [who, p] : procs_)
            if (sid_of(who) == leader) p.ctty = -1;
    }

    // setpgid(pid, pgid). Records the group against the TARGET, which is the
    // whole point: a shell always sets its CHILD's group, never its own.
    void set_pgid(std::int32_t pid, std::int32_t pgid) {
        auto& p = procs_[pid];
        if (p.pid == 0) p.pid = pid;          // first mention of this pid
        p.pgid = pgid ? pgid : pid;
    }
    void remove(std::int32_t pid) { if (pid != init_pid_) procs_.erase(pid); }

    [[nodiscard]] bool has(std::int32_t pid) const { return find(pid) != nullptr; }
    // The supplementary groups `pid` holds. fork copies the parent's (see
    // the spawn event), so an unset record means a root login's [0].
    [[nodiscard]] std::vector<std::uint32_t> groups_of(std::int32_t pid) const {
        const ProcInfo* p = find(pid);
        if (p != nullptr && p->groups_set) return p->groups;
        return {0};
    }
    void set_groups(std::int32_t pid, std::vector<std::uint32_t> g) {
        auto& p = procs_[pid];
        if (p.pid == 0) p.pid = pid;
        p.groups = std::move(g);
        p.groups_set = true;
    }
    [[nodiscard]] ProcInfo* find_mut(std::int32_t pid) {
        auto it = procs_.find(pid);
        return it == procs_.end() ? nullptr : &it->second;
    }
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
            // A record synthesized from the live table has no group of its
            // own, and leaving it 0 means pgid_of falls back to the pid --
            // i.e. "every task leads its own group", which is the bug this
            // field exists to fix. A process INHERITS its parent's group, so
            // walk up to a pid we do know about. (The recursion terminates:
            // ppid is strictly closer to pid 1, whose record is always seeded.)
            if (p.pgid == 0 && p.ppid != 0 && p.ppid != pid)
                p.pgid = pgid_of(p.ppid);
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

    // Every LIVE process in group `pgid`. kill(0)/kill(-pgid) and the
    // backends' group signalling used the process TREE as a stand-in for a
    // group, because groups were not tracked; now they are, so ask this.
    // Liveness comes from the live source when there is one -- the record
    // map keeps entries for processes that have exited.
    [[nodiscard]] std::vector<std::int32_t> members_of(std::int32_t pgid) const {
        std::vector<std::int32_t> out;
        for (std::int32_t p : pids()) {
            if (live_ && !live_->alive(p)) continue;
            if (pgid_of(p) == pgid) out.push_back(p);
        }
        return out;
    }

    // A cross-process view of the pid namespace, provided by the backend.
    struct LiveSource {
        virtual ~LiveSource() = default;
        [[nodiscard]] virtual bool alive(std::int32_t pid) const = 0;
        [[nodiscard]] virtual std::vector<std::int32_t> pids() const = 0;
        [[nodiscard]] virtual ProcInfo info(std::int32_t pid) const = 0;
    };
    void set_live_source(const LiveSource* s) noexcept { live_ = s; }

    // Guest pid/tid -> host task, for the live facts only the host kernel
    // keeps (signal masks, cpu times, memory, environ). Set by the trap
    // backend; absent, procfs falls back to modeled values.
    using HostOf = std::function<int(std::int32_t)>;
    void set_host_resolver(HostOf f) { host_of_ = std::move(f); }
    [[nodiscard]] int host_of(std::int32_t gpid) const { return host_of_ ? host_of_(gpid) : -1; }
    // and the reverse: the guest pid a host pid had, even after it exited
    // (0 if it was never one of ours)
    void set_guest_resolver(HostOf f) { guest_of_ = std::move(f); }
    [[nodiscard]] std::int32_t guest_of(int host) const { return guest_of_ && host > 0 ? guest_of_(host) : 0; }
    // who ptraces guest task `tid` (0 = nobody), and is it stopped for them
    using TracerOf = std::function<std::pair<std::int32_t, bool>(std::int32_t)>;
    void set_tracer_resolver(TracerOf f) { tracer_of_ = std::move(f); }
    [[nodiscard]] std::pair<std::int32_t, bool> tracer_of(std::int32_t tid) const {
        return tracer_of_ ? tracer_of_(tid) : std::pair<std::int32_t, bool>{0, false};
    }

    // -- pid namespaces ------------------------------------------------------
    // A process in a child pid namespace has a second, local number there
    // (1 for the first). Guest pids in the initial namespace stay the global
    // ones the rest of linuxity uses; these translate at the edges.
    struct PidNs { std::uint64_t parent{0}; std::int32_t next{1};
                   std::map<std::int32_t, std::int32_t> local_of, global_of; };
    // Give `pid` its numbers in its pid namespace and every one above it.
    void assign_ns_pid(std::int32_t pid) {
        const auto set = ns_of(pid);
        std::uint64_t ns = set.id[static_cast<int>(NsKind::pid)];
        while (ns) {
            auto& p = pidns_[ns];
            if (!p.local_of.count(pid)) {
                const auto n = p.next++;
                p.local_of[pid] = n;
                p.global_of[n] = pid;
            }
            ns = p.parent;
        }
    }
    void new_pid_ns(std::uint64_t id, std::uint64_t parent) { pidns_[id].parent = parent; }
    // Number `pid`, a child of `parent` whose record hasn't arrived yet, in
    // the pid namespace it was born into (the parent's pid_for_children).
    void assign_ns_pid_from(std::int32_t pid, std::int32_t parent) {
        const auto ps = ns_of(parent);
        std::uint64_t ns = ps.pid_for_children ? ps.pid_for_children
                                               : ps.id[static_cast<int>(NsKind::pid)];
        while (ns) {
            auto& p = pidns_[ns];
            if (!p.local_of.count(pid)) {
                const auto n = p.next++;
                p.local_of[pid] = n;
                p.global_of[n] = pid;
            }
            ns = p.parent;
        }
    }
    // The pid namespace a set's processes live in (0 = initial).
    [[nodiscard]] static std::uint64_t pid_ns(const NsSet& s) { return s.id[static_cast<int>(NsKind::pid)]; }
    // `global` as seen from pid namespace `ns`; 0 when it isn't visible there.
    [[nodiscard]] std::int32_t pid_in(std::uint64_t ns, std::int32_t global) const {
        if (!ns || global <= 0) return global;
        auto it = pidns_.find(ns);
        if (it == pidns_.end()) return 0;
        auto l = it->second.local_of.find(global);
        return l == it->second.local_of.end() ? 0 : l->second;
    }
    // A pid named inside `ns`, back to the global one; -1 when unknown.
    [[nodiscard]] std::int32_t pid_from(std::uint64_t ns, std::int32_t local) const {
        if (!ns || local <= 0) return local;
        auto it = pidns_.find(ns);
        if (it == pidns_.end()) return -1;
        auto g = it->second.global_of.find(local);
        return g == it->second.global_of.end() ? -1 : g->second;
    }
    void drop_ns_pid(std::int32_t pid) {
        for (auto& [_, p] : pidns_)
            if (auto it = p.local_of.find(pid); it != p.local_of.end()) {
                p.global_of.erase(it->second);
                p.local_of.erase(it);
            }
    }

    // The guest process making the current call, so views that depend on
    // who looks (procfs under a pid namespace) can ask. 0 = nobody.
    void set_reader(std::int32_t pid) { reader_ = pid; }
    [[nodiscard]] std::int32_t reader() const { return reader_; }
    // The reader's pid namespace (0 = initial) and its view of a pid.
    [[nodiscard]] std::uint64_t reader_pid_ns() const { return pid_ns(ns_of(reader_)); }
    [[nodiscard]] std::int32_t view_pid(std::int32_t global) const {
        return pid_in(reader_pid_ns(), global);
    }

    [[nodiscard]] Namespaces& ns() { return ns_; }
    [[nodiscard]] const Namespaces& ns() const { return ns_; }
    // Is `pid` in a network namespace of its own (one the host made real)?
    [[nodiscard]] bool net_isolated(std::int32_t pid) const {
        auto it = procs_.find(pid);
        return it != procs_.end() && ns_.net_isolated(it->second.ns);
    }
    // System V IPC objects, one set per IPC namespace (kernel/sysv_ipc.hpp)
    [[nodiscard]] SysvIpc& ipc() { return ipc_; }
    [[nodiscard]] const SysvIpc& ipc() const { return ipc_; }
    // A pid's namespaces (the initial ones for an unknown pid).
    [[nodiscard]] NsSet ns_of(std::int32_t pid) const {
        auto it = procs_.find(pid);
        return it == procs_.end() ? NsSet{} : it->second.ns;
    }
    // CLONE_NEW* flags a pending clone asked for, keyed by the parent;
    // applied to the child when it appears.
    void set_clone_ns(std::int32_t parent, std::uint64_t flags) { clone_ns_[parent] = flags; }
    [[nodiscard]] std::uint64_t take_clone_ns(std::int32_t parent) {
        auto it = clone_ns_.find(parent);
        if (it == clone_ns_.end()) return 0;
        const auto f = it->second;
        clone_ns_.erase(it);
        return f;
    }
    // Give `p` a fresh namespace of each kind in `flags`, as unshare(2)
    // does (pid and time apply to its future children).
    void unshare_ns(ProcInfo& p, std::uint64_t flags) {
        for (int k = 0; k < kNsKinds; ++k) {
            if (!(flags & kNsFlag[k])) continue;
            const auto kind = static_cast<NsKind>(k);
            const std::uint64_t old = ns_.resolve(p.ns, kind);
            const std::uint64_t id = ns_.fresh();
            if (kind == NsKind::pid) {
                new_pid_ns(id, p.ns.id[k]);
                p.ns.pid_for_children = id;
                continue;
            }
            if (kind == NsKind::time) { p.ns.time_for_children = id; continue; }
            if (kind == NsKind::uts) ns_.copy_uts(old == ns_.initial(kind) ? 0 : old, id);
            if (kind == NsKind::user) ns_.new_user_ns(id, old == ns_.initial(kind) ? 0 : old);
            if (kind == NsKind::mnt && on_new_mnt_ns_) on_new_mnt_ns_(p.ns.id[k], id);
            p.ns.id[k] = id;
        }
    }
    // A forked child's namespaces: the parent's, its pid/time-for-children
    // made current, plus whatever the clone asked for.
    void inherit_ns(ProcInfo& child, const ProcInfo& parent, std::uint64_t clone_flags) {
        child.ns = parent.ns;
        if (parent.ns.pid_for_children) child.ns.id[static_cast<int>(NsKind::pid)] = parent.ns.pid_for_children;
        if (parent.ns.time_for_children) child.ns.id[static_cast<int>(NsKind::time)] = parent.ns.time_for_children;
        child.ns.pid_for_children = child.ns.time_for_children = 0;
        if (clone_flags) {
            unshare_ns(child, clone_flags);
            if (child.ns.pid_for_children) {
                child.ns.id[static_cast<int>(NsKind::pid)] = child.ns.pid_for_children;
                child.ns.pid_for_children = 0;
            }
            if (child.ns.time_for_children) {
                child.ns.id[static_cast<int>(NsKind::time)] = child.ns.time_for_children;
                child.ns.time_for_children = 0;
            }
        }
    }

private:
    HostOf host_of_;
    HostOf guest_of_;
    TracerOf tracer_of_;
    std::map<std::int32_t, ProcInfo> procs_;
    std::int32_t init_pid_{1};
    bool host_pids_{false};
    std::int32_t last_pid_{1};
    Namespaces ns_;
    SysvIpc ipc_;
    std::map<std::uint64_t, PidNs> pidns_;
    std::int32_t reader_{0};
    std::map<std::int32_t, std::uint64_t> clone_ns_;
    std::function<void(std::uint64_t, std::uint64_t)> on_new_mnt_ns_;
public:
    // Called with (parent, child) when a mount namespace is made, so the
    // file namespace can copy its mounts.
    void set_on_new_mnt_ns(std::function<void(std::uint64_t, std::uint64_t)> f) {
        on_new_mnt_ns_ = std::move(f);
    }
private:
    const LiveSource* live_{nullptr};
    mutable std::map<std::int32_t, ProcInfo> scratch_;
};

} // namespace lx::kernel
