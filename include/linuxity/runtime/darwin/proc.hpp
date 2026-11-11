// linuxity/runtime/darwin/proc.hpp
//
// The guest process model for the HVF backend.
//
// One guest process == one host process. fork() is a real Darwin fork of
// linuxity itself (the VM is torn down and rebuilt on both sides, see
// HvfVm::fork_process), so the host kernel does everything it is good at:
// copy-on-write memory, scheduling across cores, process lifetime, reaping,
// and exit statuses. linuxity only VIRTUALIZES the numbering, so the guest
// sees a Linux pid namespace -- init is pid 1, children count up from 2 --
// rather than macOS pids like 48211.
//
// The mapping lives in an anonymous MAP_SHARED page created before the first
// fork, so every process in the tree sees one table: a grandchild's getppid()
// and a sibling's kill(pid) resolve through the same numbers.
#pragma once

#if defined(__APPLE__)

#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace lx::runtime {

class PidSpace {
public:
    static constexpr int kMax = 4096;   // concurrent guest processes

    // Root of the tree: create the table in an anonymous file the children
    // can inherit. (A MAP_SHARED|MAP_ANON page is NOT inherited across
    // posix_spawn, which is how macOS forks -- see hvf_fork.hpp -- so the
    // table is a file descriptor, passed down like any other.)
    PidSpace() {
        char tmpl[] = "/tmp/linuxity-pids-XXXXXX";
        fd_ = ::mkstemp(tmpl);
        if (fd_ < 0) return;
        ::unlink(tmpl);
        if (::ftruncate(fd_, sizeof(Shared)) != 0) return;
        map();
        if (!shared_) return;
        // A fresh ftruncate'd file IS the all-zero Shared (every member is
        // an atomic or array whose zero is its initial value), and writing
        // it out would touch every page -- the signal mailbox alone is
        // 64 MiB of sparse file. So no placement-new: only what isn't zero.
        shared_->next.store(2, std::memory_order_relaxed);
        shared_->host[1].store(::getpid(), std::memory_order_relaxed);
    }
    // A fork child: attach to the parent's table through the inherited fd.
    explicit PidSpace(int inherited_fd) : fd_{inherited_fd} { map(); }
    [[nodiscard]] int fd() const noexcept { return fd_; }
    PidSpace(const PidSpace&) = delete;
    PidSpace& operator=(const PidSpace&) = delete;
    // Deliberately no munmap in the destructor: forked children inherit the
    // object and must not unmap the table out from under the rest of the tree.

    [[nodiscard]] bool valid() const noexcept { return shared_ != nullptr; }

    // -- The VM budget --------------------------------------------------------
    // Every guest process is a host process holding a Hypervisor.framework
    // VM, and a Mac allows kMaxVms of those at once (measured: 128, the
    // framework's limit). Warm zygotes hold one each while parked, so they
    // are budgeted across the WHOLE tree: a deep process tree must not
    // spend its VMs on idle spares and then fail the fork that needed one.
    // Spares may use what is left above kKeepFree; a real fork never waits
    // on this -- it falls back to a fresh process (its own VM) when no
    // spare is parked.
    static constexpr int kMaxVms = 128;
    static constexpr int kKeepFree = 32;   // never parked: real processes' headroom
    // Processes holding (or about to hold) a VM: every bound or reserved
    // slot -- a fork in flight (kReserved) needs one as much as a live one.
    [[nodiscard]] int live_processes() const noexcept {
        int n = 0;
        for (int g = 1; g < kMax; ++g)
            if (shared_->host[g].load(std::memory_order_relaxed) != 0) ++n;
        return n;
    }
    // Reserve a VM for one more parked zygote, if the tree can spare it.
    [[nodiscard]] bool reserve_warm_vm() noexcept {
        if (!shared_) return false;
        const int busy = live_processes();
        int w = shared_->warm_vms.load(std::memory_order_relaxed);
        do {
            if (busy + w + 1 > kMaxVms - kKeepFree) return false;
        } while (!shared_->warm_vms.compare_exchange_weak(w, w + 1));
        return true;
    }
    // A parked zygote was claimed (it becomes a live process) or exited.
    void release_warm_vm() noexcept {
        if (shared_) shared_->warm_vms.fetch_sub(1, std::memory_order_relaxed);
    }

    // Allocate a guest pid. `host` may be 0 to RESERVE the slot before the
    // host process exists (fork assigns the child's pid up front); bind()
    // fills it in once the host pid is known.
    [[nodiscard]] std::int32_t allocate(pid_t host) noexcept {
        const pid_t mark = host ? host : kReserved;
        for (int tries = 0; tries < kMax; ++tries) {
            int g = shared_->next.fetch_add(1, std::memory_order_relaxed);
            if (g >= kMax) { shared_->next.store(2); g = shared_->next.fetch_add(1); }
            pid_t expected = 0;
            if (shared_->host[g].compare_exchange_strong(expected, mark))
                return g;
        }
        return -1;
    }
    void bind(std::int32_t g, pid_t host) noexcept {
        if (g > 0 && g < kMax) {
            shared_->execed[g].store(false, std::memory_order_relaxed);
            shared_->ready[g].store(false, std::memory_order_relaxed);
            shared_->want_pgid[g].store(0, std::memory_order_relaxed);
            shared_->host[g].store(host, std::memory_order_release);
        }
    }

    // -- Process groups -----------------------------------------------------
    // Every guest process belongs to a group, identified by its leader's
    // guest pid. A group is what `kill(-pgid)` and a terminal's ^C target,
    // and what a shell puts a pipeline into.
    //
    // This has to be REAL rather than "every process is its own group":
    // pacman asks for its group with getpgrp() and then SIGTERMs it to stop
    // its download workers. With a flat model that group contains only
    // pacman, so pacman kills itself -- `pacman -Sy` died with "Terminated"
    // right after reporting every database up to date.
    void set_pgid(std::int32_t pid, std::int32_t pgid) noexcept {
        if (pid > 0 && pid < kMax && pgid > 0 && pgid < kMax)
            shared_->pgid[pid].store(pgid, std::memory_order_release);
    }
    [[nodiscard]] std::int32_t pgid_of(std::int32_t pid) const noexcept {
        if (pid <= 0 || pid >= kMax) return 0;
        const std::int32_t g = shared_->pgid[pid].load(std::memory_order_acquire);
        return g ? g : pid;                 // unset => its own leader
    }
    // POSIX's orphaned process group: no member has a parent in a
    // DIFFERENT group of the SAME session (nobody left to resume it after
    // a stop). Job-control stops aimed at one are discarded; a background
    // tty read from one is EIO.
    [[nodiscard]] bool pgrp_orphaned(std::int32_t pgid) const {
        for (const std::int32_t m : members_of(pgid)) {
            const std::int32_t p = ppid_of(m);
            if (p <= 0 || !shared_->host[p < kMax ? p : 0].load(std::memory_order_relaxed)) continue;
            if (pgid_of(p) != pgid && sid_of(p) == sid_of(m)) return false;
        }
        return true;
    }
    // -- Guest ptrace slots (see Shared::tracer) ---------------------------
    [[nodiscard]] std::int32_t tracer_of(std::int32_t g) const noexcept {
        return (g > 0 && g < kMax && shared_) ? shared_->tracer[g].load(std::memory_order_acquire) : 0;
    }
    void set_tracer(std::int32_t g, std::int32_t t) noexcept {
        if (g > 0 && g < kMax && shared_) {
            shared_->trace_opts[g].store(0, std::memory_order_relaxed);
            shared_->stop_status[g].store(0, std::memory_order_relaxed);
            shared_->tracer[g].store(t, std::memory_order_release);
        }
    }
    [[nodiscard]] std::int32_t trace_opts(std::int32_t g) const noexcept {
        return (g > 0 && g < kMax && shared_) ? shared_->trace_opts[g].load() : 0;
    }
    void set_trace_opts(std::int32_t g, std::int32_t o) noexcept {
        if (g > 0 && g < kMax && shared_) shared_->trace_opts[g].store(o);
    }
    // Tracee: park at a stop until the tracer resumes it. Returns the
    // request (PTRACE_CONT 7, PTRACE_SYSCALL 24, ...) and the signal to
    // deliver. `published` holds the regs the tracer may read and change.
    struct Resume { std::int32_t cmd, sig; bool regs_changed; };
    [[nodiscard]] Resume trace_stop(std::int32_t g, std::int32_t wstatus,
                                    const std::uint64_t (&published)[34], std::uint64_t (&back)[34],
                                    const std::function<bool()>& still_traced) noexcept {
        if (g <= 0 || g >= kMax || !shared_) return {7, 0, false};
        std::memcpy(shared_->regs[g], published, sizeof published);
        shared_->regs_dirty[g].store(false, std::memory_order_relaxed);
        const std::uint32_t gen = shared_->resume[g].load(std::memory_order_acquire);
        shared_->stop_reported[g].store(false, std::memory_order_relaxed);
        shared_->stop_status[g].store(wstatus, std::memory_order_release);
        // the tracer is a parent sleeping in wait: wake it
        const std::int32_t t = shared_->tracer[g].load();
        if (const auto th = host_of(t)) ::kill(*th, SIGCHLD);
        while (shared_->resume[g].load(std::memory_order_acquire) == gen) {
            if (!still_traced()) return {7, 0, false};
            ::usleep(200);
        }
        shared_->stop_status[g].store(0, std::memory_order_release);
        const bool changed = shared_->regs_dirty[g].exchange(false);
        if (changed) std::memcpy(back, shared_->regs[g], sizeof back);
        return {shared_->resume_cmd[g].load(), shared_->resume_sig[g].load(), changed};
    }
    // Tracer: the stop g sits in (0 = running), and whether wait took it.
    [[nodiscard]] std::int32_t stop_of(std::int32_t g) const noexcept {
        return (g > 0 && g < kMax && shared_) ? shared_->stop_status[g].load(std::memory_order_acquire) : 0;
    }
    [[nodiscard]] bool take_stop_report(std::int32_t g) noexcept {
        if (g <= 0 || g >= kMax || !shared_) return false;
        return shared_->stop_status[g].load() && !shared_->stop_reported[g].exchange(true);
    }
    // A stop posted and not yet reported (wait must not sleep past it).
    [[nodiscard]] bool take_stop_report_peek(std::int32_t g) const noexcept {
        if (g <= 0 || g >= kMax || !shared_) return false;
        return shared_->stop_status[g].load() && !shared_->stop_reported[g].load();
    }
    void trace_resume(std::int32_t g, std::int32_t cmd, std::int32_t sig) noexcept {
        if (g <= 0 || g >= kMax || !shared_) return;
        shared_->resume_cmd[g].store(cmd);
        shared_->resume_sig[g].store(sig);
        shared_->resume[g].fetch_add(1, std::memory_order_acq_rel);
    }
    [[nodiscard]] std::uint64_t* trace_regs(std::int32_t g) noexcept {
        return (g > 0 && g < kMax && shared_) ? shared_->regs[g] : nullptr;
    }
    void mark_regs_dirty(std::int32_t g) noexcept {
        if (g > 0 && g < kMax && shared_) shared_->regs_dirty[g].store(true);
    }

    // Every live member of a group, for kill(-pgid) and kill(0).
    struct PeerIds { std::uint32_t euid, egid; };
    void set_ids(std::int32_t g, std::uint32_t euid, std::uint32_t egid) noexcept {
        if (g <= 0 || g >= kMax || !shared_) return;
        shared_->euid1[g].store(euid + 1, std::memory_order_relaxed);
        shared_->egid1[g].store(egid + 1, std::memory_order_relaxed);
    }
    // ...and the real ones, for another reader's /proc/<g>/status Uid/Gid
    // and ps's RUSER (everything else in /proc reads the effective ones)
    void set_real_ids(std::int32_t g, std::uint32_t uid, std::uint32_t gid) noexcept {
        if (g <= 0 || g >= kMax || !shared_) return;
        shared_->ruid1[g].store(uid + 1, std::memory_order_relaxed);
        shared_->rgid1[g].store(gid + 1, std::memory_order_relaxed);
    }
    struct AllIds { std::uint32_t uid, euid, gid, egid; };
    [[nodiscard]] std::optional<AllIds> all_ids_of(std::int32_t g) const noexcept {
        const auto e = ids_of(g);
        if (!e) return std::nullopt;
        const auto u = shared_->ruid1[g].load(std::memory_order_relaxed);
        const auto gg = shared_->rgid1[g].load(std::memory_order_relaxed);
        return AllIds{u ? u - 1 : e->euid, e->euid, gg ? gg - 1 : e->egid, e->egid};
    }
    // What only the process itself knows about its GUEST, published for the
    // others' /proc: the host task's numbers count linuxity (its threads,
    // its own memory), not the program. 0 = not published.
    void set_threads(std::int32_t g, std::uint32_t n) noexcept {
        if (g > 0 && g < kMax && shared_) shared_->nthreads[g].store(n, std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint32_t threads_of(std::int32_t g) const noexcept {
        return g > 0 && g < kMax && shared_ ? shared_->nthreads[g].load(std::memory_order_relaxed) : 0;
    }
    // Guest process g's threads, leader first: every slot bound to g's host
    // process (a thread allocates its tid here with its process's host pid).
    // For another process's /proc/<g>/task, which only g's linuxity tracks.
    [[nodiscard]] std::vector<std::int32_t> tids_of(std::int32_t g) const {
        std::vector<std::int32_t> v;
        const auto h = host_of(g);
        if (!h || *h <= 0) return v;
        v.push_back(g);
        for (int t = 1; t < kMax; ++t)
            if (t != g && shared_->host[t].load(std::memory_order_relaxed) == *h) v.push_back(t);
        return v;
    }
    void set_vsize(std::int32_t g, std::uint64_t bytes) noexcept {
        if (g > 0 && g < kMax && shared_) shared_->vsize[g].store(bytes, std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t vsize_of(std::int32_t g) const noexcept {
        return g > 0 && g < kMax && shared_ ? shared_->vsize[g].load(std::memory_order_relaxed) : 0;
    }
    [[nodiscard]] std::optional<PeerIds> ids_of(std::int32_t g) const noexcept {
        if (g <= 0 || g >= kMax || !shared_) return std::nullopt;
        const auto u = shared_->euid1[g].load(std::memory_order_relaxed);
        const auto gg = shared_->egid1[g].load(std::memory_order_relaxed);
        if (!u) return std::nullopt;
        return PeerIds{u - 1, gg ? gg - 1 : 0};
    }
    [[nodiscard]] std::vector<std::int32_t> members_of(std::int32_t pgid) const {
        std::vector<std::int32_t> out;
        for (std::int32_t p = 1; p < kMax; ++p) {
            if (!shared_->host[p].load(std::memory_order_relaxed)) continue;
            if (pgid_of(p) == pgid) out.push_back(p);
        }
        return out;
    }
    // Sessions, same model: the leader's pid names the session.
    void set_sid(std::int32_t pid, std::int32_t sid) noexcept {
        if (pid > 0 && pid < kMax && sid > 0 && sid < kMax)
            shared_->sid[pid].store(sid, std::memory_order_release);
    }
    [[nodiscard]] std::int32_t sid_of(std::int32_t pid) const noexcept {
        if (pid <= 0 || pid >= kMax) return 0;
        const std::int32_t s = shared_->sid[pid].load(std::memory_order_acquire);
        return s ? s : pid;
    }
    // vfork support: a child announces it has exec'd (its parent may run).
    // A parent's setpgid for child `g`, for the child to apply (see Shared).
    void post_pgid(std::int32_t g, std::int32_t pgid) noexcept {
        if (g > 0 && g < kMax && shared_) shared_->want_pgid[g].store(pgid, std::memory_order_release);
    }
    [[nodiscard]] std::int32_t take_pgid(std::int32_t g) noexcept {
        return (g > 0 && g < kMax && shared_) ? shared_->want_pgid[g].exchange(0, std::memory_order_acq_rel) : 0;
    }
    [[nodiscard]] bool pgid_posted(std::int32_t g) const noexcept {
        return g > 0 && g < kMax && shared_ && shared_->want_pgid[g].load(std::memory_order_acquire) != 0;
    }
    [[nodiscard]] std::int32_t posted_pgid(std::int32_t g) const noexcept {
        return (g > 0 && g < kMax && shared_) ? shared_->want_pgid[g].load(std::memory_order_acquire) : 0;
    }
    void mark_ready(std::int32_t g) noexcept {
        if (g > 0 && g < kMax && shared_) shared_->ready[g].store(true, std::memory_order_release);
    }
    [[nodiscard]] bool ready(std::int32_t g) const noexcept {
        return g > 0 && g < kMax && shared_ && shared_->ready[g].load(std::memory_order_acquire);
    }

    void mark_execed(std::int32_t g) noexcept {
        if (g > 0 && g < kMax) shared_->execed[g].store(true, std::memory_order_release);
    }
    [[nodiscard]] bool has_execed(std::int32_t g) const noexcept {
        return g > 0 && g < kMax && shared_->execed[g].load(std::memory_order_acquire);
    }
    void release(std::int32_t g) noexcept {
        if (g > 1 && g < kMax) {
            shared_->exe[g][0] = '\0';
            shared_->comm[g][0] = '\0';
            shared_->tracer[g].store(0, std::memory_order_relaxed);
            shared_->stop_status[g].store(0, std::memory_order_relaxed);
            shared_->exited[g].store(false, std::memory_order_relaxed);
            shared_->exit_final[g].store(false, std::memory_order_relaxed);
            shared_->subreaper[g].store(false, std::memory_order_relaxed);
            shared_->nthreads[g].store(0, std::memory_order_relaxed);
            shared_->vsize[g].store(0, std::memory_order_relaxed);
            shared_->euid1[g].store(0, std::memory_order_relaxed);
            shared_->egid1[g].store(0, std::memory_order_relaxed);
            shared_->ruid1[g].store(0, std::memory_order_relaxed);
            shared_->rgid1[g].store(0, std::memory_order_relaxed);
            shared_->host[g].store(0, std::memory_order_relaxed);
        }
    }

    // /proc/<pid>/exe for any guest pid. Children inherit until they exec.
    void set_exe(std::int32_t g, std::string_view path) noexcept {
        if (g <= 0 || g >= kMax || !shared_) return;
        const std::size_t n = std::min(path.size(), kExe - 1);
        std::memcpy(shared_->exe[g], path.data(), n);
        shared_->exe[g][n] = '\0';
    }
    // /proc/<pid>/comm for any guest pid; empty until the first exec
    // records one (then the exe's basename stands in).
    void set_comm(std::int32_t g, std::string_view name) noexcept {
        if (g <= 0 || g >= kMax || !shared_) return;
        const std::size_t n = std::min(name.size(), kComm - 1);
        std::memcpy(shared_->comm[g], name.data(), n);
        shared_->comm[g][n] = '\0';
    }
    [[nodiscard]] std::string comm_of(std::int32_t g) const {
        if (g <= 0 || g >= kMax || !shared_) return {};
        char buf[kComm];
        std::memcpy(buf, shared_->comm[g], kComm);
        buf[kComm - 1] = '\0';
        return buf;
    }
    [[nodiscard]] std::string exe_of(std::int32_t g) const {
        if (g <= 0 || g >= kMax || !shared_) return {};
        char buf[kExe];
        std::memcpy(buf, shared_->exe[g], kExe);
        buf[kExe - 1] = '\0';
        return buf;
    }
    // A live guest PROCESS (not a thread: threads allocate a tid here too,
    // but only processes record an image). Its host pid must still exist.
    [[nodiscard]] bool is_process(std::int32_t g) const noexcept {
        if (g <= 0 || g >= kMax || !shared_ || !shared_->exe[g][0]) return false;
        const pid_t h = shared_->host[g].load(std::memory_order_relaxed);
        return h > 0 && (::kill(h, 0) == 0 || errno == EPERM);
    }
    [[nodiscard]] std::vector<std::int32_t> processes() const {
        std::vector<std::int32_t> out;
        if (!shared_) return out;
        for (int g = 1; g < kMax; ++g)
            if (shared_->exe[g][0] && is_process(g)) out.push_back(g);
        return out;
    }
    // The guest pid that forked g (0 for init). Recorded at fork.
    void set_ppid(std::int32_t g, std::int32_t parent) noexcept {
        if (g > 0 && g < kMax && shared_) shared_->ppid[g].store(parent, std::memory_order_relaxed);
    }
    [[nodiscard]] std::int32_t ppid_of(std::int32_t g) const noexcept {
        return (g > 0 && g < kMax && shared_) ? shared_->ppid[g].load(std::memory_order_relaxed) : 0;
    }

    // -- Orphans, subreapers -----------------------------------------------
    // Every guest process is its own HOST process whose host parent is the
    // linuxity that forked it, so when a guest parent dies the HOST hands
    // the orphan to launchd -- nothing a guest can see. The guest's view is
    // kept here instead: PR_SET_CHILD_SUBREAPER marks a pid, a process
    // exiting posts its status, and a parent that has gone is replaced by
    // its nearest living subreaper ancestor, else init (1), as Linux does.
    void set_subreaper(std::int32_t g, bool on) noexcept {
        if (g > 0 && g < kMax && shared_) shared_->subreaper[g].store(on, std::memory_order_relaxed);
    }
    [[nodiscard]] bool is_subreaper(std::int32_t g) const noexcept {
        return g > 0 && g < kMax && shared_ && shared_->subreaper[g].load(std::memory_order_relaxed);
    }
    // A process records how it ended (a Linux wait status), so a guest
    // parent that isn't its HOST parent (a subreaper that adopted it) can
    // still reap it.
    void post_exit(std::int32_t g, int linux_wstatus) noexcept {
        if (g <= 0 || g >= kMax || !shared_) return;
        shared_->exit_status[g].store(linux_wstatus, std::memory_order_relaxed);
        shared_->exited[g].store(true, std::memory_order_release);
    }
    // The posted status is FINAL though g's host process hasn't ended: its
    // HOST parent reaps g from it instead of waiting for the host exit
    // (HvfTrap::end_process says when that wait would never end).
    void mark_exit_final(std::int32_t g) noexcept {
        if (g > 0 && g < kMax && shared_) shared_->exit_final[g].store(true, std::memory_order_release);
    }
    [[nodiscard]] bool exit_final(std::int32_t g) const noexcept {
        return g > 0 && g < kMax && shared_ && shared_->exit_final[g].load(std::memory_order_acquire);
    }
    [[nodiscard]] std::optional<int> exit_of(std::int32_t g) const noexcept {
        if (g <= 0 || g >= kMax || !shared_ || !shared_->exited[g].load(std::memory_order_acquire))
            return std::nullopt;
        return shared_->exit_status[g].load(std::memory_order_relaxed);
    }
    // Has guest process g ended (exited, or its host process is gone)?
    [[nodiscard]] bool gone(std::int32_t g) const noexcept {
        if (g == 1) return false;                       // init outlives the tree
        if (exit_of(g)) return true;
        const auto h = host_of(g);
        return !h || *h <= 0 || ::kill(*h, 0) != 0;
    }
    // Who adopts the children of g when g ends: its nearest living
    // subreaper ancestor, else init (1). The ONE rule, for exit and getppid.
    [[nodiscard]] std::int32_t adopter_for(std::int32_t g) const noexcept {
        std::int32_t a = g;
        for (int hops = 0; hops < kMax; ++hops) {
            a = ppid_of(a);
            if (a <= 1) return 1;
            if (is_subreaper(a) && !gone(a)) return a;
        }
        return 1;
    }
    // g is ending: its live children get their adopter now, as Linux does at
    // exit, so a subreaper's wait sees them without them asking first.
    void reparent_children_of(std::int32_t g) noexcept {
        const std::int32_t to = adopter_for(g);
        for (const std::int32_t c : children_of(g)) set_ppid(c, to);
    }
    // The parent g should report now: its recorded parent while that lives,
    // else the adopter (a parent killed before it could reparent us).
    [[nodiscard]] std::int32_t live_parent_of(std::int32_t g) noexcept {
        const std::int32_t p = ppid_of(g);
        if (p <= 1 || !gone(p)) return p;
        const std::int32_t to = adopter_for(p);
        set_ppid(g, to);
        return to;
    }
    // Live processes whose guest parent is now `parent` though it didn't
    // fork them (adopted orphans), or that are ended and posted a status.
    [[nodiscard]] std::vector<std::int32_t> children_of(std::int32_t parent) const {
        std::vector<std::int32_t> out;
        if (!shared_) return out;
        for (int g = 2; g < kMax; ++g)
            if (shared_->host[g].load(std::memory_order_relaxed) > 0 && ppid_of(g) == parent)
                out.push_back(g);
        return out;
    }

    [[nodiscard]] std::optional<pid_t> host_of(std::int32_t g) const noexcept {
        if (g <= 0 || g >= kMax) return std::nullopt;
        pid_t h = shared_->host[g].load(std::memory_order_relaxed);
        return h ? std::optional{h} : std::nullopt;
    }
    [[nodiscard]] std::int32_t guest_of(pid_t host) const noexcept {
        for (int g = 1; g < kMax; ++g)
            if (shared_->host[g].load(std::memory_order_relaxed) == host) return g;
        return -1;
    }

    // -- Scheduler state per TASK (pid or tid), tree-wide. XNU has no CPU
    //    pinning and an unprivileged process can never lower its nice, so
    //    the guest's view lives here: what it set reads back from any
    //    process, and a fork (which copies the parent's) inherits it.
    void set_nice(std::int32_t g, int n) noexcept {
        if (g > 0 && g < kMax && shared_) shared_->nice[g].store(static_cast<std::int8_t>(n));
    }
    [[nodiscard]] int nice_of(std::int32_t g) const noexcept {
        return (g > 0 && g < kMax && shared_) ? shared_->nice[g].load() : 0;
    }
    void set_policy(std::int32_t g, int pol) noexcept {
        if (g > 0 && g < kMax && shared_) shared_->policy[g].store(static_cast<std::int8_t>(pol));
    }
    [[nodiscard]] int policy_of(std::int32_t g) const noexcept {
        return (g > 0 && g < kMax && shared_) ? shared_->policy[g].load() : 0;
    }
    // 0 = every CPU (the default); else the mask's bits.
    void set_affinity(std::int32_t g, std::uint64_t mask) noexcept {
        if (g > 0 && g < kMax && shared_) shared_->affinity[g].store(mask);
    }
    [[nodiscard]] std::uint64_t affinity_of(std::int32_t g) const noexcept {
        return (g > 0 && g < kMax && shared_) ? shared_->affinity[g].load() : 0;
    }

    // -- The signal mailbox -------------------------------------------------
    // A guest signal with no host twin (16, 30, real-time 32..64) cannot be
    // sent with kill(2), and a real-time one must QUEUE (one per send, each
    // with its sender) where a host signal merges. So the sender posts it
    // here and kicks the target (kKickSignal); the target drains it at its
    // next trap. Records are a fixed ring per process: a full ring is EAGAIN,
    // which is what sigqueue says when RLIMIT_SIGPENDING is reached.
    static constexpr int kSigRing = 1024;
    struct SigRecord { std::int32_t signo, sender, code, value; };
    [[nodiscard]] bool post_signal(std::int32_t g, SigRecord r) noexcept {
        if (g <= 0 || g >= kMax || !shared_) return false;
        auto& mb = shared_->mail[g];
        const std::uint32_t h = mb.head.fetch_add(1, std::memory_order_acq_rel);
        if (h - mb.tail.load(std::memory_order_acquire) >= kSigRing) {
            mb.head.fetch_sub(1, std::memory_order_acq_rel);
            return false;
        }
        auto& slot = mb.ring[h % kSigRing];
        slot.sender.store(r.sender, std::memory_order_relaxed);
        slot.code.store(r.code, std::memory_order_relaxed);
        slot.value.store(r.value, std::memory_order_relaxed);
        slot.signo.store(r.signo, std::memory_order_release);    // published last
        return true;
    }
    // The next posted record, or signo 0.
    [[nodiscard]] SigRecord take_signal(std::int32_t g) noexcept {
        if (g <= 0 || g >= kMax || !shared_) return {};
        auto& mb = shared_->mail[g];
        const std::uint32_t t = mb.tail.load(std::memory_order_acquire);
        if (t == mb.head.load(std::memory_order_acquire)) return {};
        auto& slot = mb.ring[t % kSigRing];
        const std::int32_t s = slot.signo.exchange(0, std::memory_order_acq_rel);
        if (!s) return {};                                         // not yet published
        SigRecord r{s, slot.sender.load(), slot.code.load(), slot.value.load()};
        mb.tail.store(t + 1, std::memory_order_release);
        return r;
    }
    void clear_mail(std::int32_t g) noexcept {
        if (g <= 0 || g >= kMax || !shared_) return;
        auto& mb = shared_->mail[g];
        for (auto& s : mb.ring) s.signo.store(0, std::memory_order_relaxed);
        mb.tail.store(mb.head.load());
    }

private:
    void map() {
        void* p = ::mmap(nullptr, sizeof(Shared), PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd_, 0);
        shared_ = p == MAP_FAILED ? nullptr : static_cast<Shared*>(p);
    }
    static constexpr pid_t kReserved = -1;
    static constexpr std::size_t kExe = 256;
    static constexpr std::size_t kComm = 16;   // TASK_COMM_LEN
    struct Shared {
        std::atomic<int> next{2};
        std::atomic<pid_t> host[kMax]{};
        std::atomic<bool> execed[kMax]{};
        // Process-group and session leader per pid; 0 means "itself".
        std::atomic<std::int32_t> pgid[kMax]{};
        std::atomic<std::int32_t> sid[kMax]{};
        // Guest path of each process's current image, for /proc/<pid>/exe.
        // Every guest process is its own HOST process, so only this shared
        // page can answer "what is pid N running" for a pid other than us.
        // Written by the process itself on exec; a seqlock-free best effort
        // (a torn read can only produce a wrong name, never a crash: the
        // buffer is always NUL-terminated at kExe-1).
        char exe[kMax][kExe]{};
        // /proc/<pid>/comm: the basename of the path given to execve (NOT
        // the resolved image: `/bin/sh` -> busybox is still "sh"), or what
        // PR_SET_NAME set on the leader. Same best-effort rules as exe.
        char comm[kMax][kComm]{};
        std::atomic<std::int32_t> ppid[kMax]{};
        // See set_subreaper / post_exit.
        std::atomic<bool> subreaper[kMax]{};
        std::atomic<bool> exited[kMax]{};
        std::atomic<int> exit_status[kMax]{};
        std::atomic<bool> exit_final[kMax]{};
        // setpgid(child, g) the PARENT asked for. Darwin refuses setpgid on
        // a child that has exec'd (EACCES), and every HVF child has exec'd
        // on the host from its first instruction -- though the GUEST child
        // has not. So the parent posts the group here and the child, which
        // may always move itself, applies it at its next trap. 0 = none.
        std::atomic<std::int32_t> want_pgid[kMax]{};
        // The process is past startup (its kick handler is installed): it
        // may be sent kKickSignal. Cleared with the slot.
        std::atomic<bool> ready[kMax]{};
        // Hypervisor.framework VMs held by PARKED zygotes, tree-wide.
        std::atomic<int> warm_vms{0};
        // See set_nice/set_policy/set_affinity.
        std::atomic<std::int8_t> nice[kMax]{};
        // Each process's effective uid/gid, as it last published them (SO_PEERCRED,
        // which a peer asks about from another host process). +1, 0 = unknown.
        std::atomic<std::uint32_t> euid1[kMax]{}, egid1[kMax]{};
        std::atomic<std::uint32_t> ruid1[kMax]{}, rgid1[kMax]{};
        std::atomic<std::uint32_t> nthreads[kMax]{};
        std::atomic<std::uint64_t> vsize[kMax]{};
        // Guest ptrace (no host ptrace across HVF processes). tracer: the
        // guest pid tracing g (0 = none). A tracee that hits a stop posts
        // stop_status (a Linux wait status, nonzero) and parks on `resume`
        // until the tracer bumps it, with the request in cmd/sig. A stop is
        // reported to wait once: `reported` is set when the tracer took it.
        // The tracee publishes its registers at each stop (regs, x0..x30, sp,
        // pc, pstate) for PTRACE_GETREGSET; SETREGSET writes them back.
        std::atomic<std::int32_t> tracer[kMax]{};
        std::atomic<std::int32_t> trace_opts[kMax]{};
        std::atomic<std::int32_t> stop_status[kMax]{};
        std::atomic<bool> stop_reported[kMax]{};
        std::atomic<std::uint32_t> resume[kMax]{};
        std::atomic<std::int32_t> resume_cmd[kMax]{}, resume_sig[kMax]{};
        std::atomic<bool> regs_dirty[kMax]{};
        std::uint64_t regs[kMax][34]{};
        std::atomic<std::int8_t> policy[kMax]{};
        std::atomic<std::uint64_t> affinity[kMax]{};
        // See post_signal. Allocated lazily: kMax x 1024 records is 64 MiB
        // of address space, but an anonymous shared map only costs the
        // pages a process actually touches.
        struct Slot {
            std::atomic<std::int32_t> signo{0}, sender{0}, code{0}, value{0};
        };
        struct Mailbox {
            std::atomic<std::uint32_t> head{0}, tail{0};
            Slot ring[kSigRing];
        };
        Mailbox mail[kMax];
    };
    Shared* shared_{nullptr};
    int fd_{-1};
};

// Linux and Darwin agree on the wait status ENCODING (WIFEXITED etc. are the
// same bit layout), but not on every signal NUMBER. Translate the ones that
// differ so a guest shell reports "Killed"/"Terminated"/"Segmentation fault"
// correctly. The low 15 are POSIX-fixed and identical.
// The host signal one guest process sends another to say "look at your
// mailbox in the shared table" (a parent's setpgid). Darwin's SIGEMT: it
// exists on no Linux arch the guest runs, so no guest signal maps to it.
inline constexpr int kKickSignal = SIGEMT;

// The two numberings agree on 1-6, 8, 9, 11, 13-15 and nothing else. Every
// other Linux signal either has a Darwin twin under ANOTHER number or none.
// Mapping must be a bijection on what it maps: passing an unmatched Linux
// number through unchanged lands on a DIFFERENT Darwin signal -- Linux 30
// (SIGPWR) is Darwin's SIGUSR1, Linux 10 (SIGUSR1) Darwin's SIGBUS -- so a
// guest that merely set SIGPWR to SIG_DFL (Python does, for every signal)
// reset the host's SIGUSR1 and the next kill(SIGUSR1) killed the process.
// Linux-only signals (16 SIGSTKFLT, 30 SIGPWR, 32..64 real-time) have no
// host signal: 0, and the guest keeps them in its own pending set.
[[nodiscard]] constexpr int signal_to_linux(int s) noexcept {
    switch (s) {
        case SIGEMT:  return 0;          // linuxity's own kick (kKickSignal)
        case SIGBUS:  return 7;
        case SIGUSR1: return 10;
        case SIGUSR2: return 12;
        case SIGCHLD: return 17;
        case SIGCONT: return 18;
        case SIGSTOP: return 19;
        case SIGTSTP: return 20;
        case SIGTTIN: return 21;
        case SIGTTOU: return 22;
        case SIGURG:  return 23;
        case SIGXCPU: return 24;
        case SIGXFSZ: return 25;
        case SIGVTALRM: return 26;
        case SIGPROF: return 27;
        case SIGWINCH: return 28;
        case SIGIO:   return 29;
        case SIGSYS:  return 31;
        case SIGINFO: return 0;          // Darwin-only
        default:      return s >= 1 && s <= 15 && s != 7 && s != 10 && s != 12 ? s : 0;
    }
}
[[nodiscard]] constexpr int signal_from_linux(int s) noexcept {
    switch (s) {
        case 7:  return SIGBUS;
        case 10: return SIGUSR1;
        case 12: return SIGUSR2;
        case 17: return SIGCHLD;
        case 18: return SIGCONT;
        case 19: return SIGSTOP;
        case 20: return SIGTSTP;
        case 21: return SIGTTIN;
        case 22: return SIGTTOU;
        case 23: return SIGURG;
        case 24: return SIGXCPU;
        case 25: return SIGXFSZ;
        case 26: return SIGVTALRM;
        case 27: return SIGPROF;
        case 28: return SIGWINCH;
        case 29: return SIGIO;
        case 31: return SIGSYS;
        default: return s >= 1 && s <= 15 ? s : 0;     // 16, 30, 32..64: none
    }
}
static_assert(signal_to_linux(signal_from_linux(10)) == 10);
static_assert(signal_from_linux(30) == 0 && signal_from_linux(16) == 0 && signal_from_linux(40) == 0);
static_assert(signal_to_linux(SIGUSR1) == 10 && signal_to_linux(SIGBUS) == 7);

// A Darwin wait status -> the Linux encoding of the same event.
[[nodiscard]] constexpr int wstatus_to_linux(int st) noexcept {
    // Darwin's "continued" is a stop by SIGCONT (0x137f); Linux's is 0xffff.
    // Test it FIRST: WIFSTOPPED is true of it too.
    if (WIFCONTINUED(st)) return 0xffff;
    if (WIFEXITED(st))   return (WEXITSTATUS(st) & 0xff) << 8;
    if (WIFSIGNALED(st)) return (signal_to_linux(WTERMSIG(st)) & 0x7f) | (WCOREDUMP(st) ? 0x80 : 0);
    if (WIFSTOPPED(st))  return (signal_to_linux(WSTOPSIG(st)) << 8) | 0x7f;
    return st;
}

} // namespace lx::runtime

#endif // __APPLE__
