// Guest ptrace, included inside class PtraceTrap (ptrace_trap.hpp).
//
// linuxity is every guest task's real tracer, and a task can have only one,
// so a guest that traces another guest (strace, gdb, anything built on
// ptrace) is emulated here. The tracee really is stopped -- in linuxity's own
// ptrace stop -- and those stops are shown to the guest tracer through wait4,
// SIGCHLD and the ptrace requests, which linuxity carries out on the tracee
// with its own real ptrace. Register and memory access are the kernel's.

public:
    // glibc types ptrace's request as an enum, bionic and musl as int
#if defined(__GLIBC__)
    using PtReq = __ptrace_request;
#else
    using PtReq = int;
#endif
    // ptrace(2) by the current task. Returns the syscall result.
    [[nodiscard]] std::int64_t guest_ptrace(std::int64_t req, std::int64_t pid_view,
                                            std::uint64_t addr, std::uint64_t data) {
        constexpr std::int64_t kTraceme = 0, kPeekText = 1, kPeekData = 2, kPeekUsr = 3,
            kPokeText = 4, kPokeData = 5, kPokeUsr = 6, kCont = 7, kKill = 8, kStep = 9,
            kGetRegs = 12, kSetRegs = 13, kGetFpRegs = 14, kSetFpRegs = 15, kAttach = 16,
            kDetach = 17, kGetFpxRegs = 18, kSetFpxRegs = 19, kSyscall = 24, kSysemu = 31,
            kSysemuStep = 32, kSetOptions = 0x4200, kGetEventMsg = 0x4201,
            kGetSiginfo = 0x4202, kSetSiginfo = 0x4203, kGetRegset = 0x4204,
            kSetRegset = 0x4205, kSeize = 0x4206, kInterrupt = 0x4207, kListen = 0x4208,
            kPeekSiginfo = 0x4209, kGetSigmask = 0x420a, kSetSigmask = 0x420b,
            kSeccompGetFilter = 0x420c, kSeccompGetMeta = 0x420d, kGetSyscallInfo = 0x420e,
            kGetRseq = 0x420f;
        const ::pid_t me = cur_;
        const ::pid_t me_tg = host_tgid_of(me);

        if (req == kTraceme) {
            if (gtr_.count(me)) return -EPERM;
            const ::pid_t parent = host_ppid_of(me);
            // the parent has to be a guest task to act as the tracer
            if (parent <= 0 || known_gpid_of(parent) <= 0) return -EPERM;
            GtTrace tr;
            tr.tracer = host_tgid_of(parent);
            gtr_.emplace(me, tr);
            return 0;
        }

        // the tracee, named the way the caller names pids
        const std::int32_t viewer = known_gpid_of(me_tg);
        const std::int32_t gp = global_pid(viewer, static_cast<std::int32_t>(pid_view));
        const ::pid_t host = gp > 0 ? host_tid_of(gp) : -1;
        if (host <= 0 || !tasks_.count(host)) return -ESRCH;

        if (req == kAttach || req == kSeize) {
            if (host_tgid_of(host) == me_tg) return -EPERM;
            if (gtr_.count(host)) return -EPERM;
            if (gt_yama_ >= 3) return -EPERM;
            if (req == kSeize && (data & ~kGtOptMask)) return -EINVAL;
            GtTrace tr;
            tr.tracer = me_tg;
            tr.seized = req == kSeize;
            tr.opts = req == kSeize ? data : 0;
            auto& t = gtr_.emplace(host, tr).first->second;
            if (t.opts & kOptExit) gt_sync_exit_opt(host, t);
            if (req == kAttach) {
                if (stopped_.count(host)) {
                    // already in a group-stop: that is its attach stop
                    gt_queue(host, gt_sig_report(SIGSTOP, nullptr, true));
                    gt_park(host);
                } else {
                    t.attach_pending = true;
                    // a task not yet at its first stop reports it there
                    if (gt_first_seen_.count(host) || host == root_pid_)
                        ::syscall(SYS_tgkill, host_tgid_of(host), host, SIGSTOP);
                }
            }
            return 0;
        }

        auto it = gtr_.find(host);
        if (it == gtr_.end() || it->second.tracer != me_tg) return -ESRCH;
        GtTrace& tr = it->second;

        if (req == kKill) {
            ::syscall(SYS_tgkill, host_tgid_of(host), host, SIGKILL);
            return 0;
        }
        if (req == kInterrupt) {
            if (!tr.seized) return -EIO;
            if (!tr.parked && !tr.interrupt_pending) {
                tr.interrupt_pending = true;
                if (gt_first_seen_.count(host) || host == root_pid_)
                    ::syscall(SYS_tgkill, host_tgid_of(host), host, SIGSTOP);
            }
            return 0;
        }
        if (req == kDetach) {
            if (!tr.parked) return -ESRCH;
            const int sig = static_cast<int>(data);
            const bool owes = tasks_[host].in_call;
            gtr_.erase(it);
            ::ptrace(PTRACE_SETOPTIONS, host, 0, base_opts_);
            if (owes) ::ptrace(PTRACE_SYSCALL, host, 0, sig);
            else      resume_run(host, sig);
            return 0;
        }
        if (!tr.parked) return -ESRCH;   // every other request needs a stopped tracee
        GtReport& rep = tr.q.front();

        switch (req) {
            case kCont: case kSyscall: case kStep: case kSysemu: case kSysemuStep: {
                const int sig = static_cast<int>(data);
                if (sig < 0 || sig > 64) return -EIO;
                const int mode = req == kSyscall ? kModeSyscall
                               : (req == kStep || req == kSysemuStep) ? kModeStep : kModeCont;
                gt_release(host, sig, mode);
                return 0;
            }
            case kListen:
                if (!tr.seized) return -EIO;
                tr.reported = true;
                return 0;
            case kPeekText: case kPeekData: case kPeekUsr: {
                errno = 0;
                const int op = req == kPeekUsr ? PTRACE_PEEKUSER : PTRACE_PEEKDATA;
                const long v = ::ptrace(static_cast<PtReq>(op), host,
                                        reinterpret_cast<void*>(addr), nullptr);
                if (errno) return -errno;
                if (!gt_put(data, &v, sizeof v)) return -EFAULT;
                return 0;
            }
            case kPokeText: case kPokeData: case kPokeUsr: {
                const int op = req == kPokeUsr ? PTRACE_POKEUSER : PTRACE_POKEDATA;
                if (::ptrace(static_cast<PtReq>(op), host, reinterpret_cast<void*>(addr),
                             reinterpret_cast<void*>(data)) != 0)
                    return -errno;
                return 0;
            }
            case kGetRegs: case kGetFpRegs: case kGetFpxRegs: case kSetRegs: case kSetFpRegs: case kSetFpxRegs: {
#if defined(__x86_64__)
                const bool get = req == kGetRegs || req == kGetFpRegs || req == kGetFpxRegs;
                const std::size_t n = (req == kGetRegs || req == kSetRegs) ? 216 : 512;
                std::vector<std::byte> buf(n);
                if (!get && !gt_get(data, buf.data(), n)) return -EFAULT;
                if (::ptrace(static_cast<PtReq>(req), host, nullptr, buf.data()) != 0) return -errno;
                if (get && !gt_put(data, buf.data(), n)) return -EFAULT;
                return 0;
#else
                return -EIO;   // not on this arch, as on Linux
#endif
            }
            case kGetRegset: case kSetRegset: {
                std::uint64_t iov[2];
                if (!gt_get(data, iov, sizeof iov)) return -EFAULT;
                const std::size_t n = std::min<std::uint64_t>(iov[1], 1u << 16);
                std::vector<std::byte> buf(n);
                if (req == kSetRegset && !gt_get(iov[0], buf.data(), n)) return -EFAULT;
                ::iovec local{buf.data(), n};
                if (::ptrace(static_cast<PtReq>(req), host, reinterpret_cast<void*>(addr), &local) != 0)
                    return -errno;
                if (req == kGetRegset) {
                    if (local.iov_len && !gt_put(iov[0], buf.data(), local.iov_len)) return -EFAULT;
                    iov[1] = local.iov_len;
                    if (!gt_put(data, iov, sizeof iov)) return -EFAULT;
                }
                return 0;
            }
            case kGetSiginfo:
                if (rep.kind == GtReport::group) return -EINVAL;   // a group-stop has none
                if (!gt_put(data, &rep.si, sizeof rep.si)) return -EFAULT;
                return 0;
            case kSetSiginfo:
                if (rep.kind == GtReport::group) return -EINVAL;
                if (!gt_get(data, &rep.si, sizeof rep.si)) return -EFAULT;
                rep.si_changed = true;
                return 0;
            case kGetEventMsg:
                if (!gt_put(data, &rep.msg, sizeof rep.msg)) return -EFAULT;
                return 0;
            case kSetOptions:
                if (data & ~kGtOptMask) return -EINVAL;
                tr.opts = data;
                gt_sync_exit_opt(host, tr);
                return 0;
            case kGetSyscallInfo:
                return gt_syscall_info(host, tr, addr, data);
            case kPeekSiginfo: {
                struct { std::uint64_t off; std::uint32_t flags; std::int32_t nr; } a{};
                if (!gt_get(addr, &a, sizeof a)) return -EFAULT;
                const int nr = std::clamp(a.nr, 0, 64);
                std::vector<siginfo_t> buf(static_cast<std::size_t>(nr ? nr : 1));
                a.nr = nr;
                const long got = ::ptrace(static_cast<PtReq>(kPeekSiginfo), host, &a, buf.data());
                if (got < 0) return -errno;
                if (got && !gt_put(data, buf.data(), static_cast<std::size_t>(got) * sizeof(siginfo_t))) return -EFAULT;
                return got;
            }
            case kGetSigmask: case kSetSigmask: case kGetRseq: {
                std::uint64_t buf[8]{};
                const std::size_t n = std::min<std::uint64_t>(addr, sizeof buf);
                if (req == kSetSigmask && !gt_get(data, buf, n)) return -EFAULT;
                const long r = ::ptrace(static_cast<PtReq>(req), host, reinterpret_cast<void*>(addr), buf);
                if (r < 0) return -errno;
                if (req != kSetSigmask && !gt_put(data, buf, n)) return -EFAULT;
                return r;
            }
            case kSeccompGetFilter: case kSeccompGetMeta:
                return -EINVAL;   // the guest installed no filter of its own
            default:
                return -EIO;
        }
    }

    // wait4 by the current task: a stop or exit of one of its tracees, if
    // it has one to report. forward = not about tracees, let it run; block
    // = it has tracees but nothing yet (poll the real wait4 and try again).
    enum class GtWait { forward, answered, block };
    [[nodiscard]] GtWait guest_wait4(std::int64_t pid_host, std::uint64_t status_addr, int options,
                                     std::uint64_t rusage, std::int64_t& ret) {
        if (gtr_.empty() && gt_exits_.empty()) return GtWait::forward;
        const ::pid_t me_tg = host_tgid_of(cur_);
        if (pid_host < -1) return GtWait::forward;
        auto match = [&](::pid_t w) { return pid_host <= 0 || w == pid_host; };
        bool have = false;
        for (auto& [w, tr] : gtr_) {
            if (tr.tracer != me_tg || !match(w)) continue;
            have = true;
            if (!tr.parked || tr.reported || tr.q.empty()) continue;
            const int st = tr.q.front().status;
            if (status_addr && !gt_put(status_addr, &st, sizeof st)) { ret = -EFAULT; return GtWait::answered; }
            if (rusage) { std::array<std::byte, 144> z{}; (void)gt_put(rusage, z.data(), z.size()); }
            if (!(options & 0x01000000 /*WNOWAIT*/)) tr.reported = true;
            ret = gt_view_of(w);
            return GtWait::answered;
        }
        if (auto e = gt_exits_.find(me_tg); e != gt_exits_.end()) {
            for (auto x = e->second.begin(); x != e->second.end(); ++x) {
                if (pid_host > 0 && x->host != pid_host) continue;
                if (status_addr && !gt_put(status_addr, &x->status, sizeof x->status)) { ret = -EFAULT; return GtWait::answered; }
                ret = local_pid(known_gpid_of(me_tg), x->gpid);
                if (!(options & 0x01000000)) e->second.erase(x);
                return GtWait::answered;
            }
        }
        return have ? GtWait::block : GtWait::forward;
    }

    // For /proc: who traces guest task `gtid` (global guest pid, 0 = nobody)
    // and whether it is stopped for that tracer right now.
    [[nodiscard]] std::pair<std::int32_t, bool> guest_trace_info(std::int32_t gtid) const {
        const ::pid_t host = host_tid_of(gtid);
        auto it = gtr_.find(host);
        if (it == gtr_.end()) return {0, false};
        return {known_gpid_of(it->second.tracer), it->second.parked};
    }

private:
    static constexpr std::uint64_t kGtOptMask = 0x003000ff;
    static constexpr std::uint64_t kOptSysGood = 1, kOptFork = 2, kOptVfork = 4, kOptClone = 8,
                                   kOptExec = 0x10, kOptExit = 0x40, kOptExitKill = 0x100000;
    static constexpr int kModeCont = 0, kModeSyscall = 1, kModeStep = 2;

    struct GtReport {
        enum Kind { sig, group, sys_entry, sys_exit, event } kind{sig};
        int status{0};
        int signo{0};                // the signal a signal-delivery-stop holds
        siginfo_t si{};
        bool si_changed{false};
        unsigned long msg{0};
        bool restore{false};         // put `saved` back once this stop is done
        Regs saved{};
    };
    struct GtTrace {
        ::pid_t tracer{0};          // the tracer's thread group (host)
        std::uint64_t opts{0};
        bool seized{false};
        int mode{kModeCont};
        bool parked{false};          // stopped for the tracer, showing q.front()
        bool reported{false};        // its wait4 already saw q.front()
        std::deque<GtReport> q;
        bool in_sys{false};          // an entry was reported, its exit not yet
        Regs entry{};                // the registers at that entry stop
        bool redispatch{false};      // no-seccomp entry: dispatch it on release
        bool after_event{false};     // parked at a fork/exec event stop
        bool exec_exit_pending{false};
        bool defer_exec{false};      // loader-started exec, stop held
        bool deferred_exit_seen{false};
        int defer_left{0};
        bool entry_after{false};     // after the held exec, show this entry
        bool attach_pending{false};
        bool interrupt_pending{false};
        bool auto_attach{false};     // a child auto-traced via TRACEFORK etc
        int carry_sig{0};
    };
    struct GtExit { ::pid_t host; std::int32_t gpid; int status; };

    std::unordered_map<::pid_t, GtTrace> gtr_;
    std::unordered_map<::pid_t, std::deque<GtExit>> gt_exits_;   // by tracer tgid
    std::unordered_map<::pid_t, std::deque<std::pair<std::int32_t, int>>> gt_chld_;
    std::deque<::pid_t> redispatch_;
    int gt_yama_{1};

    [[nodiscard]] static int gt_status(int sig, int event = 0) { return ((sig | (event << 8)) << 8) | 0x7f; }
    [[nodiscard]] bool gt_put(std::uint64_t addr, const void* p, std::size_t n) {
        return copy_out(uaddr(addr), {static_cast<const std::byte*>(p), n}).has_value();
    }
    [[nodiscard]] bool gt_get(std::uint64_t addr, void* p, std::size_t n) {
        return copy_in(uaddr(addr), {static_cast<std::byte*>(p), n}).has_value();
    }
    // The tracer's view of a tracee: its guest pid in the tracer's pid namespace.
    [[nodiscard]] std::int32_t gt_view_of(::pid_t w) {
        const auto it = gtr_.find(w);
        const ::pid_t tracer = it == gtr_.end() ? 0 : it->second.tracer;
        const std::int32_t l = local_pid(known_gpid_of(tracer), gpid_of(w));
        return l > 0 ? l : gpid_of(w);
    }
    [[nodiscard]] static ::pid_t host_ppid_of(::pid_t w) {
        char path[64];
        std::snprintf(path, sizeof path, "/proc/%d/status", w);
        std::FILE* f = std::fopen(path, "re");
        if (!f) return -1;
        char line[256];
        ::pid_t pp = -1;
        while (std::fgets(line, sizeof line, f))
            if (std::sscanf(line, "PPid: %d", &pp) == 1) break;
        std::fclose(f);
        return pp;
    }

    [[nodiscard]] GtReport gt_sig_report(int sig, const siginfo_t* si, bool group = false) {
        GtReport r;
        r.kind = group ? GtReport::group : GtReport::sig;
        r.signo = sig;
        r.status = gt_status(sig);
        if (si) r.si = *si;
        else { r.si.si_signo = sig; r.si.si_code = SI_USER; }
        return r;
    }
    [[nodiscard]] GtReport gt_sys_report(const GtTrace& tr, bool entry) {
        GtReport r;
        r.kind = entry ? GtReport::sys_entry : GtReport::sys_exit;
        const int code = SIGTRAP | ((tr.opts & kOptSysGood) ? 0x80 : 0);
        r.status = gt_status(code);
        r.si.si_signo = SIGTRAP;
        r.si.si_code = code;
        r.msg = entry ? 1 : 2;   // PTRACE_EVENTMSG_SYSCALL_ENTRY / _EXIT
        return r;
    }
    [[nodiscard]] static GtReport gt_event_report(int event, unsigned long msg) {
        GtReport r;
        r.kind = GtReport::event;
        r.status = gt_status(SIGTRAP, event);
        r.si.si_signo = SIGTRAP;
        r.si.si_code = SIGTRAP | (event << 8);
        r.msg = msg;
        return r;
    }

    void gt_queue(::pid_t w, GtReport r) { gtr_[w].q.push_back(std::move(r)); }
    // Show the tracer the first queued stop (if it isn't already looking at one).
    void gt_park(::pid_t w) {
        auto& tr = gtr_[w];
        if (tr.q.empty() || tr.parked) return;
        tr.parked = true;
        tr.reported = false;
        gt_notify(w);
    }
    // SIGCHLD to the tracer, CLD_TRAPPED like the kernel's (rewrite_siginfo_pid
    // fills the details when it is delivered).
    void gt_notify(::pid_t w) {
        const auto& tr = gtr_[w];
        const int stopsig = tr.q.empty() ? SIGTRAP : (tr.q.front().status >> 8) & 0x7f;
        gt_chld_[tr.tracer].push_back({gpid_of(w), stopsig});
        ::kill(tr.tracer, SIGCHLD);
    }
    // Rewrite a SIGCHLD we sent a tracer into CLD_TRAPPED for its tracee.
    bool gt_fix_chld(::pid_t w, siginfo_t& si) {
        if (si.si_signo != SIGCHLD || si.si_code != SI_USER || si.si_pid != ::getpid()) return false;
        auto it = gt_chld_.find(host_tgid_of(w));
        if (it == gt_chld_.end() || it->second.empty()) return false;
        const auto [g, stopsig] = it->second.front();
        it->second.pop_front();
        si.si_code = CLD_TRAPPED;
        si.si_pid = local_pid(known_gpid_of(host_tgid_of(w)), g);
        si.si_uid = 0;
        si.si_status = stopsig;
        return true;
    }

    // The tracer resumed its tracee with `sig`, in `mode`.
    void gt_release(::pid_t w, int sig, int mode) {
        auto& tr = gtr_[w];
        tr.mode = mode;
        if (mode != kModeSyscall) { tr.in_sys = false; tr.exec_exit_pending = false; }
        GtReport cur = std::move(tr.q.front());
        tr.q.pop_front();
        if (cur.restore) (void)cur.saved.store(w);
        // a signal only means something leaving a signal or syscall stop
        if (cur.kind == GtReport::event || cur.kind == GtReport::group) sig = 0;
        if (cur.kind == GtReport::sig && sig && cur.si_changed && sig == cur.signo)
            ::ptrace(PTRACE_SETSIGINFO, w, 0, &cur.si);
        if (!tr.q.empty()) {
            if (sig) tr.carry_sig = sig;
            tr.reported = false;
            gt_notify(w);
            return;
        }
        tr.parked = false;
        if (!sig) sig = std::exchange(tr.carry_sig, 0);
        if (tr.entry_after) {
            // parked at a syscall entry after the held exec
            tr.entry_after = false;
            if (mode == kModeSyscall) {
                (void)Regs::fetch(w, tr.entry);
                tr.in_sys = true;
                tr.parked = false;
                if (!seccomp_) tr.redispatch = true;
                gt_queue(w, gt_sys_report(tr, true));
                if (sig) tr.carry_sig = sig;
                gt_park(w);
                return;
            }
            if (!seccomp_) {
                tasks_[w].pending_sig = sig;
                redispatch_.push_back(w);
                return;
            }
            ::ptrace(PTRACE_CONT, w, 0, sig);
            return;
        }
        if (tr.redispatch) {
            tr.redispatch = false;
            tasks_[w].pending_sig = sig;
            redispatch_.push_back(w);
            return;
        }
        if (tr.after_event) {
            tr.after_event = false;
            if (tasks_[w].in_call) { ::ptrace(PTRACE_SYSCALL, w, 0, sig); return; }
        }
        gt_plain_resume(w, sig);
    }
    // Run a traced task the way its tracer asked.
    void gt_plain_resume(::pid_t w, int sig) {
        const auto& tr = gtr_[w];
        if (tr.defer_exec || tasks_[w].in_call || tr.mode == kModeSyscall || tr.exec_exit_pending)
            ::ptrace(PTRACE_SYSCALL, w, 0, sig);
        else if (tr.mode == kModeStep)
            ::ptrace(PTRACE_SINGLESTEP, w, 0, sig);
        else
            ::ptrace(seccomp_ ? PTRACE_CONT : PTRACE_SYSCALL, w, 0, sig);
    }

    // linuxity finished serving a syscall for `w`. A tracee whose entry was
    // shown gets its exit shown too, with the arguments as the guest passed
    // them (path rewriting may have changed them).
    void sys_done(::pid_t w, bool kernel_owes_exit = false) {
        tasks_[w].in_call = false;
        auto it = gtr_.find(w);
        if (it == gtr_.end() || !it->second.in_sys || it->second.exec_exit_pending ||
            it->second.defer_exec) return;
        // answered at the entry: the kernel still stops at the (skipped)
        // call's exit, and that stop is shown as the exit
        if (kernel_owes_exit) return;
        GtTrace& tr = it->second;
        tr.in_sys = false;
        Regs now{};
        if (Regs::fetch(w, now)) {
            for (int k = 1; k < 6; ++k) now.set_arg(k, tr.entry.arg(k));
#if defined(__x86_64__)
            now.set_arg(0, tr.entry.arg(0));
#endif
            (void)now.store(w);
        }
        gt_queue(w, gt_sys_report(tr, false));
    }

    // Is `w` a traced task whose syscall exit must be shown? (forward() may
    // not skip the exit stop for it.)
    [[nodiscard]] bool gt_wants_exit(::pid_t w) const {
        auto it = gtr_.find(w);
        return it != gtr_.end() && it->second.in_sys && !it->second.defer_exec;
    }

    // ---- hooks from the stop loop -------------------------------------------
    // A signal stop for a traced task. True if handled (task stays stopped).
    bool gt_on_signal_stop(::pid_t w, int sig) {
        auto it = gtr_.find(w);
        if (it == gtr_.end()) return false;
        GtTrace& tr = it->second;
        siginfo_t si{};
        const bool have_si = ::ptrace(PTRACE_GETSIGINFO, w, 0, &si) == 0;
        if (!have_si && errno == EINVAL) {   // a group-stop
            gt_queue(w, gt_sig_report(sig, nullptr, true));
            gt_park(w);
            return true;
        }
        if (sig == SIGSTOP && tr.interrupt_pending && have_si && si.si_pid == ::getpid()) {
            tr.interrupt_pending = false;
            gt_queue(w, gt_event_report(128 /*PTRACE_EVENT_STOP*/, 0));
            gt_park(w);
            return true;
        }
        if (sig == SIGSTOP && tr.attach_pending && have_si && si.si_pid == ::getpid()) {
            tr.attach_pending = false;
            GtReport r = gt_sig_report(SIGSTOP, &si);
            r.si.si_pid = 0;
            gt_queue(w, std::move(r));
            gt_park(w);
            return true;
        }
        rewrite_siginfo_pid(w);
        (void)::ptrace(PTRACE_GETSIGINFO, w, 0, &si);
        gt_queue(w, gt_sig_report(sig, have_si ? &si : nullptr));
        gt_park(w);
        return true;
    }

    // A fresh task's first (attach) stop: auto-trace it if its creator is
    // traced with TRACEFORK/VFORK/CLONE, and show that first stop.
    bool gt_on_new_task(::pid_t w) {
        gt_first_seen_.insert(w);
        auto mine = gtr_.find(w);
        if (mine != gtr_.end() && mine->second.auto_attach) {
            mine->second.auto_attach = false;
            gt_queue(w, mine->second.seized ? gt_event_report(128, 0) : gt_sig_report(SIGSTOP, nullptr));
            gt_park(w);
            return true;
        }
        if (mine != gtr_.end()) {
            // our attach/interrupt SIGSTOP merged into this first stop
            GtTrace& tr = mine->second;
            if (tr.interrupt_pending) {
                tr.interrupt_pending = false;
                gt_queue(w, gt_event_report(128, 0));
                gt_park(w);
                return true;
            }
            if (tr.attach_pending) {
                tr.attach_pending = false;
                gt_queue(w, gt_sig_report(SIGSTOP, nullptr));
                gt_park(w);
                return true;
            }
            return false;
        }
        // the creator: the thread group for a thread, else the parent
        const ::pid_t tg = tgid_of(w);
        const bool thread = tg != w;
        const ::pid_t creator_tg = thread ? tg : host_ppid_of(w);
        if (creator_tg <= 0) return false;
        // its creator is traced with clone/fork options, but the creator's
        // event (which makes it a tracee) hasn't come yet: hold it until then
        for (const auto& [t, tr] : gtr_)
            if (host_tgid_of(t) == creator_tg && (tr.opts & (kOptFork | kOptVfork | kOptClone))) {
                gt_held_new_.insert(w);
                return true;
            }
        return false;
    }
    std::unordered_set<::pid_t> gt_held_new_;
    std::unordered_set<::pid_t> gt_first_seen_;   // tasks past their first stop

    // A fork/vfork/clone event of `w`: auto-trace the child and queue the
    // event stop for the parent if its options ask for it.
    void gt_on_fork_event(::pid_t w, int event, ::pid_t child) {
        auto it = gtr_.find(w);
        if (it == gtr_.end() || child <= 0) {
            // not traced after all: let a held child go
            if (gt_held_new_.erase(child)) resume_run(child, 0);
            return;
        }
        const std::uint64_t want = event == PTRACE_EVENT_FORK ? kOptFork
                                 : event == PTRACE_EVENT_VFORK ? kOptVfork : kOptClone;
        if (!(it->second.opts & want)) {
            if (gt_held_new_.erase(child)) resume_run(child, 0);
            return;
        }
        if (!gtr_.count(child)) {
            GtTrace c;
            c.tracer = it->second.tracer;
            c.opts = it->second.opts;
            c.seized = it->second.seized;
            c.auto_attach = true;
            gtr_.emplace(child, c);
        }
        // a child that already took its first stop shows it now
        if (gt_held_new_.erase(child)) gt_on_new_task(child);
        GtTrace& tr = gtr_[w];
        gt_queue(w, gt_event_report(event, static_cast<unsigned long>(local_pid(known_gpid_of(tr.tracer), gpid_of(child)))));
        tr.after_event = true;
    }

    // An exec by `w`: the event stop with TRACEEXEC, else the classic SIGTRAP.
    // When linuxity started the program through its loader (the kernel ran
    // ld.so), the program isn't mapped yet; the stop waits until the loader
    // has mapped it, so the tracer sees what a kernel exec looks like.
    void gt_on_exec(::pid_t w) {
        auto it = gtr_.find(w);
        if (it == gtr_.end()) return;
        GtTrace& tr = it->second;
        if (gt_started_via_loader(w)) {
            tr.defer_exec = true;
            tr.defer_left = 400;
            tr.exec_exit_pending = false;
            return;
        }
        tr.exec_exit_pending = true;
        gt_queue(w, gt_exec_report(tr, w));
    }
    [[nodiscard]] GtReport gt_exec_report(const GtTrace& tr, ::pid_t w) {
        if (tr.opts & kOptExec)
            return gt_event_report(PTRACE_EVENT_EXEC, static_cast<unsigned long>(gt_view_of(w)));
        return gt_sig_report(SIGTRAP, nullptr);
    }
    // The kernel ran the loader as the program (`ld.so prog`)?
    [[nodiscard]] static bool gt_started_via_loader(::pid_t w) {
        char exe[4096];
        const ::ssize_t n = ::readlink(("/proc/" + std::to_string(w) + "/exe").c_str(), exe, sizeof exe - 1);
        if (n <= 0) return false;
        const std::string_view e{exe, static_cast<std::size_t>(n)};
        const auto base = e.substr(e.rfind('/') + 1);
        return base.starts_with("ld-linux") || base.starts_with("ld-musl") || base.starts_with("ld64.so");
    }
    // Has the loader mapped the program's writable segment (its last)?
    [[nodiscard]] static bool gt_prog_mapped(::pid_t w) {
        char exe[4096];
        const ::ssize_t n = ::readlink(("/proc/" + std::to_string(w) + "/exe").c_str(), exe, sizeof exe - 1);
        if (n <= 0) return true;
        const std::string ldso(exe, static_cast<std::size_t>(n));
        std::FILE* m = std::fopen(("/proc/" + std::to_string(w) + "/maps").c_str(), "re");
        if (!m) return true;
        char line[4352];
        bool found = false;
        std::string prog;
        while (std::fgets(line, sizeof line, m)) {
            unsigned long lo, hi, off;
            char perms[8], path[4096] = {0};
            if (std::sscanf(line, "%lx-%lx %7s %lx %*s %*s %4095[^\n]", &lo, &hi, perms, &off, path) < 4) continue;
            std::string p = path;
            while (!p.empty() && p.front() == ' ') p.erase(0, 1);
            if (p.empty() || p[0] != '/' || p == ldso) continue;
            if (prog.empty()) {
                if (off != 0 || p.ends_with(".so") || p.find(".so.") != std::string::npos) continue;
                prog = p;
            }
            if (p == prog && perms[1] == 'w') { found = true; break; }
        }
        std::fclose(m);
        return found;
    }

    // A SIGTRAP|0x80 stop while a loader-started exec is held. True if
    // handled.
    bool gt_defer_stop(::pid_t w, GtTrace& tr) {
        struct { std::uint8_t op; std::uint8_t pad[3]; std::uint32_t arch; std::uint64_t ip, sp; } info{};
        const long got = ::ptrace(static_cast<PtReq>(0x420e), w, reinterpret_cast<void*>(sizeof info), &info);
        const bool exit_stop = got > 0 && info.op == 2;
        if (exit_stop && !tr.deferred_exit_seen) {
            tr.deferred_exit_seen = true;   // the execve's own exit
            ::ptrace(PTRACE_SYSCALL, w, 0, 0);
            return true;
        }
        if (exit_stop || (!gt_prog_mapped(w) && --tr.defer_left > 0)) {
            ::ptrace(PTRACE_SYSCALL, w, 0, 0);
            return true;
        }
        // mapped, at the next syscall's entry: show the exec now
        tr.defer_exec = false;
        tr.deferred_exit_seen = false;
        gt_queue(w, gt_exec_report(tr, w));
        if (tr.in_sys) {
            // the execve's exit, as it returned 0
            tr.in_sys = false;
            GtReport r = gt_sys_report(tr, false);
            Regs now{};
            if (Regs::fetch(w, now)) {
                r.restore = true;
                r.saved = now;
                Regs shown = now;
                shown.set_ret(0);
                (void)shown.store(w);
                // the first report shows the same registers
                tr.q.front().restore = false;
            }
            gt_queue(w, std::move(r));
        }
        tr.entry_after = true;   // then this entry, if they trace syscalls
        gt_park(w);
        return true;
    }

    // A SIGTRAP|0x80 stop of a traced task that linuxity is not serving.
    // True if handled.
    bool gt_on_sys_stop(::pid_t w, Task& t) {
        auto it = gtr_.find(w);
        if (it == gtr_.end()) return false;
        GtTrace& tr = it->second;
        if (tr.defer_exec && !t.in_call) return gt_defer_stop(w, tr);
        if (tr.exec_exit_pending) {
            tr.exec_exit_pending = false;
            if (tr.in_sys) {
                tr.in_sys = false;
                gt_queue(w, gt_sys_report(tr, false));
                gt_park(w);
            } else {
                gt_plain_resume(w, 0);
            }
            return true;
        }
        if (t.in_call) return false;            // linuxity's own exit stop
        if (!tr.in_sys) {
            if (tr.mode != kModeSyscall) return false;
            (void)Regs::fetch(w, tr.entry);
            tr.in_sys = true;
            if (!seccomp_) tr.redispatch = true;  // linuxity serves it on release
            gt_queue(w, gt_sys_report(tr, true));
            gt_park(w);
            return true;
        }
        // the exit of a syscall linuxity let run natively
        tr.in_sys = false;
        gt_queue(w, gt_sys_report(tr, false));
        gt_park(w);
        return true;
    }

    // A traced task about to exit (PTRACE_EVENT_EXIT, which linuxity turns on
    // only for tracees whose tracer asked). True if it now waits for them.
    bool gt_on_exit_event(::pid_t w) {
        auto it = gtr_.find(w);
        if (it == gtr_.end() || !(it->second.opts & kOptExit)) return false;
        unsigned long code = 0;
        ::ptrace(PTRACE_GETEVENTMSG, w, 0, &code);
        gt_queue(w, gt_event_report(PTRACE_EVENT_EXIT, code));
        it->second.after_event = true;
        gt_park(w);
        return true;
    }
    // linuxity's own options plus TRACEEXIT when the guest tracer asked.
    void gt_sync_exit_opt(::pid_t w, const GtTrace& tr) {
        ::ptrace(PTRACE_SETOPTIONS, w, 0,
                 base_opts_ | ((tr.opts & kOptExit) ? PTRACE_O_TRACEEXIT : 0));
    }

    // A traced task or a tracer exited.
    void gt_on_exit(::pid_t w, int status) {
        gt_first_seen_.erase(w);
        gt_held_new_.erase(w);
        if (auto it = gtr_.find(w); it != gtr_.end()) {
            const ::pid_t tracer = it->second.tracer;
            gtr_.erase(it);
            // the tracer learns of the exit: always for a thread, and for a
            // process when it isn't also the real parent (who gets it anyway)
            const auto c = tgid_cache_.find(w);
            const bool leader = c == tgid_cache_.end() || c->second == w;
            if (tracer > 0 && (!leader || host_ppid_of(w) != tracer)) {
                gt_exits_[tracer].push_back({w, gpid_of(w), status});
                gt_chld_[tracer].push_back({gpid_of(w), 0});
                ::kill(tracer, SIGCHLD);
            }
        }
        // a tracer's tracees: killed with EXITKILL, else let go
        for (auto it = gtr_.begin(); it != gtr_.end();) {
            if (it->second.tracer != w) { ++it; continue; }
            const ::pid_t t = it->first;
            const bool kill_it = it->second.opts & kOptExitKill;
            const bool parked = it->second.parked;
            it = gtr_.erase(it);
            if (kill_it) ::syscall(SYS_tgkill, host_tgid_of(t), t, SIGKILL);
            else if (parked) resume_run(t, 0);
        }
        gt_exits_.erase(w);
        gt_chld_.erase(w);
    }

    // PTRACE_GET_SYSCALL_INFO for the current stop.
    [[nodiscard]] std::int64_t gt_syscall_info(::pid_t w, GtTrace& tr, std::uint64_t size, std::uint64_t addr) {
        std::array<std::byte, 88> b{};
        auto put = [&](std::size_t off, auto v) { std::memcpy(b.data() + off, &v, sizeof v); };
        Regs now{};
        (void)Regs::fetch(w, now);
        const auto kind = tr.q.front().kind;
        const std::uint8_t op = kind == GtReport::sys_entry ? 1 : kind == GtReport::sys_exit ? 2 : 0;
        put(0, op);
        put(4, static_cast<std::uint32_t>(kTraceeArch == abi::Arch::x86_64 ? 0xc000003eu : 0xc00000b7u));
        put(8, static_cast<std::uint64_t>(now.pc()));
        put(16, static_cast<std::uint64_t>(now.sp()));
        std::size_t actual = 24;
        if (op == 1) {
            put(24, static_cast<std::uint64_t>(tr.entry.nr()));
            for (int k = 0; k < 6; ++k) put(32 + 8 * static_cast<std::size_t>(k), static_cast<std::uint64_t>(tr.entry.arg(k)));
            actual = 80;
        } else if (op == 2) {
            const auto rv = static_cast<std::int64_t>(now.ret());
            put(24, rv);
            put(32, static_cast<std::uint8_t>(rv < 0 && rv >= -4095));
            actual = 33;
        }
        const std::size_t n = std::min<std::uint64_t>(size, actual);
        if (n && !gt_put(addr, b.data(), n)) return -EFAULT;
        return static_cast<std::int64_t>(actual);
    }
