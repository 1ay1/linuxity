// linuxity/runtime/linux/fastpath.inc -- included inside class PtraceTrap.
//
// The trap side of the in-guest fast path (see fastpath.hpp): which tasks
// get a region, when a site gets patched, keeping the dispatcher's fd table
// in step with what the blob did, and turning a fault in the blob into "fall
// back". Everything here runs with the current task stopped.
public:
    // Create the table (once, before the first guest call) and hook the
    // kernel's change logs. Off if anything is missing: every call traps.
    template <class K, class S>
    void fp_setup(K& k, S& sys) {
        if (!fastpath::wanted() || !fastpath::key().armed || !fastpath::layout().ok) return;
        if (!fp_own_.open(host::tmp_base())) return;
        fp_table_ = &fp_own_;
        auto& fs = k.files();
        fs.set_on_clean_dir([this](std::string_view d, bool in_upper) { if (fp_live_) fp_own_.add_dir(d, in_upper); });
        fs.set_whiteout_log(&fp_wo_log_);
        fs.meta().set_change_log(&fp_meta_log_);
        fp_rebuild(k, sys);
    }

    // Bring the table up to date with everything that changed since the
    // last trap. Cheap when nothing did.
    template <class K, class S>
    void fp_sync(K& k, S& sys) {
        if (!fp_table_) return;
        auto& fs = k.files();
        const bool off = sys.landlock_active() || fs.has_private_mounts() ||
                         fp_own_.exc_crowded();
        if (off != fp_off_) {
            fp_off_ = off;
            fp_own_.set_enabled(!off);
            fp_live_ = !off;
        }
        if (off) { fp_meta_log_.clear(); fp_wo_log_.clear(); return; }
        if (fs.layout_version() != fp_layout_seen_ ||
            fs.links().version() != fp_links_seen_ ||
            sys.sock_placeholder_count() != fp_socks_seen_) {
            fp_rebuild(k, sys);
            return;
        }
        for (const auto& p : fp_meta_log_) fp_own_.add_leaf(p);
        for (const auto& p : fp_wo_log_) fp_own_.add_whiteout(p);
        if (!fp_wo_log_.empty() || fs.dirs_version() != fp_dirs_seen_) {
            fp_own_.bump_dirs();
            fp_dirs_seen_ = fs.dirs_version();
        }
        fp_meta_log_.clear();
        fp_wo_log_.clear();
    }

    // Before the dispatcher looks at a trapped call: apply the fd changes
    // the blob made, in any process, so the dispatcher's fd tables are as
    // current as the processes' real ones. Cheap when there are none.
    template <class K>
    void fp_before_dispatch(K& k) {
        if (!fp_table_) return;
        const std::uint32_t sum = fp_own_.evsum();
        if (sum == fp_evsum_seen_) return;
        fp_evsum_seen_ = sum;
        for (auto& [tg, reg] : fp_regions_) {
            if (!reg.base || !reg.owner) continue;
            const std::uint32_t n = fp_own_.ev_count(tg);
            if (n == reg.ev_seen) continue;
            reg.ev_seen = n;
            fp_drain(k, tg, reg);
        }
    }

    // The current task trapped on a handled syscall. Count the site; at the
    // threshold, map the region (once per process) and patch the site, then
    // run the call again down the new route. True when it did that (the
    // call is handled, don't dispatch it); false to dispatch as usual.
    template <class K, class S>
    [[nodiscard]] bool fp_maybe_patch(const abi::Regs& ar, std::uint64_t pc, K& k, S& sys) {
        if (!fp_table_) return false;
        fp_sync(k, sys);
        const abi::Sysno sc = abi::decode(kTraceeArch, ar.nr);
        if (!fastpath::handled(sc)) return false;
        const ::pid_t tg = host_tgid_of(cur_);
        auto it = fp_regions_.find(tg);
        if (it == fp_regions_.end()) fp_note_cwd_of(k, tg);
        else fp_note_privileged(it->second, sys.caller_privileged());
        return fp_try_patch(ar, pc, k, sys);
    }

    // After the dispatcher ran any call: publish what it changed (a chmod, an
    // unlink, a mount) before the task runs on and can ask the blob, and keep
    // the fd map and the cwd in step with a trapped close, dup2 or chdir.
    template <class K, class S>
    void fp_after_dispatch(const abi::Regs& ar, K& k, S& sys) {
        if (!fp_table_) return;
        fp_sync(k, sys);
        if (fp_regions_.empty()) return;
        const abi::Sysno sc = abi::decode(kTraceeArch, ar.nr);
        const ::pid_t tg = host_tgid_of(cur_);
        auto it = fp_regions_.find(tg);
        if (it == fp_regions_.end() || !it->second.base) return;
        using S2 = abi::Sysno;
        if (sc == S2::dup2 || sc == S2::dup3) { fp_mark_bound(it->second, static_cast<int>(ar.arg[1])); fp_clear_fd(it->second, static_cast<int>(ar.arg[1])); }
        else if (sc == S2::chdir || sc == S2::fchdir) fp_note_cwd_of(k, tg);
        else if (sc == S2::getdents64 || sc == S2::lseek) fp_note_stream(k, it->second, static_cast<int>(ar.arg[0]));
        else fp_note_privileged(it->second, sys.caller_privileged());
    }

    // Before the dispatcher acts on an fd whose merged listing the blob was
    // serving (a getdents or lseek the blob gave up on, a dup, an exec that
    // keeps it open): take the listing over at the cookie the blob reached,
    // so the guest reads on from the same entry.
    template <class K>
    void fp_before_call(const abi::Regs& ar, K& k) {
        if (fp_regions_.empty()) return;
        using S2 = abi::Sysno;
        const abi::Sysno sc = abi::decode(kTraceeArch, ar.nr);
        // A trapped close: forget the fd while this task still holds the
        // number. Once the kernel frees it another thread can open it, and a
        // late clear would wipe that thread's entry.
        if (sc == S2::close || sc == S2::close_range) {
            auto it = fp_regions_.find(host_tgid_of(cur_));
            if (it == fp_regions_.end() || !it->second.base) return;
            if (sc == S2::close) {
                fp_mark_bound(it->second, static_cast<int>(ar.arg[0]));
                fp_clear_fd(it->second, static_cast<int>(ar.arg[0]));
            } else {
                fp_clear_range(it->second, ar.arg[0], ar.arg[1]);
            }
            return;
        }
        const bool exec = sc == S2::execve || sc == S2::execveat;
        if (!exec && sc != S2::getdents64 && sc != S2::lseek && sc != S2::dup &&
            sc != S2::dup2 && sc != S2::dup3 && sc != S2::fcntl)
            return;
        const ::pid_t tg = host_tgid_of(cur_);
        auto it = fp_regions_.find(tg);
        if (it == fp_regions_.end() || !it->second.base || !it->second.owner) return;
        const std::uint64_t base = it->second.base;
        if (!exec) {
            fp_take_union(k, tg, base, static_cast<int>(ar.arg[0]));
            return;
        }
        for (std::uint32_t i = 0; i < LX_FP_UNIONS; ++i) {
            std::int32_t fd1 = 0;
            if (fp_get(cur_, base + LX_FP_UNION_OFF + i * sizeof(lx_fp_union) + offsetof(lx_fp_union, fd), fd1) && fd1 > 0)
                fp_take_union(k, tg, base, fd1 - 1);
        }
    }

    // A trapped open or dup just made fd `fd` for guest path `gp`: write what
    // it is into the process's fd map. Called with the task still stopped,
    // so its next call sees the entry.
    template <class K>
    void fp_note_fd(K& k, int fd, const std::string& gp) {
        if (!fp_table_ || fd < 0 || fd >= static_cast<int>(LX_FP_FDS)) return;
        const ::pid_t tg = host_tgid_of(cur_);
        auto it = fp_regions_.find(tg);
        if (it == fp_regions_.end() || !it->second.base) return;
        fp_mark_bound(it->second, fd);
        fp_write_fd(it->second.base, fd, fp_entry_for(k, fd, gp, gpid_of(tg)));
    }

    void fp_report() {
        if (!fp_table_) return;
        std::fprintf(stderr, "linuxity fast path: %llu calls answered in the guest, %llu sites patched\n",
                     static_cast<unsigned long long>(fp_hits()),
                     static_cast<unsigned long long>(fp_patch_count_));
        fp_own_.report_gate();
    }

    [[nodiscard]] bool fp_on() const noexcept {
        return fp_table_ && fp_table_->enabled() && fastpath::layout().ok && seccomp_;
    }
    // Calls answered in the guest.
    [[nodiscard]] std::uint64_t fp_hits() const { return fp_table_ ? fp_table_->hits() : 0; }

    // A SIGSEGV/SIGBUS in the blob's guarded copy: resume at its fault
    // return (which makes the call fall back) instead of delivering it.
    [[nodiscard]] bool fp_fixup_fault(::pid_t w) {
        if (fp_regions_.empty()) return false;
        Regs r{};
        if (!Regs::fetch(w, r)) return false;
        auto it = fp_regions_.find(host_tgid_of(w));
        if (it == fp_regions_.end() || !it->second.base) return false;
        const auto& L = fastpath::layout();
        const std::uint64_t b = it->second.base;
        if (r.pc() < b + L.guard_start || r.pc() >= b + L.guard_end) return false;
        if (fp_debug()) std::fprintf(stderr, "[fp] %d fault in a guarded copy, falling back\n", w);
        r.set_pc(b + L.fault_ret);
        return r.store(w);
    }

    // exec replaced the image: its region and patches are gone. A vfork
    // parent that shared its memory owns it alone again.
    void fp_forget(::pid_t tg) {
        auto it = fp_regions_.find(tg);
        if (it == fp_regions_.end()) return;
        const fastpath::Region gone = std::move(it->second);
        fp_regions_.erase(it);
        if (gone.shared && gone.parent_tg) fp_unshare(gone.parent_tg);
    }
    // the process is gone (its pid may be reused)
    void fp_reaped(::pid_t tg) {
        fp_forget(tg);
        if (fp_table_) fp_table_->drop_cwd(tg);
    }
    // fork copies the region, the patched code and the fd map: the child's
    // copy describes the child's fds, which are a copy too. A vfork (or any
    // CLONE_VM) child shares the parent's memory instead, so the map is the
    // parent's and neither may change fds in the guest until the child
    // execs or exits.
    void fp_inherit(::pid_t parent_tg, ::pid_t child_tg) {
        auto it = fp_regions_.find(parent_tg);
        if (it == fp_regions_.end() || child_tg == parent_tg) return;
        fastpath::Region r = it->second;
        r.hits.clear();
        r.verified = false;
        r.parent_tg = parent_tg;
        r.ev_seen = 0;
        r.privileged = -1;
        const bool shared = it->second.base && fp_shares_memory(child_tg, it->second.base);
        r.shared = shared;
        r.owner = !shared && it->second.base;
        fp_regions_[child_tg] = std::move(r);
        if (it->second.base) {
            if (shared) {
                // no one changes fds in the guest now; the parent's map stays
                fp_set_owner(child_tg, it->second.base, 0);
            } else {
                // the child's own copy of the proc page names the child
                fp_set_owner(child_tg, it->second.base, child_tg);
                // the child's ring is a copy of the parent's: anything the
                // parent logged but we hadn't applied was applied to the
                // parent's table, which the child's table copies at its
                // first call (set_current_pid); start the child's ring empty
                fp_reset_ring(child_tg, it->second.base);
            }
        }
        // a child starts in its parent's directory
        if (fp_table_) fp_table_->copy_cwd(parent_tg, child_tg);
    }

private:
    static constexpr std::uint32_t kFpThreshold = 3;
    static constexpr std::uint32_t kFpMapAfter = 24;
    static constexpr std::size_t kFpMaxSites = 512;
    fastpath::Table* fp_table_{nullptr};
    fastpath::Table fp_own_;
    std::unordered_map<::pid_t, fastpath::Region> fp_regions_;
    std::uint64_t fp_patch_count_{0};
    std::vector<std::string> fp_meta_log_, fp_wo_log_;
    std::uint64_t fp_layout_seen_{~0ull}, fp_links_seen_{~0ull}, fp_dirs_seen_{0};
    std::size_t fp_socks_seen_{~std::size_t{0}};
    std::uint32_t fp_evsum_seen_{0};
    bool fp_off_{true}, fp_live_{false};

    static bool fp_debug() {
        static const bool on = std::getenv("LINUXITY_FP_DEBUG") != nullptr;
        return on;
    }
    bool fp_skip(const char* why, std::uint64_t site) {
        if (fp_debug()) std::fprintf(stderr, "[fp] %d site %#llx: %s\n", cur_,
                                     static_cast<unsigned long long>(site), why);
        return false;
    }

    // -- the per-process page and the fd map, written from here ---------------

    template <class T>
    bool fp_put(::pid_t w, std::uint64_t at, const T& v) {
        ::iovec l{const_cast<T*>(&v), sizeof v}, r{reinterpret_cast<void*>(at), sizeof v};
        return ::process_vm_writev(w, &l, 1, &r, 1, 0) == static_cast<ssize_t>(sizeof v);
    }
    template <class T>
    bool fp_get(::pid_t w, std::uint64_t at, T& v) {
        ::iovec l{&v, sizeof v}, r{reinterpret_cast<void*>(at), sizeof v};
        return ::process_vm_readv(w, &l, 1, &r, 1, 0) == static_cast<ssize_t>(sizeof v);
    }
    static std::uint64_t fp_proc_field(std::uint64_t base, std::size_t off) { return base + LX_FP_PROC_OFF + off; }

    void fp_set_owner(::pid_t w, std::uint64_t base, ::pid_t owner) {
        (void)fp_put(w, fp_proc_field(base, offsetof(lx_fp_proc, owner)), static_cast<std::int32_t>(owner));
    }
    void fp_reset_ring(::pid_t w, std::uint64_t base) {
        std::uint32_t wr = 0;
        if (fp_get(w, fp_proc_field(base, offsetof(lx_fp_proc, ev_wr)), wr))
            (void)fp_put(w, fp_proc_field(base, offsetof(lx_fp_proc, ev_rd)), wr);
    }
    // The child shares the parent's memory if a write through one shows in
    // the other.
    bool fp_shares_memory(::pid_t child, std::uint64_t base) {
        const std::uint64_t at = fp_proc_field(base, offsetof(lx_fp_proc, probe));
        const std::uint64_t token = (static_cast<std::uint64_t>(child) << 32) ^ ++fp_probe_seq_;
        if (!fp_put(cur_, at, token)) return true;   // can't tell: assume shared
        std::uint64_t seen = 0;
        if (!fp_get(child, at, seen)) return true;
        return seen == token;
    }
    std::uint64_t fp_probe_seq_{0};
    // A vfork child that shared `tg`'s memory has gone: `tg` owns its map again.
    void fp_unshare(::pid_t tg) {
        auto it = fp_regions_.find(tg);
        if (it == fp_regions_.end() || !it->second.base) return;
        it->second.owner = true;
        fp_set_owner(tg, it->second.base, tg);
    }
    void fp_note_privileged(fastpath::Region& reg, bool priv) {
        if (!reg.base || reg.privileged == (priv ? 1 : 0)) return;
        if (fp_put(cur_, fp_proc_field(reg.base, offsetof(lx_fp_proc, privileged)),
                   static_cast<std::uint32_t>(priv ? 1 : 0)))
            reg.privileged = priv ? 1 : 0;
    }

    // Seqlock write of one entry into the current task's memory.
    void fp_write_fd(std::uint64_t base, int fd, lx_fp_fd e) {
        if (fd < 0 || fd >= static_cast<int>(LX_FP_FDS)) return;
        const std::uint64_t at = base + LX_FP_FDMAP_OFF + static_cast<std::uint64_t>(fd) * sizeof(lx_fp_fd);
        std::uint32_t seq = 0;
        if (!fp_get(cur_, at, seq)) return;
        // even: nobody is writing it (the task is stopped, and a blob writer
        // in another thread would be mid-call: then leave the entry to it)
        if (seq & 1) return;
        if (!fp_put(cur_, at, seq + 1)) return;
        e.seq = seq + 1;
        e.flags |= LX_FP_FD_BYSUP;
        ::iovec lb{reinterpret_cast<char*>(&e) + sizeof e.seq, sizeof e - sizeof e.seq};
        ::iovec rb{reinterpret_cast<void*>(at + sizeof e.seq), sizeof e - sizeof e.seq};
        (void)::process_vm_writev(cur_, &lb, 1, &rb, 1, 0);
        (void)fp_put(cur_, at, seq + 2);
    }
    void fp_clear_fd(fastpath::Region& reg, int fd) {
        if (reg.base) fp_write_fd(reg.base, fd, lx_fp_fd{});
    }
    void fp_clear_range(fastpath::Region& reg, std::uint64_t lo, std::uint64_t hi) {
        if (!reg.base) return;
        for (std::uint64_t fd = lo; fd <= hi && fd < LX_FP_FDS; ++fd)
            fp_write_fd(reg.base, static_cast<int>(fd), lx_fp_fd{});
    }

    // What fd map entry fd `fd` (bound to guest path `gp`) gets: a host
    // file or dir, and how its listing goes.
    template <class K>
    lx_fp_fd fp_entry_for(K& k, int fd, const std::string& gp, std::int32_t gpid) {
        lx_fp_fd e{};
        auto& fs = k.files();
        if (gp.empty() || gp.size() >= LX_FP_FD_PATH || gp[0] != '/') return e;
        const auto pc = fs.classify(gp);
        if (pc.realm != kernel::Realm2::host_backed) return e;
        char link[64];
        std::snprintf(link, sizeof link, "/proc/%d/fd/%d", cur_, fd);
        struct ::stat st{};
        if (::stat(link, &st) != 0 || !(S_ISDIR(st.st_mode) || S_ISREG(st.st_mode))) return e;
        e.kind = LX_FP_FD_HOST;
        e.len = static_cast<std::uint16_t>(gp.size());
        // opened in the upper layer: the host path the classify picked
        if (const auto up = fs.upper_path_of(gp); !up.empty()) {
            struct ::stat us{};
            if (::lstat(up.c_str(), &us) == 0 && us.st_dev == st.st_dev && us.st_ino == st.st_ino)
                e.flags |= LX_FP_FD_UPPER;
        }
        if (S_ISDIR(st.st_mode)) {
            e.flags |= LX_FP_FD_DIR;
            // A listing the dispatcher serves (a union being read, a virtual
            // dir): only it may read or seek. An overlay dir not read yet
            // stays undecided (the blob or the dispatcher decides at the
            // first getdents, the dispatcher's open may not have bound its
            // stream yet). A plain bind-mounted dir is the host's own.
            const int ds = fs.dir_state_in(gpid, fd);
            if (ds == 2) e.flags |= LX_FP_FD_STREAM;
            else if (ds == 0 && !fs.is_overlay_path(gp)) e.flags |= LX_FP_FD_NATIVE;
        }
        e.gen = fp_own_.dir_gen();
        e.dev = static_cast<std::uint64_t>(st.st_dev);
        e.ino = static_cast<std::uint64_t>(st.st_ino);
        std::memcpy(e.path, gp.data(), gp.size());
        return e;
    }

    // A trapped getdents or lseek on a dir: the dispatcher is now serving
    // that fd's listing, so the blob must leave it alone.
    template <class K>
    void fp_note_stream(K& k, fastpath::Region& reg, int fd) {
        if (fd < 0 || fd >= static_cast<int>(LX_FP_FDS) || !reg.base) return;
        if (k.files().dir_state_in(gpid_of(host_tgid_of(cur_)), fd) != 2) return;
        lx_fp_fd e{};
        const std::uint64_t at = reg.base + LX_FP_FDMAP_OFF + static_cast<std::uint64_t>(fd) * sizeof(lx_fp_fd);
        if (!fp_get(cur_, at, e) || e.kind != LX_FP_FD_HOST || (e.flags & LX_FP_FD_STREAM)) return;
        e.flags = static_cast<std::uint8_t>((e.flags | LX_FP_FD_STREAM) & ~LX_FP_FD_NATIVE);
        fp_write_fd(reg.base, fd, e);
    }

    // The dispatcher just (un)bound fd `fd` itself, at a trap: blob events
    // for it reserved before now are older than that, and must not undo it.
    void fp_mark_bound(fastpath::Region& reg, int fd) {
        if (fd < 0 || fd >= static_cast<int>(LX_FP_FDS) || !reg.base) return;
        std::uint32_t wr = 0;
        if (!fp_get(cur_, fp_proc_field(reg.base, offsetof(lx_fp_proc, ev_wr)), wr)) return;
        reg.fd_mark[fd] = wr;
    }

    // Was blob event `idx` for fd `fd` reserved before the dispatcher's own
    // last (un)bind of that fd?
    static bool fp_older(const fastpath::Region& reg, int fd, std::uint32_t idx) {
        auto it = reg.fd_mark.find(fd);
        return it != reg.fd_mark.end() && static_cast<std::int32_t>(idx - it->second) < 0;
    }

    // Take fd's merged listing from the blob (see fp_before_call). Close the
    // slot to new users first, let a call already inside finish, then read
    // where it got to. Closed is -(fd+1), not 0: union_alloc takes a 0 slot
    // as free and would rewind it before we read cum.
    template <class K>
    void fp_take_union(K& k, ::pid_t tg, std::uint64_t base, int fd) {
        if (fd < 0 || fd >= static_cast<int>(LX_FP_FDS)) return;
        const std::uint64_t fat = base + LX_FP_FDMAP_OFF + static_cast<std::uint64_t>(fd) * sizeof(lx_fp_fd);
        lx_fp_fd e{};
        if (!fp_get(cur_, fat, e) || (e.seq & 1) || !(e.flags & LX_FP_FD_UNION)) return;
        if (!e.ref || e.ref > LX_FP_UNIONS) return;
        const std::uint64_t ua = base + LX_FP_UNION_OFF + (e.ref - 1) * sizeof(lx_fp_union);
        std::int32_t fd1 = 0;
        if (!fp_get(cur_, ua + offsetof(lx_fp_union, fd), fd1)) return;
        std::uint64_t cum = 0;
        const bool ours = fd1 == fd + 1;
        if (ours) {
            (void)fp_put(cur_, ua + offsetof(lx_fp_union, fd), std::int32_t{-(fd + 1)});
            // a thread mid-call releases the lock within microseconds; a
            // stopped one never will, so don't wait for long
            for (int i = 0; i < 20000; ++i) {
                std::uint32_t lock = 0;
                if (!fp_get(cur_, ua + offsetof(lx_fp_union, lock), lock) || lock == 0) break;
            }
            (void)fp_get(cur_, ua + offsetof(lx_fp_union, cum), cum);
        }
        k.files().seek_dir_in(gpid_of(tg), fd, cum);
        e.flags = static_cast<std::uint8_t>((e.flags | LX_FP_FD_STREAM) & ~LX_FP_FD_UNION);
        e.ref = 0;
        fp_write_fd(base, fd, e);
        if (ours) (void)fp_put(cur_, ua + offsetof(lx_fp_union, fd), std::int32_t{0});
    }

    // Apply process tg's logged fd events to the dispatcher's table. An
    // event names only an fd; what it is now is read from the fd map, which
    // the blob wrote before logging. So order and repeats don't matter.
    template <class K>
    void fp_drain(K& k, ::pid_t tg, fastpath::Region& reg) {
        std::uint32_t rd = 0, wr = 0;
        const std::uint64_t pb = reg.base + LX_FP_PROC_OFF;
        if (!fp_get(tg, pb + offsetof(lx_fp_proc, ev_rd), rd) ||
            !fp_get(tg, pb + offsetof(lx_fp_proc, ev_wr), wr))
            return;
        const std::int32_t g = gpid_of(tg);
        auto& fs = k.files();
        // Replay in reservation order. A slot another thread hasn't finished
        // writing blocks the rest (a later event may be for the same fd);
        // that thread is mid-call in the blob, so wait for it a little.
        std::uint32_t i = rd;
        int spins = 0;
        while (i != wr) {
            lx_fp_ev ev{};
            const std::uint64_t at = pb + offsetof(lx_fp_proc, ev) +
                                     static_cast<std::uint64_t>(i & (LX_FP_EVENTS - 1)) * sizeof(lx_fp_ev);
            if (!fp_get(tg, at, ev)) break;
            if (ev.seq != i + 1) {
                if (++spins > 20000) break;   // leave it for the next trap
                continue;
            }
            const std::uint32_t idx = i++;
            if (ev.op == LX_FP_EV_NOOP || ev.fd < 0 || ev.fd >= static_cast<int>(LX_FP_FDS)) continue;
            if (fp_older(reg, ev.fd, idx)) continue;   // the dispatcher rebound it since
            if (ev.op == LX_FP_EV_CLOSE) {
                fs.apply_guest_fd(g, ev.fd, nullptr, false);
                continue;
            }
            if (ev.len >= LX_FP_FD_PATH) continue;
            const std::string p(ev.path, ev.len);
            const bool lazy = (ev.flags & LX_FP_FD_DIR) && !(ev.flags & LX_FP_FD_NATIVE);
            // the decision to list natively, for an fd the dispatcher already
            // has bound to this path: drop just its unbuilt stream
            const bool same = fs.path_of_fd_in(g, ev.fd) == p &&
                              (fs.dir_state_in(g, ev.fd) != 0) == lazy;
            if (!same) fs.apply_guest_fd(g, ev.fd, &p, lazy);
        }
        if (i != rd) (void)fp_put(tg, pb + offsetof(lx_fp_proc, ev_rd), i);
        if (i != wr) {
            // something unfinished: look again at the next trap
            fp_evsum_seen_ = ~fp_own_.evsum();
            reg.ev_seen = ~reg.ev_seen;
        }
    }

    template <class K>
    void fp_note_cwd_of(K& k, ::pid_t tg) {
        const std::int32_t g = gpid_of(tg);
        auto& fs = k.files();
        if (fs.cwd_known(g)) fp_own_.set_cwd(tg, fs.cwd_of(g));
        else fp_own_.set_cwd(tg, {});
    }

    // Everything from scratch: mounts, exceptions, dirs.
    template <class K, class S>
    void fp_rebuild(K& k, S& sys) {
        auto& fs = k.files();
        std::vector<fastpath::Mount> ms;
        bool describable = true;
        fs.for_each_shared_mount([&](const std::string& prefix, const std::string& base,
                                     const std::string& upper, bool is_virtual, bool ro,
                                     bool moved, std::uint64_t idx) {
            (void)ro;
            if (moved && !is_virtual) describable = false;
            ms.push_back({prefix, base, upper, is_virtual, static_cast<std::uint32_t>(idx + 21)});
        });
        if (!describable) ms.clear();
        fp_own_.set_mounts(ms);
        fp_own_.clear_exc_begin();
        fs.meta().for_each_path([&](const std::string& p) { fp_own_.add_leaf(p); });
        fs.for_each_whiteout([&](const std::string& p) { fp_own_.add_whiteout(p); });
        fs.links().for_each_path([&](const std::string& p) { fp_own_.add_leaf(p); });
        sys.for_each_sock_placeholder([&](const std::string& p) { fp_own_.add_leaf(p); });
        fp_own_.clear_exc_end();
        fp_meta_log_.clear();
        fp_wo_log_.clear();
        fp_layout_seen_ = fs.layout_version();
        fp_links_seen_ = fs.links().version();
        fp_dirs_seen_ = fs.dirs_version();
        fp_socks_seen_ = sys.sock_placeholder_count();
        const bool off = sys.landlock_active() || fs.has_private_mounts() || ms.empty() ||
                         fp_own_.exc_crowded();
        fp_off_ = off;
        fp_live_ = !off;
        fp_own_.set_enabled(!off);
    }

    // -- mapping a region and patching a site ----------------------------------

    template <class K, class S>
    [[nodiscard]] bool fp_try_patch(const abi::Regs& ar, std::uint64_t pc, K& k, S& sys) {
        if (!fp_on()) return fp_skip("off", pc);
        Task& t = tasks_[cur_];
        if (t.refused) return false;
        const ::pid_t tg = host_tgid_of(cur_);
        fastpath::Region& reg = fp_regions_[tg];
        if (reg.failed) return fp_skip("region failed", pc);
        const std::uint64_t site = pc - fastpath::kSiteLen;
        if (reg.patched.count(site)) return false;   // patched, or not patchable
        // a stub's own code (an x86 stub's jump back lands on the original
        // syscall, never here, but be sure)
        if (fp_in_own_pages(reg, site)) return false;
        // A short-lived process (the loader's few opens, then exit or exec)
        // would pay more to set up the region than the traps it saves.
        if (!reg.base && ++reg.calls < kFpMapAfter) return false;
        if (++reg.hits[site] < kFpThreshold) return false;
        if (reg.patched.size() >= kFpMaxSites) return fp_skip("too many sites", site);

        // read the site and check it is the exact pattern
        unsigned char code[16]{};
        if (!fp_peek(cur_, site, code, sizeof code)) { reg.hits[site] = 0; return fp_skip("peek", site); }
        if (!fastpath::site_ok(code, static_cast<std::uint32_t>(ar.nr))) {
            reg.hits[site] = 0;
            reg.patched.insert(site);   // never look at it again
            return fp_skip("not a plain site", site);
        }
        // A record copied at fork may be stale: a vfork child can exec
        // before its fork event is seen, and its new image has no region.
        if (reg.base && !reg.verified) {
            std::uint64_t magic = 0;
            if (!fp_get(cur_, reg.base, magic) || magic != LX_FP_MAGIC) {
                reg = fastpath::Region{};
                reg.hits[site] = kFpThreshold;
            }
            reg.verified = true;
        }
        // a vfork child: its memory is its parent's, leave it alone
        if (reg.shared) return false;
        if (!reg.base && !fp_map_region(reg, tg, k, sys)) return fp_skip("map region", site);
        const std::uint64_t stub = fp_alloc_stub(reg, site);
        if (!stub) {
            reg.patched.insert(site);
            return fp_skip("no stub page in range", site);
        }
        if (!fp_write_stub(reg, stub, site, code)) return fp_skip("write stub", site);
        if (!fp_patch_site(site, stub)) { reg.patched.insert(site); return fp_skip("patch", site); }
        reg.patched.insert(site);
        ++fp_patch_count_;
        if (fp_debug()) std::fprintf(stderr, "[fp] %d patched %#llx -> %#llx\n", cur_,
                                     static_cast<unsigned long long>(site), static_cast<unsigned long long>(stub));
        // run the guest's call again from the patched site
        return fp_restart_at(site);
    }

    // Resume the current task at `at` (a patched site) with the registers it
    // had when its syscall trapped: the moved instruction runs again in the
    // stub, so redoing it is harmless (it only loads the syscall number or
    // a stack slot). The trapped call is skipped.
    bool fp_restart_at(std::uint64_t at) {
        Task& t = tasks_[cur_];
        const Regs entry = t.regs;
        Regs skip = entry;
        skip.skip_call();
        skip.set_ret(-static_cast<std::int64_t>(EINTR));
        if (!store_and_skip(skip)) return true;
        if (!step_to_exit(cur_)) return true;
        Regs back = entry;
        back.set_pc(at);
        back.restore_nr_reg();
        (void)back.store(cur_);
        t.regs = entry;
        sys_done(cur_);
        t.action = Action::none;
        resume_task(cur_);
        return true;
    }

    static bool fp_in_own_pages(const fastpath::Region& reg, std::uint64_t at) {
        if (reg.base && at >= reg.base && at < reg.base + LX_FP_REGION_SIZE) return true;
        for (const auto& [page, used] : reg.used) {
            (void)used;
            if (at >= page && at < page + LX_FP_NEAR_SIZE) return true;
        }
        return false;
    }

    static bool fp_peek(::pid_t w, std::uint64_t at, unsigned char* out, std::size_t n) {
        ::iovec l{out, n}, r{reinterpret_cast<void*>(at), n};
        if (::process_vm_readv(w, &l, 1, &r, 1, 0) == static_cast<ssize_t>(n)) return true;
        for (std::size_t off = 0; off < n; off += sizeof(long)) {
            errno = 0;
            const long v = ::ptrace(PTRACE_PEEKTEXT, w, reinterpret_cast<void*>((at + off) & ~7ull), 0);
            if (errno) return false;
            const std::uint64_t base = (at + off) & ~7ull;
            for (int k = 0; k < 8; ++k) {
                const std::uint64_t a = base + static_cast<std::uint64_t>(k);
                if (a >= at && a < at + n) out[a - at] = static_cast<unsigned char>(static_cast<unsigned long>(v) >> (8 * k));
            }
        }
        return true;
    }
    // Writes through ptrace, which can write read-only (text) pages.
    static bool fp_poke(::pid_t w, std::uint64_t at, const unsigned char* src, std::size_t n) {
        std::size_t off = 0;
        while (off < n) {
            const std::uint64_t word = (at + off) & ~7ull;
            errno = 0;
            long v = ::ptrace(PTRACE_PEEKTEXT, w, reinterpret_cast<void*>(word), 0);
            if (errno) return false;
            auto* b = reinterpret_cast<unsigned char*>(&v);
            for (int k = 0; k < 8; ++k) {
                const std::uint64_t a = word + static_cast<std::uint64_t>(k);
                if (a >= at + off && a < at + n) b[k] = src[a - at];
            }
            if (::ptrace(PTRACE_POKETEXT, w, reinterpret_cast<void*>(word), reinterpret_cast<void*>(v)) != 0)
                return false;
            off = (word + 8) - at;
        }
        return true;
    }

    // Map the region into the current task's process: anonymous memory for
    // code, the proc page, the fd map and the stacks, and the table file over
    // its slot. Then seed the fd map from what the dispatcher knows.
    template <class K, class S>
    bool fp_map_region(fastpath::Region& reg, ::pid_t tg, K& k, S& sys) {
        using Sn = abi::Sysno;
        const auto blob = fastpath::blob();
        const std::string& tpath = fp_table_->path();
        const Regs entry = tasks_[cur_].regs;
        const std::uint64_t spath = (entry.sp() - 1024 - tpath.size() - 1) & ~std::uint64_t{15};
        if (!poke_path(spath, tpath, /*dead_scratch=*/true)) { reg.failed = true; return false; }
        constexpr std::uint64_t kProt = PROT_READ | PROT_WRITE;
        constexpr std::uint64_t kPriv = MAP_PRIVATE | MAP_ANONYMOUS;
        const std::uint64_t sz = LX_FP_REGION_SIZE;
        std::vector<std::int64_t> rets;
        std::uint64_t base = 0;
        bool good = false;
        {
            const std::vector<GuestCall> first = {
                {Sn::mmap, {0, sz, kProt, kPriv, static_cast<std::uint64_t>(-1), 0}},
                {Sn::openat, {static_cast<std::uint64_t>(-100), spath, O_RDWR | O_CLOEXEC, 0, 0, 0}},
            };
            if (!fp_run(first, rets)) return false;
            if (rets.size() < 2 || rets[0] < 0 || rets[1] < 0) {
                if (!rets.empty() && rets[0] >= 0) (void)fp_run1(Sn::munmap, {static_cast<std::uint64_t>(rets[0]), sz, 0, 0, 0, 0});
                if (rets.size() >= 2 && rets[1] >= 0) (void)fp_run1(Sn::close, {static_cast<std::uint64_t>(rets[1]), 0, 0, 0, 0, 0});
                reg.failed = true;
                return false;
            }
            base = static_cast<std::uint64_t>(rets[0]);
            const auto fd = static_cast<std::uint64_t>(rets[1]);
            const std::int64_t m = fp_run1(Sn::mmap, {base + LX_FP_TABLE_OFF, LX_FP_TABLE_SIZE, PROT_READ,
                                                      MAP_SHARED | MAP_FIXED, fd, 0});
            const std::int64_t s = fp_run1(Sn::mmap, {base + LX_FP_STATS_OFF, 0x1000, PROT_READ | PROT_WRITE,
                                                      MAP_SHARED | MAP_FIXED, fd, LX_FP_TABLE_SIZE});
            (void)fp_run1(Sn::close, {fd, 0, 0, 0, 0, 0});
            good = m == static_cast<std::int64_t>(base + LX_FP_TABLE_OFF) &&
                   s == static_cast<std::int64_t>(base + LX_FP_STATS_OFF);
        }
        if (good) {
            ::iovec l{const_cast<unsigned char*>(blob.data()), blob.size()};
            ::iovec r{reinterpret_cast<void*>(base), blob.size()};
            good = ::process_vm_writev(cur_, &l, 1, &r, 1, 0) == static_cast<ssize_t>(blob.size()) ||
                   fp_poke(cur_, base, blob.data(), blob.size());
        }
        if (good) {
            // code r-x; guard pages after the proc page and below the stacks
            good = fp_run1(Sn::mprotect, {base, LX_FP_CODE_MAX, PROT_READ | PROT_EXEC, 0, 0, 0}) == 0 &&
                   fp_run1(Sn::mprotect, {base + LX_FP_PROC_OFF + LX_FP_PROC_SIZE,
                                          LX_FP_FDMAP_OFF - LX_FP_PROC_OFF - LX_FP_PROC_SIZE, PROT_NONE, 0, 0, 0}) == 0 &&
                   fp_run1(Sn::mprotect, {base + LX_FP_STACKS_OFF - 0x1000, 0x1000, PROT_NONE, 0, 0, 0}) == 0;
        }
        if (!good) {
            (void)fp_run1(Sn::munmap, {base, sz, 0, 0, 0, 0});
            reg.failed = true;
            return false;
        }
        reg.base = base;
        reg.verified = true;
        reg.owner = true;
        reg.ev_seen = fp_own_.ev_count(tg);
        fp_set_owner(cur_, base, tg);
        fp_note_privileged(reg, sys.caller_privileged());
        // what the dispatcher already knows of this process's fds
        const std::int32_t gp = gpid_of(tg);
        k.files().for_each_fd_path_in(gp, [&](int fd, const std::string& p) {
            if (fd >= 0 && fd < static_cast<int>(LX_FP_FDS)) fp_write_fd(base, fd, fp_entry_for(k, fd, p, gp));
        });
        return true;
    }

    // One call in the current task; its raw return.
    std::int64_t fp_run1(abi::Sysno nr, std::array<std::uint64_t, 6> a) {
        std::vector<std::int64_t> rets;
        if (!fp_run({{nr, a}}, rets) || rets.empty()) return -EIO;
        return rets[0];
    }
    // Run calls in the current task and leave it at the entry stop it trapped
    // on, as if nothing happened.
    bool fp_run(const std::vector<GuestCall>& calls, std::vector<std::int64_t>& rets) {
        Task& t = tasks_[cur_];
        const Regs entry = t.regs;
        rets.clear();
        for (const auto& c : calls) {
            Regs r = entry;
            for (int k = 0; k < 6; ++k) {
                std::uint64_t v = c.a[static_cast<std::size_t>(k)];
                if (v >= kStepRet && v < kStepRet + rets.size()) v = static_cast<std::uint64_t>(rets[v - kStepRet]);
                r.set_arg(k, v);
            }
            r.set_nr(encode(kTraceeArch, c.nr));
            if (!r.store(cur_) || !r.commit_nr(cur_)) return false;
            if (!step_to_exit(cur_)) return false;
            Regs after{};
            if (!Regs::fetch(cur_, after)) return false;
            rets.push_back(static_cast<std::int64_t>(after.ret()));
            Regs again = entry;
            again.rewind_to_syscall();
            if (!again.store(cur_)) return false;
            if (!step_to_entry(cur_)) return false;
        }
        (void)entry.store(cur_);
        (void)entry.commit_nr(cur_);
        return true;
    }

    // A stub slot within branch range of `site`, mapping a page if needed.
    std::uint64_t fp_alloc_stub(fastpath::Region& reg, std::uint64_t site) {
        using Sn = abi::Sysno;
        for (auto& [page, used] : reg.used)
            if (used < LX_FP_SLOTS && fastpath::in_branch_range(site, page) &&
                fastpath::in_branch_range(site, page + LX_FP_NEAR_SIZE))
                return page + static_cast<std::uint64_t>(used++) * LX_FP_SLOT_SIZE;
        const std::uint64_t win = site & ~(LX_FP_NEAR_SIZE - 1);
        for (int k = 1; k <= 64; ++k) {
            for (const int sign : {-1, 1}) {
                const std::int64_t delta = sign * static_cast<std::int64_t>(k) * 0x1000000LL;   // 16MB steps
                const std::uint64_t hint = static_cast<std::uint64_t>(static_cast<std::int64_t>(win) + delta);
                if (hint < 0x10000) continue;
                const std::int64_t got = fp_run1(Sn::mmap, {hint, LX_FP_NEAR_SIZE, PROT_READ | PROT_WRITE,
                                                            MAP_PRIVATE | MAP_ANONYMOUS | 0x100000 /*FIXED_NOREPLACE*/,
                                                            static_cast<std::uint64_t>(-1), 0});
                if (got < 0 && got >= -4095) continue;
                const auto page = static_cast<std::uint64_t>(got);
                if (!fastpath::in_branch_range(site, page) ||
                    !fastpath::in_branch_range(site, page + LX_FP_NEAR_SIZE)) {
                    (void)fp_run1(Sn::munmap, {page, LX_FP_NEAR_SIZE, 0, 0, 0, 0});
                    continue;
                }
                reg.near[win] = page;
                reg.used[page] = 1;
                return page;
            }
        }
        return 0;
    }

    bool fp_write_stub(fastpath::Region& reg, std::uint64_t stub, std::uint64_t site, const unsigned char* code) {
        using Sn = abi::Sysno;
        const auto s = fastpath::make_stub(stub, reg.base + fastpath::layout().common, code, site);
        if (s.size() > LX_FP_SLOT_SIZE) return false;
        if (!fp_poke(cur_, stub, s.data(), s.size())) return false;
        const std::uint64_t page = stub & ~(LX_FP_NEAR_SIZE - 1);
        if (!reg.near_rx.count(page)) {
            if (fp_run1(Sn::mprotect, {page, LX_FP_NEAR_SIZE, PROT_READ | PROT_EXEC, 0, 0, 0}) != 0) return false;
            reg.near_rx.insert(page);
        }
#if defined(__aarch64__)
        // new code in a page another thread may run: make it visible
        (void)fp_run1(Sn::membarrier, {1u << 3 /*PRIVATE_EXPEDITED_SYNC_CORE*/, 0, 0, 0, 0, 0});
#endif
        return true;
    }

    // Replace the site's moved instruction with a jump to the stub. With
    // other threads in the process, only as part of one aligned 8-byte
    // write, so none can run half of the old and half of the new.
    bool fp_patch_site(std::uint64_t site, std::uint64_t stub) {
        const ::pid_t tg = host_tgid_of(cur_);
        std::size_t threads = 0;
        for (const auto& [tid, task] : tasks_) {
            (void)task;
            if (host_tgid_of(tid) == tg && ++threads > 1) break;
        }
        const auto j = fastpath::make_jump(site, stub);
#if defined(__x86_64__)
        if (threads > 1 && (site & 7) + j.size() > 8) return false;
        return fp_poke(cur_, site, j.data(), j.size());
#else
        (void)threads;   // one aligned word: atomic for any number of threads
        if (!fp_poke(cur_, site, j.data(), j.size())) return false;
        (void)fp_run1(abi::Sysno::membarrier, {1u << 3, 0, 0, 0, 0, 0});
        return true;
#endif
    }
