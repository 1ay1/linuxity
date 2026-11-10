// linuxity/runtime/linux/fastpath.inc -- included inside class PtraceTrap.
//
// The trap side of the in-guest fast path (see fastpath.hpp): which tasks
// get a region, when a site gets patched, and how a fault in the blob is
// turned into "fall back". All of it runs with the task stopped at a seccomp
// stop for one of the handled syscalls.
public:
    // Create the table (once, before the first guest call) and hook the
    // kernel's change logs. Off if anything is missing: every call traps.
    template <class K, class S>
    void fp_setup(K& k, S& sys) {
        if (!fastpath::wanted() || !fastpath::key().armed || !fastpath::layout().ok) return;
        if (!fp_own_.open(host::tmp_base())) return;
        fp_table_ = &fp_own_;
        auto& fs = k.files();
        fs.set_on_clean_dir([this](std::string_view d) { if (fp_live_) fp_own_.add_dir(d); });
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
        for (const auto& p : fp_wo_log_) fp_own_.add_tree(p);
        if (!fp_wo_log_.empty() || fs.dirs_version() != fp_dirs_seen_) {
            fp_own_.bump_dirs();
            fp_dirs_seen_ = fs.dirs_version();
        }
        fp_meta_log_.clear();
        fp_wo_log_.clear();
    }

    // The current task trapped on a handled syscall. Count the site; at the
    // threshold, map the region (once per process) and patch the site, then
    // run the call again down the new route. True when it did that (the
    // call is handled, don't dispatch it); false to dispatch as usual.
    template <class K, class S>
    [[nodiscard]] bool fp_maybe_patch(const abi::Regs& ar, std::uint64_t pc, K& k, S& sys) {
        if (!fp_table_) return false;
        fp_sync(k, sys);
        if (!fastpath::handled(abi::decode(kTraceeArch, ar.nr))) return false;
        const ::pid_t tg = host_tgid_of(cur_);
        if (!fp_regions_.count(tg)) fp_note_cwd_of(k, tg);
        return fp_try_patch(ar, pc);
    }

    // After the dispatcher ran any call: publish what it changed (a chmod, an
    // unlink, a mount) before the task runs on and can ask the blob. Moving
    // the cwd (chdir, fchdir) updates the blob's copy too.
    template <class K, class S>
    void fp_after_dispatch(const abi::Regs& ar, K& k, S& sys) {
        if (!fp_table_) return;
        fp_sync(k, sys);
        if (fp_regions_.empty()) return;
        const abi::Sysno sc = abi::decode(kTraceeArch, ar.nr);
        if (sc != abi::Sysno::chdir && sc != abi::Sysno::fchdir) return;
        const ::pid_t tg = host_tgid_of(cur_);
        if (fp_regions_.count(tg)) fp_note_cwd_of(k, tg);
    }

    void fp_report() {
        if (!fp_table_) return;
        std::fprintf(stderr, "linuxity fast path: %llu calls answered in the guest, %llu sites patched\n",
                     static_cast<unsigned long long>(fp_hits()),
                     static_cast<unsigned long long>(fp_patch_count_));
    }

private:
    fastpath::Table fp_own_;
    std::vector<std::string> fp_meta_log_, fp_wo_log_;
    std::uint64_t fp_layout_seen_{~0ull}, fp_links_seen_{~0ull}, fp_dirs_seen_{0};
    std::size_t fp_socks_seen_{~std::size_t{0}};
    bool fp_off_{true}, fp_live_{false};

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
            // a moved virtual mount or a read-only one answers like a plain one
            // for reads, but keep it simple: the blob only reads
            (void)ro;
            if (moved && !is_virtual) describable = false;
            ms.push_back({prefix, base, upper, is_virtual, static_cast<std::uint32_t>(idx + 21)});
        });
        if (!describable) ms.clear();
        fp_own_.set_mounts(ms);
        fp_own_.clear_exc_begin();
        fs.meta().for_each_path([&](const std::string& p) { fp_own_.add_leaf(p); });
        fs.for_each_whiteout([&](const std::string& p) { fp_own_.add_tree(p); });
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

public:
    [[nodiscard]] bool fp_on() const noexcept {
        return fp_table_ && fp_table_->enabled() && fastpath::layout().ok && seccomp_;
    }
    // Calls answered in the guest.
    [[nodiscard]] std::uint64_t fp_hits() const { return fp_table_ ? fp_table_->hits() : 0; }

private:
    static bool fp_debug() {
        static const bool on = std::getenv("LINUXITY_FP_DEBUG") != nullptr;
        return on;
    }
    bool fp_skip(const char* why, std::uint64_t site) {
        if (fp_debug()) std::fprintf(stderr, "[fp] %d site %#llx: %s\n", cur_,
                                     static_cast<unsigned long long>(site), why);
        return false;
    }
    [[nodiscard]] bool fp_try_patch(const abi::Regs& ar, std::uint64_t pc) {
        if (!fp_on()) return fp_skip("off", pc);
        Task& t = tasks_[cur_];
        if (t.refused) return false;
        const ::pid_t tg = host_tgid_of(cur_);
        fastpath::Region& reg = fp_regions_[tg];
        if (reg.failed) return fp_skip("region failed", pc);
        const std::uint64_t site = pc - fastpath::kSiteLen;
        if (reg.patched.count(site)) return false;   // already patched: a fallback trapped
        // a stub's own fallback syscall: leave it be (on aarch64 it looks
        // like any other site, and patching it would chain stubs forever)
        if (fp_in_own_pages(reg, site)) return false;
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
            ::iovec l{&magic, sizeof magic}, r{reinterpret_cast<void*>(reg.base), sizeof magic};
            if (::process_vm_readv(cur_, &l, 1, &r, 1, 0) != static_cast<ssize_t>(sizeof magic) ||
                magic != LX_FP_MAGIC) {
                reg = fastpath::Region{};
                reg.hits[site] = kFpThreshold;
            }
            reg.verified = true;
        }
        if (!reg.base && !fp_map_region(reg)) return fp_skip("map region", site);
        const std::uint64_t stub = fp_alloc_stub(reg, site);
        if (!stub) {
            reg.patched.insert(site);
            return fp_skip("no stub page in range", site);
        }
        if (!fp_write_stub(reg, stub, site, static_cast<std::uint32_t>(ar.nr))) return fp_skip("write stub", site);
        if (!fp_patch_site(site, stub, code)) { reg.patched.insert(site); return fp_skip("patch", site); }
        reg.patched.insert(site);
        ++fp_patch_count_;
        if (fp_debug()) std::fprintf(stderr, "[fp] %d patched %#llx -> %#llx\n", cur_,
                                     static_cast<unsigned long long>(site), static_cast<unsigned long long>(stub));
        // run the guest's call again from the patched site
        std::vector<std::int64_t> rets;
        return inject_then_retry({}, rets) || true;
    }

    // A SIGSEGV/SIGBUS in the blob's guarded copy: resume at its fault
    // return (which makes the call fall back) instead of delivering it.
    [[nodiscard]] bool fp_fixup_fault(::pid_t w) {
        if (fp_regions_.empty()) return false;
        Regs r{};
        if (!Regs::fetch(w, r)) return false;
        const ::pid_t tg = host_tgid_of(w);
        auto it = fp_regions_.find(tg);
        if (fp_debug()) {
            siginfo_t si{};
            (void)::ptrace(PTRACE_GETSIGINFO, w, 0, &si);
            std::fprintf(stderr, "[fp] %d fault pc=%#llx sp=%#llx addr=%p region=%#llx\n", w,
                         static_cast<unsigned long long>(r.pc()), static_cast<unsigned long long>(r.sp()),
                         si.si_addr, static_cast<unsigned long long>(it != fp_regions_.end() ? it->second.base : 0));
        }
        if (it == fp_regions_.end() || !it->second.base) return false;
        const auto& L = fastpath::layout();
        const std::uint64_t b = it->second.base;
        if (r.pc() < b + L.guard_start || r.pc() >= b + L.guard_end) return false;
        r.set_pc(b + L.fault_ret);
        return r.store(w);
    }

    // exec replaced the image: its region and patches are gone.
    void fp_forget(::pid_t tg) {
        auto it = fp_regions_.find(tg);
        if (it == fp_regions_.end()) return;
        fp_regions_.erase(it);
    }
    // the process is gone (its pid may be reused)
    void fp_reaped(::pid_t tg) {
        fp_forget(tg);
        if (fp_table_) fp_table_->drop_cwd(tg);
    }
    // fork copies the region and the patched code: the child shares both
    // (the region is private but the table is a shared file mapping).
    void fp_inherit(::pid_t parent_tg, ::pid_t child_tg) {
        auto it = fp_regions_.find(parent_tg);
        if (it == fp_regions_.end() || child_tg == parent_tg) return;
        fastpath::Region r = it->second;
        r.hits.clear();
        r.verified = false;
        fp_regions_[child_tg] = std::move(r);
        // a child starts in its parent's directory
        if (fp_table_) fp_table_->copy_cwd(parent_tg, child_tg);
    }

private:
    static constexpr std::uint32_t kFpThreshold = 3;
    static constexpr std::size_t kFpMaxSites = 256;
    fastpath::Table* fp_table_{nullptr};
    std::unordered_map<::pid_t, fastpath::Region> fp_regions_;
    std::uint64_t fp_patch_count_{0};

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
            // aligned reads; copy the bytes that fall in range
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
    // code, the proc page and the stacks, and the table file on top of its
    // slot. The calls run in the task, so they need no special trust.
    bool fp_map_region(fastpath::Region& reg) {
        using S = abi::Sysno;
        const auto blob = fastpath::blob();
        const std::string& tpath = fp_table_->path();
        // the path goes on the task's stack, below the red zone
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
            // the whole region read-write for now, and the table file
            const std::vector<GuestCall> first = {
                {S::mmap, {0, sz, kProt, kPriv, static_cast<std::uint64_t>(-1), 0}},
                {S::openat, {static_cast<std::uint64_t>(-100), spath, O_RDWR | O_CLOEXEC, 0, 0, 0}},
            };
            if (!fp_run(first, rets)) return false;
            if (rets.size() < 2 || rets[0] < 0 || rets[1] < 0) {
                if (!rets.empty() && rets[0] >= 0) (void)fp_run1(S::munmap, {static_cast<std::uint64_t>(rets[0]), sz, 0, 0, 0, 0});
                if (rets.size() >= 2 && rets[1] >= 0) (void)fp_run1(S::close, {static_cast<std::uint64_t>(rets[1]), 0, 0, 0, 0, 0});
                reg.failed = true;
                return false;
            }
            base = static_cast<std::uint64_t>(rets[0]);
            const auto fd = static_cast<std::uint64_t>(rets[1]);
            const std::int64_t m = fp_run1(S::mmap, {base + LX_FP_TABLE_OFF, LX_FP_TABLE_SIZE, PROT_READ,
                                                     MAP_SHARED | MAP_FIXED, fd, 0});
            const std::int64_t s = fp_run1(S::mmap, {base + LX_FP_STATS_OFF, 0x1000, PROT_READ | PROT_WRITE,
                                                     MAP_SHARED | MAP_FIXED, fd, LX_FP_TABLE_SIZE});
            (void)fp_run1(S::close, {fd, 0, 0, 0, 0, 0});
            good = m == static_cast<std::int64_t>(base + LX_FP_TABLE_OFF) &&
                   s == static_cast<std::int64_t>(base + LX_FP_STATS_OFF);
            if (!good && fp_debug())
                std::fprintf(stderr, "[fp] map: base=%#llx table=%lld stats=%lld\n",
                             static_cast<unsigned long long>(base), static_cast<long long>(m),
                             static_cast<long long>(s));
        }
        // the code and the proc page, written while still writable
        if (good) {
            ::iovec l{const_cast<unsigned char*>(blob.data()), blob.size()};
            ::iovec r{reinterpret_cast<void*>(base), blob.size()};
            good = ::process_vm_writev(cur_, &l, 1, &r, 1, 0) == static_cast<ssize_t>(blob.size()) ||
                   fp_poke(cur_, base, blob.data(), blob.size());
        }
        if (good) {
            // code r-x, the gap below the stacks inaccessible (a guard)
            good = fp_run1(S::mprotect, {base, LX_FP_CODE_MAX, PROT_READ | PROT_EXEC, 0, 0, 0}) == 0 &&
                   fp_run1(S::mprotect, {base + LX_FP_PROC_OFF + 0x1000,
                                         LX_FP_STACKS_OFF - LX_FP_PROC_OFF - 0x1000, PROT_NONE, 0, 0, 0}) == 0;
        }
        if (!good) {
            (void)fp_run1(S::munmap, {base, sz, 0, 0, 0, 0});
            reg.failed = true;
            return false;
        }
        reg.base = base;
        reg.verified = true;
        return true;
    }

    // One call in the current task; its raw return.
    std::int64_t fp_run1(abi::Sysno nr, std::array<std::uint64_t, 6> a) {
        std::vector<std::int64_t> rets;
        if (!fp_run({{nr, a}}, rets) || rets.empty()) return -EIO;
        return rets[0];
    }
    // Run calls in the current task and leave it at the entry stop it trapped
    // on, as if nothing happened (the dispatcher or the retry takes it from
    // there).
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
            // back to the entry stop of the guest's own call
            Regs again = entry;
            again.rewind_to_syscall();
            if (!again.store(cur_)) return false;
            if (!step_to_entry(cur_)) return false;
        }
        // the entry stop again, with the guest's registers
        (void)entry.store(cur_);
        (void)entry.commit_nr(cur_);
        return true;
    }

    // A stub slot within branch range of `site`, mapping a page if needed.
    std::uint64_t fp_alloc_stub(fastpath::Region& reg, std::uint64_t site) {
        using S = abi::Sysno;
        // reuse a page in range with a free slot
        for (auto& [page, used] : reg.used)
            if (used < LX_FP_SLOTS && fastpath::in_branch_range(site, page) &&
                fastpath::in_branch_range(site, page + LX_FP_NEAR_SIZE))
                return page + static_cast<std::uint64_t>(used++) * LX_FP_SLOT_SIZE;
        // map one near the site: try addresses just below it, then above
        const std::uint64_t win = site & ~(LX_FP_NEAR_SIZE - 1);
        for (int k = 1; k <= 64; ++k) {
            for (const int sign : {-1, 1}) {
                const std::int64_t delta = sign * static_cast<std::int64_t>(k) * 0x1000000LL;   // 16MB steps
                const std::uint64_t hint = static_cast<std::uint64_t>(static_cast<std::int64_t>(win) + delta);
                if (hint < 0x10000) continue;
                const std::int64_t got = fp_run1(S::mmap, {hint, LX_FP_NEAR_SIZE, PROT_READ | PROT_WRITE,
                                                           MAP_PRIVATE | MAP_ANONYMOUS | 0x100000 /*FIXED_NOREPLACE*/,
                                                           static_cast<std::uint64_t>(-1), 0});
                if (got < 0 && got >= -4095) continue;
                const auto page = static_cast<std::uint64_t>(got);
                if (!fastpath::in_branch_range(site, page) ||
                    !fastpath::in_branch_range(site, page + LX_FP_NEAR_SIZE)) {
                    (void)fp_run1(S::munmap, {page, LX_FP_NEAR_SIZE, 0, 0, 0, 0});
                    continue;
                }
                reg.near[win] = page;
                reg.used[page] = 1;
                return page;
            }
        }
        return 0;
    }

    bool fp_write_stub(fastpath::Region& reg, std::uint64_t stub, std::uint64_t site, std::uint32_t nr) {
        using S = abi::Sysno;
        const auto s = fastpath::make_stub(stub, reg.base + fastpath::layout().common, nr,
                                           site + fastpath::kSiteLen);
        if (s.size() > LX_FP_SLOT_SIZE) return false;
        // the page may already be r-x; ptrace pokes write it either way
        if (!fp_poke(cur_, stub, s.data(), s.size())) return false;
        const std::uint64_t page = stub & ~(LX_FP_NEAR_SIZE - 1);
        if (!reg.near_rx.count(page)) {
            if (fp_run1(S::mprotect, {page, LX_FP_NEAR_SIZE, PROT_READ | PROT_EXEC, 0, 0, 0}) != 0) return false;
            reg.near_rx.insert(page);
        }
#if defined(__aarch64__)
        // new code in a page another thread may run: make it visible
        (void)fp_run1(S::membarrier, {1u << 3 /*PRIVATE_EXPEDITED_SYNC_CORE*/, 0, 0, 0, 0, 0});
#endif
        return true;
    }

    // Replace the site with a jump to the stub. With other threads in the
    // process, only as one aligned 8-byte write, so none can run half of the
    // old and half of the new; alone (the stopped task), any alignment.
    bool fp_patch_site(std::uint64_t site, std::uint64_t stub, const unsigned char* code) {
        (void)code;
        const ::pid_t tg = host_tgid_of(cur_);
        std::size_t threads = 0;
        for (const auto& [tid, task] : tasks_) {
            (void)task;
            if (host_tgid_of(tid) == tg && ++threads > 1) break;
        }
#if defined(__x86_64__)
        // jmp rel32 over the 5-byte mov; the 2-byte syscall stays
        const std::int64_t rel = static_cast<std::int64_t>(stub) - static_cast<std::int64_t>(site + 5);
        unsigned char j[5] = {0xe9};
        const auto r32 = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel));
        std::memcpy(j + 1, &r32, 4);
        if (threads > 1 && (site & 7) > 3) return false;
        return fp_poke(cur_, site, j, sizeof j);
#else
        // one aligned 4-byte word: atomic for any number of threads
        (void)threads;
        const std::int64_t rel = (static_cast<std::int64_t>(stub) - static_cast<std::int64_t>(site)) / 4;
        const std::uint32_t b = 0x14000000u | (static_cast<std::uint32_t>(rel) & 0x3ffffffu);
        if (!fp_poke(cur_, site, reinterpret_cast<const unsigned char*>(&b), 4)) return false;
        (void)fp_run1(abi::Sysno::membarrier, {1u << 3, 0, 0, 0, 0, 0});
        return true;
#endif
    }
