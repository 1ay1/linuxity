// SysV IPC handlers, included inside class Syscalls (abi/syscall.hpp).
// Forwarded where the host has SysV IPC; served from kernel/sysv_ipc.hpp
// where it doesn't (Android builds its kernel with CONFIG_SYSVIPC off).

    // The host's objects for the initial IPC namespace; linuxity's own for
    // any namespace a guest made (the host has only the one) and on hosts
    // without SysV IPC at all.
    [[nodiscard]] bool host_has_sysv() { return kernel::SysvIpc::host_backed() && ipc_ns() == 0; }
    [[nodiscard]] std::uint64_t ipc_ns() { return me().ns.id[static_cast<int>(kernel::NsKind::ipc)]; }
    [[nodiscard]] kernel::IpcSpace& ipc_space() { return k_.procs().ipc().space(ipc_ns()); }
    [[nodiscard]] static std::int64_t now_s() { return static_cast<std::int64_t>(std::time(nullptr)); }

    // ipcperms(): may the caller do `want` (4 read, 2 write) to this object?
    [[nodiscard]] bool ipc_allowed(const kernel::IpcPerm& p, std::uint32_t want) {
        const auto& m = me();
        if (creds::capable(m, 13 /*CAP_IPC_OWNER*/)) return true;
        const std::uint32_t uid = m.uids[1], gid = m.gids[1];
        std::uint32_t bits = p.mode & 07;
        if (uid == p.uid || uid == p.cuid) bits = (p.mode >> 6) & 07;
        else if (gid == p.gid || gid == p.cgid) bits = (p.mode >> 3) & 07;
        return (bits & want) == want;
    }
    [[nodiscard]] bool ipc_owner(const kernel::IpcPerm& p) {
        const auto& m = me();
        return creds::capable(m, 21 /*CAP_SYS_ADMIN*/) || m.uids[1] == p.uid || m.uids[1] == p.cuid;
    }
    // The shared *get logic: find by key, honour IPC_CREAT/IPC_EXCL.
    template <class Map, class Make>
    [[nodiscard]] Outcome ipc_get(Map& m, std::int32_t key, std::uint32_t flg, Make make) {
        constexpr std::uint32_t kCreat = 01000, kExcl = 02000;
        if (key != 0) {
            for (auto& [id, o] : m) {
                if (o.perm.key != key) continue;
                if constexpr (requires { o.removed; }) if (o.removed) continue;
                if ((flg & kCreat) && (flg & kExcl)) return eno(Errno::eexist);
                const std::uint32_t want = ((flg & 0444) ? 4u : 0u) | ((flg & 0222) ? 2u : 0u);
                if (!ipc_allowed(o.perm, want)) return eno(Errno::eacces);
                if (const Errno e = make(o, false); e != Errno::ok) return eno(e);
                return val(id);
            }
            if (!(flg & kCreat)) return eno(Errno::enoent);
        }
        const std::int32_t id = ipc_space().new_id(m);
        if (id < 0) return eno(Errno::enospc);
        typename Map::mapped_type o{};
        o.perm.key = key;
        o.perm.uid = o.perm.cuid = me().uids[1];
        o.perm.gid = o.perm.cgid = me().gids[1];
        o.perm.mode = flg & 0777;
        o.perm.seq = static_cast<std::uint16_t>(id / 32768);
        if (const Errno e = make(o, true); e != Errno::ok) return eno(e);
        m.emplace(id, std::move(o));
        return val(id);
    }
    template <class V>
    static void put_at(std::vector<std::byte>& b, std::size_t off, V v) { std::memcpy(b.data() + off, &v, sizeof v); }
    void put_perm(std::vector<std::byte>& b, const kernel::IpcPerm& p) {
        put_at(b, 0, static_cast<std::uint32_t>(p.key));
        put_at(b, 4, ns_id(p.uid, false));  put_at(b, 8, ns_id(p.gid, true));
        put_at(b, 12, ns_id(p.cuid, false)); put_at(b, 16, ns_id(p.cgid, true));
        put_at(b, 20, p.mode);
        put_at(b, 24, p.seq);
    }
    // IPC_SET: uid, gid and the permission bits of a guest ipc_perm.
    [[nodiscard]] bool get_perm_set(std::uint64_t addr, kernel::IpcPerm& p) {
        std::array<std::byte, 24> raw{};
        if (!mem_.copy_in(uaddr(addr), raw)) return false;
        std::uint32_t uid, gid, mode;
        std::memcpy(&uid, raw.data() + 4, 4);
        std::memcpy(&gid, raw.data() + 8, 4);
        std::memcpy(&mode, raw.data() + 20, 4);
        p.uid = in_ns(uid, false);
        p.gid = in_ns(gid, true);
        p.mode = (p.mode & ~0777u) | (mode & 0777);
        return true;
    }
    // A global guest pid as the caller numbers it (pid namespaces).
    [[nodiscard]] std::int32_t global_to_view(std::int32_t pid) const {
        return pid > 0 ? k_.procs().view_pid(pid) : pid;
    }
    // The object an *_STAT index names (the low part of an id).
    template <class Map>
    [[nodiscard]] static auto by_index(Map& m, std::int32_t idx) {
        for (auto j = m.begin(); j != m.end(); ++j) if (j->first % 32768 == idx) return j;
        return m.end();
    }
    [[nodiscard]] bool copy_struct(std::uint64_t to, const void* p, std::size_t n) {
        return !to || mem_.copy_out(uaddr(to), {reinterpret_cast<const std::byte*>(p), n});
    }
    template <class Map>
    [[nodiscard]] static std::int64_t max_index(const Map& m) {
        std::int64_t hi = 0;
        for (const auto& [id, _] : m) hi = std::max<std::int64_t>(hi, id % 32768);
        return hi;
    }

    // ---- message queues ---------------------------------------------------
    [[nodiscard]] Outcome do_msgget(const Regs& r) {
        if (host_has_sysv()) return fwd();
        return ipc_get(ipc_space().msq, static_cast<std::int32_t>(r.arg[0]),
                       static_cast<std::uint32_t>(r.arg[1]),
                       [&](kernel::MsgQueue& q, bool fresh) {
                           if (fresh) q.ctime = now_s();
                           return Errno::ok;
                       });
    }
    // msgsnd(id, msgp, size, flg): msgp is {long mtype; char mtext[]}
    [[nodiscard]] Outcome do_msgsnd(const Regs& r) {
        if (host_has_sysv()) return fwd();
        auto& sp = ipc_space();
        const auto id = static_cast<std::int32_t>(r.arg[0]);
        const auto sz = static_cast<std::int64_t>(r.arg[2]);
        const auto flg = static_cast<std::uint32_t>(r.arg[3]);
        auto it = sp.msq.find(id);
        if (it == sp.msq.end()) return eno(Errno::einval);
        if (sz < 0 || sz > 8192 /*MSGMAX*/) return eno(Errno::einval);
        auto& q = it->second;
        if (!ipc_allowed(q.perm, 2)) return eno(Errno::eacces);
        std::vector<std::byte> buf(8 + static_cast<std::size_t>(sz));
        if (!mem_.copy_in(uaddr(r.arg[1]), buf)) return eno(Errno::efault);
        std::int64_t mtype;
        std::memcpy(&mtype, buf.data(), 8);
        if (mtype < 1) return eno(Errno::einval);
        if (q.cbytes + static_cast<std::uint64_t>(sz) > q.qbytes) {
            if (flg & 04000 /*IPC_NOWAIT*/) return eno(Errno::eagain);
            return Virtualize::retry_after(2'000'000);   // full: wait for a reader
        }
        q.msgs.emplace_back(mtype, std::string(reinterpret_cast<const char*>(buf.data() + 8),
                                               static_cast<std::size_t>(sz)));
        q.cbytes += static_cast<std::uint64_t>(sz);
        q.stime = now_s();
        q.lspid = ids().pid;
        return val(0);
    }
    // msgrcv(id, msgp, size, type, flg)
    [[nodiscard]] Outcome do_msgrcv(const Regs& r) {
        if (host_has_sysv()) return fwd();
        auto& sp = ipc_space();
        const auto id = static_cast<std::int32_t>(r.arg[0]);
        const auto cap = static_cast<std::int64_t>(r.arg[2]);
        const auto type = static_cast<std::int64_t>(r.arg[3]);
        const auto flg = static_cast<std::uint32_t>(r.arg[4]);
        constexpr std::uint32_t kNoWait = 04000, kNoError = 010000, kExcept = 020000, kCopy = 040000;
        auto it = sp.msq.find(id);
        if (it == sp.msq.end()) return eno(Errno::einval);   // or removed while we waited (EIDRM)
        if (cap < 0) return eno(Errno::einval);
        auto& q = it->second;
        if (!ipc_allowed(q.perm, 4)) return eno(Errno::eacces);
        auto pick = q.msgs.end();
        if (flg & kCopy) {
            if (!(flg & kNoWait) || (flg & kExcept)) return eno(Errno::einval);
            if (type < 0 || static_cast<std::size_t>(type) >= q.msgs.size()) return eno(Errno::enomsg);
            pick = q.msgs.begin() + type;
        } else if (type == 0) {
            pick = q.msgs.begin();
        } else if (type > 0) {
            for (auto m = q.msgs.begin(); m != q.msgs.end(); ++m)
                if ((flg & kExcept) ? m->first != type : m->first == type) { pick = m; break; }
        } else {
            for (auto m = q.msgs.begin(); m != q.msgs.end(); ++m)   // lowest type <= |type|
                if (m->first <= -type && (pick == q.msgs.end() || m->first < pick->first)) pick = m;
        }
        if (pick == q.msgs.end()) {
            if (flg & kNoWait) return eno(Errno::enomsg);
            return Virtualize::retry_after(2'000'000);   // wait for a sender
        }
        const auto len = static_cast<std::int64_t>(pick->second.size());
        if (len > cap && !(flg & kNoError)) return eno(Errno::e2big);
        const auto n = static_cast<std::size_t>(std::min(len, cap));
        std::vector<std::byte> out(8 + n);
        std::memcpy(out.data(), &pick->first, 8);
        std::memcpy(out.data() + 8, pick->second.data(), n);
        if (!mem_.copy_out(uaddr(r.arg[1]), out)) return eno(Errno::efault);
        if (!(flg & kCopy)) {
            q.cbytes -= static_cast<std::uint64_t>(len);
            q.msgs.erase(pick);
            q.rtime = now_s();
            q.lrpid = ids().pid;
        }
        return val(static_cast<std::int64_t>(n));
    }
    // msgctl(id, cmd, buf)
    [[nodiscard]] Outcome do_msgctl(const Regs& r) {
        if (host_has_sysv()) return fwd();
        auto& sp = ipc_space();
        const auto id = static_cast<std::int32_t>(r.arg[0]);
        const int cmd = static_cast<int>(r.arg[1] & ~0x100u);   // without IPC_64
        if (cmd == 3 /*IPC_INFO*/ || cmd == 12 /*MSG_INFO*/) {
            // struct msginfo: msgpool msgmap msgmax msgmnb msgmni msgssz msgtql msgseg
            std::array<std::int32_t, 8> mi{};
            if (cmd == 3) mi = {32768, 32000, 8192, 16384, 32000, 16, 32000, 0xffff};
            else {
                std::int32_t qn = 0, by = 0;
                for (const auto& [_, q] : sp.msq) { qn += static_cast<std::int32_t>(q.msgs.size()); by += static_cast<std::int32_t>(q.cbytes); }
                mi = {static_cast<std::int32_t>(sp.msq.size()), qn, 8192, 16384, 32000, 16, by, 0xffff};
            }
            if (!copy_struct(r.arg[2], mi.data(), sizeof mi)) return eno(Errno::efault);
            return val(max_index(sp.msq));
        }
        auto it = (cmd == 11 || cmd == 13) ? by_index(sp.msq, id) : sp.msq.find(id);
        if (it == sp.msq.end()) return eno(Errno::einval);
        auto& q = it->second;
        switch (cmd) {
            case 0:   // IPC_RMID
                if (!ipc_owner(q.perm)) return eno(Errno::eperm);
                sp.msq.erase(it);
                return val(0);
            case 1: {   // IPC_SET
                if (!ipc_owner(q.perm)) return eno(Errno::eperm);
                if (!get_perm_set(r.arg[2], q.perm)) return eno(Errno::efault);
                std::array<std::byte, 8> raw{};
                std::uint64_t qb = 0;
                if (mem_.copy_in(uaddr(r.arg[2] + 88), raw)) std::memcpy(&qb, raw.data(), 8);
                if (qb > 16384 && !creds::capable(me(), 24 /*CAP_SYS_RESOURCE*/)) return eno(Errno::eperm);
                if (qb) q.qbytes = qb;
                q.ctime = now_s();
                return val(0);
            }
            case 2: case 11: case 13: {   // IPC_STAT, MSG_STAT, MSG_STAT_ANY
                if (cmd != 13 && !ipc_allowed(q.perm, 4)) return eno(Errno::eacces);
                std::vector<std::byte> b(120);
                put_perm(b, q.perm);
                put_at(b, 48, q.stime); put_at(b, 56, q.rtime); put_at(b, 64, q.ctime);
                put_at(b, 72, q.cbytes); put_at(b, 80, static_cast<std::uint64_t>(q.msgs.size()));
                put_at(b, 88, q.qbytes);
                put_at(b, 96, global_to_view(q.lspid)); put_at(b, 100, global_to_view(q.lrpid));
                if (!mem_.copy_out(uaddr(r.arg[2]), b)) return eno(Errno::efault);
                return val(cmd == 2 ? 0 : it->first);
            }
            default: return eno(Errno::einval);
        }
    }

    // ---- semaphores -------------------------------------------------------
    [[nodiscard]] Outcome do_semget(const Regs& r) {
        if (host_has_sysv()) return fwd();
        const auto n = static_cast<std::int64_t>(static_cast<std::int32_t>(r.arg[1]));
        return ipc_get(ipc_space().sem, static_cast<std::int32_t>(r.arg[0]),
                       static_cast<std::uint32_t>(r.arg[2]),
                       [&](kernel::SemSet& s, bool fresh) {
                           if (fresh) {
                               if (n <= 0 || n > 32000 /*SEMMSL*/) return Errno::einval;
                               s.sems.resize(static_cast<std::size_t>(n));
                               s.ctime = now_s();
                           } else if (n > static_cast<std::int64_t>(s.sems.size())) {
                               return Errno::einval;
                           }
                           return Errno::ok;
                       });
    }
    // semop/semtimedop(id, sops, nsops[, timeout]): all of them or none
    [[nodiscard]] Outcome do_semop(const Regs& r, bool timed) {
        if (host_has_sysv()) return fwd();
        auto& sp = ipc_space();
        const auto id = static_cast<std::int32_t>(r.arg[0]);
        const auto nsops = static_cast<std::size_t>(r.arg[2]);
        if (nsops == 0) return eno(Errno::einval);
        if (nsops > 500 /*SEMOPM*/) return eno(Errno::e2big);
        auto it = sp.sem.find(id);
        if (it == sp.sem.end()) return eno(Errno::einval);
        auto& s = it->second;
        std::vector<std::byte> raw(nsops * 6);
        if (!mem_.copy_in(uaddr(r.arg[1]), raw)) return eno(Errno::efault);
        struct Op { std::uint16_t num; std::int16_t op; std::int16_t flg; };
        std::vector<Op> ops(nsops);
        std::memcpy(ops.data(), raw.data(), raw.size());
        bool alter = false;
        for (const auto& o : ops) {
            if (o.num >= s.sems.size()) return eno(Errno::efbig);
            alter |= o.op != 0;
        }
        if (!ipc_allowed(s.perm, alter ? 2u : 4u)) return eno(Errno::eacces);
        auto vals = s.sems;
        for (const auto& o : ops) {
            auto& v = vals[o.num].val;
            const bool nowait = o.flg & 04000;
            if (o.op > 0) {
                if (static_cast<int>(v) + o.op > 32767 /*SEMVMX*/) return eno(Errno::erange);
                v = static_cast<std::uint16_t>(v + o.op);
            } else if (o.op < 0 ? static_cast<int>(v) + o.op < 0 : v != 0) {
                if (nowait) return eno(Errno::eagain);
                return sem_wait(r, timed);
            } else if (o.op < 0) {
                v = static_cast<std::uint16_t>(v + o.op);
            }
        }
        const auto pid = ids().pid;
        for (const auto& o : ops) {
            vals[o.num].pid = pid;
            if ((o.flg & 010000 /*SEM_UNDO*/) && o.op)
                k_.procs().ipc().note_undo(pid, {ipc_ns(), id, o.num}, o.op);
        }
        s.sems = std::move(vals);
        s.otime = now_s();
        sem_waits_.erase(ids().tid);
        return val(0);
    }
    // A semop that has to block waits in the guest's kernel and tries again;
    // a timed one gives up with EAGAIN once its timeout has passed.
    [[nodiscard]] Outcome sem_wait(const Regs& r, bool timed) {
        const auto tid = ids().tid;
        const auto now = std::chrono::steady_clock::now();
        const auto start = sem_waits_.try_emplace(tid, now).first->second;
        if (timed && r.arg[3]) {
            std::array<std::byte, 16> ts{};
            if (!mem_.copy_in(uaddr(r.arg[3]), ts)) { sem_waits_.erase(tid); return eno(Errno::efault); }
            std::int64_t sec, nsec;
            std::memcpy(&sec, ts.data(), 8);
            std::memcpy(&nsec, ts.data() + 8, 8);
            if (sec < 0 || nsec < 0 || nsec >= 1'000'000'000) { sem_waits_.erase(tid); return eno(Errno::einval); }
            if (now - start >= std::chrono::seconds{sec} + std::chrono::nanoseconds{nsec}) {
                sem_waits_.erase(tid);
                return eno(Errno::eagain);
            }
        }
        return Virtualize::retry_after(1'000'000);
    }
    // semctl(id, num, cmd, arg)
    [[nodiscard]] Outcome do_semctl(const Regs& r) {
        if (host_has_sysv()) return fwd();
        auto& sp = ipc_space();
        const auto id = static_cast<std::int32_t>(r.arg[0]);
        const auto num = static_cast<std::int32_t>(r.arg[1]);
        const int cmd = static_cast<int>(r.arg[2] & ~0x100u);
        const std::uint64_t arg = r.arg[3];
        if (cmd == 3 /*IPC_INFO*/ || cmd == 19 /*SEM_INFO*/) {
            // struct seminfo: map mni mns mnu msl opm ume usz vmx aem
            std::array<std::int32_t, 10> si{1024000000, 32000, 1024000000, 32000, 32000,
                                            500, 32000, 20, 32767, 0};
            if (cmd == 19) {
                std::int32_t total = 0;
                for (const auto& [_, s] : sp.sem) total += static_cast<std::int32_t>(s.sems.size());
                si[7] = static_cast<std::int32_t>(sp.sem.size());   // semusz: sets in use
                si[9] = total;                                     // semaem: semaphores
            }
            if (!copy_struct(arg, si.data(), sizeof si)) return eno(Errno::efault);
            return val(max_index(sp.sem));
        }
        auto it = (cmd == 18 || cmd == 20) ? by_index(sp.sem, id) : sp.sem.find(id);
        if (it == sp.sem.end()) return eno(Errno::einval);
        auto& s = it->second;
        const auto nsems = s.sems.size();
        const bool valid = num >= 0 && static_cast<std::size_t>(num) < nsems;
        switch (cmd) {
            case 0:   // IPC_RMID
                if (!ipc_owner(s.perm)) return eno(Errno::eperm);
                k_.procs().ipc().clear_undo(ipc_ns(), id);
                sp.sem.erase(it);
                return val(0);
            case 1:   // IPC_SET
                if (!ipc_owner(s.perm)) return eno(Errno::eperm);
                if (!get_perm_set(arg, s.perm)) return eno(Errno::efault);
                s.ctime = now_s();
                return val(0);
            case 2: case 18: case 20: {   // IPC_STAT, SEM_STAT, SEM_STAT_ANY
                if (cmd != 20 && !ipc_allowed(s.perm, 4)) return eno(Errno::eacces);
                const bool x86 = arch_ == Arch::x86_64;
                std::vector<std::byte> b(x86 ? 104 : 88);
                put_perm(b, s.perm);
                put_at(b, 48, s.otime);
                put_at(b, x86 ? 64 : 56, s.ctime);
                put_at(b, x86 ? 80 : 64, static_cast<std::uint64_t>(nsems));
                if (!mem_.copy_out(uaddr(arg), b)) return eno(Errno::efault);
                return val(cmd == 2 ? 0 : it->first);
            }
            case 11: case 12: case 14: case 15: {   // GETPID GETVAL GETNCNT GETZCNT
                if (!valid) return eno(Errno::einval);
                if (!ipc_allowed(s.perm, 4)) return eno(Errno::eacces);
                const auto& sem = s.sems[static_cast<std::size_t>(num)];
                if (cmd == 11) return val(global_to_view(sem.pid));
                if (cmd == 12) return val(sem.val);
                return val(0);
            }
            case 13: {   // GETALL
                if (!ipc_allowed(s.perm, 4)) return eno(Errno::eacces);
                std::vector<std::uint16_t> v;
                for (const auto& x : s.sems) v.push_back(x.val);
                if (!mem_.copy_out(uaddr(arg), {reinterpret_cast<const std::byte*>(v.data()), v.size() * 2}))
                    return eno(Errno::efault);
                return val(0);
            }
            case 16: {   // SETVAL
                if (!valid) return eno(Errno::einval);
                if (!ipc_allowed(s.perm, 2)) return eno(Errno::eacces);
                const auto v = static_cast<std::int32_t>(arg);
                if (v < 0 || v > 32767) return eno(Errno::erange);
                s.sems[static_cast<std::size_t>(num)] = {static_cast<std::uint16_t>(v), ids().pid};
                k_.procs().ipc().clear_undo(ipc_ns(), id, static_cast<std::size_t>(num));
                s.ctime = now_s();
                return val(0);
            }
            case 17: {   // SETALL
                if (!ipc_allowed(s.perm, 2)) return eno(Errno::eacces);
                std::vector<std::uint16_t> v(nsems);
                if (!mem_.copy_in(uaddr(arg), {reinterpret_cast<std::byte*>(v.data()), v.size() * 2}))
                    return eno(Errno::efault);
                for (const auto x : v) if (x > 32767) return eno(Errno::erange);
                for (std::size_t i = 0; i < nsems; ++i) s.sems[i] = {v[i], ids().pid};
                k_.procs().ipc().clear_undo(ipc_ns(), id);
                s.ctime = now_s();
                return val(0);
            }
            default: return eno(Errno::einval);
        }
    }

    // ---- shared memory ----------------------------------------------------
    // The memory is a host file; each attach maps it MAP_SHARED inside the
    // guest task, so every attacher really shares the same pages.
    [[nodiscard]] Outcome do_shmget(const Regs& r) {
        if (host_has_sysv()) return fwd();
        const std::uint64_t size = r.arg[1];
        return ipc_get(ipc_space().shm, static_cast<std::int32_t>(r.arg[0]),
                       static_cast<std::uint32_t>(r.arg[2]),
                       [&](kernel::ShmSeg& g, bool fresh) {
                           if (!fresh) return size > g.size ? Errno::einval : Errno::ok;
                           if (size < 1 || size > (std::uint64_t{1} << 40)) return Errno::einval;
                           const std::string dir = k_.procs().ipc().seg_dir();
                           if (dir.empty()) return Errno::enomem;
                           g.file = dir + "/seg-" + std::to_string(++shm_serial_);
                           const int fd = ::open(g.file.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
                           if (fd < 0) return Errno::enomem;
                           const bool sized = ::ftruncate(fd, static_cast<off_t>(size)) == 0;
                           ::close(fd);
                           if (!sized) { ::unlink(g.file.c_str()); return Errno::enomem; }
                           (void)::chmod(g.file.c_str(), 0666);
                           g.size = size;
                           g.cpid = ids().pid;
                           g.ctime = now_s();
                           return Errno::ok;
                       });
    }
    // shmat(id, addr, flg)
    [[nodiscard]] Outcome do_shmat(const Regs& r) {
        if (host_has_sysv()) return fwd();
        auto& sp = ipc_space();
        const auto id = static_cast<std::int32_t>(r.arg[0]);
        std::uint64_t addr = r.arg[1];
        const auto flg = static_cast<std::uint32_t>(r.arg[2]);
        constexpr std::uint32_t kRdonly = 010000, kRnd = 020000, kRemap = 040000, kExec = 0100000;
        auto it = sp.shm.find(id);
        // a removed segment can still be attached by id (Linux allows it)
        if (it == sp.shm.end()) return eno(Errno::einval);
        auto& g = it->second;
        const bool ro = flg & kRdonly;
        if (!ipc_allowed(g.perm, ro ? 4u : 6u)) return eno(Errno::eacces);
        if (addr) {
            if (flg & kRnd) addr &= ~std::uint64_t{0xfff};   // SHMLBA
            else if (addr & 0xfff) return eno(Errno::einval);
        } else if (flg & kRemap) {
            return eno(Errno::einval);
        }
        const std::uint64_t prot = 1 /*R*/ | (ro ? 0u : 2u) | ((flg & kExec) ? 4u : 0u);
        const std::uint64_t mflags = 0x01 /*MAP_SHARED*/ | (addr ? 0x10 /*MAP_FIXED*/ : 0u);
        GuestCalls gc;
        gc.strings = {g.file};
        gc.steps = {
            {Sysno::openat, {static_cast<std::uint64_t>(-100) /*AT_FDCWD*/, GuestCalls::str0,
                             static_cast<std::uint64_t>((ro ? 0 : 2) | 02000000 /*O_CLOEXEC*/), 0, 0, 0}},
            {Sysno::mmap, {addr, g.size, prot, mflags, GuestCalls::prev, 0}},
            // the fd is only needed until the mapping exists
            {Sysno::close, {GuestCalls::prev_of(0), 0, 0, 0, 0, 0}},
        };
        gc.result_of = 1;   // shmat returns the address
        const auto ns = ipc_ns();
        const auto pid = ids().pid;
        const auto size = g.size;
        gc.done = [this, ns, id, pid, size](std::int64_t ret) {
            if (ret < 0 && ret >= -4095) return;
            auto& s2 = k_.procs().ipc().space(ns);
            if (auto j = s2.shm.find(id); j != s2.shm.end()) {
                ++j->second.nattch;
                j->second.atime = now_s();
                j->second.lpid = pid;
            }
            k_.procs().ipc().attach(pid, static_cast<std::uint64_t>(ret), {ns, id, size});
        };
        return gc;
    }
    // shmdt(addr)
    [[nodiscard]] Outcome do_shmdt(const Regs& r) {
        if (host_has_sysv()) return fwd();
        const auto pid = ids().pid;
        const auto a = k_.procs().ipc().attachment(pid, r.arg[0]);
        if (!a) return eno(Errno::einval);
        auto& sp = k_.procs().ipc().space(a->ns);
        if (auto j = sp.shm.find(a->shmid); j != sp.shm.end()) { j->second.dtime = now_s(); j->second.lpid = pid; }
        k_.procs().ipc().detach(pid, r.arg[0]);
        GuestCalls gc;
        gc.steps = {{Sysno::munmap, {r.arg[0], a->size, 0, 0, 0, 0}}};
        return gc;
    }
    // shmctl(id, cmd, buf)
    [[nodiscard]] Outcome do_shmctl(const Regs& r) {
        if (host_has_sysv()) return fwd();
        auto& sp = ipc_space();
        const auto id = static_cast<std::int32_t>(r.arg[0]);
        const int cmd = static_cast<int>(r.arg[1] & ~0x100u);
        if (cmd == 3 /*IPC_INFO*/) {
            // struct shminfo: shmmax shmmin shmmni shmseg shmall + 4 unused
            std::array<std::uint64_t, 9> si{std::uint64_t{1} << 40, 1, 4096, 4096, std::uint64_t{1} << 40, 0, 0, 0, 0};
            if (!copy_struct(r.arg[2], si.data(), sizeof si)) return eno(Errno::efault);
            return val(max_index(sp.shm));
        }
        if (cmd == 14 /*SHM_INFO*/) {
            // struct shm_info: int used_ids; ulong shm_tot, shm_rss, shm_swp, swap_attempts, swap_successes
            std::vector<std::byte> b(48);
            std::uint64_t tot = 0;
            for (const auto& [_, g] : sp.shm) tot += (g.size + 4095) / 4096;
            put_at(b, 0, static_cast<std::int32_t>(sp.shm.size()));
            put_at(b, 8, tot); put_at(b, 16, tot);
            if (r.arg[2] && !mem_.copy_out(uaddr(r.arg[2]), b)) return eno(Errno::efault);
            return val(max_index(sp.shm));
        }
        auto it = (cmd == 13 || cmd == 15) ? by_index(sp.shm, id) : sp.shm.find(id);
        if (it == sp.shm.end()) return eno(Errno::einval);
        auto& g = it->second;
        switch (cmd) {
            case 0:   // IPC_RMID: no new attaches; freed at the last detach
                if (!ipc_owner(g.perm)) return eno(Errno::eperm);
                g.removed = true;
                g.perm.mode |= 01000;   // SHM_DEST
                g.perm.key = 0;
                k_.procs().ipc().maybe_free(ipc_ns(), id);
                return val(0);
            case 1:   // IPC_SET
                if (!ipc_owner(g.perm)) return eno(Errno::eperm);
                if (!get_perm_set(r.arg[2], g.perm)) return eno(Errno::efault);
                g.ctime = now_s();
                return val(0);
            case 2: case 13: case 15: {   // IPC_STAT, SHM_STAT, SHM_STAT_ANY
                if (cmd != 15 && !ipc_allowed(g.perm, 4)) return eno(Errno::eacces);
                std::vector<std::byte> b(112);
                put_perm(b, g.perm);
                put_at(b, 48, g.size);
                put_at(b, 56, g.atime); put_at(b, 64, g.dtime); put_at(b, 72, g.ctime);
                put_at(b, 80, global_to_view(g.cpid)); put_at(b, 84, global_to_view(g.lpid));
                put_at(b, 88, g.nattch);
                if (!mem_.copy_out(uaddr(r.arg[2]), b)) return eno(Errno::efault);
                return val(cmd == 2 ? 0 : it->first);
            }
            case 11: case 12:   // SHM_LOCK, SHM_UNLOCK: CAP_IPC_LOCK, or the owner
                if (!creds::capable(me(), 14 /*CAP_IPC_LOCK*/) && !ipc_owner(g.perm)) return eno(Errno::eperm);
                if (cmd == 11) g.perm.mode |= 02000; else g.perm.mode &= ~02000u;
                return val(0);
            default: return eno(Errno::einval);
        }
    }
