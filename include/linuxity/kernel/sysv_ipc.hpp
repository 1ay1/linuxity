// linuxity/kernel/sysv_ipc.hpp
//
// System V IPC (sysvipc(7)) for hosts without it: Android builds its kernel
// with CONFIG_SYSVIPC off, so msgget/semget/shmget are ENOSYS there. The
// queues and semaphore sets live here; a shared memory segment is a real
// host file that each attaching guest process maps MAP_SHARED, so the memory
// is genuinely shared. One registry per IPC namespace.
#pragma once

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace lx::kernel {

struct IpcPerm {
    std::int32_t key{0};
    std::uint32_t uid{0}, gid{0}, cuid{0}, cgid{0};
    std::uint32_t mode{0};
    std::uint16_t seq{0};
};

struct MsgQueue {
    IpcPerm perm;
    std::deque<std::pair<std::int64_t, std::string>> msgs;   // (mtype, text)
    std::uint64_t cbytes{0}, qbytes{16384};                  // MSGMNB
    std::int64_t stime{0}, rtime{0}, ctime{0};
    std::int32_t lspid{0}, lrpid{0};
};

struct Sem { std::uint16_t val{0}; std::int32_t pid{0}; };
struct SemSet {
    IpcPerm perm;
    std::vector<Sem> sems;
    std::int64_t otime{0}, ctime{0};
    std::uint32_t ncnt{0}, zcnt{0};   // tasks waiting (approximate, for GETNCNT/GETZCNT)
};

struct ShmSeg {
    IpcPerm perm;
    std::uint64_t size{0};
    std::string file;                 // the host file holding the memory
    std::int64_t atime{0}, dtime{0}, ctime{0};
    std::int32_t cpid{0}, lpid{0};
    std::uint64_t nattch{0};
    bool removed{false};              // IPC_RMID'd: goes when nattch hits 0
};

// One IPC namespace's objects. Ids follow Linux: index + seq * 32768.
struct IpcSpace {
    std::map<std::int32_t, MsgQueue> msq;
    std::map<std::int32_t, SemSet> sem;
    std::map<std::int32_t, ShmSeg> shm;
    std::uint16_t seq{0};
    template <class M> [[nodiscard]] std::int32_t new_id(const M& m) {
        for (std::int32_t idx = 0; idx < 32000; ++idx) {
            const std::int32_t id = idx + static_cast<std::int32_t>(seq % 64) * 32768;
            if (!m.count(id)) { ++seq; return id; }
        }
        return -1;
    }
};

struct ShmAttach { std::uint64_t ns; std::int32_t shmid; std::uint64_t size; };

class SysvIpc {
public:
    ~SysvIpc() {
#if !defined(_WIN32)
        for (auto& [_, s] : spaces_)
            for (auto& [__, g] : s.shm) if (!g.file.empty()) ::unlink(g.file.c_str());
        if (!dir_.empty()) ::rmdir(dir_.c_str());
#endif
    }
    [[nodiscard]] IpcSpace& space(std::uint64_t ns) { return spaces_[ns]; }
    // Does the host kernel have SysV IPC? Then the syscalls (and
    // /proc/sysvipc) are the host's; otherwise linuxity's own objects.
    // LINUXITY_EMULATE_SYSV=1 forces the emulation, for testing.
    [[nodiscard]] static bool host_backed() {
#if defined(_WIN32)
        return false;
#else
        static const bool has = [] {
            if (std::getenv("LINUXITY_EMULATE_SYSV")) return false;
            const long id = ::syscall(SYS_msgget, 0 /*IPC_PRIVATE*/, 01000 | 0600);
            if (id < 0) return errno != ENOSYS;
            ::syscall(SYS_msgctl, id, 0 /*IPC_RMID*/, nullptr);
            return true;
        }();
        return has;
#endif
    }
    [[nodiscard]] const IpcSpace* find_space(std::uint64_t ns) const {
        auto it = spaces_.find(ns);
        return it == spaces_.end() ? nullptr : &it->second;
    }

    // Where segment files live: a private dir both linuxity and its guests
    // can open (TMPDIR on Android is /data/local/tmp).
    [[nodiscard]] std::string seg_dir() {
#if defined(_WIN32)
        return {};
#else
        if (!dir_.empty()) return dir_;
        const char* t = std::getenv("TMPDIR");
        std::string base = t && *t ? t : "/tmp";
        std::string d = base + "/linuxity-sysvipc-" + std::to_string(::getpid());
        if (::mkdir(d.c_str(), 0700) == 0 || errno == EEXIST) dir_ = d;
        return dir_;
#endif
    }

    // -- attachments, per guest process --------------------------------------
    void attach(std::int32_t pid, std::uint64_t addr, ShmAttach a) { att_[pid][addr] = a; }
    [[nodiscard]] std::optional<ShmAttach> attachment(std::int32_t pid, std::uint64_t addr) const {
        auto p = att_.find(pid);
        if (p == att_.end()) return std::nullopt;
        auto a = p->second.find(addr);
        if (a == p->second.end()) return std::nullopt;
        return a->second;
    }
    void detach(std::int32_t pid, std::uint64_t addr) {
        auto p = att_.find(pid);
        if (p == att_.end()) return;
        if (auto a = p->second.find(addr); a != p->second.end()) {
            drop_attach(a->second);
            p->second.erase(a);
        }
    }
    // A forked child shares its parent's attachments (each counts once more).
    void inherit(std::int32_t child, std::int32_t parent) {
        auto p = att_.find(parent);
        if (p == att_.end() || p->second.empty()) return;
        for (const auto& [addr, a] : p->second) {
            att_[child][addr] = a;
            if (auto* g = seg(a)) ++g->nattch;
        }
    }
    // exec: every mapping is gone (SEM_UNDO stays with the process).
    void process_gone_maps(std::int32_t pid) {
        if (auto p = att_.find(pid); p != att_.end()) {
            for (auto& [_, a] : p->second) drop_attach(a);
            att_.erase(p);
        }
    }
    // exit: every mapping is gone, and SEM_UNDO adjustments apply.
    void process_gone(std::int32_t pid) {
        process_gone_maps(pid);
        if (auto u = undo_.find(pid); u != undo_.end()) {
            for (const auto& [k, adj] : u->second) {
                auto& s = spaces_[k.ns];
                if (auto it = s.sem.find(k.semid); it != s.sem.end() && k.num < it->second.sems.size()) {
                    auto& v = it->second.sems[k.num].val;
                    const int nv = static_cast<int>(v) + adj;
                    v = static_cast<std::uint16_t>(nv < 0 ? 0 : nv > 32767 ? 32767 : nv);
                }
            }
            undo_.erase(u);
        }
    }

    // -- SEM_UNDO ------------------------------------------------------------
    struct UndoKey {
        std::uint64_t ns; std::int32_t semid; std::size_t num;
        bool operator<(const UndoKey& o) const {
            return std::tie(ns, semid, num) < std::tie(o.ns, o.semid, o.num);
        }
    };
    void note_undo(std::int32_t pid, UndoKey k, int op) { undo_[pid][k] -= op; }
    void clear_undo(std::uint64_t ns, std::int32_t semid, std::optional<std::size_t> num = {}) {
        for (auto& [_, m] : undo_)
            std::erase_if(m, [&](const auto& e) {
                return e.first.ns == ns && e.first.semid == semid && (!num || e.first.num == *num);
            });
    }

    // Free a segment's memory once removed and unattached.
    void maybe_free(std::uint64_t ns, std::int32_t id) {
        auto& s = spaces_[ns];
        auto it = s.shm.find(id);
        if (it == s.shm.end() || !it->second.removed || it->second.nattch) return;
#if !defined(_WIN32)
        if (!it->second.file.empty()) ::unlink(it->second.file.c_str());
#endif
        s.shm.erase(it);
    }

private:
    ShmSeg* seg(const ShmAttach& a) {
        auto& s = spaces_[a.ns];
        auto it = s.shm.find(a.shmid);
        return it == s.shm.end() ? nullptr : &it->second;
    }
    void drop_attach(const ShmAttach& a) {
        if (auto* g = seg(a)) {
            if (g->nattch) --g->nattch;
            maybe_free(a.ns, a.shmid);
        }
    }
    std::map<std::uint64_t, IpcSpace> spaces_;
    std::map<std::int32_t, std::map<std::uint64_t, ShmAttach>> att_;
    std::map<std::int32_t, std::map<UndoKey, int>> undo_;
    std::string dir_;
};

}  // namespace lx::kernel
