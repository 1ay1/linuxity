// linuxity/runtime/linux/fastpath_table.hpp
//
// The supervisor's side of the in-guest fast path's shared table (see
// fastpath_abi.h): a file every guest process maps read-only, holding what the
// fast path needs to answer a path query exactly as the dispatcher would --
// the mount table, the directories known to be free of symlinks, and the
// paths it must leave to the dispatcher (chmod records, whiteouts, emulated
// links, socket placeholders).
//
// Changes are published with a seqlock; a guest call that overlaps one falls
// back to the trap. Entries are only added between rebuilds, so a stale entry
// costs a fallback, never a wrong answer.
#pragma once

#include "linuxity/runtime/linux/fastpath_abi.h"

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#if defined(__linux__)
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>
#endif

namespace lx::runtime::fastpath {

static_assert(sizeof(lx_fp_table) <= LX_FP_TABLE_SIZE, "fast path table outgrew its mapping");
static_assert(sizeof(lx_fp_proc) <= LX_FP_PROC_SIZE, "per-process area");
static_assert(LX_FP_PROC_OFF + LX_FP_PROC_SIZE + 0x1000 <= LX_FP_FDMAP_OFF, "proc area overlaps the fd map");
static_assert(sizeof(lx_fp_stats) <= 0x1000, "stats page is one page");
static_assert(sizeof(lx_fp_fd) == 256, "fd map entry");
static_assert(LX_FP_FDMAP_OFF + LX_FP_FDS * sizeof(lx_fp_fd) + 0x1000 <= LX_FP_STACKS_OFF, "fd map overlaps the stacks");
static_assert(LX_FP_STACKS_OFF + LX_FP_STACKS * LX_FP_STACK_SIZE <= LX_FP_TABLE_OFF, "stacks overlap the table");

// The 128-bit key the fast path's own syscalls carry (see seccomp_filter.hpp).
// Made once, before the first guest is forked, so the filter and the table
// agree.
struct Key { std::uint64_t k[2]{0, 0}; bool armed{false}; };
inline Key& key() {
    static Key k;
    return k;
}
// On unless LINUXITY_FASTPATH=0 (or seccomp is off: the blob's calls need
// the filter to let them through).
inline bool wanted() {
    static const bool on = [] {
        const char* v = std::getenv("LINUXITY_FASTPATH");
        if (v && *v == '0') return false;
        return std::getenv("LINUXITY_NO_SECCOMP") == nullptr;
    }();
    return on;
}
inline void arm() {
#if defined(__linux__)
    Key& k = key();
    if (k.armed) return;
    if (::getrandom(k.k, sizeof k.k, 0) != static_cast<ssize_t>(sizeof k.k)) return;
    if (k.k[0] == 0 && k.k[1] == 0) return;
    k.armed = true;
#endif
}

struct Mount {
    std::string prefix, base, upper;
    bool is_virtual{false};
    std::uint32_t id{0};
};

class Table {
public:
    Table() = default;
    Table(const Table&) = delete;
    Table& operator=(const Table&) = delete;
    ~Table() { close(); }

    // Create the backing file in `dir`. False leaves the fast path off.
    bool open(const std::string& dir) {
#if defined(__linux__)
        path_ = dir + "/linuxity-fp-" + std::to_string(::getpid()) + "-" +
                std::to_string(key().k[0] & 0xffffffu);
        const int fd = ::open(path_.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) { path_.clear(); return false; }
        if (::ftruncate(fd, static_cast<off_t>(kFileSize)) != 0) {
            ::close(fd); ::unlink(path_.c_str()); path_.clear(); return false;
        }
        void* p = ::mmap(nullptr, kFileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        ::close(fd);
        if (p == MAP_FAILED) { ::unlink(path_.c_str()); path_.clear(); return false; }
        t_ = static_cast<lx_fp_table*>(p);
        stats_ = reinterpret_cast<lx_fp_stats*>(static_cast<char*>(p) + LX_FP_TABLE_SIZE);
        t_->magic = LX_FP_MAGIC;
        t_->version = LX_FP_VERSION;
        t_->key[0] = key().k[0];
        t_->key[1] = key().k[1];
        t_->dir_gen = 1;
        if (const char* o = std::getenv("LINUXITY_FP_OFF_OPS")) t_->off_ops = static_cast<std::uint32_t>(std::strtoul(o, nullptr, 0));
        return true;
#else
        (void)dir;
        return false;
#endif
    }
    void close() {
#if defined(__linux__)
        if (t_) { ::munmap(t_, kFileSize); t_ = nullptr; stats_ = nullptr; }
        if (!path_.empty()) { ::unlink(path_.c_str()); path_.clear(); }
#endif
    }

    [[nodiscard]] bool ok() const noexcept { return t_ != nullptr; }
    [[nodiscard]] const std::string& path() const noexcept { return path_; }
    // the table, then one page of counters the guests write
    static constexpr std::size_t kFileSize = LX_FP_TABLE_SIZE + 0x1000;
    [[nodiscard]] std::uint64_t hits() const {
        return stats_ ? __atomic_load_n(&stats_->hits, __ATOMIC_RELAXED) : 0;
    }
    // Bumped by the blob each time any process logs an fd event, and per
    // process (by tgid slot).
    [[nodiscard]] std::uint32_t evsum() const {
        return stats_ ? __atomic_load_n(&stats_->evsum, __ATOMIC_ACQUIRE) : 0;
    }
    [[nodiscard]] std::uint32_t ev_count(int tgid) const {
        return stats_ ? __atomic_load_n(&stats_->ev[static_cast<std::uint32_t>(tgid) & (LX_FP_CWD_SLOTS - 1)],
                                         __ATOMIC_ACQUIRE) : 0;
    }

    void set_enabled(bool on) { store(&t_->enabled, on ? 1u : 0u); }
    [[nodiscard]] bool enabled() const { return t_ && t_->enabled != 0; }

    void set_mounts(const std::vector<Mount>& ms) {
        begin();
        std::uint32_t n = 0;
        bool ok = true;
        for (const Mount& m : ms) {
            if (n == LX_FP_MAX_MOUNTS) { ok = false; break; }
            if (m.prefix.size() >= sizeof t_->mounts[0].prefix ||
                m.base.size() >= sizeof t_->mounts[0].base ||
                m.upper.size() >= sizeof t_->mounts[0].upper) { ok = false; break; }
            lx_fp_mount& d = t_->mounts[n++];
            std::memset(&d, 0, sizeof d);
            put(d.prefix, d.prefix_len, m.prefix);
            put(d.base, d.base_len, m.base);
            put(d.upper, d.upper_len, m.upper);
            d.kind = m.is_virtual ? LX_FP_MNT_VIRTUAL
                     : m.upper.empty() ? LX_FP_MNT_BIND : LX_FP_MNT_OVERLAY;
            d.mnt_id = m.id;
        }
        // a table we can't describe whole would answer from the wrong mount
        t_->n_mounts = ok ? n : 0;
        bump_dirs_locked();
        end();
    }

    // A path (and everything under it) the fast path must not answer.
    void add_tree(std::string_view guest) { add_exc(lx_fp_hash(guest.data(), len(guest))); }
    // A removed name: the path itself, and its directory may not be listed
    // natively (the merged listing hides the name).
    void add_whiteout(std::string_view guest) {
        add_tree(guest);
        const std::size_t cut = guest.rfind('/');
        const std::string_view dir = cut == 0 ? std::string_view{"/"} : guest.substr(0, cut);
        if (cut != std::string_view::npos)
            add_exc(lx_fp_hash(dir.data(), len(dir)) ^ LX_FP_WO_DIR_SALT);
    }
    // Exactly this guest path, or this host path.
    void add_leaf(std::string_view path) { add_exc(lx_fp_hash(path.data(), len(path)) ^ LX_FP_LEAF_SALT); }

    // Forget every exception, before adding the live set back.
    void clear_exc_begin() {
        begin();
        std::memset(t_->exc, 0, sizeof t_->exc);
        exc_count_ = 0;
    }
    void clear_exc_end() { end(); }
    [[nodiscard]] bool exc_crowded() const { return exc_count_ > LX_FP_EXC_SLOTS / 2; }

    // A guest directory whose whole path is free of symlinks right now.
    void add_dir(std::string_view guest, bool in_upper = true) {
        if (guest.empty() || guest.size() > 0xffff) return;
        const std::uint64_t h = lx_fp_hash(guest.data(), len(guest));
        const std::uint32_t gen = t_->dir_gen;
        const std::uint32_t i = static_cast<std::uint32_t>(h) & (LX_FP_DIR_SLOTS - 1);
        for (std::uint32_t k = 0; k < LX_FP_PROBES; ++k) {
            lx_fp_dir& d = t_->dirs[(i + k) & (LX_FP_DIR_SLOTS - 1)];
            const std::uint32_t g = d.gen;
            if (g == gen && d.hash == h && d.len == guest.size()) return;   // there
            if (g == gen && d.hash != 0) continue;                           // taken
            store(&d.gen, 0u);
            store64(&d.hash, h);
            d.len = static_cast<std::uint16_t>(guest.size());
            d.no_upper = in_upper ? 0 : 1;
            store(&d.gen, gen);
            return;
        }
    }
    // Every directory answer so far may be wrong (a rename, an rmdir).
    void bump_dirs() { begin(); bump_dirs_locked(); end(); }
    [[nodiscard]] std::uint32_t dir_gen() const { return t_ ? t_->dir_gen : 0; }

    // The cwd the blob uses for relative paths in host process `tgid`.
    // Unknown, long or full: no slot, and relative paths fall back.
    void set_cwd(int tgid, std::string_view cwd) {
        if (!t_ || tgid <= 0) return;
        lx_fp_cwd* slot = find_cwd(tgid, true);
        if (!slot) return;
        const bool ok = !cwd.empty() && cwd[0] == '/' && cwd.size() < LX_FP_CWD_MAX;
        store(&slot->seq, slot->seq + 1);
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        slot->len = ok ? static_cast<std::uint32_t>(cwd.size()) : 0u;
        if (ok) std::memcpy(slot->path, cwd.data(), cwd.size());
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        store(&slot->seq, slot->seq + 1);
    }
    void copy_cwd(int from, int to) {
        lx_fp_cwd* src = t_ ? find_cwd(from, false) : nullptr;
        if (!src) return;
        set_cwd(to, std::string_view{src->path, src->len});
    }
    void drop_cwd(int tgid) {
        lx_fp_cwd* slot = t_ ? find_cwd(tgid, false) : nullptr;
        if (!slot) return;
        // leave the tgid (a tombstone keeps later probes' chains intact) but
        // drop the path; a reused pid gets it back at its first trap
        store(&slot->seq, slot->seq + 1);
        slot->len = 0;
        store(&slot->seq, slot->seq + 1);
    }

private:
    lx_fp_table* t_{nullptr};
    lx_fp_stats* stats_{nullptr};
    std::string path_;
    std::size_t exc_count_{0};

    lx_fp_cwd* find_cwd(int tgid, bool make) {
        const std::uint32_t start = static_cast<std::uint32_t>(tgid) & (LX_FP_CWD_SLOTS - 1);
        for (std::uint32_t k = 0; k < LX_FP_CWD_SLOTS; ++k) {
            lx_fp_cwd& c = t_->cwds[(start + k) & (LX_FP_CWD_SLOTS - 1)];
            if (c.tgid == tgid) return &c;
            if (c.tgid == 0) {
                if (!make) return nullptr;
                c.len = 0;
                __atomic_store_n(&c.tgid, tgid, __ATOMIC_RELEASE);
                return &c;
            }
        }
        return nullptr;
    }
    static std::uint32_t len(std::string_view s) { return static_cast<std::uint32_t>(s.size()); }
    template <std::size_t N>
    static void put(char (&dst)[N], std::uint16_t& n, const std::string& s) {
        std::memcpy(dst, s.data(), s.size());
        dst[s.size()] = 0;
        n = static_cast<std::uint16_t>(s.size());
    }
    static void store(std::uint32_t* p, std::uint32_t v) { __atomic_store_n(p, v, __ATOMIC_RELEASE); }
    static void store64(std::uint64_t* p, std::uint64_t v) { __atomic_store_n(p, v, __ATOMIC_RELEASE); }
    void begin() { store(&t_->seq, t_->seq + 1); __atomic_thread_fence(__ATOMIC_SEQ_CST); }
    void end() { __atomic_thread_fence(__ATOMIC_SEQ_CST); store(&t_->seq, t_->seq + 1); }
    void bump_dirs_locked() {
        std::uint32_t g = t_->dir_gen + 1;
        if (g == 0) {   // wrapped: old entries could match again
            std::memset(t_->dirs, 0, sizeof t_->dirs);
            g = 1;
        }
        store(&t_->dir_gen, g);
    }
    void add_exc(std::uint64_t h) {
        if (!t_) return;
        const std::uint32_t i = static_cast<std::uint32_t>(h) & (LX_FP_EXC_SLOTS - 1);
        for (std::uint32_t k = 0; k < LX_FP_PROBES; ++k) {
            std::uint64_t& slot = t_->exc[(i + k) & (LX_FP_EXC_SLOTS - 1)];
            if (slot == h) return;
            if (slot == 0) {
                begin();
                store64(&slot, h);
                end();
                ++exc_count_;
                return;
            }
        }
        // a full run: readers can't find a free slot either, so they treat
        // the whole run as excepted -- including h
        ++exc_count_;
    }
};

}  // namespace lx::runtime::fastpath
