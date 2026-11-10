// linuxity/runtime/linux/inguest_table.hpp
//
// The supervisor's side of the in-guest handler's shared table (see
// inguest_abi.h): a file every guest process maps read-only, holding what the
// handler needs to answer a path query exactly as the dispatcher would --
// the mount table, the directories known to be free of symlinks, and the
// paths it must leave to the dispatcher (chmod records, whiteouts, emulated
// links, socket placeholders).
//
// Changes are published with a seqlock; a guest call that overlaps one falls
// back to the trap. Entries are only added between rebuilds, so a stale entry
// costs a fallback, never a wrong answer.
#pragma once

#include "linuxity/runtime/linux/inguest_abi.h"

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

namespace lx::runtime::inguest {

static_assert(sizeof(lx_ig_table) <= LX_IG_TABLE_SIZE, "in-guest table outgrew its mapping");
static_assert(sizeof(lx_ig_proc) <= LX_IG_PROC_SIZE, "per-process area");
static_assert(LX_IG_PROC_OFF + LX_IG_PROC_SIZE + 0x1000 <= LX_IG_FDMAP_OFF, "proc area overlaps the fd map");
static_assert(sizeof(lx_ig_stats) <= 0x1000, "stats page is one page");
static_assert(sizeof(lx_ig_fd) == 256, "fd map entry");
static_assert(LX_IG_FDMAP_OFF + LX_IG_FDS * sizeof(lx_ig_fd) + 0x1000 <= LX_IG_STACKS_OFF, "fd map overlaps the stacks");
static_assert(LX_IG_STACKS_OFF + LX_IG_STACKS * LX_IG_STACK_SIZE <= LX_IG_UNION_OFF, "stacks overlap the union slots");
static_assert(LX_IG_UNION_OFF + LX_IG_UNIONS * sizeof(lx_ig_union) <= LX_IG_VDIR_OFF, "union slots overlap the dir cache");
static_assert(LX_IG_VDIR_OFF + LX_IG_VDIRS * sizeof(lx_ig_dir) <= LX_IG_TABLE_OFF, "dir cache overlaps the table");

// The 128-bit key the in-guest handler's own syscalls carry (see seccomp_filter.hpp).
// Made once, before the first guest is forked, so the filter and the table
// agree.
struct Key { std::uint64_t k[2]{0, 0}; bool armed{false}; };
inline Key& key() {
    static Key k;
    return k;
}
// Always on. It needs seccomp (the filter lets the blob's own calls
// through), so LINUXITY_TEST_NO_SECCOMP turns it off with it.
// LINUXITY_TEST_ALL_TRAP is for the tests only: it makes every call trap, to
// give them a reference to diff the guest's answers against.
inline bool wanted() {
    static const bool on = [] {
        if (const char* t = std::getenv("LINUXITY_TEST_ALL_TRAP"); t && *t) return false;
        return std::getenv("LINUXITY_TEST_NO_SECCOMP") == nullptr;
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

    // Create the backing file in `dir`. False leaves the in-guest handler off.
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
        t_ = static_cast<lx_ig_table*>(p);
        stats_ = reinterpret_cast<lx_ig_stats*>(static_cast<char*>(p) + LX_IG_TABLE_SIZE);
        t_->magic = LX_IG_MAGIC;
        t_->version = LX_IG_VERSION;
        t_->key[0] = key().k[0];
        t_->key[1] = key().k[1];
        t_->dir_gen = 1;
        if (const char* o = std::getenv("LINUXITY_IG_OFF_OPS")) t_->off_ops = static_cast<std::uint32_t>(std::strtoul(o, nullptr, 0));
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
    static constexpr std::size_t kFileSize = LX_IG_TABLE_SIZE + 0x1000;
    [[nodiscard]] std::uint64_t hits() const {
        return stats_ ? __atomic_load_n(&stats_->hits, __ATOMIC_RELAXED) : 0;
    }
    void report_gate() const {
        if (!stats_ || !(t_->off_ops >> 31)) return;
        std::fprintf(stderr, "  blob host calls:");
        for (int nr = 0; nr < 512; ++nr)
            if (stats_->gate[nr]) std::fprintf(stderr, " %d:%u", nr, stats_->gate[nr]);
        std::fprintf(stderr, "\n");
    }
    // Bumped by the blob each time any process logs an fd event, and per
    // process (by tgid slot).
    [[nodiscard]] std::uint32_t evsum() const {
        return stats_ ? __atomic_load_n(&stats_->evsum, __ATOMIC_ACQUIRE) : 0;
    }
    [[nodiscard]] std::uint32_t ev_count(int tgid) const {
        return stats_ ? __atomic_load_n(&stats_->ev[static_cast<std::uint32_t>(tgid) & (LX_IG_CWD_SLOTS - 1)],
                                         __ATOMIC_ACQUIRE) : 0;
    }

    void set_enabled(bool on) { store(&t_->enabled, on && !dead_ ? 1u : 0u); }
    [[nodiscard]] bool enabled() const { return t_ && t_->enabled != 0; }

    void set_mounts(const std::vector<Mount>& ms) {
        begin();
        std::uint32_t n = 0;
        bool ok = true;
        for (const Mount& m : ms) {
            if (n == LX_IG_MAX_MOUNTS) { ok = false; break; }
            if (m.prefix.size() >= sizeof t_->mounts[0].prefix ||
                m.base.size() >= sizeof t_->mounts[0].base ||
                m.upper.size() >= sizeof t_->mounts[0].upper) { ok = false; break; }
            lx_ig_mount& d = t_->mounts[n++];
            std::memset(&d, 0, sizeof d);
            put(d.prefix, d.prefix_len, m.prefix);
            put(d.base, d.base_len, m.base);
            put(d.upper, d.upper_len, m.upper);
            d.kind = m.is_virtual ? LX_IG_MNT_VIRTUAL
                     : m.upper.empty() ? LX_IG_MNT_BIND : LX_IG_MNT_OVERLAY;
            d.mnt_id = m.id;
        }
        // a table we can't describe whole would answer from the wrong mount
        t_->n_mounts = ok ? n : 0;
        bump_dirs_locked();
        end();
    }

    // A path (and everything under it) the in-guest handler must not answer.
    void add_tree(std::string_view guest) { add_exc(lx_ig_hash(guest.data(), len(guest))); }
    // A removed name: the path itself, and its directory may not be listed
    // natively (the merged listing hides the name).
    void add_whiteout(std::string_view guest) {
        add_tree(guest);
        const std::size_t cut = guest.rfind('/');
        const std::string_view dir = cut == 0 ? std::string_view{"/"} : guest.substr(0, cut);
        if (cut != std::string_view::npos)
            add_exc(lx_ig_hash(dir.data(), len(dir)) ^ LX_IG_WO_DIR_SALT);
    }
    // Exactly this guest path, or this host path.
    void add_leaf(std::string_view path) { add_exc(lx_ig_hash(path.data(), len(path)) ^ LX_IG_LEAF_SALT); }

    // Forget every exception, before adding the live set back.
    void clear_exc_begin() {
        begin();
        std::memset(t_->exc, 0, sizeof t_->exc);
        std::memset(t_->exc_bloom, 0, sizeof t_->exc_bloom);
        exc_count_ = 0;
    }
    void clear_exc_end() { end(); }
    [[nodiscard]] bool exc_crowded() const { return exc_count_ > LX_IG_EXC_SLOTS / 2; }

    // A guest directory whose whole path is free of symlinks right now.
    void add_dir(std::string_view guest, bool in_upper = true) {
        if (guest.empty() || guest.size() > 0xffff) return;
        const std::uint64_t h = lx_ig_hash(guest.data(), len(guest));
        const std::uint32_t gen = t_->dir_gen;
        const std::uint32_t i = static_cast<std::uint32_t>(h) & (LX_IG_DIR_SLOTS - 1);
        for (std::uint32_t k = 0; k < LX_IG_PROBES; ++k) {
            lx_ig_dir& d = t_->dirs[(i + k) & (LX_IG_DIR_SLOTS - 1)];
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
        lx_ig_cwd* slot = find_cwd(tgid, true);
        if (!slot) return;
        const bool ok = !cwd.empty() && cwd[0] == '/' && cwd.size() < LX_IG_CWD_MAX;
        store(&slot->seq, slot->seq + 1);
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        slot->len = ok ? static_cast<std::uint32_t>(cwd.size()) : 0u;
        if (ok) std::memcpy(slot->path, cwd.data(), cwd.size());
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        store(&slot->seq, slot->seq + 1);
    }
    void copy_cwd(int from, int to) {
        lx_ig_cwd* src = t_ ? find_cwd(from, false) : nullptr;
        if (!src) return;
        set_cwd(to, std::string_view{src->path, src->len});
    }
    void drop_cwd(int tgid) {
        lx_ig_cwd* slot = t_ ? find_cwd(tgid, false) : nullptr;
        if (!slot) return;
        // leave the tgid (a tombstone keeps later probes' chains intact) but
        // drop the path; a reused pid gets it back at its first trap
        store(&slot->seq, slot->seq + 1);
        slot->len = 0;
        store(&slot->seq, slot->seq + 1);
    }

private:
    lx_ig_table* t_{nullptr};
    bool dead_{false};
    lx_ig_stats* stats_{nullptr};
    std::string path_;
    std::size_t exc_count_{0};

    lx_ig_cwd* find_cwd(int tgid, bool make) {
        const std::uint32_t start = static_cast<std::uint32_t>(tgid) & (LX_IG_CWD_SLOTS - 1);
        for (std::uint32_t k = 0; k < LX_IG_CWD_SLOTS; ++k) {
            lx_ig_cwd& c = t_->cwds[(start + k) & (LX_IG_CWD_SLOTS - 1)];
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
        // wrapped (2^31 writes): old entries could match again. The shared
        // cache is cleared; processes' own caches can't be, so the in-guest handler
        // goes off rather than risk a stale answer.
        if (g >= 0x7fffffffu) {
            std::memset(t_->dirs, 0, sizeof t_->dirs);
            dead_ = true;
            store(&t_->enabled, 0u);
            g = 1;
        }
        store(&t_->dir_gen, g);
    }
    void bloom_set(std::uint64_t h) {
        constexpr std::uint32_t kBits = LX_IG_EXC_BLOOM_WORDS * 64;
        for (const std::uint32_t b : {static_cast<std::uint32_t>(h) & (kBits - 1),
                                      static_cast<std::uint32_t>(h >> 32) & (kBits - 1)})
            __atomic_fetch_or(&t_->exc_bloom[b / 64], std::uint64_t{1} << (b % 64), __ATOMIC_RELEASE);
    }
    void add_exc(std::uint64_t h) {
        if (!t_) return;
        // the bloom first: a reader that finds h in exc[] has seen its bits
        bloom_set(h);
        const std::uint32_t i = static_cast<std::uint32_t>(h) & (LX_IG_EXC_SLOTS - 1);
        for (std::uint32_t k = 0; k < LX_IG_PROBES; ++k) {
            std::uint64_t& slot = t_->exc[(i + k) & (LX_IG_EXC_SLOTS - 1)];
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
        // the whole run as excepted -- including h. Bump seq so a call
        // already past the check doesn't use its answer.
        begin();
        end();
        ++exc_count_;
    }
};

}  // namespace lx::runtime::inguest
