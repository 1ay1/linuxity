// linuxity/kernel/fsnotify.hpp
//
// inotify, as linuxity's own subsystem, for hosts whose native watching can't
// say what Linux's does.
//
// Darwin's kqueue watches an inode and reports "this directory changed": no
// entry name, no create-vs-delete, no rename pairs, nothing about opens and
// reads. An editor, a build tool or a file manager needs exactly those. But
// the dispatcher performs (or redirects) every path operation and knows each
// one by guest path -- so it is the event source, and this file turns events
// into inotify records against the guest's watches.
//
// Every guest process on such a host is its own linuxity, and a watcher must
// see writes from a shell it spawned. So the tree shares one directory
// (<upper>/.linuxity-fsnotify):
//
//   <id>.w    an instance's watches, "mask isdir path" per line, rewritten
//             atomically by the watcher on every add/rm
//   <id>.log  events for that instance, "mask cookie path" per line,
//             appended by whichever process caused them
//
// An emitter appends an event only to the logs of instances it CONCERNS
// (the same rule that makes records, records_for), so a watcher's log --
// and the pollable fd watching it -- grows exactly when a read will return
// something. Order is the log's: the order the operations completed in.
//
// Pure policy over strings and files: backend-free, testable.
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

namespace lx::kernel::fsnotify {

// The inotify(7) bits, as the guest sees them.
inline constexpr std::uint32_t kAccess = 0x001, kModify = 0x002, kAttrib = 0x004,
    kCloseWrite = 0x008, kCloseNowrite = 0x010, kOpen = 0x020, kMovedFrom = 0x040,
    kMovedTo = 0x080, kCreate = 0x100, kDelete = 0x200, kDeleteSelf = 0x400,
    kMoveSelf = 0x800, kIgnored = 0x8000, kIsDir = 0x40000000, kOneshot = 0x80000000,
    kMaskAdd = 0x20000000, kAllEvents = 0xfff;

// What happened, as the dispatcher reports it: one event bit (+ kIsDir) on
// the object at guest path `path`. Watchers on its directory see it as a
// child named by its last component; watchers on the object, as "self".
struct Event {
    std::uint32_t mask{0};
    std::uint32_t cookie{0};    // pairs MOVED_FROM with MOVED_TO
    std::string path;           // absolute guest path
};

[[nodiscard]] inline std::string_view parent_of(std::string_view p) noexcept {
    const auto s = p.find_last_of('/');
    if (s == std::string_view::npos) return {};
    return s == 0 ? std::string_view{"/"} : p.substr(0, s);
}
[[nodiscard]] inline std::string_view leaf_of(std::string_view p) noexcept {
    const auto s = p.find_last_of('/');
    return s == std::string_view::npos ? p : p.substr(s + 1);
}

// -- What one watch makes of one event (THE rule) ---------------------------
struct WatchSpec { std::uint32_t mask; bool is_dir; std::string path; };
struct Record { std::int32_t wd; std::uint32_t mask, cookie; std::string name; };

// The event the object itself sees, or 0: deleting it is DELETE_SELF,
// moving it away MOVE_SELF, and an entry event on its own name (it was
// created, or moved in) is its parent's business only.
[[nodiscard]] constexpr std::uint32_t self_bit(std::uint32_t bit) noexcept {
    switch (bit) {
        case kDelete:    return kDeleteSelf;
        case kMovedFrom: return kMoveSelf;
        case kCreate: case kMovedTo: return 0;
        default:         return bit;
    }
}

// Append to `out` the records watch `w` (descriptor `wd`) owes for `e`.
// Returns true if the watch is now finished (oneshot fired, or its object
// was deleted) and must end with IN_IGNORED.
inline bool records_for(const WatchSpec& w, int wd, const Event& e, std::vector<Record>* out) {
    const std::uint32_t bit = e.mask & ~kIsDir;
    bool fired = false, ends = false;
    // a watched directory sees its children's events, by name
    if (w.is_dir && parent_of(e.path) == w.path && (w.mask & bit)) {
        if (out) out->push_back({wd, e.mask, e.cookie, std::string{leaf_of(e.path)}});
        fired = true;
    }
    // every watch sees its own object's events, unnamed
    if (w.path == e.path) {
        if (const std::uint32_t self = self_bit(bit); self && ((w.mask & self) || self == kDeleteSelf)) {
            const bool tag_dir = w.is_dir && self != kDeleteSelf && self != kMoveSelf;
            if (out) out->push_back({wd, self | (tag_dir ? kIsDir : 0u), 0, {}});
            fired = true;
            ends = self == kDeleteSelf;
        }
    }
    return ends || (fired && (w.mask & kOneshot));
}
[[nodiscard]] inline bool concerns(const WatchSpec& w, const Event& e) {
    std::vector<Record> r;
    (void)records_for(w, 0, e, &r);
    return !r.empty();
}

// -- One inotify instance --------------------------------------------------
class Instance {
public:
    // inotify_add_watch on a guest path; returns the wd. The same path again
    // updates (or with IN_MASK_ADD extends) the mask and keeps the wd.
    [[nodiscard]] int add(const std::string& path, std::uint32_t mask, bool is_dir) {
        for (Watch& w : watches_)
            if (w.spec.path == path) {
                w.spec.mask = (mask & kMaskAdd) ? (w.spec.mask | mask) : mask;
                w.spec.is_dir = is_dir;
                return w.wd;
            }
        watches_.push_back({next_++, {mask, is_dir, path}});
        return watches_.back().wd;
    }
    // inotify_rm_watch: 0 (queueing IN_IGNORED), or -EINVAL.
    [[nodiscard]] int remove(int wd) { return end(wd) ? 0 : -22; }

    void deliver(const Event& e) {
        std::vector<int> finished;
        std::vector<Record> fresh;
        for (const Watch& w : watches_)
            if (records_for(w.spec, w.wd, e, &fresh)) finished.push_back(w.wd);
        // fsnotify_merge: an event identical to the last one still queued
        // (same wd, mask, cookie, name) is dropped -- why Linux reports one
        // MODIFY for a burst of writes, and one ACCESS for a chunked read.
        for (Record& r : fresh) {
            const bool dup = !queue_.empty() && queue_.back().wd == r.wd && queue_.back().mask == r.mask &&
                             queue_.back().cookie == r.cookie && queue_.back().name == r.name;
            if (!dup) queue_.push_back(std::move(r));
        }
        for (int wd : finished) (void)end(wd);
        follow_move(e);
    }

    [[nodiscard]] std::vector<WatchSpec> specs() const {
        std::vector<WatchSpec> v;
        for (const Watch& w : watches_) v.push_back(w.spec);
        return v;
    }
    [[nodiscard]] bool pending() const noexcept { return !queue_.empty(); }
    [[nodiscard]] const std::vector<Record>& queued() const noexcept { return queue_; }

    // As many records as fit in `cap`, struct inotify_event layout (name
    // NUL-padded to 4). 0 = nothing queued; -EINVAL = the first won't fit.
    [[nodiscard]] long encode(std::byte* out, std::size_t cap) {
        std::size_t used = 0, taken = 0;
        for (; taken < queue_.size(); ++taken) {
            const Record& r = queue_[taken];
            const std::size_t namelen = r.name.empty() ? 0 : ((r.name.size() + 1 + 3) & ~std::size_t{3});
            const std::size_t need = 16 + namelen;
            if (used + need > cap) {
                if (used == 0) return -22;
                break;
            }
            const std::int32_t wd = r.wd;
            const std::uint32_t hdr[3] = {r.mask, r.cookie, static_cast<std::uint32_t>(namelen)};
            std::memcpy(out + used, &wd, 4);
            std::memcpy(out + used + 4, hdr, 12);
            std::memset(out + used + 16, 0, namelen);
            std::memcpy(out + used + 16, r.name.data(), r.name.size());
            used += need;
        }
        queue_.erase(queue_.begin(), queue_.begin() + static_cast<std::ptrdiff_t>(taken));
        return static_cast<long>(used);
    }

private:
    struct Watch { int wd; WatchSpec spec; };
    bool end(int wd) {
        for (auto it = watches_.begin(); it != watches_.end(); ++it)
            if (it->wd == wd) {
                queue_.push_back({wd, kIgnored, 0, {}});
                watches_.erase(it);
                return true;
            }
        return false;
    }
    // A watched object that is renamed keeps its watch under the new name
    // (the kernel watches the inode). Both halves of a move arrive together.
    void follow_move(const Event& e) {
        const std::uint32_t bit = e.mask & ~kIsDir;
        if (bit == kMovedFrom) { moving_ = {e.cookie, e.path}; return; }
        if (bit != kMovedTo || !moving_ || moving_->first != e.cookie) return;
        const std::string from = moving_->second;
        moving_.reset();
        for (Watch& w : watches_) {
            if (w.spec.path == from) w.spec.path = e.path;
            else if (w.spec.path.starts_with(from + "/")) w.spec.path = e.path + w.spec.path.substr(from.size());
        }
    }
    std::vector<Watch> watches_;
    std::vector<Record> queue_;
    std::optional<std::pair<std::uint32_t, std::string>> moving_;
    int next_{1};
};

// -- Log lines -------------------------------------------------------------
[[nodiscard]] inline std::string line_of(const Event& e) {
    char head[32];
    const int n = std::snprintf(head, sizeof head, "%u %u ", e.mask, e.cookie);
    return std::string(head, static_cast<std::size_t>(n)) + e.path + '\n';
}
// Events of `file` from byte `at` on; advances `at` past whole lines only.
[[nodiscard]] inline std::vector<Event> read_log(const std::string& file, long long& at) {
    std::vector<Event> out;
    std::FILE* f = std::fopen(file.c_str(), "re");
    if (!f) return out;
    if (std::fseek(f, static_cast<long>(at), SEEK_SET) != 0) { std::fclose(f); return out; }
    char line[8192];
    while (std::fgets(line, sizeof line, f)) {
        const std::size_t len = std::strlen(line);
        if (len == 0 || line[len - 1] != '\n') break;        // torn tail: later
        at += static_cast<long long>(len);
        line[len - 1] = '\0';
        Event e;
        char* p = line;
        e.mask = static_cast<std::uint32_t>(std::strtoul(p, &p, 10));
        e.cookie = static_cast<std::uint32_t>(std::strtoul(p, &p, 10));
        if (*p == ' ') ++p;
        e.path = p;
        out.push_back(std::move(e));
    }
    std::fclose(f);
    return out;
}

// -- The tree's hub: the registry, read by emitters and written by watchers --
class Hub {
public:
    void attach(std::string dir) { dir_ = std::move(dir); }
    [[nodiscard]] bool attached() const noexcept { return !dir_.empty(); }

    // Does any instance in the tree exist? Then the dispatcher plans events.
    // A "no" is re-checked at most every 100 ms -- the most a watch another
    // process just added can wait to hear from us; our own instances say
    // "yes" at once.
    [[nodiscard]] bool active() {
        std::lock_guard l{mu_};
        if (dir_.empty()) return false;
        if (!registry_.empty()) return true;
        const long long now = now_ms();
        if (now - checked_ms_ < 100) return false;
        checked_ms_ = now;
        refresh_locked();
        return !registry_.empty();
    }

    // The emitter side. A rename is a pair: both halves go to every instance
    // either concerns, so a watch on the moved object can follow it.
    void emit(const Event& e) { emit_all({e}); }
    void emit_all(const std::vector<Event>& evs) {
        if (evs.empty()) return;
        std::lock_guard l{mu_};
        if (dir_.empty()) return;
        refresh_locked();
        std::string lines;
        for (const Event& e : evs) lines += line_of(e);
        for (const auto& [id, specs] : registry_) {
            bool want = false;
            for (const Event& e : evs)
                for (const WatchSpec& w : specs) want = want || concerns(w, e);
            if (!want) continue;
            const int fd = ::open(log_path(id).c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
            if (fd < 0) continue;
            (void)!::write(fd, lines.data(), lines.size());   // one write: atomic append
            ::close(fd);
        }
    }

    // The watcher side: a new instance's id and empty log.
    [[nodiscard]] std::string open_instance() {
        std::lock_guard l{mu_};
        if (dir_.empty()) return {};
        (void)::mkdir(dir_.c_str(), 0700);
        static unsigned n = 0;
        const std::string id = std::to_string(::getpid()) + "-" + std::to_string(++n);
        const int fd = ::open(log_path(id).c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) return {};
        ::close(fd);
        return id;
    }
    void publish(const std::string& id, const std::vector<WatchSpec>& specs) {
        std::lock_guard l{mu_};
        std::string body;
        for (const WatchSpec& w : specs)
            body += std::to_string(w.mask) + " " + (w.is_dir ? "1 " : "0 ") + w.path + "\n";
        const std::string tmp = dir_ + "/." + id + ".tmp", dst = dir_ + "/" + id + ".w";
        const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) return;
        (void)!::write(fd, body.data(), body.size());
        ::close(fd);
        ::rename(tmp.c_str(), dst.c_str());
        registry_[id] = specs;          // our own view is current at once
    }
    void close_instance(const std::string& id) {
        std::lock_guard l{mu_};
        ::unlink((dir_ + "/" + id + ".w").c_str());
        ::unlink(log_path(id).c_str());
        registry_.erase(id);
    }
    [[nodiscard]] std::string log_path(const std::string& id) const { return dir_ + "/" + id + ".log"; }

private:
    static long long now_ms() {
        struct ::timespec t{};
        ::clock_gettime(CLOCK_MONOTONIC, &t);
        return static_cast<long long>(t.tv_sec) * 1000 + t.tv_nsec / 1'000'000;
    }
    // Reload the registry when the directory changed (a .w was renamed in or
    // removed). Instances of processes that died are swept.
    void refresh_locked() {
        struct ::stat st{};
        if (::stat(dir_.c_str(), &st) != 0) { registry_.clear(); return; }
#if defined(__APPLE__)
        const long long m = static_cast<long long>(st.st_mtimespec.tv_sec) * 1'000'000'000 + st.st_mtimespec.tv_nsec;
#else
        const long long m = static_cast<long long>(st.st_mtim.tv_sec) * 1'000'000'000 + st.st_mtim.tv_nsec;
#endif
        if (m == dir_mtime_) return;
        dir_mtime_ = m;
        registry_.clear();
        ::DIR* d = ::opendir(dir_.c_str());
        if (!d) return;
        while (const ::dirent* de = ::readdir(d)) {
            const std::string_view name{de->d_name};
            if (!name.ends_with(".w")) continue;
            const std::string id{name.substr(0, name.size() - 2)};
            const long pid = std::strtol(id.c_str(), nullptr, 10);
            if (pid > 0 && ::kill(static_cast<pid_t>(pid), 0) != 0 && errno == ESRCH) {
                ::unlink((dir_ + "/" + id + ".w").c_str());      // its watcher is gone
                ::unlink(log_path(id).c_str());
                continue;
            }
            std::vector<WatchSpec> specs;
            if (std::FILE* f = std::fopen((dir_ + "/" + id + ".w").c_str(), "re")) {
                char line[8192];
                while (std::fgets(line, sizeof line, f)) {
                    char* p = line;
                    WatchSpec w{};
                    w.mask = static_cast<std::uint32_t>(std::strtoul(p, &p, 10));
                    w.is_dir = std::strtol(p, &p, 10) != 0;
                    if (*p == ' ') ++p;
                    w.path = p;
                    if (!w.path.empty() && w.path.back() == '\n') w.path.pop_back();
                    specs.push_back(std::move(w));
                }
                std::fclose(f);
            }
            registry_[id] = std::move(specs);
        }
        ::closedir(d);
    }

    std::mutex mu_;
    std::string dir_;
    std::map<std::string, std::vector<WatchSpec>> registry_;
    long long dir_mtime_{-1};
    long long checked_ms_{-1000};
};

// A fresh MOVED cookie, unique across the tree (pid in the high bits).
[[nodiscard]] inline std::uint32_t new_cookie() noexcept {
    static std::uint32_t n = 0;
    return (static_cast<std::uint32_t>(::getpid()) << 12) | (++n & 0xfff) | 1u;
}

// The registry directory's name in the tree's upper layer, hidden from listings.
inline constexpr std::string_view kDirLeaf = ".linuxity-fsnotify";

}  // namespace lx::kernel::fsnotify
