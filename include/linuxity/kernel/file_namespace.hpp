// linuxity/kernel/file_namespace.hpp
//
// The filesystem namespace the guest actually lives in.
//
// This is the piece that makes `--root <rootfs>` a REAL, unprivileged Linux
// world. Every path-taking syscall the guest issues is resolved here, and
// each path falls into exactly one realm:
//
//   * HOST-BACKED  (a HostFs mount) — the named file exists on the real disk
//     under the rootfs base. We translate guest-path -> real-host-path and
//     let the child run the syscall against that path. Because the child
//     ends up with a real host fd, native ld.so can mmap the actual library
//     file: this is what carries a dynamically-linked distro binary to main.
//
//   * VIRTUAL  (procfs, sysfs, tmpfs, an overlay upper) — nothing exists on
//     disk. We synthesize the bytes and hand them back through guest memory
//     (for read/stat) or a memfd (for open+mmap). /proc/self/*, /proc/mounts,
//     /proc/cpuinfo, /etc overlays all live here.
//
// The namespace is a kernel subsystem: it owns the mount table (a `Vfs`), the
// guest CWD, and the guest fd table. The syscall dispatcher is a thin natural
// transformation on top of it — it never mentions ptrace, memfd, or hostfs.
#pragma once

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/types.hpp"
#include "linuxity/kernel/meta_store.hpp"

#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <cstdint>
#include <algorithm>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace lx::kernel {

// How a resolved path must be serviced.
enum class Realm2 { host_backed, virtual_file, absent };

// The classification of a guest path.
struct PathClass {
    Realm2      realm{Realm2::absent};
    std::string host_path;   // real on-disk path (host_backed only)
    Errno       error{Errno::enoent};  // meaningful when realm == absent
    // For virtual_file results reached by following a cross-mount symlink
    // (e.g. /etc/mtab -> /proc/self/mounts), this is the RESOLVED guest path
    // whose producer must be consulted — not the original link path. Empty
    // means "same as the path passed to classify".
    std::string virtual_path;
    // Set for a REMOVE (unlink/rmdir) whose target exists ONLY in the
    // read-only lower layer. The pristine rootfs must never be mutated, so the
    // dispatcher records a WHITEOUT (hiding the lower file in the overlay view)
    // and reports success WITHOUT forwarding the unlink to the host. When set,
    // `host_path` is empty and the syscall must NOT be redirected.
    bool whiteout_lower{false};
};

// A synthesized virtual file: a producer of bytes for a virtual path. If
// `is_dir`, `entries` names its children (for getdents enumeration) and
// `bytes` is ignored.
struct VirtualDirent { std::string name; bool is_dir{false}; };
struct VirtualFile {
    std::vector<std::byte> bytes;
    bool is_dir{false};
    std::vector<VirtualDirent> entries;   // populated when is_dir

    // A virtual node that is REALLY a host device/file: when set, classify()
    // resolves this path to `redirect_host` in the HOST-BACKED realm instead
    // of injecting bytes. This is how /dev/null, /dev/urandom, /dev/zero get
    // TRUE character-device semantics — the guest ends up with a real host
    // fd on the actual device node (endless sink/source, native mmap), not a
    // frozen memfd snapshot. The producer still owns stat/getdents for the
    // node, but open/read/write/mmap ride the real device.
    std::string redirect_host;

    // A virtual SYMLINK: its readlink(2) contents. Guest-absolute targets
    // (e.g. /dev/stdin -> /proc/self/fd/0) resolve through OUR namespace.
    std::string symlink_target;
};

// The filesystem namespace. Backends register two kinds of mounts:
//   * a HOST mount   (prefix -> host base dir): host_backed realm.
//   * a VIRTUAL mount(prefix -> producer fn):   virtual_file realm.
// Longest-prefix wins, exactly like the Linux mount table.
class FileNamespace {
public:
    using Producer = std::function<Result<VirtualFile>(std::string_view /*abs path*/)>;

    // Mount a real host directory at an absolute guest prefix ("/" for the
    // rootfs). `host_base` is the on-disk directory it maps to. `upper`, if
    // given, is a WRITABLE on-disk scratch dir stacked over `host_base`: the
    // rootfs stays read-only (pristine) and all guest writes copy-up into the
    // upper layer — exactly the overlayfs lowerdir/upperdir model.
    void mount_host(std::string prefix, std::string host_base,
                    std::string upper = {}) {
        if (prefix.size() > 1 && prefix.back() == '/') prefix.pop_back();
        if (!host_base.empty() && host_base.back() == '/') host_base.pop_back();
        if (!upper.empty() && upper.back() == '/') upper.pop_back();
        // The shadow metadata journal lives in the ROOT mount's upper layer,
        // so uid/mode overlays for the whole guest tree share one store that
        // persists across runs. Attach the first time a rooted overlay mounts.
        if (prefix == "/" && !upper.empty() && !meta_attached_) {
            meta_.attach(upper);
            meta_attached_ = true;
            whiteout_journal_ = upper + "/.linuxity-whiteout";
            load_whiteouts();
        }
        mounts_.push_back(Mount{std::move(prefix), std::move(host_base),
                                std::move(upper), {}});
    }

    // The shadow permission/ownership store (per-path mode/uid/gid overlay).
    // The dispatcher records guest chmod/chown here and overlays it back onto
    // host stat results, so a uid-0 world round-trips coherently.
    [[nodiscard]] MetaStore& meta() noexcept { return meta_; }
    [[nodiscard]] const MetaStore& meta() const noexcept { return meta_; }

    // Mount a virtual producer at an absolute guest prefix ("/proc", "/sys").
    void mount_virtual(std::string prefix, Producer prod) {
        if (prefix.size() > 1 && prefix.back() == '/') prefix.pop_back();
        mounts_.push_back(Mount{std::move(prefix), {}, {}, std::move(prod)});
    }

    [[nodiscard]] std::string_view cwd() const noexcept { return cwd_; }
    void set_cwd(std::string c) { cwd_ = normalize(c); }

    // Resolve a (possibly relative, possibly dirfd-relative) path to an
    // absolute guest path. `dir_path` is the path bound to a guest dirfd, or
    // empty for AT_FDCWD.
    [[nodiscard]] std::string absolutize(std::string_view path,
                                         std::string_view dir_path = {}) const {
        if (!path.empty() && path.front() == '/') return normalize(std::string{path});
        std::string base = dir_path.empty() ? cwd_ : std::string{dir_path};
        if (base.empty()) base = "/";
        if (base.back() != '/') base += '/';
        base += path;
        return normalize(base);
    }

    // How a write-intent classify should prepare the overlay upper layer.
    //   copy_leaf  — copy the lower file up to upper (O_CREAT/O_WRONLY on an
    //                existing file needs its bytes); the DEFAULT.
    //   parents_only — the syscall CREATES the leaf itself (mkdir, mknod,
    //                rename/link/symlink destination), so materializing it
    //                would leave a bogus node the create then trips over.
    //                Only the parent chain is mirrored into upper.
    //   remove     — rmdir/unlink: DON'T materialize anything; resolve to the
    //                layer where the target actually lives (upper if already
    //                copied up, else the read-only lower).
    enum class WriteIntent { copy_leaf, parents_only, remove };

    // Classify an ABSOLUTE, normalized guest path into its realm. For
    // host-backed paths, returns the translated real host path. `for_write`
    // selects the overlay UPPER layer (copying the file up from the read-only
    // lower first, and creating parent dirs), so the pristine rootfs is never
    // mutated. Existence is NOT checked for reads — the forwarded host syscall
    // reports ENOENT itself.
    [[nodiscard]] PathClass classify(std::string_view abs,
                                     bool for_write = false,
                                     bool follow = true,
                                     WriteIntent wi = WriteIntent::copy_leaf) const {
        return classify_impl(abs, for_write, follow, wi, 0);
    }

    [[nodiscard]] PathClass classify_impl(std::string_view abs,
                                     bool for_write,
                                     bool follow,
                                     WriteIntent wi,
                                     int depth) const {
        const Mount* m = deepest(abs);
        if (!m) return PathClass{Realm2::absent, {}, Errno::enoent, {}};
        if (m->producer) {
            auto vf = m->producer(abs);
            if (!vf) return PathClass{Realm2::absent, {}, vf.error(), {}};
            // A device node backed by a real host device (/dev/null, ...):
            // resolve to the host path so open/read/write/mmap ride the true
            // character device with native semantics.
            if (!vf->redirect_host.empty())
                return PathClass{Realm2::host_backed,
                                 std::move(vf->redirect_host), Errno::enoent, {}};
            return PathClass{Realm2::virtual_file, {}, Errno::enoent,
                             std::string{abs}};
        }
        std::string_view rel = abs;
        rel.remove_prefix(m->prefix == "/" ? 0 : m->prefix.size());
        while (!rel.empty() && rel.front() == '/') rel.remove_prefix(1);

        // Overlay: an upper layer means writes (and files already copied up)
        // resolve to upper; reads of not-yet-copied files fall through to the
        // read-only lower.
        if (!m->upper.empty()) {
            std::string up = join_host(m->upper, rel);
            std::string lo = join_host(m->host_base, rel);
            if (for_write) {
                if (wi == WriteIntent::remove) {
                    // Resolve to the layer holding the target; don't create.
                    if (exists(up.c_str()))
                        return PathClass{Realm2::host_backed, std::move(up),
                                         Errno::enoent, {}};
                    // Target lives ONLY in the read-only lower layer. Forwarding
                    // the unlink to `lo` would DESTROY the pristine rootfs. If
                    // the lower file doesn't exist at all (or is already whited
                    // out), the removal is a no-op ENOENT. Otherwise signal a
                    // whiteout: the dispatcher records it and reports success
                    // without touching the host.
                    if (is_whiteout(abs) || !exists(lo.c_str()))
                        return PathClass{Realm2::absent, {}, Errno::enoent, {}};
                    PathClass wo{Realm2::absent, {}, Errno::enoent, {}};
                    wo.whiteout_lower = true;
                    return wo;
                }
                if (wi == WriteIntent::parents_only)
                    mirror_parents_from_lower(up, lo);
                else
                    copy_up(up, lo);
                // A create/write at a whited-out path revives it: the upper
                // now shadows the (still-pristine) lower, so drop the whiteout.
                if (!whiteouts_.empty()) clear_whiteout(std::string{abs});
                return PathClass{Realm2::host_backed, std::move(up), Errno::enoent, {}};
            }
            // READ. A whited-out path that hasn't been re-created in the upper
            // reads back as absent — the lower file was "removed" in the
            // overlay view even though the pristine rootfs still holds it.
            if (!whiteouts_.empty() && !exists(up.c_str()) && is_whiteout(abs))
                return PathClass{Realm2::absent, {}, Errno::enoent, {}};
            std::string host = exists(up.c_str()) ? up : lo;
            if (follow) return follow_symlink(*m, std::move(host), for_write, wi, depth);
            return PathClass{Realm2::host_backed, std::move(host), Errno::enoent, {}};
        }
        std::string full = join_host(m->host_base, rel);
        if (follow) return follow_symlink(*m, std::move(full), for_write, wi, depth);
        return PathClass{Realm2::host_backed, std::move(full), Errno::enoent, {}};
    }

    // Produce the bytes of a virtual file (for read/open/getdents on it).
    [[nodiscard]] Result<VirtualFile> produce(std::string_view abs) const {
        const Mount* m = deepest(abs);
        if (!m || !m->producer) return err<VirtualFile>(Errno::enoent);
        return m->producer(abs);
    }

    // The UNION listing of a host-backed directory across an overlay: entries
    // from the read-only lower merged with the writable upper (upper wins on
    // name collision). Returns entries only when `abs` names a real directory
    // in at least one layer; empty optional means "not an overlay dir" (the
    // caller should just forward getdents to the single real fd). This is what
    // makes `ls /` show the rootfs even though the upper layer starts empty.
    [[nodiscard]] std::vector<VirtualDirent>
    overlay_dir_union(std::string_view abs) const {
        const Mount* m = deepest(abs);
        std::vector<VirtualDirent> out;
        if (!m || m->producer || m->upper.empty()) return out;  // not overlaid
        std::string_view rel = abs;
        rel.remove_prefix(m->prefix == "/" ? 0 : m->prefix.size());
        while (!rel.empty() && rel.front() == '/') rel.remove_prefix(1);
        std::string lo = join_host(m->host_base, rel);
        std::string up = join_host(m->upper, rel);
        if (!is_dir(lo.c_str()) && !is_dir(up.c_str())) return out;
        std::unordered_map<std::string, bool> seen;   // name -> is_dir
        merge_dir(up, seen);   // upper first (wins)
        merge_dir(lo, seen);
        // The shadow-metadata journal is an implementation file in the upper
        // layer, not part of the guest tree — never let it show up in a listing.
        seen.erase(std::string{MetaStore::journal_leaf()});
        seen.erase(".linuxity-whiteout");
        // Drop names whited-out from the lower layer (removed in the overlay
        // view but still present on the pristine rootfs) unless the upper has
        // re-created them (merge_dir(up) already recorded those, so a name
        // present in `seen` from the upper survives — only lower-only whited
        // names must go).
        if (!whiteouts_.empty()) {
            std::string dir{abs};
            if (dir != "/" && dir.back() == '/') dir.pop_back();
            std::string up_dir = up;
            for (auto it = seen.begin(); it != seen.end();) {
                std::string child = (dir == "/" ? "/" : dir + "/") + it->first;
                if (is_whiteout(child) &&
                    !exists((up_dir + "/" + it->first).c_str()))
                    it = seen.erase(it);
                else
                    ++it;
            }
        }
        out.reserve(seen.size());
        for (auto& [name, isdir] : seen) out.push_back({name, isdir});
        return out;
    }

    // -- Guest fd table ----------------------------------------------------
    // Records the guest path bound to a real (forwarded) fd, so readlinkat,
    // getdents, and fd-relative openat can recover the path. The fd number is
    // the REAL host fd the child holds (redirect/inject both yield real fds).
    void bind_fd(int fd, std::string abs) { fd_paths_[fd] = std::move(abs); }
    void unbind_fd(int fd) { fd_paths_.erase(fd); dir_streams_.erase(fd); }
    [[nodiscard]] std::string_view path_of_fd(int fd) const {
        auto it = fd_paths_.find(fd);
        return it == fd_paths_.end() ? std::string_view{} : std::string_view{it->second};
    }

    // -- Virtual directory streams -----------------------------------------
    // When the guest opens a VIRTUAL directory (procfs/sysfs), we bind its
    // synthesized entries to the fd so getdents64 can enumerate them (the
    // real backing fd is an empty temp file; enumeration is fully virtual).
    struct DirStream { std::vector<VirtualDirent> entries; std::size_t pos{0}; };
    void bind_dir(int fd, std::vector<VirtualDirent> entries) {
        dir_streams_[fd] = DirStream{std::move(entries), 0};
    }
    [[nodiscard]] bool is_virtual_dir_fd(int fd) const {
        return dir_streams_.count(fd) != 0;
    }
    [[nodiscard]] DirStream* dir_stream(int fd) {
        auto it = dir_streams_.find(fd);
        return it == dir_streams_.end() ? nullptr : &it->second;
    }

    // Normalize an absolute path: collapse "//", resolve "." and "..", drop a
    // trailing slash (except root). Pure lexical (no symlink following).
    [[nodiscard]] static std::string normalize(std::string_view p) {
        std::vector<std::string_view> stack;
        std::size_t i = 0;
        while (i < p.size()) {
            while (i < p.size() && p[i] == '/') ++i;
            std::size_t j = i;
            while (j < p.size() && p[j] != '/') ++j;
            if (j > i) {
                std::string_view comp = p.substr(i, j - i);
                if (comp == ".") {
                    // skip
                } else if (comp == "..") {
                    if (!stack.empty()) stack.pop_back();
                } else {
                    stack.push_back(comp);
                }
            }
            i = j;
        }
        std::string out = "/";
        for (std::size_t k = 0; k < stack.size(); ++k) {
            out += stack[k];
            if (k + 1 < stack.size()) out += '/';
        }
        return out;
    }

private:
    struct Mount {
        std::string prefix;      // absolute guest prefix
        std::string host_base;   // real (lower) dir; empty for virtual mounts
        std::string upper;       // writable overlay upper dir; empty = no COW
        Producer    producer;    // set for virtual mounts
    };

    static std::string join_host(std::string_view base, std::string_view rel) {
        std::string p{base};
        if (!rel.empty()) { p += '/'; p += rel; }
        return p;
    }

    // Resolve a rootfs symlink to a PathClass. A rootfs is full of absolute
    // symlinks (Alpine's /bin/sh -> /bin/busybox, /lib -> /usr/lib): their
    // targets are GUEST-absolute, so the host kernel would resolve them against
    // the HOST root and miss. Here we chase the chain ourselves, re-rooting
    // each within-mount target under the mount base (upper first, then lower).
    // Relative links resolve against the link's own directory.
    //
    // CROSS-MOUNT targets: a rootfs symlink can point into a DIFFERENT mount —
    // /etc/mtab -> /proc/self/mounts crosses from the rootfs '/' mount into the
    // virtual /proc. Re-rooting under '/' would fabricate a nonexistent
    // <rootfs>/proc/self/mounts. So when a resolved guest-absolute target lands
    // in a different mount, we RE-CLASSIFY it through the whole namespace: a
    // virtual target correctly returns the virtual_file realm (so open injects
    // it), a target in another host mount lands in that mount's base.
    // Bounded to avoid symlink loops.
    PathClass follow_symlink(const Mount& m, std::string host,
                             bool for_write, WriteIntent wi, int depth) const {
        for (int hops = 0; hops < 40; ++hops) {
            char buf[4096];
            ::ssize_t n = ::readlink(host.c_str(), buf, sizeof buf - 1);
            if (n < 0)                              // not a symlink (or gone)
                return PathClass{Realm2::host_backed, std::move(host), Errno::enoent, {}};
            buf[n] = '\0';
            std::string target{buf};
            std::string guest_abs;
            if (!target.empty() && target.front() == '/') {
                guest_abs = normalize(target);       // absolute: re-root it
            } else {
                // relative: resolve against the link's guest directory. Map
                // the host path back to a guest path via the mount base.
                std::string_view base = m.upper.empty() ? std::string_view{m.host_base}
                    : (host.rfind(m.upper, 0) == 0 ? std::string_view{m.upper}
                                                   : std::string_view{m.host_base});
                std::string_view relhost = host;
                relhost.remove_prefix(base.size());
                std::string guest_link = m.prefix == "/" ? std::string{relhost}
                                       : m.prefix + std::string{relhost};
                auto slash = guest_link.find_last_of('/');
                std::string dir = slash == std::string::npos ? "/"
                                    : guest_link.substr(0, slash);
                guest_abs = normalize(dir + "/" + target);
            }
            // CROSS-MOUNT: the target belongs to a different mount than the
            // link. Re-classify through the whole namespace (bounded recursion).
            if (deepest(guest_abs) != &m) {
                if (depth >= 8)
                    return PathClass{Realm2::absent, {}, Errno::eloop, {}};
                return classify_impl(guest_abs, for_write, /*follow=*/true, wi,
                                     depth + 1);
            }
            // Within-mount: re-root the guest-absolute target here (upper|lower).
            std::string_view rel = guest_abs;
            if (m.prefix != "/") rel.remove_prefix(
                std::min(rel.size(), m.prefix.size()));
            while (!rel.empty() && rel.front() == '/') rel.remove_prefix(1);
            std::string up = m.upper.empty() ? std::string{}
                                             : join_host(m.upper, rel);
            std::string lo = join_host(m.host_base, rel);
            host = (!up.empty() && exists(up.c_str())) ? up : lo;
        }
        return PathClass{Realm2::host_backed, std::move(host), Errno::enoent, {}};
    }

    static bool exists(const char* path) {
        struct ::stat st{};
        return ::lstat(path, &st) == 0;
    }

    static bool is_dir(const char* path) {
        struct ::stat st{};
        return ::stat(path, &st) == 0 && S_ISDIR(st.st_mode);
    }

    // Read a real host directory's entries into `seen` (name -> is_dir),
    // skipping "."/".." and not overwriting a name already present (so the
    // caller can merge upper before lower and have upper win).
    static void merge_dir(const std::string& host_dir,
                          std::unordered_map<std::string, bool>& seen) {
        ::DIR* d = ::opendir(host_dir.c_str());
        if (!d) return;
        while (::dirent* e = ::readdir(d)) {
            std::string name = e->d_name;
            if (name == "." || name == "..") continue;
            if (seen.count(name)) continue;
            bool isdir = e->d_type == DT_DIR;
            if (e->d_type == DT_UNKNOWN)
                isdir = is_dir((host_dir + "/" + name).c_str());
            seen.emplace(std::move(name), isdir);
        }
        ::closedir(d);
    }

    // Ensure `up` exists in the upper layer, copying its bytes up from the
    // read-only lower `lo` on first write and creating parent directories.
    // Best-effort: if the lower doesn't exist this just preps the parent dirs
    // so an O_CREAT open can make the new file in upper.
    //
    // Crucially, the parent chain is MIRRORED from lower to upper: a directory
    // that exists only in the read-only lower (e.g. /opt from the pristine
    // rootfs) has no upper counterpart, so a bare mkdir/create of a CHILD in
    // upper would ENOENT on the missing parent. mirror_parents_from_lower
    // reproduces each lower ancestor as a real upper directory first, so the
    // upper layer is a coherent writable view of the whole tree.
    static void copy_up(const std::string& up, const std::string& lo) {
        mirror_parents_from_lower(up, lo);
        if (exists(up.c_str())) return;                 // already copied up
        // If the lower is a DIRECTORY, mirror it as a directory in upper (do
        // NOT open+copy it as a regular file — that would leave a bogus file
        // where a mkdir/child-create expects a dir, yielding EEXIST/ENOTDIR).
        if (is_dir(lo.c_str())) { ::mkdir(up.c_str(), 0755); return; }
        int in = ::open(lo.c_str(), O_RDONLY | O_CLOEXEC);
        if (in < 0) return;                             // no lower => new file
        int out = ::open(up.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (out < 0) { ::close(in); return; }
        char buf[65536];
        for (;;) {
            ::ssize_t n = ::read(in, buf, sizeof buf);
            if (n <= 0) break;
            for (::ssize_t off = 0; off < n; ) {
                ::ssize_t w = ::write(out, buf + off, static_cast<std::size_t>(n - off));
                if (w <= 0) { off = n; break; }
                off += w;
            }
        }
        ::close(in); ::close(out);
    }

    // Reproduce every ANCESTOR directory of `up` in the upper layer, matching
    // the corresponding lower ancestor. `up` and `lo` are the upper/lower host
    // paths of the SAME guest path, so they share a common suffix of
    // components below their respective bases; we create each upper ancestor
    // (ignoring EEXIST). Directories that exist only in lower thus gain a real
    // upper twin, so a child create in upper resolves.
    static void mirror_parents_from_lower(const std::string& up,
                                          const std::string& lo) {
        // Walk `up`'s ancestor prefixes; for each, mkdir it in upper. We can't
        // know the exact lower/upper base split here, but creating each
        // ancestor of `up` bottom-up is sufficient and idempotent.
        std::size_t slash = up.find_last_of('/');
        if (slash == std::string::npos || slash == 0) return;
        std::string dir = up.substr(0, slash);
        for (std::size_t i = 1; i <= dir.size(); ++i) {
            if (i == dir.size() || dir[i] == '/') {
                std::string sub = dir.substr(0, i);
                ::mkdir(sub.c_str(), 0755);   // ignore EEXIST
            }
        }
        (void)lo;
    }

    // mkdir -p for the directory component of a host path.
    static void make_parents(const std::string& path) {
        std::size_t slash = path.find_last_of('/');
        if (slash == std::string::npos || slash == 0) return;
        std::string dir = path.substr(0, slash);
        for (std::size_t i = 1; i <= dir.size(); ++i) {
            if (i == dir.size() || dir[i] == '/') {
                std::string sub = dir.substr(0, i);
                ::mkdir(sub.c_str(), 0755);   // ignore EEXIST
            }
        }
    }

    [[nodiscard]] const Mount* deepest(std::string_view abs) const {
        const Mount* best = nullptr;
        std::size_t best_len = 0;
        for (const auto& m : mounts_) {
            const std::string& pre = m.prefix;
            bool match = pre == "/" ? true
                : (abs.starts_with(pre) &&
                   (abs.size() == pre.size() || abs[pre.size()] == '/'));
            if (match && pre.size() >= best_len) { best = &m; best_len = pre.size(); }
        }
        return best;
    }

    std::vector<Mount> mounts_;
    std::string cwd_{"/"};
    std::unordered_map<int, std::string> fd_paths_;
    std::unordered_map<int, DirStream> dir_streams_;
    MetaStore meta_{};
    bool meta_attached_{false};

    // WHITEOUTS. Removing a file that lives ONLY in the read-only lower layer
    // must not touch the pristine rootfs. Instead we record the guest path
    // here so it reads back as absent (classify) and is filtered from
    // directory listings (overlay_dir_union). A re-create at the same path
    // (copy_leaf/parents_only classify, or an open O_CREAT) clears the
    // whiteout. Journaled to `.linuxity-whiteout` in the upper layer so the
    // removal persists across runs, exactly like copied-up files and meta.
    mutable std::unordered_set<std::string> whiteouts_;
    std::string whiteout_journal_;

public:
    // Record a lower-only removal. Returns nothing; the caller reports success.
    void add_whiteout(const std::string& guest_path) const {
        if (whiteouts_.insert(guest_path).second && !whiteout_journal_.empty()) {
            if (std::FILE* fp = std::fopen(whiteout_journal_.c_str(), "a")) {
                std::fputs(guest_path.c_str(), fp);
                std::fputc('\n', fp);
                std::fclose(fp);
            }
        }
    }

    // Clear a whiteout because the path is being (re-)created. In-memory only;
    // the create materializes a real upper file that shadows the lower, and a
    // stale journal line is harmless (replay is order-preserving: a later
    // create in the upper wins over an earlier whiteout at read time). We
    // append a clearing marker so a cross-run replay stays exact.
    void clear_whiteout(const std::string& guest_path) const {
        if (whiteouts_.erase(guest_path) && !whiteout_journal_.empty()) {
            if (std::FILE* fp = std::fopen(whiteout_journal_.c_str(), "a")) {
                std::fputc('!', fp);            // '!' prefix = un-whiteout
                std::fputs(guest_path.c_str(), fp);
                std::fputc('\n', fp);
                std::fclose(fp);
            }
        }
    }

    [[nodiscard]] bool is_whiteout(std::string_view guest_path) const {
        return whiteouts_.find(std::string{guest_path}) != whiteouts_.end();
    }

private:
    void load_whiteouts() {
        if (whiteout_journal_.empty()) return;
        std::FILE* fp = std::fopen(whiteout_journal_.c_str(), "r");
        if (!fp) return;
        char line[4096];
        while (std::fgets(line, sizeof line, fp)) {
            std::string s{line};
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
                s.pop_back();
            if (s.empty()) continue;
            if (s.front() == '!') whiteouts_.erase(s.substr(1)); // un-whiteout
            else                  whiteouts_.insert(s);
        }
        std::fclose(fp);
    }
};

} // namespace lx::kernel
