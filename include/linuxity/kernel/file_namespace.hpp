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

#include "linuxity/abi/wire/path.hpp"
#include "linuxity/abi/result.hpp"
#include "linuxity/abi/types.hpp"
#include "linuxity/kernel/meta_store.hpp"
#include "linuxity/kernel/socket_ns.hpp"

#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include "linuxity/host/win_posix.hpp"
#include "linuxity/host/dirent_type.hpp"

#include <cstdint>
#include <algorithm>
#include <cstring>
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
enum class DType : std::uint8_t { regular, dir, symlink };
struct VirtualDirent {
    std::string name;
    DType type{DType::regular};
    // The REAL host inode, when this entry came from a host directory.
    //
    // getdents64 must report the same d_ino that a later stat() of the same
    // name reports: libalpm reads the package DB by enumerating
    // /var/lib/pacman/local, then stats each entry and matches st_ino against
    // the d_ino it saw. A synthesized counter makes every comparison fail, so
    // `pacman -Q` lists nothing even though the DB is intact.
    //
    // 0 means "no host inode" -- a purely synthesized entry (procfs, sysfs, a
    // virtual dir) where the dispatcher falls back to a positional value.
    std::uint64_t ino{0};
    // Back-compat helpers so existing `{name, true/false}` sites and .is_dir
    // reads keep working while carrying the richer symlink type.
    VirtualDirent() = default;
    VirtualDirent(std::string n, bool dir)
        : name(std::move(n)), type(dir ? DType::dir : DType::regular) {}
    VirtualDirent(std::string n, DType t) : name(std::move(n)), type(t) {}
    VirtualDirent(std::string n, DType t, std::uint64_t i)
        : name(std::move(n)), type(t), ino(i) {}
    [[nodiscard]] bool is_dir() const noexcept { return type == DType::dir; }
    [[nodiscard]] bool is_symlink() const noexcept { return type == DType::symlink; }
};
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
        // Every host path in the mount table is ABSOLUTE, made so here -- the
        // one door every host path comes through (--root, --persist, --bind,
        // the private /tmp, any future caller).
        //
        // A relative one is not just untidy, it is a live bug: the host path
        // classify() hands out is used by the SUPERVISOR's own calls (the
        // one-stop stat, whiteouts, the meta journal) AND spliced into the
        // guest's registers for a REDIRECT, which the kernel then resolves
        // against the GUEST's cwd and dirfd, not ours. With `--persist
        // ./arch-upper` on Android, rm -rf's fts unlinks relative to an open
        // dirfd, so "./arch-upper/.../f" resolved under the guest's directory
        // and removed nothing. The trace showed REDIRECT to the right-looking
        // path, the file stayed on disk, and rmdir failed ENOTEMPTY. The same
        // run with absolute --root/--persist was clean.
        //
        // Lexical, not realpath(): this file is the portable core and makes
        // no host calls. The base is the supervisor's cwd at mount time,
        // passed in by the backend that knows it.
        host_base = absolute_host(std::move(host_base));
        upper     = absolute_host(std::move(upper));
        // Strip a trailing slash, but never reduce "/" to "": an empty
        // host_base makes join_host(base, "") return "", so classify("/")
        // handed the dispatcher an empty host path and stat("/") came back
        // ENOENT. Deeper paths accidentally worked (join_host("", "usr") is
        // "/usr"), which is why only the root itself was broken -- and that
        // was enough to make `rm -r` fail, since it stats "/" walking up.
        if (host_base.size() > 1 && host_base.back() == '/') host_base.pop_back();
        if (upper.size() > 1 && upper.back() == '/') upper.pop_back();
        // The shadow metadata journal lives in the ROOT mount's upper layer,
        // so uid/mode overlays for the whole guest tree share one store that
        // persists across runs. Attach the first time a rooted overlay mounts.
        if (prefix == "/" && !upper.empty() && !meta_attached_) {
            // Only the ROOT linuxity process (no guest running yet) may
            // compact journals or repair pacman's db. A guest fork is a fresh
            // linuxity that mounts again -- doing it there deleted pacman's
            // LIVE db.lck and in-progress local entries mid-transaction from
            // any helper pacman spawned, and rescanned the db per fork.
            meta_.set_host_bases({upper, host_base});
            meta_.attach(upper, /*compact=*/is_root_);
            meta_attached_ = true;
            whiteout_journal_ = upper + "/.linuxity-whiteout";
            const std::size_t wl = load_whiteouts();
            if (is_root_ && wl > 1024 && wl > whiteouts_.size() * 4) rewrite_whiteouts();
            if (is_root_) repair_pacman_db(upper);
        }
        mounts_.push_back(Mount{std::move(prefix), std::move(host_base),
                                std::move(upper), {}});
    }
    // A fork child (a guest process started by another guest process) must
    // not do root-only hygiene. Set before the first mount_host.
    void set_fork_child(bool child) noexcept { is_root_ = !child; }

    // The shadow permission/ownership store (per-path mode/uid/gid overlay).
    // The dispatcher records guest chmod/chown here and overlays it back onto
    // host stat results, so a uid-0 world round-trips coherently.
    [[nodiscard]] MetaStore& meta() noexcept { return meta_; }
    [[nodiscard]] const MetaStore& meta() const noexcept { return meta_; }

    // The SUPERVISOR's cwd at startup -- the base mount_host() uses to make a
    // relative host path absolute. Set once by the backend, before mounting;
    // unset means "/". Distinct from every guest cwd on purpose: those live in
    // cwds_ and are what the GUEST sees, this is where the host tool ran.
    void set_host_cwd(std::string c) { host_cwd_ = normalize(std::move(c)); }

    // A host path made absolute against host_cwd_. Lexical only: the portable
    // core makes no host calls, so no realpath().
    [[nodiscard]] std::string absolute_host(std::string p) const {
        if (p.empty()) return p;
        if (p.front() == '/') return normalize(p);
        std::string base = host_cwd_.empty() ? std::string{"/"} : host_cwd_;
        if (base.back() != '/') base += '/';
        return normalize(base + p);
    }

    // Mount a virtual producer at an absolute guest prefix ("/proc", "/sys").
    void mount_virtual(std::string prefix, Producer prod) {
        if (prefix.size() > 1 && prefix.back() == '/') prefix.pop_back();
        mounts_.push_back(Mount{std::move(prefix), {}, {}, std::move(prod)});
    }

    // Does this path LIVE in a virtual mount, whether or not the leaf exists?
    // classify() answers about the leaf, so a name procfs does not produce
    // comes back `absent` -- which makes a rename inside /proc look like it
    // crosses a mount boundary. Callers that need the mount, not the file,
    // ask here.
    [[nodiscard]] bool under_virtual_mount(std::string_view abs) const {
        for (const auto& m : mounts_) {
            if (!m.producer) continue;
            if (abs.size() >= m.prefix.size() &&
                abs.compare(0, m.prefix.size(), m.prefix) == 0 &&
                (abs.size() == m.prefix.size() || abs[m.prefix.size()] == '/'))
                return true;
        }
        return false;
    }

    [[nodiscard]] std::string_view cwd() const noexcept { return cwd_of(cur_pid_); }
    void set_cwd(std::string c) { cwds_[cur_pid_] = normalize(c); last_cwd_ = cwds_[cur_pid_]; }

    // How AF_UNIX sockets are named on this host. Filesystem everywhere POSIX
    // lets us create a socket node; abstract where it does not (Android's
    // SELinux denies the bind in every directory an app can write). Probed
    // once at startup rather than assumed, because guessing wrong means every
    // socket-using guest daemon fails with EACCES.
    [[nodiscard]] SocketNs socket_ns() const noexcept { return socket_ns_; }
    void set_socket_ns(SocketNs ns) noexcept { socket_ns_ = ns; }

    // Distinguishes concurrent linuxity instances in the abstract namespace.
    [[nodiscard]] std::uint64_t instance_id() const noexcept { return instance_id_; }
    void set_instance_id(std::uint64_t id) noexcept { instance_id_ = id; }

    // Per-process cwd. linuxity runs a whole guest PROCESS TREE against one
    // FileNamespace, but each process has its OWN current directory — a single
    // shared cwd_ let a forked child's chdir clobber the parent's (git's
    // pack helpers chdir into .git/objects/pack/tmp_pack_* and, on exit, left
    // the shell resolving relative paths against the deleted tempdir, e.g.
    // `cd repo` after a clone -> "cannot open directory '.'"). The dispatcher
    // sets cur_pid_ to the trapped task's guest pid before each syscall, so
    // chdir/fchdir/getcwd and every relative-path absolutize act on the RIGHT
    // process's cwd. A pid with no record inherits the tree default "/".
    void set_current_pid(std::int32_t pid) const noexcept { cur_pid_ = pid; }
    // The pid whose syscall is being served right now. A virtual-file producer
    // needs it to answer per-process questions (/dev/tty is "MY controlling
    // terminal"), and the producer signature carries only the path.
    [[nodiscard]] std::int32_t current_pid() const noexcept { return cur_pid_; }
    // Select the active pid AND, if this pid has no cwd record yet, seed it
    // from its parent's cwd (a freshly forked child inherits the parent's
    // directory). Called by the dispatcher with (pid, ppid) it already knows,
    // so inheritance happens on the child's very first syscall without the
    // trap layer having to plumb fork events into the filesystem.
    void set_current_pid(std::int32_t pid, std::int32_t ppid) const {
        // The dispatcher calls this before EVERY syscall, and the pid almost
        // never changes between two consecutive syscalls -- a task runs a
        // burst of them before another task traps. `seeded_pid_` caches the
        // pid whose cwd record we already know exists, so the steady state
        // is one integer compare instead of two unordered_map lookups
        // (~40 ns of hashing) on every single syscall.
        cur_pid_ = pid;
        if (pid == seeded_pid_) return;
        if (cwds_.find(pid) == cwds_.end()) {
            auto it = cwds_.find(ppid);
            // No record for the parent either. That happens when a task's
            // first syscall arrives before its parent link is known -- under
            // `make -j10` the dispatcher saw ppid=0 for roughly one task per
            // run. inherited_cwd_ is only ever assigned by the macOS
            // fresh-process fork path, so on Linux it stayed "/" forever and
            // the task resolved every relative path against the ROOT. That is
            // the "gcc: can't create s7.o: Permission denied" under a parallel
            // build: the trace shows it opening /s7.o.
            //
            // Fall back to the cwd of the task that was running most recently
            // instead. A new task is created BY a running one and inherits its
            // cwd, so that value is the parent's by construction -- and it is
            // never "/" unless the guest really is there.
            cwds_[pid] = (it != cwds_.end()) ? it->second : last_cwd_;
            // A forked child also inherits COPIES of the parent's fds, so it
            // inherits their bindings. Done here for the same reason the cwd
            // is: this is the child's first syscall, before it can open
            // anything of its own.
            const std::int32_t from = (it != cwds_.end()) ? ppid : last_pid_;
            if (have_inherited_fds_) {
                // Fresh-process fork (darwin): the parent's fds arrived via
                // import_process_state before we knew this pid.
                fd_tables_[pid] = std::move(inherited_fds_);
                inherited_fds_ = FdTable{};
                have_inherited_fds_ = false;
            } else if (auto fp = fd_tables_.find(from); fp != fd_tables_.end()) {
                fd_tables_[pid] = fp->second.copy_for_fork();
            }
        }
        seeded_pid_ = pid;
        last_pid_ = pid;
        // Remember this task's cwd as the fallback for the next task whose
        // parent we have not learned yet.
        if (const auto& c = cwds_[pid]; !c.empty()) last_cwd_ = c;
    }
    // On fork/clone the child inherits a COPY of the parent's cwd.
    void inherit_cwd(std::int32_t child, std::int32_t parent) {
        auto it = cwds_.find(parent);
        cwds_[child] = (it != cwds_.end()) ? it->second : std::string{"/"};
    }
    // Dropping a pid's record must also drop the "already seeded" claim:
    // the kernel recycles pids, and a new task reusing this number has to
    // re-seed from ITS parent rather than skip straight past the check.
    void forget_pid(std::int32_t pid) {
        cwds_.erase(pid);
        if (pid == seeded_pid_) seeded_pid_ = 0;
    }
    [[nodiscard]] std::string_view cwd_of(std::int32_t pid) const noexcept {
        auto it = cwds_.find(pid);
        return it != cwds_.end() ? std::string_view{it->second}
                                 : std::string_view{"/"};
    }

    // Resolve a (possibly relative, possibly dirfd-relative) path to an
    // absolute guest path. `dir_path` is the path bound to a guest dirfd, or
    // empty for AT_FDCWD.
    [[nodiscard]] std::string absolutize(std::string_view path,
                                         std::string_view dir_path = {}) const {
        // `normalize` takes a string_view -- the old `std::string{path}` here
        // allocated a throwaway copy of every absolute path the guest ever
        // passed, which is most of them.
        if (!path.empty() && path.front() == '/') return normalize(path);
        std::string base = dir_path.empty() ? std::string{cwd()} : std::string{dir_path};
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
                    if (exists(up.c_str())) {
                        PathClass r{Realm2::host_backed, std::move(up),
                                    Errno::enoent, {}};
                        // Removing the UPPER copy unshadows the lower one, so
                        // the file would come back from the pristine rootfs.
                        // A whiteout is still needed. pacman reinstalling the
                        // same package twice hit this: the first install put
                        // the file in the upper, the second unlinked it, and
                        // the lower copy reappeared so O_EXCL said EEXIST.
                        if (exists(lo.c_str())) r.whiteout_lower = true;
                        return r;
                    }
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
                // now shadows the (still-pristine) lower, so drop the
                // whiteout. Doing this HERE, before O_EXCL's own existence
                // probe, is deliberate -- the probe then sees the name as
                // free and the exclusive create succeeds, which is what an
                // overlay must do for a file that only exists in the
                // read-only lower layer.
                if (!whiteouts_.empty()) clear_whiteout(std::string{abs});
                return PathClass{Realm2::host_backed, std::move(up), Errno::enoent, {}};
            }
            // READ. One probe of the upper layer answers everything the read
            // path needs: whether the upper shadows the lower (layer pick),
            // and if so whether it is a symlink to chase. This used to be two
            // `exists(up)` calls -- the same lstat twice, since `whiteouts_`
            // is usually non-empty -- plus a third `readlink` inside
            // follow_symlink on the path we just stat'd.
            std::string target;
            const Probe up_probe = probe_link(up.c_str(), target);
            // A whited-out path that hasn't been re-created in the upper
            // reads back as absent -- the lower file was "removed" in the
            // overlay view even though the pristine rootfs still holds it.
            if (up_probe == Probe::absent && !whiteouts_.empty() && is_whiteout(abs))
                return PathClass{Realm2::absent, {}, Errno::enoent, {}};
            if (up_probe == Probe::absent) {
                if (follow) return follow_symlink(*m, std::move(lo), for_write, wi, depth);
                return PathClass{Realm2::host_backed, std::move(lo), Errno::enoent, {}};
            }
            // The upper wins. If it is a symlink and we must follow, hand the
            // ALREADY-READ target to the resolver so it doesn't re-readlink.
            if (follow && up_probe == Probe::symlink)
                return resolve_link_target(*m, up, std::move(target), for_write, wi, depth);
            return PathClass{Realm2::host_backed, std::move(up), Errno::enoent, {}};
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
        // No is_dir() probes here: opendir inside merge_dir already answers
        // "does this directory exist and can I read it", so stat'ing both
        // layers first was two wasted host syscalls per enumerated directory
        // -- and `ls -lR` enumerates thousands.
        NameMap seen;                                  // name -> type
        const bool had_up = merge_dir(up, seen);       // upper first (wins)
        const bool had_lo = merge_dir(lo, seen);
        if (!had_up && !had_lo) return out;            // neither layer exists
        // The shadow-metadata journal is an implementation file in the upper
        // layer, not part of the guest tree — never let it show up in a listing.
        // Erase via find(): transparent erase(K&&) is C++23, but a transparent
        // find() plus erase(iterator) is C++20 and allocates nothing either.
        for (std::string_view hide : {MetaStore::journal_leaf(),
                                      std::string_view{".linuxity-whiteout"}})
            if (auto it = seen.find(hide); it != seen.end()) seen.erase(it);
        // Drop names whited-out from the lower layer (removed in the overlay
        // view but still present on the pristine rootfs) unless the upper has
        // re-created them (merge_dir(up) already recorded those, so a name
        // present in `seen` from the upper survives — only lower-only whited
        // names must go).
        if (!whiteouts_.empty()) {
            std::string dir{abs};
            if (dir != "/" && dir.back() == '/') dir.pop_back();
            // Build both candidate paths by TRUNCATING a reused buffer rather
            // than concatenating fresh strings per entry: this loop runs over
            // every name in every enumerated directory, and the old form made
            // two allocations each time just to ask a set-membership question.
            std::string child = (dir == "/" ? std::string{"/"} : dir + "/");
            const std::size_t child_base = child.size();
            std::string up_child = up;
            up_child += '/';
            const std::size_t up_base = up_child.size();
            for (auto it = seen.begin(); it != seen.end();) {
                child.resize(child_base);
                child += it->first;
                // is_whiteout is an in-memory set probe; exists() is a host
                // syscall. Test the cheap one first and let && skip the stat
                // for the overwhelming majority of entries, which are not
                // whited out at all.
                if (!is_whiteout(child)) { ++it; continue; }
                up_child.resize(up_base);
                up_child += it->first;
                if (!exists(up_child.c_str()))
                    it = seen.erase(it);
                else
                    ++it;
            }
        }
        // A directory listing MUST begin with "." and ".." (both directories):
        // the getdents(2) contract guarantees them, and tools that count or
        // recurse over entries (find, du, cmake/make's progress counter) break
        // without them. merge_dir deliberately drops the host layers' own
        // "."/"..", so we synthesize exactly one pair here for the merged view.
        out.reserve(seen.size() + 2);
        out.push_back({".",  DType::dir});
        out.push_back({"..", DType::dir});
        for (auto& [name, info] : seen)
            out.push_back({name, info.type, info.ino});
        return out;
    }

    // -- Guest fd table ----------------------------------------------------
    // Records the guest path bound to a real (forwarded) fd, so readlinkat,
    // getdents, and fd-relative openat can recover the path. The fd number is
    // the REAL host fd the child holds (redirect/inject both yield real fds).
    void bind_fd(int fd, std::string abs) { fds().paths[fd] = std::move(abs); }
    void unbind_fd(int fd) { auto& t = fds(); t.paths.erase(fd); t.dirs.erase(fd); }
    // Copy the path binding AND (if any) the virtual-directory stream from
    // `from` onto `to`. Used after a dup/dup2/dup3/fcntl(F_DUPFD): the new fd
    // aliases the same open description, so an *at call or getdents on it must
    // resolve the SAME path/entries. The dir stream is duplicated with a fresh
    // read position (the dup'd fd shares the file offset in the real kernel,
    // but our virtual enumeration is independent and each fd enumerates from
    // the start). No-op if `from` has no binding.
    void mirror_fd(int from, int to) {
        if (from == to) return;
        auto& t = fds();
        if (auto it = t.paths.find(from); it != t.paths.end())
            t.paths[to] = it->second;
        if (auto it = t.dirs.find(from); it != t.dirs.end())
            t.dirs[to] = DirStream{it->second.entries, 0, it->second.lazy, 0};
    }
    [[nodiscard]] std::string_view path_of_fd(int fd) const {
        const auto& t = fds();
        auto it = t.paths.find(fd);
        return it == t.paths.end() ? std::string_view{} : std::string_view{it->second};
    }

    // -- Per-process state that a fork must carry to the child --------------
    // A backend that forks by spawning a FRESH process (macOS: see
    // runtime/darwin/fork.hpp) rebuilds the mounts from the same command line,
    // but the dynamic state -- this process's cwd and which guest path each
    // fd names -- exists only in the parent. These two functions are the
    // complete list; a length-prefixed byte format keeps them trivially
    // forward-compatible.
    [[nodiscard]] std::string export_process_state() const {
        std::string out;
        auto put = [&out](std::string_view s) {
            const auto n = static_cast<std::uint32_t>(s.size());
            out.append(reinterpret_cast<const char*>(&n), 4);
            out.append(s);
        };
        put(cwd());
        const auto& paths = fds().paths;
        const auto count = static_cast<std::uint32_t>(paths.size());
        out.append(reinterpret_cast<const char*>(&count), 4);
        for (const auto& [fd, path] : paths) {
            out.append(reinterpret_cast<const char*>(&fd), sizeof fd);
            put(path);
        }
        return out;
    }
    void import_process_state(std::string_view in) {
        std::size_t at = 0;
        auto u32 = [&]() -> std::uint32_t {
            std::uint32_t v = 0;
            if (at + 4 <= in.size()) std::memcpy(&v, in.data() + at, 4);
            at += 4;
            return v;
        };
        auto str = [&]() {
            const std::uint32_t n = u32();
            std::string s{in.substr(std::min(at, in.size()), n)};
            at += n;
            return s;
        };
        // The fork child is a FRESH host process: its cwd table holds no
        // record for its own pid or its parent's, so its first syscall's
        // set_current_pid() would fall back to "/". (Storing via set_cwd()
        // here filed it under the default cur_pid_ 1 instead -- every
        // relative path in a forked child, e.g. `g++ hey.cpp` -> cc1,
        // resolved against "/".) Make the parent's cwd the fallback.
        inherited_cwd_ = normalize(str());
        if (inherited_cwd_.empty()) inherited_cwd_ = "/";
        cwds_.clear();
        seeded_pid_ = 0;          // no record survives the clear
        // The child's pid is not known yet, so park the inherited fds; the
        // child's first set_current_pid() adopts them (see inherited_fds_).
        fd_tables_.clear();
        inherited_fds_ = FdTable{};
        for (std::uint32_t i = 0, n = u32(); i < n && at < in.size(); ++i) {
            int fd = 0;
            std::memcpy(&fd, in.data() + at, sizeof fd);
            at += sizeof fd;
            inherited_fds_.paths[fd] = str();
        }
        have_inherited_fds_ = true;
    }

    // -- Virtual directory streams -----------------------------------------
    // When the guest opens a VIRTUAL directory (procfs/sysfs), we bind its
    // synthesized entries to the fd so getdents64 can enumerate them (the
    // real backing fd is an empty temp file; enumeration is fully virtual).
    // `lazy` holds the guest path of an OVERLAID host directory whose union
    // has not been computed yet: enumerating it costs two readdir sweeps plus
    // a hash map, and the overwhelming majority of opened directories are
    // never read (openat(O_PATH|O_DIRECTORY) as an *at base, a dirfd kept for
    // fchdir, libalpm's per-package parent handles). Paying that at open time
    // made every open O(directory size) and dominated the profile -- a single
    // `pacman -S python` spent 96% of its host CPU in overlay_dir_union. So
    // record the intent and materialize on the FIRST getdents64 instead.
    struct DirStream {
        std::vector<VirtualDirent> entries;
        std::size_t pos{0};
        std::string lazy;                      // non-empty => not yet built
        // Byte position of the cursor, the unit d_off and lseek both use.
        // Kept alongside pos so a seek can map a cookie back to an index.
        std::uint64_t byte_off{0};
    };

    // One process's fd bindings. A fd NUMBER means nothing without the
    // process holding it: two processes that each open a different file
    // routinely get the same number. These used to be keyed by fd alone and
    // shared across the whole traced tree, so a child's open of fd 11
    // re-pointed its PARENT's fd 11 -- /proc/self/fd/11 named the child's
    // file in both, and the parent's *at calls and getdents resolved against
    // the wrong path. Keyed by guest pid instead, which threads share, the
    // way they share a real fd table.
    struct FdTable {
        std::unordered_map<int, std::string> paths;
        std::unordered_map<int, DirStream> dirs;
        // A fork copies the fd table but each copy has its OWN file offset
        // for a virtual directory stream, so the child starts fresh streams.
        [[nodiscard]] FdTable copy_for_fork() const {
            FdTable t;
            t.paths = paths;
            for (const auto& [fd, d] : dirs)
                t.dirs[fd] = DirStream{d.entries, d.pos, d.lazy, d.byte_off};
            return t;
        }
    };
    [[nodiscard]] FdTable& fds() const { return fd_tables_[cur_pid_]; }

    void bind_dir(int fd, std::vector<VirtualDirent> entries) {
        fds().dirs[fd] = DirStream{std::move(entries), 0, {}, 0};
    }
    // Bind an overlaid host directory whose union is computed on demand.
    void bind_lazy_dir(int fd, std::string abs) {
        fds().dirs[fd] = DirStream{{}, 0, std::move(abs), 0};
    }
    [[nodiscard]] bool is_virtual_dir_fd(int fd) const {
        return fds().dirs.count(fd) != 0;
    }
    [[nodiscard]] DirStream* dir_stream(int fd) {
        auto& dirs = fds().dirs;
        auto it = dirs.find(fd);
        if (it == dirs.end()) return nullptr;
        // First read of a lazily-bound overlay directory: build the union now.
        // If the union comes back empty the directory is not actually overlaid
        // (it vanished, or the mount changed), so drop the stream and let the
        // caller enumerate the real fd natively.
        if (!it->second.lazy.empty()) {
            std::string abs = std::move(it->second.lazy);
            it->second.lazy.clear();
            it->second.entries = overlay_dir_union(abs);
            if (it->second.entries.empty()) {
                dirs.erase(it);
                return nullptr;
            }
        }
        return &it->second;
    }

    // The INVERSE of classify(): given a real host path, what does the guest
    // call it? Empty when the path is not inside any of our mounts -- a host
    // library the guest never sees, which the caller should leave alone.
    //
    // Needed because /proc/<pid>/maps names real files, and the guest must
    // be told its binary is /usr/bin/sh rather than wherever the rootfs
    // happens to be unpacked. Longest base wins, so an overlay upper inside
    // a lower does not resolve to the outer mount.
    [[nodiscard]] std::string guest_path_of(std::string_view host) const {
        const Mount* best = nullptr;
        std::size_t best_len = 0;
        bool via_upper = false;
        auto under = [&](std::string_view base) {
            if (base.empty() || host.size() < base.size()) return false;
            if (host.substr(0, base.size()) != base) return false;
            return host.size() == base.size() || host[base.size()] == '/';
        };
        for (const Mount& m : mounts_) {
            if (under(m.upper) && m.upper.size() > best_len) {
                best = &m; best_len = m.upper.size(); via_upper = true;
            }
            if (under(m.host_base) && m.host_base.size() > best_len) {
                best = &m; best_len = m.host_base.size(); via_upper = false;
            }
        }
        if (!best) return {};
        const std::string& base = via_upper ? best->upper : best->host_base;
        std::string rel{host.substr(base.size())};
        if (best->prefix == "/") return rel.empty() ? "/" : rel;
        return rel.empty() ? best->prefix : best->prefix + rel;
    }

    // Is this guest path one of our mount points? umount2 of something that
    // was never mounted is EINVAL, and that is how a program tests whether
    // it holds a mount -- answering 0 to everything told it yes always.
    [[nodiscard]] bool is_mount_point(std::string_view abs) const {
        const std::string n = normalize(abs);
        for (const Mount& m : mounts_)
            if (m.prefix == n) return true;
        return false;
    }

    // Is this absolute path one WE produced -- i.e. already a host-side path
    // inside one of our mount roots, rather than a guest path to translate?
    //
    // Needed because sockaddr translation rewrites the caller's buffer IN
    // PLACE, so a program that reuses one sockaddr for bind and then connect
    // presents an already-translated path the second time. Translating twice
    // doubled the prefix and the two peers never met. Checking against the
    // mount roots makes translation idempotent.
    //
    // Two things this must NOT do, both of which open a confinement hole by
    // leaving a guest path untranslated:
    //   * match on a root mount (host_base "/"), since every absolute path
    //     is "under" it -- that made every socket path look pre-translated.
    //   * match a bare prefix, so "/a/bc" is not treated as inside "/a/b".
    // A root base is therefore skipped outright: a path already translated
    // through it is indistinguishable from a guest path, so there is nothing
    // to detect and the double-translation it would cause is a no-op anyway.
    [[nodiscard]] bool is_host_side_path(std::string_view abs) const {
        auto under = [&](std::string_view base) {
            if (base.size() < 2 || base == "/") return false;   // not a root
            if (abs.size() <= base.size()) return false;
            if (abs.substr(0, base.size()) != base) return false;
            return abs[base.size()] == '/';
        };
        for (const Mount& m : mounts_)
            if (under(m.host_base) || under(m.upper)) return true;
        return false;
    }

    // Normalize an absolute path: collapse "//", resolve "." and "..", drop a
    // trailing slash (except root). Pure lexical (no symlink following).
    //
    // Collapse `.`, `..` and duplicate separators in an absolute guest path.
    //
    // The algorithm lives in abi/wire/path.hpp, host-free, because it was
    // implemented twice: here, and again as normalize_guest() in
    // windows/sys.hpp with a different structure. They agreed on every input
    // I diffed, which is exactly the kind of coincidence that breaks the
    // first time someone fixes an edge case in one copy. Path normalization
    // is also security-relevant -- a `..` that escapes the root is a sandbox
    // hole -- so it gets one implementation and one set of tests.
    [[nodiscard]] static std::string normalize(std::string_view p) {
        return abi::wire::normalize_path(p);
    }

private:
    SocketNs      socket_ns_{SocketNs::filesystem};
    std::uint64_t instance_id_{0};

    struct Mount {
        std::string prefix;      // absolute guest prefix
        std::string host_base;   // real (lower) dir; empty for virtual mounts
        std::string upper;       // writable overlay upper dir; empty = no COW
        Producer    producer;    // set for virtual mounts
    };

    static std::string join_host(std::string_view base, std::string_view rel) {
        std::string p{base};
        if (!rel.empty()) {
            // A base of "/" already ends in the separator; appending another
            // gives "//usr". Harmless to the kernel, but it leaks into
            // host_path and then into every error message and golden trace.
            if (!p.empty() && p.back() != '/') p += '/';
            p += rel;
        }
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
        return follow_from(m, std::move(host), {}, for_write, wi, depth);
    }

    // Continue a chase whose FIRST readlink has already been done by the
    // caller (the overlay read path probes the upper layer anyway, and that
    // probe yields the target). `first` is that target; empty means "read it
    // yourself".
    PathClass resolve_link_target(const Mount& m, std::string host,
                                  std::string first, bool for_write,
                                  WriteIntent wi, int depth) const {
        return follow_from(m, std::move(host), std::move(first), for_write, wi, depth);
    }

    PathClass follow_from(const Mount& m, std::string host, std::string pre,
                          bool for_write, WriteIntent wi, int depth) const {
        for (int hops = 0; hops < 40; ++hops) {
            std::string target;
            if (!pre.empty()) {
                target = std::move(pre);
                pre.clear();
            } else {
                char buf[4096];
                ::ssize_t n = ::readlink(host.c_str(), buf, sizeof buf - 1);
                if (n < 0) {
                    // Not a symlink -- or not THERE, which is a different
                    // thing: a PREFIX component may be the link, and the
                    // kernel walks a path one component at a time. Without
                    // this, `chmod d/f1/bad` with f1 a symlink answered
                    // ENOENT, and a cycle in the prefix never surfaced as
                    // ELOOP.
                    if (errno == ENOENT || errno == ELOOP) {
                        if (auto pre_cls = chase_prefix(m, host, for_write, wi,
                                                        depth, hops))
                            return std::move(*pre_cls);
                    }
                    return PathClass{Realm2::host_backed, std::move(host), Errno::enoent, {}};
                }
                target.assign(buf, static_cast<std::size_t>(n));
            }
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
            // Pick the layer for the NEXT hop with the same fused probe the
            // entry path uses: if the upper holds a symlink we already have
            // its target, so the loop skips a readlink as well as an lstat.
            if (up.empty()) { host = std::move(lo); continue; }
            std::string next;
            switch (probe_link(up.c_str(), next)) {
                case Probe::symlink:
                    host = std::move(up);
                    pre = std::move(next);
                    break;
                case Probe::present:
                    // The probe already proved this is NOT a symlink, so the
                    // chase ends here. Looping would spend another readlink
                    // to be told EINVAL a second time.
                    return PathClass{Realm2::host_backed, std::move(up),
                                     Errno::enoent, {}};
                case Probe::absent:
                    host = std::move(lo);
                    break;
            }
        }
        // The hop budget ran out: this is a symlink LOOP, not a path that
        // resolved. Returning host_backed here made the caller treat the
        // last link in the cycle as a real file -- stat(self-link) succeeded
        // and chmod answered ENOENT, where the kernel says ELOOP.
        return PathClass{Realm2::absent, {}, Errno::eloop, {}};
    }

    // The leaf of `host` could not be read as a link because it is not there.
    // Walk UP its components looking for one that IS a symlink, then resolve
    // from that link's target with the remainder re-attached. That is what a
    // component-by-component walk does, and it is how a cycle in the prefix
    // becomes ELOOP rather than "the leaf is missing".
    //
    // nullopt when no component is a link, so the caller keeps its ENOENT.
    [[nodiscard]] std::optional<PathClass> chase_prefix(
        const Mount& m, const std::string& host, bool for_write, WriteIntent wi,
        int depth, int hops) const {
        // hops counts the chase we are already inside; only the depth and the
        // caller's own 40-hop budget bound recursion here.
        if (hops >= 39 || depth >= 8)
            return PathClass{Realm2::absent, {}, Errno::eloop, {}};
        std::string head = host;
        std::string tail;
        for (;;) {
            const auto slash = head.rfind('/');
            if (slash == std::string::npos || slash == 0) return std::nullopt;
            tail.insert(0, head.substr(slash));
            head.resize(slash);
            char buf[4096];
            const ::ssize_t n = ::readlink(head.c_str(), buf, sizeof buf - 1);
            if (n < 0) {
                // Still not a link. If this component does not exist either,
                // keep walking up; anything else is the real answer.
                if (errno == ENOENT) continue;
                if (errno == ELOOP)
                    return PathClass{Realm2::absent, {}, Errno::eloop, {}};
                return std::nullopt;
            }
            // Found the link. Re-resolve its target (absolute targets are
            // GUEST paths; relative ones sit beside the link) with the tail
            // we stripped put back on.
            std::string target(buf, static_cast<std::size_t>(n));
            std::string next;
            if (!target.empty() && target.front() == '/') {
                next = std::move(target);
            } else {
                next = head.substr(0, head.rfind('/') + 1) + target;
                next = host_to_guest(m, next);
            }
            next += tail;
            return classify_impl(normalize(next), for_write, /*follow=*/true,
                                 wi, depth + 1);
        }
    }

    // Map a HOST path inside this mount back to the guest path it serves, so
    // a resolved link target can re-enter classify_impl (which speaks guest).
    [[nodiscard]] static std::string host_to_guest(const Mount& m,
                                                   const std::string& host) {
        for (const std::string* base : {&m.upper, &m.host_base}) {
            if (base->empty()) continue;
            if (host.size() >= base->size() &&
                host.compare(0, base->size(), *base) == 0) {
                std::string rel = host.substr(base->size());
                std::string out = m.prefix == "/" ? std::string{} : m.prefix;
                if (!rel.empty() && rel.front() != '/') out += '/';
                out += rel;
                return out.empty() ? std::string{"/"} : out;
            }
        }
        return host;
    }

    static bool exists(const char* path) {
        struct ::stat st{};
        return ::lstat(path, &st) == 0;
    }

    // One readlink answers the three questions the overlay read path asks of
    // a candidate layer, where the obvious code asks them with two syscalls
    // (lstat to pick the layer, then readlink to chase the link):
    //
    //   n >= 0        -> exists AND is a symlink; `out` is its target
    //   errno EINVAL  -> exists, is NOT a symlink (the common case)
    //   anything else -> treat as absent (ENOENT, ENOTDIR, EACCES...)
    //
    // Halving the host syscalls here matters because openat/readlinkat/statx
    // are ~33% of a real workload's calls and every one of them classifies a
    // path. ENOTDIR and EACCES deliberately fold into "absent" for LAYER
    // SELECTION only: if the upper can't be traversed, the lower is the right
    // candidate, and the forwarded syscall reports the true error itself.
    enum class Probe { symlink, present, absent };
    static Probe probe_link(const char* path, std::string& out) {
        char buf[4096];
        const ::ssize_t n = ::readlink(path, buf, sizeof buf - 1);
        if (n >= 0) { out.assign(buf, static_cast<std::size_t>(n)); return Probe::symlink; }
        return errno == EINVAL ? Probe::present : Probe::absent;
    }

    static bool is_dir(const char* path) {
        struct ::stat st{};
        return ::stat(path, &st) == 0 && S_ISDIR(st.st_mode);
    }

    // Transparent hash/equality so a directory-union map can be probed with a
    // std::string_view. A readdir name is a char* into the DIR buffer, and the
    // default unordered_map<std::string,...> has to materialize a std::string
    // for every lookup just to throw it away -- one malloc/free per duplicate
    // entry on a union of two populated directories.
    struct SvHash {
        using is_transparent = void;
        [[nodiscard]] std::size_t operator()(std::string_view s) const noexcept {
            return std::hash<std::string_view>{}(s);
        }
    };
    struct SvEq {
        using is_transparent = void;
        [[nodiscard]] bool operator()(std::string_view a,
                                      std::string_view b) const noexcept {
            return a == b;
        }
    };
    // What a merged listing remembers per name: its type, and the real host
    // inode so getdents64 can report a d_ino that matches a later stat().
    struct DirEntryInfo {
        DType         type{DType::regular};
        std::uint64_t ino{0};
    };
    using NameMap = std::unordered_map<std::string, DirEntryInfo, SvHash, SvEq>;

    // Read a real host directory's entries into `seen` (name -> type),
    // skipping "."/".." and not overwriting a name already present (so the
    // caller can merge upper before lower and have upper win). Symlink type is
    // captured (via d_type or an lstat that does NOT follow the link) so the
    // overlay listing reports DT_LNK -- git and other tools probe symlink
    // support by lstat-checking S_ISLNK on a listed entry.
    // Returns true if the directory existed and was enumerated. The caller
    // uses that instead of a separate is_dir() probe: opendir already tells
    // us everything a stat would, so stat'ing first is a wasted syscall.
    // name -> (type, real host inode). The inode rides along so the merged
    // listing can report the same d_ino a later stat() will return.
    static bool merge_dir(const std::string& host_dir, NameMap& seen) {
        ::DIR* d = ::opendir(host_dir.c_str());
        if (!d) return false;
        while (::dirent* e = ::readdir(d)) {
            const std::string_view name{e->d_name};
            if (name == "." || name == "..") continue;
            // Look up by string_view (C++20 heterogeneous lookup) so a name
            // already recorded by the upper layer costs no allocation at
            // all -- on a union of two full directories that is one skipped
            // malloc/free pair per duplicate entry.
            if (seen.find(name) != seen.end()) continue;
            DType t;
            // readdir already carries the inode, so recording it is free.
            std::uint64_t ino = static_cast<std::uint64_t>(e->d_ino);
            const auto dt = dirent_type(e);
            if      (dt == DT_LNK) t = DType::symlink;
            else if (dt == DT_DIR) t = DType::dir;
            else if (dt == DT_REG) t = DType::regular;
            else {                                   // DT_UNKNOWN: lstat it
                struct ::stat ls{};
                std::string full = host_dir;
                full += '/';
                full.append(name);
                if (::lstat(full.c_str(), &ls) == 0) {
                    t = S_ISLNK(ls.st_mode) ? DType::symlink
                      : S_ISDIR(ls.st_mode) ? DType::dir
                                            : DType::regular;
                    ino = static_cast<std::uint64_t>(ls.st_ino);
                } else {
                    t = DType::regular;
                }
            }
            seen.emplace(name, DirEntryInfo{t, ino});
        }
        ::closedir(d);
        return true;
    }

    // Manager-layer repair of a durable pacman DB in the overlay upper, run
    // ONCE at attach while no guest is live. An interrupted transaction can
    // leave two artifacts that poison the NEXT run:
    //   (1) a stale lock  <upper>/var/lib/pacman/db.lck  -> `unable to lock
    //       database` (or the misleading `... unless you are root`);
    //   (2) a half-written local-DB entry  <upper>/var/lib/pacman/local/<pkg>/
    //       with `mtree` but no `desc`  -> `could not open file .../desc` and
    //       `invalid or corrupted package`.
    // Both are exactly what a killed pacman leaves on a real machine, where
    // the fix is `rm db.lck` + reinstall. We do the equivalent, touching ONLY
    // the writable upper (never the pristine lower). A local dir is considered
    // partial iff it has no `desc` file; removing it makes pacman re-create a
    // clean entry on the next install.
    static void repair_pacman_db(const std::string& upper) {
        std::string lck = upper + "/var/lib/pacman/db.lck";
        if (exists(lck.c_str())) ::unlink(lck.c_str());

        std::string localdir = upper + "/var/lib/pacman/local";
        DIR* d = ::opendir(localdir.c_str());
        if (!d) return;
        struct ::dirent* e;
        while ((e = ::readdir(d)) != nullptr) {
            std::string name = e->d_name;
            if (name == "." || name == "..") continue;
            std::string entry = localdir + "/" + name;
            if (!is_dir(entry.c_str())) continue;
            std::string desc = entry + "/desc";
            if (exists(desc.c_str())) continue;      // complete entry
            // Partial: drop the whole dir (best-effort recursive unlink).
            remove_tree(entry);
        }
        ::closedir(d);
    }

    // Best-effort recursive removal of a host directory tree (upper-layer
    // scratch only). Used to prune a half-written pacman DB entry.
    static void remove_tree(const std::string& path) {
        DIR* d = ::opendir(path.c_str());
        if (d) {
            struct ::dirent* e;
            while ((e = ::readdir(d)) != nullptr) {
                std::string name = e->d_name;
                if (name == "." || name == "..") continue;
                std::string child = path + "/" + name;
                if (is_dir(child.c_str())) remove_tree(child);
                else ::unlink(child.c_str());
            }
            ::closedir(d);
        }
        ::rmdir(path.c_str());
    }

    // Ensure `up` exists in the upper layer, copying its bytes up from the
    // read-only lower `lo` on first write and creating parent directories.
    // Best-effort: if the lower doesn't exist this just preps the parent dirs
    // so an O_CREAT open can make the new file in upper.
    static void copy_up(const std::string& up, const std::string& lo) {
        mirror_parents_from_lower(up, lo);
        if (exists(up.c_str())) return;                 // already copied up
        // If the lower is a DIRECTORY, mirror it as a directory in upper (do
        // NOT open+copy it as a regular file — that would leave a bogus file
        // where a mkdir/child-create expects a dir, yielding EEXIST/ENOTDIR).
        // The lower file's own mode, so a copy-up does not silently
        // re-permission it. An executable copied up as 0644 stops being
        // runnable, which is exactly what a package manager's shipped
        // binaries are.
        struct ::stat lst{};
        const bool have_mode = ::stat(lo.c_str(), &lst) == 0;
        const ::mode_t lmode = have_mode ? (lst.st_mode & 07777) : 0;
        if (is_dir(lo.c_str())) {
            if (::mkdir(up.c_str(), have_mode ? lmode : 0755) == 0 && have_mode)
                (void)::chmod(up.c_str(), lmode);   // past umask
            return;
        }
        int in = ::open(lo.c_str(), O_RDONLY | O_CLOEXEC);
        if (in < 0) return;                             // no lower => new file
        int out = ::open(up.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                         have_mode ? lmode : 0644);
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
    // upper twin, so a child create in upper resolves — each with the MODE its
    // counterpart has in the lower layer.
    //
    // The mode is not cosmetic. /root is 750 and /tmp is 1777 in a real
    // rootfs, and mirroring them as 755 both exposes a private directory and
    // breaks the sticky bit every multi-user temp directory relies on. It
    // also makes pacman complain -- "directory permissions differ on /etc/,
    // filesystem: 777 package: 755" -- because it compares what it finds
    // against what the package says.
    static void mirror_parents_from_lower(const std::string& up,
                                          const std::string& lo) {
        // Walk `up`'s ancestor prefixes; for each, mkdir it in upper. We can't
        // know the exact lower/upper base split here, but creating each
        // ancestor of `up` bottom-up is sufficient and idempotent.
        std::size_t slash = up.find_last_of('/');
        if (slash == std::string::npos || slash == 0) return;
        const std::size_t lo_slash = lo.find_last_of('/');
        const std::string lo_dir =
            lo_slash == std::string::npos ? std::string{} : lo.substr(0, lo_slash);
        std::string dir = up.substr(0, slash);
        for (std::size_t i = 1; i <= dir.size(); ++i) {
            if (i != dir.size() && dir[i] != '/') continue;
            std::string sub = dir.substr(0, i);
            // The lower counterpart shares the TAIL of the path, so take the
            // same number of trailing components off the lower directory.
            ::mode_t mode = 0755;
            if (!lo_dir.empty()) {
                const std::size_t tail = dir.size() - i;
                if (tail <= lo_dir.size()) {
                    struct ::stat st{};
                    const std::string lsub = lo_dir.substr(0, lo_dir.size() - tail);
                    if (::stat(lsub.c_str(), &st) == 0 && S_ISDIR(st.st_mode))
                        mode = st.st_mode & 07777;
                }
            }
            if (::mkdir(sub.c_str(), mode) != 0) continue;   // EEXIST: leave it
            // mkdir masks the mode through umask, and the sticky/setgid bits
            // never survive it, so set them explicitly on the one we created.
            if ((mode & ~static_cast<::mode_t>(0777)) != 0 || (mode & 0077) != 0)
                (void)::chmod(sub.c_str(), mode);
        }
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
    // Per-process current directory (see set_current_pid/inherit_cwd). cur_pid_
    // is mutable so a const cwd()/absolutize path can select the active pid.
    mutable std::unordered_map<std::int32_t, std::string> cwds_{};
    mutable std::int32_t cur_pid_{1};   // root/init
    // The pid whose cwds_ record set_current_pid has already confirmed, so
    // the common "same task as last syscall" case costs one compare. Any
    // path that CLEARS or re-seeds cwds_ must reset this to a pid that can
    // never match (0 is not a valid guest pid).
    mutable std::int32_t seeded_pid_{0};
    // cwd for a pid with no record and no recorded parent: "/" for the root
    // process, the parent's cwd in a forked child (import_process_state).
    std::string inherited_cwd_{"/"};
    // The SUPERVISOR's cwd (not any guest's), for absolute_host().
    std::string host_cwd_;
    // The cwd of the most recently seen task, used to seed a task whose parent
    // link is not known yet (see set_current_pid). Mutable for the same reason
    // cwds_ is: set_current_pid is const because it only updates bookkeeping.
    mutable std::string last_cwd_{"/"};
    // Per guest pid; see FdTable. mutable for the same reason cur_pid_ is:
    // set_current_pid() is const and seeds a child's table on first sight.
    mutable std::unordered_map<std::int32_t, FdTable> fd_tables_;
    // Darwin's fork lands in a fresh process before the child's guest pid is
    // known; import_process_state parks the fds here for the first pid seen.
    mutable FdTable inherited_fds_;
    mutable bool    have_inherited_fds_{false};
    mutable std::int32_t last_pid_{0};
    MetaStore meta_{};
    bool meta_attached_{false};
    bool is_root_{true};

    // WHITEOUTS. Removing a file that lives ONLY in the read-only lower layer
    // must not touch the pristine rootfs. Instead we record the guest path
    // here so it reads back as absent (classify) and is filtered from
    // directory listings (overlay_dir_union). A re-create at the same path
    // (copy_leaf/parents_only classify, or an open O_CREAT) clears the
    // whiteout. Journaled to `.linuxity-whiteout` in the upper layer so the
    // removal persists across runs, exactly like copied-up files and meta.
    mutable std::unordered_set<std::string, SvHash, SvEq> whiteouts_;
    std::string whiteout_journal_;

public:
    // Drop a whiteout because the path really exists again (an upper-layer
    // file now shadows the lower one). Safe to call for a path that was
    // never deleted -- the common case, so it checks the set first.
    void clear_whiteout_if_any(const std::string& guest_path) const {
        if (!whiteouts_.empty()) clear_whiteout(guest_path);
    }

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

    // Probed once per entry while enumerating a directory, so it must not
    // allocate: the transparent hash/equality pair lets an unordered_set of
    // std::string be looked up by std::string_view directly, instead of
    // materializing a std::string per call just to throw it away.
    [[nodiscard]] bool is_whiteout(std::string_view guest_path) const {
        return whiteouts_.find(guest_path) != whiteouts_.end();
    }

private:
    std::size_t load_whiteouts() {
        if (whiteout_journal_.empty()) return 0;
        std::FILE* fp = std::fopen(whiteout_journal_.c_str(), "r");
        if (!fp) return 0;
        std::size_t lines = 0;
        char line[4096];
        while (std::fgets(line, sizeof line, fp)) {
            ++lines;
            std::string s{line};
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
                s.pop_back();
            if (s.empty()) continue;
            if (s.front() == '!') whiteouts_.erase(s.substr(1)); // un-whiteout
            else                  whiteouts_.insert(s);
        }
        std::fclose(fp);
        return lines;
    }
    // The whiteout journal is append-only too (100k lines for 4.8k live
    // entries after a few upgrades). Rewrite it to the live set, atomically.
    void rewrite_whiteouts() {
        const std::string tmp = whiteout_journal_ + ".tmp";
        std::FILE* fp = std::fopen(tmp.c_str(), "w");
        if (!fp) return;
        for (const auto& w : whiteouts_) std::fprintf(fp, "%s\n", w.c_str());
        if (std::fclose(fp) == 0) std::rename(tmp.c_str(), whiteout_journal_.c_str());
        else std::remove(tmp.c_str());
    }
};

} // namespace lx::kernel
