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
#include "linuxity/abi/wire/dirent64.hpp"
#include "linuxity/abi/result.hpp"
#include "linuxity/abi/types.hpp"
#include "linuxity/kernel/link_table.hpp"
#include "linuxity/kernel/meta_store.hpp"
#include "linuxity/kernel/socket_ns.hpp"

#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include "linuxity/host/win_posix.hpp"
#include "linuxity/host/dirent_type.hpp"
#include "linuxity/host/long_path.hpp"
#include "linuxity/kernel/fork_state.hpp"
#include "linuxity/kernel/journal_tail.hpp"
#include "linuxity/kernel/fsnotify.hpp"

#include <cstdint>
#include <algorithm>
#include <cstring>
#include <functional>
#include <map>
#include <set>
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

    // The node's owner, when it isn't root: everything under /proc/<pid> is
    // the process's (its effective uid/gid), which is how ps and top learn
    // whose a process is. Global ids; the reader's namespace maps them.
    std::optional<std::uint32_t> uid, gid;
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
            links_.attach(upper);
            meta_attached_ = true;
            if (fsnotify_emulated_) fsnotify_.attach(upper + "/" + std::string{fsnotify::kDirLeaf});
            whiteout_journal_ = upper + "/.linuxity-whiteout";
            whiteout_tail_.set_path(whiteout_journal_);
            const std::size_t wl = load_whiteouts();
            if (is_root_ && wl > 1024 && wl > whiteouts_.size() * 4) rewrite_whiteouts();
            if (is_root_) repair_pacman_db(upper);
        }
        mounts_.push_back(Mount{std::move(prefix), std::move(host_base),
                                std::move(upper), {}});
        ++layout_version_;
    }
    // A fork child (a guest process started by another guest process) must
    // not do root-only hygiene. Set before the first mount_host.
    void set_fork_child(bool child) noexcept { is_root_ = !child; }
    // Every guest process is its own linuxity with its own copy of this
    // namespace (macOS). Then deletions another process made must be read
    // before a lookup trusts the in-memory whiteout set -- one stat of the
    // journal when nothing changed. A host where all guest processes share
    // one namespace (Linux) needs none of it.
    void set_shared_with_other_processes(bool on) noexcept { follow_journals_ = on; }

    // The files linuxity keeps at the top of an upper layer: never part of
    // the guest's tree, neither in a listing nor by name. The ONE list.
    [[nodiscard]] static constexpr std::array<std::string_view, 5> internal_leaves() noexcept {
        return {MetaStore::journal_leaf(), LinkTable::journal_leaf(), fsnotify::kDirLeaf,
                std::string_view{".linuxity-whiteout"}, std::string_view{".linuxity-meta.ok"}};
    }
    [[nodiscard]] bool is_internal_path(std::string_view abs) const noexcept {
        if (abs.size() < 2 || abs[0] != '/') return false;
        abs.remove_prefix(1);
        const auto slash = abs.find('/');
        const std::string_view first = abs.substr(0, slash);
        for (std::string_view l : internal_leaves()) if (first == l) return meta_attached_;
        return false;
    }
    // The host can't report named directory events (kqueue), so linuxity
    // keeps inotify itself: the dispatcher writes every path event to one
    // log per tree (kernel/fsnotify.hpp). Set before the first mount_host.
    void set_fsnotify_emulated(bool on) noexcept { fsnotify_emulated_ = on; }
    [[nodiscard]] fsnotify::Hub& fsnotify() const noexcept { return fsnotify_; }

    // The shadow permission/ownership store (per-path mode/uid/gid overlay).
    // The dispatcher records guest chmod/chown here and overlays it back onto
    // host stat results, so a uid-0 world round-trips coherently.
    [[nodiscard]] MetaStore& meta() noexcept { return meta_; }
    [[nodiscard]] const MetaStore& meta() const noexcept { return meta_; }

    // Emulated hardlinks (see link_table.hpp). classify() resolves aliases,
    // and the dispatcher's link/unlink/rename paths maintain the table.
    [[nodiscard]] LinkTable& links() noexcept { return links_; }
    [[nodiscard]] const LinkTable& links() const noexcept { return links_; }

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
        ++layout_version_;
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

    // A successful rename of `from` to `to`: every current directory and
    // every fd path at or below `from` now names the moved object. The
    // kernel tracks both by inode, so `cd a; mv ../a ../b; pwd` says b, and
    // an *at call on a dirfd keeps working after its directory moves.
    void moved(const std::string& from, const std::string& to) {
        if (from.empty() || from == "/" || from == to) return;
        auto fix = [&](std::string& p) {
            if (p.size() >= from.size() && p.compare(0, from.size(), from) == 0 &&
                (p.size() == from.size() || p[from.size()] == '/'))
                p = to + p.substr(from.size());
        };
        for (auto& [pid, c] : cwds_) fix(c);
        fix(last_cwd_);
        for (auto& [pid, t] : fd_tables_)
            for (auto& [fd, p] : t.paths) fix(p);
        for (auto& [fd, p] : inherited_fds_.paths) fix(p);
    }

    // How AF_UNIX sockets are named on this host. Filesystem everywhere POSIX
    // lets us create a socket node; abstract where it does not (Android's
    // SELinux denies the bind in every directory an app can write). Probed
    // once at startup rather than assumed, because guessing wrong means every
    // socket-using guest daemon fails with EACCES.
    [[nodiscard]] SocketNs socket_ns() const noexcept { return socket_ns_; }
    void set_socket_ns(SocketNs ns) noexcept { socket_ns_ = ns; }
    // The host refuses mkfifo (Android's SELinux, everywhere a shell can
    // write), so the dispatcher emulates named FIFOs over real pipes.
    [[nodiscard]] bool fifos_emulated() const noexcept { return fifos_emulated_; }
    void set_fifos_emulated(bool on) noexcept { fifos_emulated_ = on; }

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
    // Move pid `from`'s cwd and fd table to `to` (init gets its host pid).
    void rekey_pid(std::int32_t from, std::int32_t to) {
        if (from == to) return;
        if (auto n = cwds_.extract(from)) { n.key() = to; cwds_.insert(std::move(n)); }
        if (auto n = fd_tables_.extract(from)) { n.key() = to; fd_tables_.insert(std::move(n)); }
        if (cur_pid_ == from) cur_pid_ = to;
        if (seeded_pid_ == from) seeded_pid_ = to;
    }
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
            // run. The fallback used to be inherited_cwd_, which only the
            // macOS fresh-process fork path ever assigned, so on Linux it
            // stayed "/" forever and
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
    // On fork/clone the child inherits a COPY of the parent's cwd and of its
    // fd bindings. Both are taken here, at fork time: set_current_pid only
    // copies when the child has no cwd record yet, and this makes one.
    void inherit_cwd(std::int32_t child, std::int32_t parent) {
        auto it = cwds_.find(parent);
        cwds_[child] = (it != cwds_.end()) ? it->second : std::string{"/"};
        // a child that already ran has its own (copied at its first call)
        if (!fd_tables_.count(child))
            if (auto fp = fd_tables_.find(parent); fp != fd_tables_.end())
                fd_tables_[child] = fp->second.copy_for_fork();
        if (child == seeded_pid_) seeded_pid_ = 0;
    }
    // Dropping a pid's record must also drop the "already seeded" claim:
    // the kernel recycles pids, and a new task reusing this number has to
    // re-seed from ITS parent rather than skip straight past the check.
    void forget_pid(std::int32_t pid) {
        cwds_.erase(pid);
        fd_tables_.erase(pid);
        if (pid == seeded_pid_) seeded_pid_ = 0;
    }
    [[nodiscard]] bool cwd_known(std::int32_t pid) const noexcept { return cwds_.count(pid) != 0; }
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
        if (!path.empty() && path.front() == '/') return resolve_dotdot(path);
        std::string base = dir_path.empty() ? std::string{cwd()} : std::string{dir_path};
        if (base.empty()) base = "/";
        if (base.back() != '/') base += '/';
        base += path;
        return resolve_dotdot(base);
    }

    // normalize(), except ".." after a symlink goes to the parent of the
    // link's TARGET, as in the kernel. Popping a component that isn't a
    // symlink is the same either way, so only those are checked.
    [[nodiscard]] std::string resolve_dotdot(std::string_view p, int depth = 0) const {
        if (p.find("..") == std::string_view::npos) return normalize(p);
        std::string cur;   // "" means "/"
        std::size_t i = 0;
        while (i < p.size()) {
            while (i < p.size() && p[i] == '/') ++i;
            if (i >= p.size()) break;
            std::size_t j = p.find('/', i);
            if (j == std::string_view::npos) j = p.size();
            const std::string_view c = p.substr(i, j - i);
            i = j;
            if (c == ".") continue;
            if (c != "..") { cur += '/'; cur += c; continue; }
            if (cur.empty()) continue;   // "/.." is "/"
            const std::string phys = physical_if_symlink(cur, depth);
            if (!phys.empty()) cur = phys == "/" ? std::string{} : phys;
            cur.resize(cur.rfind('/'));
        }
        return cur.empty() ? std::string{"/"} : cur;
    }

    // The guest path `abs` names once a final symlink chain is followed
    // (itself if it isn't a link). For keying per-file state on the file,
    // not on one of the names that point at it.
    [[nodiscard]] std::string resolve_links(const std::string& abs) const {
        std::string t = physical_if_symlink(abs);
        return t.empty() ? abs : t;
    }

    // If guest path `abs` is a symlink, the guest path it finally resolves
    // to; otherwise "". Targets are guest paths (an absolute rootfs link
    // means the guest's root), so this is walked here, not by the host.
    [[nodiscard]] std::string physical_if_symlink(const std::string& abs, int depth = 0) const {
#if defined(_WIN32)
        (void)abs; (void)depth;
        return {};
#else
        if (depth > 40) return {};   // ELOOP: let the host report it
        const PathClass lc = classify(abs, false, /*follow=*/false);
        if (lc.realm != Realm2::host_backed || lc.host_path.empty()) return {};
        char tgt[PATH_MAX];
        const ::ssize_t n = ::readlink(lc.host_path.c_str(), tgt, sizeof tgt - 1);
        if (n <= 0) return {};   // not a symlink
        const std::string_view t{tgt, static_cast<std::size_t>(n)};
        std::string next = t.front() == '/'
            ? std::string{t}
            : abs.substr(0, abs.rfind('/')) + "/" + std::string{t};
        next = resolve_dotdot(next, depth + 1);
        const std::string deeper = physical_if_symlink(next, depth + 1);
        return deeper.empty() ? next : deeper;
#endif
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
        if (follow_journals_) catch_up_whiteouts();
        PathClass pc = classify_impl(abs, for_write, follow, wi, 0);
        // a write through a read-only mount; device nodes are exempt, as in
        // the kernel
        if (for_write && pc.realm == Realm2::host_backed && read_only(abs)) {
            struct ::stat st{};
            const bool special = ::lstat(pc.host_path.c_str(), &st) == 0 &&
                                 (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode) ||
                                  S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode));
            if (!special) return PathClass{Realm2::absent, {}, Errno::erofs, {}};
        }
        // An emulated hardlink: the name is a placeholder, the data lives at
        // the backing. Everything except removal acts on the backing, so
        // open/stat/chmod/truncate on either name hit one inode. Removal acts
        // on the NAME, and the dispatcher handles it (see LinkTable).
        if (!links_.empty() && pc.realm == Realm2::host_backed &&
            wi != WriteIntent::remove)
            if (const std::string* b = links_.backing_of(pc.host_path))
                pc.host_path = *b;
        return pc;
    }

    // classify() WITHOUT alias resolution: the host path of the NAME. For the
    // operations that act on a name rather than the file behind it -- rename
    // moves a name, and must move a hardlink alias's placeholder, not the
    // shared data it points at.
    [[nodiscard]] PathClass classify_name(std::string_view abs,
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
        // linuxity's own files at the top of the upper layer are not part of
        // the guest's tree: absent by name, as in a listing
        if (is_internal_path(abs)) return PathClass{Realm2::absent, {}, Errno::enoent, {}};
        const Mount* m = deepest(abs);
        if (!m) return PathClass{Realm2::absent, {}, Errno::enoent, {}};
        if (m->producer) {
            auto vf = run_producer(*m, abs);
            if (!vf) {
                // As the kernel's walk: if an existing ancestor is not a
                // directory, the answer is ENOTDIR, not ENOENT.
                Errno e = vf.error();
                if (e == Errno::enoent && depth == 0) {
                    std::string_view up = abs;
                    while (up.size() > m->prefix.size()) {
                        const std::size_t cut = up.rfind('/');
                        if (cut == std::string_view::npos || cut == 0) break;
                        up = up.substr(0, cut);
                        const PathClass pc = classify_impl(up, false, true, wi, depth + 1);
                        if (pc.realm == Realm2::absent) continue;
                        bool dir = false;
                        if (pc.realm == Realm2::host_backed)
                            dir = is_dir(pc.host_path.c_str());
                        else if (auto pv = run_producer(*m, up))
                            dir = pv->is_dir;
                        if (!dir) e = Errno::enotdir;
                        break;
                    }
                }
                return PathClass{Realm2::absent, {}, e, {}};
            }
            // A device node backed by a real host device (/dev/null, ...):
            // resolve to the host path so open/read/write/mmap ride the true
            // character device with native semantics.
            if (!vf->redirect_host.empty()) {
                // /sys/class/hwmon/hwmon4 is a host symlink into /sys/devices;
                // a following lookup lands on its target, kept inside /sys or
                // /dev so a redirect can't lead the guest elsewhere. Never for
                // /proc: /proc/self there is linuxity, not the guest.
                if (follow && (vf->redirect_host.starts_with("/sys/") ||
                               vf->redirect_host.starts_with("/dev/")))
                    if (char* rp = ::realpath(vf->redirect_host.c_str(), nullptr)) {
                        const std::string_view r{rp};
                        if (r.starts_with("/sys/") || r.starts_with("/dev/")) vf->redirect_host = rp;
                        std::free(rp);
                    }
                return PathClass{Realm2::host_backed,
                                 std::move(vf->redirect_host), Errno::enoent, {}};
            }
            // A virtual SYMLINK with a RELATIVE target (/sys/class/net/lo ->
            // ../../devices/virtual/net/lo): a following lookup lands on the
            // target, like any link. Absolute ones (/dev/stdin ->
            // /proc/self/fd/0) name /proc magic links that only the
            // dispatcher can resolve, so it keeps doing that itself.
            if (follow && !vf->symlink_target.empty() && vf->symlink_target.front() != '/' &&
                vf->symlink_target != "(proc-link)") {
                if (depth >= 40) return PathClass{Realm2::absent, {}, Errno::eloop, {}};
                const std::string next = normalize(
                    std::string{abs.substr(0, abs.rfind('/') + 1)} + vf->symlink_target);
                return classify_impl(next, for_write, true, wi, depth + 1);
            }
            return PathClass{Realm2::virtual_file, {}, Errno::enoent,
                             std::string{abs}};
        }
        std::string_view rel = abs;
        rel.remove_prefix(m->prefix == "/" ? 0 : m->prefix.size());
        while (!rel.empty() && rel.front() == '/') rel.remove_prefix(1);

        // A path goes where the merged view says its directory is. When a
        // directory on the way is a symlink (merged-/usr: /lib -> usr/lib),
        // resolve it first and start over from the target, as a kernel
        // would. Otherwise a write's copy-up makes a real upper/lib that
        // hides the image's symlink (dpkg then says the system isn't
        // merged-/usr), and a read through /lib looks only in the image
        // and misses what was installed into /usr/lib since. Bind mounts
        // too: left to the host, `ln -s /etc /tmp/x` made /tmp/x/passwd the
        // HOST's passwd. Only the parent dirs: the last component is the
        // caller's business (O_NOFOLLOW, unlink, rename all differ).
        if (depth < 8) {
            // Directories rarely become symlinks, so each answer is kept
            // until the guest writes anything or a mount changes (a write
            // is where a dir could be replaced by a link). Without the
            // cache this was a readlink per path component on every
            // stat and open.
            if (for_write) { dirlink_cache_.clear(); ++dirs_version_; }
            std::size_t end = 0;
            bool clean = true;
            bool parent_in_upper = !m->upper.empty() && rel.find('/') == std::string_view::npos;
            while ((end = rel.find('/', end)) != std::string_view::npos) {
                const std::string_view sub = rel.substr(0, end);
                const std::string guest = (m->prefix == "/" ? std::string{} : m->prefix) + "/" + std::string{sub};
                std::string target;
                Probe p;
                std::string key = guest;
                key.push_back('\0');
                key += m->upper;
                key.push_back('\0');
                key += m->host_base;
                bool in_upper = false;
                if (auto it = dirlink_cache_.find(key); it != dirlink_cache_.end()) {
                    p = it->second.first;
                    target = it->second.second;
                    in_upper = it->second.third;
                } else {
                    p = m->upper.empty() ? Probe::absent : probe_link(join_host(m->upper, sub).c_str(), target);
                    in_upper = p != Probe::absent;
                    if (p == Probe::absent) {
                        if (!m->upper.empty() && !whiteouts_.empty() && is_whiteout(guest)) p = Probe::notdir;   // stop here
                        else p = probe_link(join_host(m->host_base, sub).c_str(), target);
                    }
                    if (dirlink_cache_.size() > 65536) dirlink_cache_.clear();
                    dirlink_cache_.emplace(std::move(key), DirProbe{p, target, in_upper});
                }
                parent_in_upper = in_upper;
                if (p == Probe::absent || p == Probe::notdir) { clean = false; break; }
                if (p == Probe::symlink) {
                    const std::string rest{rel.substr(end + 1)};
                    const std::string base = target.starts_with('/')
                        ? target : guest.substr(0, guest.rfind('/') + 1) + target;
                    return classify_impl(normalize(base + "/" + rest), for_write, follow, wi, depth + 1);
                }
                ++end;
            }
            // every directory on the way is a real one: the in-guest handler
            // may answer for names in the leaf's parent
            if (clean && on_clean_dir_ && depth == 0) {
                const std::size_t cut = abs.rfind('/');
                if (cut != std::string_view::npos && cut > 0)
                    on_clean_dir_(abs.substr(0, cut), m->upper.empty() || parent_in_upper);
            }
        }

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
                // Anything mirrored or copied up with extra owner access for
                // linuxity's sake still has to LOOK like it shipped: record
                // the real mode against each entry's guest path. `up` and
                // `abs` end in the same relative path, so an entry that sits
                // N characters before the end of `up` is N before the end of
                // `abs` too.
                Widened widened;
                // A path deleted in this overlay (whited out) is NEW when it
                // is written again: copying the lower file up would bring the
                // deleted contents back (`rm f; touch f` showed the old bytes,
                // and `rm f; echo x >> f` appended to them).
                const bool deleted = !whiteouts_.empty() && is_whiteout(abs);
                if (wi == WriteIntent::parents_only || deleted)
                    mirror_parents_from_lower(up, lo, &widened);
                else
                    copy_up(up, lo, &widened);
                for (const auto& [tail, real] : widened)
                    if (tail <= abs.size())
                        meta_.set_mode(std::string{abs.substr(0, abs.size() - tail)}, real);
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
        return run_producer(*m, abs);
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
        if (follow_journals_) catch_up_whiteouts();
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
        std::vector<std::string_view> order;           // readdir order, upper then lower (as overlayfs)
        const bool had_up = merge_dir(up, seen, &order);   // upper first (wins)
        const bool had_lo = merge_dir(lo, seen, &order);
        if (!had_up && !had_lo) return out;            // neither layer exists
        // The shadow-metadata journal is an implementation file in the upper
        // layer, not part of the guest tree — never let it show up in a listing.
        // Erase via find(): transparent erase(K&&) is C++23, but a transparent
        // find() plus erase(iterator) is C++20 and allocates nothing either.
        for (std::string_view hide : internal_leaves())
            if (auto it = seen.find(hide); it != seen.end()) it->second.hidden = true;
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
            for (auto it = seen.begin(); it != seen.end(); ++it) {
                child.resize(child_base);
                child += it->first;
                // is_whiteout is an in-memory set probe; exists() is a host
                // syscall. Test the cheap one first and let && skip the stat
                // for the overwhelming majority of entries, which are not
                // whited out at all.
                if (!is_whiteout(child)) continue;
                up_child.resize(up_base);
                up_child += it->first;
                if (!exists(up_child.c_str())) it->second.hidden = true;
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
        for (const std::string_view name : order)
            if (auto it = seen.find(name); it != seen.end() && !it->second.hidden)
                out.push_back({it->first, it->second.type, it->second.ino});
        return out;
    }

    // Materialize `dst` from an OPEN FD's contents.
    //
    // The O_TMPFILE case on a host that refuses link(2): the file exists
    // only as a descriptor, with no name to alias, so the new name gets a
    // copy of what has been written so far. glibc's sem_open writes the
    // semaphore's state into the temp before linking it, so that is enough
    // for the one real user.
    [[nodiscard]] Errno emulate_link_from_fd(int fd,
                                             const std::string& dst) const {
        struct ::stat st{};
        if (::fstat(fd, &st) != 0) return static_cast<Errno>(errno);
        struct ::stat dt{};
        if (::lstat(dst.c_str(), &dt) == 0) return Errno::eexist;
        const int out = ::open(dst.c_str(),
                               O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                               st.st_mode & 07777);
        if (out < 0) return static_cast<Errno>(errno);
        // Read from offset 0 without disturbing the caller's file position:
        // the guest still holds this fd and will keep using it.
        char buf[65536];
        ::off_t off = 0;
        for (;;) {
            const ssize_t n = ::pread(fd, buf, sizeof buf, off);
            if (n == 0) break;
            if (n < 0 || ::write(out, buf, static_cast<std::size_t>(n)) != n) {
                const int e = errno;
                ::close(out);
                ::unlink(dst.c_str());
                return static_cast<Errno>(e);
            }
            off += n;
        }
        ::close(out);
        (void)::chmod(dst.c_str(), st.st_mode & 07777);
        return Errno::ok;
    }

    // -- Guest fd table ----------------------------------------------------
    // Records the guest path bound to a real (forwarded) fd, so readlinkat,
    // getdents, and fd-relative openat can recover the path. The fd number is
    // the REAL host fd the child holds (redirect/inject both yield real fds).
    void bind_fd(int fd, std::string abs) { fds().paths[fd] = std::move(abs); }
    void unbind_fd(int fd) { auto& t = fds(); t.paths.erase(fd); t.dirs.erase(fd); t.ll_layers.erase(fd); }
    // How many landlock layers the caller had when it opened `fd` (0 if it
    // had none, or we never saw the open). The file keeps those rights.
    void set_fd_ll_layers(int fd, std::uint32_t n) { if (n) fds().ll_layers[fd] = n; }
    [[nodiscard]] std::uint32_t fd_ll_layers(int fd) const {
        const auto& t = fds();
        auto it = t.ll_layers.find(fd);
        return it == t.ll_layers.end() ? 0 : it->second;
    }
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
        if (auto it = t.ll_layers.find(from); it != t.ll_layers.end())
            t.ll_layers[to] = it->second;
        else
            t.ll_layers.erase(to);
    }
    [[nodiscard]] std::string_view path_of_fd(int fd) const {
        const auto& t = fds();
        auto it = t.paths.find(fd);
        return it == t.paths.end() ? std::string_view{} : std::string_view{it->second};
    }
    // A directory fd's listing state: 0 none, 1 an overlay union not built
    // yet, 2 a listing being served (built union or virtual entries).
    [[nodiscard]] int dir_state(int fd) const {
        const auto& t = fds();
        auto it = t.dirs.find(fd);
        if (it == t.dirs.end()) return 0;
        return it->second.lazy.empty() ? 2 : 1;
    }
    // The same, for process `pid` rather than the current one.
    [[nodiscard]] std::string_view path_of_fd_in(std::int32_t pid, int fd) const {
        auto t = fd_tables_.find(pid);
        if (t == fd_tables_.end()) return {};
        auto it = t->second.paths.find(fd);
        return it == t->second.paths.end() ? std::string_view{} : std::string_view{it->second};
    }
    [[nodiscard]] int dir_state_in(std::int32_t pid, int fd) const {
        auto t = fd_tables_.find(pid);
        if (t == fd_tables_.end()) return 0;
        auto it = t->second.dirs.find(fd);
        if (it == t->second.dirs.end()) return 0;
        return it->second.lazy.empty() ? 2 : 1;
    }
    // the in-guest handler was serving fd's merged listing and stopped at
    // byte cookie `cookie`: build the union here and stand at the same spot
    // (the first entry starting at or after it, as lseek does).
    void seek_dir_in(std::int32_t pid, int fd, std::uint64_t cookie) {
        auto t = fd_tables_.find(pid);
        if (t == fd_tables_.end()) return;
        auto it = t->second.dirs.find(fd);
        if (it == t->second.dirs.end()) return;
        DirStream& ds = it->second;
        if (!ds.lazy.empty()) {
            std::string abs = std::move(ds.lazy);
            ds.lazy.clear();
            ds.entries = overlay_dir_union(abs);
        }
        std::uint64_t cur = 0;
        std::size_t idx = 0;
        for (; idx < ds.entries.size() && cur < cookie; ++idx)
            cur += abi::wire::dirent_reclen(ds.entries[idx].name.size());
        ds.pos = idx;
        ds.byte_off = cur;
    }
    // The upper-layer host path of `abs` (empty if its mount has no upper).
    [[nodiscard]] std::string upper_path_of(std::string_view abs) const {
        const Mount* m = deepest(abs);
        if (!m || m->upper.empty()) return {};
        std::string_view rel = abs;
        rel.remove_prefix(m->prefix == "/" ? 0 : m->prefix.size());
        while (!rel.empty() && rel.front() == '/') rel.remove_prefix(1);
        return join_host(m->upper, rel);
    }
    // Is `abs` in a mount with an upper layer (or a virtual one)? Its listing
    // may be a merge, not one host dir's.
    [[nodiscard]] bool is_overlay_path(std::string_view abs) const {
        const Mount* m = deepest(abs);
        return !m || m->producer || !m->upper.empty();
    }
    // the in-guest handler opened, dup'd or closed `fd` in process `pid`:
    // make the table say what the fd is now, as note_opened_fd would have
    // for a read-only open of a host path. `path` null means closed.
    void apply_guest_fd(std::int32_t pid, int fd, const std::string* path, bool lazy_dir) {
        // A process the dispatcher hasn't served yet gets its table (a copy
        // of its parent's) at its first call; making one here would block
        // that. Its first trapped call comes after this, and re-seeds the
        // fd map from that table.
        auto it = fd_tables_.find(pid);
        if (it == fd_tables_.end()) return;
        auto& t = it->second;
        t.paths.erase(fd);
        t.dirs.erase(fd);
        t.ll_layers.erase(fd);
        if (!path) return;
        t.paths[fd] = *path;
        if (lazy_dir) t.dirs[fd] = DirStream{{}, 0, *path, 0};
    }
    // Every fd with a recorded path in process `pid` (no change of the
    // current pid, which has side effects: a first sight seeds the cwd).
    template <class F> void for_each_fd_path_in(std::int32_t pid, F&& f) const {
        auto t = fd_tables_.find(pid);
        if (t == fd_tables_.end()) return;
        for (const auto& [fd, p] : t->second.paths) f(fd, p);
    }

    // -- Per-process state that a fork must carry to the child --------------
    // A backend that forks by spawning a FRESH process (macOS: see
    // runtime/darwin/fork.hpp) rebuilds the mounts from the same command line,
    // but the dynamic state -- this process's cwd and which guest path each
    // fd names -- exists only in the parent. These two functions are the
    // complete list; a length-prefixed byte format keeps them trivially
    // forward-compatible.
    [[nodiscard]] std::string export_process_state() const {
        fork_state::Writer w;
        w.str(cwd());
        const auto& paths = fds().paths;
        w.pod(static_cast<std::uint32_t>(paths.size()));
        for (const auto& [fd, path] : paths) {
            w.pod(fd);
            w.str(path);
        }
        return w.take();
    }
    void import_process_state(std::string_view in) {
        fork_state::Reader r{in};
        // The fork child is a FRESH host process: its cwd table holds no
        // record for its own pid or its parent's, so its first syscall's
        // set_current_pid() takes the fallback, last_cwd_. (Storing via
        // set_cwd() here filed it under the default cur_pid_ 1 instead --
        // every relative path in a forked child, e.g. `g++ hey.cpp` -> cc1,
        // resolved against "/". And when the fallback moved from
        // inherited_cwd_ to last_cwd_, a write to inherited_cwd_ alone
        // stopped reaching anything: every macOS child started at "/".)
        // So the parent's cwd IS the fallback; there is no second copy.
        last_cwd_ = normalize(r.str());
        if (last_cwd_.empty()) last_cwd_ = "/";
        cwds_.clear();
        seeded_pid_ = 0;          // no record survives the clear
        // The child's pid is not known yet, so park the inherited fds; the
        // child's first set_current_pid() adopts them (see inherited_fds_).
        fd_tables_.clear();
        inherited_fds_ = FdTable{};
        for (std::uint32_t i = 0, n = r.pod<std::uint32_t>(); i < n && r.more(); ++i) {
            const int fd = r.pod<int>();
            inherited_fds_.paths[fd] = r.str();
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
        std::unordered_map<int, std::uint32_t> ll_layers;   // see fd_ll_layers
        // A fork copies the fd table but each copy has its OWN file offset
        // for a virtual directory stream, so the child starts fresh streams.
        [[nodiscard]] FdTable copy_for_fork() const {
            FdTable t;
            t.paths = paths;
            t.ll_layers = ll_layers;
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
    // statx's stx_mnt_id for a guest path: which of OUR mounts holds it,
    // and whether the path is that mount's root (STATX_ATTR_MOUNT_ROOT).
    // Path walkers (systemd's chase, so libudev and lsusb) need both.
    struct MountOf { std::uint64_t id{0}; bool root{false}; };
    [[nodiscard]] MountOf mount_of(std::string_view abs) const {
        const Mount* m = deepest(abs);
        if (!m) return {};
        const auto idx = static_cast<std::uint64_t>(m - mounts_.data());
        return {idx + 21, abs == m->prefix};
    }
    // Every host directory that backs guest path `abs`: an overlay's upper
    // and lower, a bind's one dir. Empty for our virtual trees. A sandbox
    // rule on the guest path has to name all of them, or a write that
    // copies up lands where the rule doesn't reach.
    [[nodiscard]] std::vector<std::string> host_layers(std::string_view abs) const {
        std::vector<std::string> out;
        const Mount* m = deepest(abs);
        if (!m || m->producer) return out;
        std::string_view rel = abs;
        rel.remove_prefix(m->prefix == "/" ? 0 : m->prefix.size());
        while (!rel.empty() && rel.front() == '/') rel.remove_prefix(1);
        if (!m->upper.empty()) out.push_back(join_host(m->upper, rel));
        if (!m->host_base.empty()) out.push_back(join_host(m->host_base, rel));
        return out;
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
            if (!visible(m)) continue;
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
            if (m.prefix == n && visible(m)) return true;
        return false;
    }

    // -- mounts the guest makes, private to its mount namespace -------------
    // The current call's mount namespace (0 = the initial one).
    void set_current_mnt_ns(std::uint64_t ns) const noexcept {
        cur_mnt_ns_ = ns;
        cur_pivoted_ = ns != 0 && pivoted_.count(ns) != 0;
    }
    [[nodiscard]] std::uint64_t current_mnt_ns() const noexcept { return cur_mnt_ns_; }
    // A new mount namespace starts as a copy of its parent's guest mounts.
    void clone_mnt_ns(std::uint64_t parent, std::uint64_t child) {
        mnt_parent_[child] = parent;
        if (pivoted_.count(parent)) pivoted_.insert(child);
        std::vector<Mount> copies;
        for (const auto& m : mounts_)
            if (m.guest && m.mnt_ns == parent) {
                Mount c = m;
                c.mnt_ns = child;
                copies.push_back(std::move(c));
            }
        for (auto& c : copies) mounts_.push_back(std::move(c));
        ++layout_version_;
    }
    // Mount a real host directory at a guest path, seen only in mount
    // namespace `ns` (a tmpfs is a fresh scratch dir; a bind is its source).
    void mount_guest(std::string prefix, std::string host_dir, std::uint64_t ns, bool ro = false) {
        prefix = normalize(prefix);
        Mount m{std::move(prefix), std::move(host_dir), {}, {}, ns, true};
        m.ro = ro;
        mounts_.push_back(std::move(m));
        ++layout_version_;
    }
    // Bind guest path `src` at `target` in `ns` by copying the mount that
    // holds it (a virtual tree like /proc, or an overlay) instead of naming
    // one host dir. `rec` brings the mounts under `src` along.
    bool bind_guest(std::string_view src, std::string target, std::uint64_t ns, bool rec) {
        src = trim_root(src);
        target = normalize(target);
        const Mount* m = deepest(src);
        if (!m) return false;
        std::vector<Mount> add;
        add.push_back(sub_mount(*m, src, target, ns));
        if (rec)
            for (const Mount& c : mounts_)
                if (&c != m && visible(c) && strictly_under(c.prefix, src))
                    add.push_back(sub_mount(c, c.prefix, join_guest(target, c.prefix.substr(src.size())), ns));
        for (auto& a : add) mounts_.push_back(std::move(a));
        return true;
    }
    // A fresh instance of one of our filesystems (mount -t proc at
    // `target`): a copy of the initial namespace's mount at `origin`.
    bool mount_like(std::string_view origin, std::string target, std::uint64_t ns) {
        const Mount* best = nullptr;
        for (const Mount& m : mounts_)
            if (m.mnt_ns == 0 && m.producer && under(origin, m.prefix) &&
                (!best || m.prefix.size() >= best->prefix.size()))
                best = &m;
        if (!best) return false;
        Mount c = sub_mount(*best, origin, normalize(target), ns);
        mounts_.push_back(std::move(c));
        return true;
    }
    // Remove the newest guest mount at `prefix` in `ns`. `detach` takes the
    // mounts stacked on it too; without it those make the unmount EBUSY.
    Errno umount_guest(std::string_view prefix, std::uint64_t ns, bool detach = true) {
        const std::string n = normalize(prefix);
        for (std::size_t i = mounts_.size(); i-- > 0;) {
            if (!(mounts_[i].guest && mounts_[i].prefix == n && mounts_[i].mnt_ns == ns)) continue;
            std::vector<std::size_t> kids;
            for (std::size_t j = i + 1; j < mounts_.size(); ++j)
                if (mounts_[j].mnt_ns == ns && under(mounts_[j].prefix, n)) kids.push_back(j);
            if (!kids.empty() && !detach) return Errno::ebusy;
            for (auto k = kids.rbegin(); k != kids.rend(); ++k)
                mounts_.erase(mounts_.begin() + static_cast<std::ptrdiff_t>(*k));
            mounts_.erase(mounts_.begin() + static_cast<std::ptrdiff_t>(i));
            ++layout_version_;
            return Errno::ok;
        }
        return Errno::einval;
    }
    // MS_MOVE: the guest mount at `src` and those under it move to `target`.
    bool move_guest(std::string_view src, std::string target, std::uint64_t ns) {
        const std::string s = normalize(src);
        target = normalize(target);
        bool found = false;
        for (const auto& m : mounts_) found |= m.mnt_ns == ns && m.prefix == s;
        if (!found) return false;
        for (auto& m : mounts_)
            if (m.mnt_ns == ns && under(m.prefix, s)) {
                if (m.producer && m.origin.empty()) m.origin = m.prefix;
                m.prefix = join_guest(target, s == "/" ? std::string_view{m.prefix}
                                                        : std::string_view{m.prefix}.substr(s.size()));
            }
        return true;
    }
    // Set or clear read-only on the newest mount at `prefix` in `ns`, or on
    // every mount at and under it with `rec`. False if it isn't a mount.
    bool set_mount_ro(std::string_view prefix, std::uint64_t ns, bool ro, bool rec) {
        const std::string n = normalize(prefix);
        Mount* top = nullptr;
        for (auto& m : mounts_)
            if (m.mnt_ns == ns && m.prefix == n) top = &m;
        if (!top) return false;
        top->ro = ro;
        if (rec)
            for (auto& m : mounts_)
                if (m.mnt_ns == ns && under(m.prefix, n)) m.ro = ro;
        return true;
    }
    // Is the mount holding `abs` read-only?
    [[nodiscard]] bool read_only(std::string_view abs) const {
        const Mount* m = deepest(abs);
        return m && m->ro;
    }

    // pivot_root in mount namespace `ns`: the mounts under `new_root` move
    // up to "/", everything else goes under `put_old`. After the first
    // pivot the namespace no longer sees the shared mounts, only its copies.
    // `pids` are the tasks whose cwd and fd paths get renamed to match.
    Errno pivot_root(std::uint64_t ns, std::string new_root, std::string put_old,
                     const std::vector<std::int32_t>& pids) {
        if (ns == 0) return Errno::eperm;
        new_root = normalize(new_root);
        put_old = normalize(put_old);
        if (new_root == "/") return Errno::ebusy;
        if (!is_mount_point(new_root)) return Errno::einval;
        if (!under(put_old, new_root)) return Errno::einval;
        const std::string old_at = put_old.size() == new_root.size()
            ? std::string{"/"} : put_old.substr(new_root.size());
        auto renamed = [&](const std::string& p) {
            if (under(p, new_root))
                return p.size() == new_root.size() ? std::string{"/"} : p.substr(new_root.size());
            return join_guest(old_at, p);
        };
        std::vector<Mount> keep, old;
        for (Mount& m : mounts_) {
            if (!visible(m)) { keep.push_back(std::move(m)); continue; }
            if (m.mnt_ns == ns && m.producer && m.origin.empty()) m.origin = m.prefix;
            if (m.mnt_ns == ns && under(m.prefix, new_root)) {
                m.prefix = renamed(m.prefix);
                keep.push_back(std::move(m));
            } else if (m.mnt_ns == ns) {
                m.prefix = renamed(m.prefix);
                old.push_back(std::move(m));
            } else {
                // a shared mount: this namespace gets its own copy
                Mount c = m;
                if (c.producer && c.origin.empty()) c.origin = c.prefix;
                c.prefix = renamed(c.prefix);
                c.mnt_ns = ns;
                c.guest = true;
                old.push_back(std::move(c));
                keep.push_back(std::move(m));
            }
        }
        // the old root lands last, so at put_old == new_root it sits on top
        for (auto& m : old) keep.push_back(std::move(m));
        mounts_ = std::move(keep);
        pivoted_.insert(ns);
        ++layout_version_;
        set_current_mnt_ns(cur_mnt_ns_);
        for (const std::int32_t pid : pids) {
            if (auto it = cwds_.find(pid); it != cwds_.end()) it->second = renamed(it->second);
            if (auto it = fd_tables_.find(pid); it != fd_tables_.end()) {
                for (auto& [fd, p] : it->second.paths)
                    if (!p.empty() && p.front() == '/') p = renamed(p);
                for (auto& [fd, d] : it->second.dirs)
                    if (!d.lazy.empty()) d.lazy = renamed(d.lazy);
            }
        }
        last_cwd_ = std::string{cwd()};
        return Errno::ok;
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
    bool          fifos_emulated_{false};
    std::uint64_t instance_id_{0};

    struct Mount {
        std::string prefix;      // absolute guest prefix
        std::string host_base;   // real (lower) dir; empty for virtual mounts
        std::string upper;       // writable overlay upper dir; empty = no COW
        Producer    producer;    // set for virtual mounts
        std::uint64_t mnt_ns{0}; // the mount namespace that sees it; 0 = everyone
        bool        guest{false}; // mounted by the guest (umount may remove it)
        bool        ro{false};    // writes through it are EROFS
        // the path the producer knows `prefix` as, when the mount was moved
        // or bound somewhere else; empty = prefix
        std::string origin{};
    };
    // What the producer of `m` calls guest path `abs`.
    [[nodiscard]] static std::string producer_path(const Mount& m, std::string_view abs) {
        if (m.origin.empty()) return std::string{abs};
        std::string_view rel = abs;
        rel.remove_prefix(m.prefix == "/" ? 0 : std::min(rel.size(), m.prefix.size()));
        if (rel.empty() || rel == "/") return m.origin;
        return m.origin == "/" ? std::string{rel} : m.origin + std::string{rel};
    }
    [[nodiscard]] Result<VirtualFile> run_producer(const Mount& m, std::string_view abs) const {
        if (m.origin.empty()) return m.producer(abs);
        return m.producer(producer_path(m, abs));
    }
    // `m` seen from guest path `src` (at or under its prefix), mounted at `at`.
    [[nodiscard]] static Mount sub_mount(const Mount& m, std::string_view src, std::string at,
                                         std::uint64_t ns) {
        Mount c = m;
        std::string rel{src.substr(m.prefix == "/" ? 0 : std::min(src.size(), m.prefix.size()))};
        if (rel == "/") rel.clear();
        if (m.producer) {
            c.origin = producer_path(m, src);
        } else if (!rel.empty()) {
            c.host_base = join_host(m.host_base, rel.substr(1));
            if (!c.upper.empty()) c.upper = join_host(m.upper, rel.substr(1));
        }
        c.prefix = std::move(at);
        c.mnt_ns = ns;
        c.guest = true;
        return c;
    }
    [[nodiscard]] static bool under(std::string_view p, std::string_view dir) {
        if (dir == "/") return true;
        return p.starts_with(dir) && (p.size() == dir.size() || p[dir.size()] == '/');
    }
    [[nodiscard]] static bool strictly_under(std::string_view p, std::string_view dir) {
        return p.size() > dir.size() && under(p, dir);
    }
    [[nodiscard]] static std::string join_guest(std::string_view dir, std::string_view p) {
        if (dir == "/") return std::string{p.empty() ? "/" : p};
        if (p == "/" || p.empty()) return std::string{dir};
        return std::string{dir} + std::string{p};
    }
    [[nodiscard]] static std::string_view trim_root(std::string_view p) {
        while (p.size() > 1 && p.back() == '/') p.remove_suffix(1);
        return p;
    }
    // A mount namespace as a copy of its parent's guest mounts: a fork of
    // the table, so later mounts on either side stay private.
    std::map<std::uint64_t, std::uint64_t> mnt_parent_;
    mutable std::uint64_t cur_mnt_ns_{0};
    // namespaces that pivot_root'ed away from the shared mounts
    std::set<std::uint64_t> pivoted_;
    mutable bool cur_pivoted_{false};
    [[nodiscard]] bool visible(const Mount& m) const {
        if (m.mnt_ns == 0) return !cur_pivoted_;
        return m.mnt_ns == cur_mnt_ns_;
    }

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
                case Probe::notdir:
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
        if (::lstat(path, &st) == 0) return true;
        if (errno != ENAMETOOLONG) return false;
        return at_long_parent(path, [&](int dfd, const char* leaf) {
            return ::fstatat(dfd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0;
        });
    }

    // Run fn(dirfd, leaf) for a path too long for the host (host/long_path.hpp).
    template <class F>
    static bool at_long_parent(const char* path, F&& fn) {
        return host::at_long_parent(path, std::forward<F>(fn));
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
    // path. EACCES folds into "absent" for LAYER SELECTION only: if the upper
    // can't be traversed, the lower is the right candidate, and the forwarded
    // syscall reports the true error itself.
    //
    // ENOTDIR does NOT. It means some component in the UPPER is a
    // non-directory, and an upper non-directory is opaque: nothing beneath
    // it exists, whatever the lower holds at that path. Folding it into
    // "absent" sent `open("file/x")` to the lower layer, which usually has no
    // such parent at all and answered ENOENT where Linux says ENOTDIR.
    enum class Probe { symlink, present, absent, notdir };
    static Probe probe_link(const char* path, std::string& out) {
        char buf[4096];
        ::ssize_t n = ::readlink(path, buf, sizeof buf - 1);
        if (n < 0 && errno == ENAMETOOLONG)
            (void)at_long_parent(path, [&](int dfd, const char* leaf) {
                n = ::readlinkat(dfd, leaf, buf, sizeof buf - 1);
                return n >= 0;
            });
        if (n >= 0) { out.assign(buf, static_cast<std::size_t>(n)); return Probe::symlink; }
        if (errno == EINVAL) return Probe::present;
        return errno == ENOTDIR ? Probe::notdir : Probe::absent;
    }

    static bool is_dir(const char* path) {
        struct ::stat st{};
        if (::stat(path, &st) == 0) return S_ISDIR(st.st_mode);
        if (errno != ENAMETOOLONG) return false;
        return at_long_parent(path, [&](int dfd, const char* leaf) {
            return ::fstatat(dfd, leaf, &st, 0) == 0 && S_ISDIR(st.st_mode);
        });
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
        bool          hidden{false};   // dropped from the union (kept so views into keys stay valid)
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
    static bool merge_dir(const std::string& host_dir, NameMap& seen,
                          std::vector<std::string_view>* order = nullptr) {
        ::DIR* d = ::opendir(host_dir.c_str());
#if !defined(_WIN32)
        if (!d && errno == ENAMETOOLONG) {
            int dfd = -1;
            (void)at_long_parent(host_dir.c_str(), [&](int pfd, const char* leaf) {
                dfd = ::openat(pfd, leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                return dfd >= 0;
            });
            if (dfd >= 0 && !(d = ::fdopendir(dfd))) ::close(dfd);
        }
#endif
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
            const auto ins = seen.emplace(name, DirEntryInfo{t, ino});
            if (order && ins.second) order->push_back(ins.first->first);
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
        // pacman holds db.lck for a whole transaction, so a half-written
        // entry always comes with a lock left behind. No lock: nothing to
        // repair, and no stat of every installed package on every start.
        std::string lck = upper + "/var/lib/pacman/db.lck";
        if (!exists(lck.c_str())) return;
        ::unlink(lck.c_str());

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

    // What a mirror/copy-up had to widen for linuxity's own access, as
    // (characters of `up` after that entry, the real lower mode). The caller
    // turns each back into a guest path and records the real mode.
    using Widened = std::vector<std::pair<std::size_t, std::uint32_t>>;

    // Ensure `up` exists in the upper layer, copying its bytes up from the
    // read-only lower `lo` on first write and creating parent directories.
    // Best-effort: if the lower doesn't exist this just preps the parent dirs
    // so an O_CREAT open can make the new file in upper.
    //
    // Anything the copy had to give MORE access than the lower has (see
    // below) is reported through `widened`, so the real mode can be recorded.
    static void copy_up(const std::string& up, const std::string& lo,
                        Widened* widened = nullptr) {
        mirror_parents_from_lower(up, lo, widened);
        if (exists(up.c_str())) return;                 // already copied up
        // The lower file's own mode, so a copy-up does not silently
        // re-permission it: an executable copied up as 0644 stops being
        // runnable, which is exactly what a package manager's shipped
        // binaries are.
        //
        // But never LESS than owner read/write (owner rwx for a directory).
        // The guest is root and ignores permission bits; linuxity is an
        // ordinary host user and does not. Copying /etc/machine-id up as its
        // shipped 0444 left a file linuxity could not then open for writing,
        // so guest root got EACCES and systemd-machine-id-setup concluded
        // /etc was read-only. The exact mode goes in the shadow store instead.
        struct ::stat lst{};
        const bool have_mode = ::stat(lo.c_str(), &lst) == 0;
        const ::mode_t lmode = have_mode ? (lst.st_mode & 07777) : 0;
        const bool dir = is_dir(lo.c_str());
        const ::mode_t host_mode = !have_mode ? (dir ? 0755 : 0644)
                                              : lmode | (dir ? 0700 : 0600);
        if (widened != nullptr && have_mode && host_mode != lmode)
            widened->emplace_back(0, lmode);
        // If the lower is a DIRECTORY, mirror it as a directory in upper (do
        // NOT open+copy it as a regular file — that would leave a bogus file
        // where a mkdir/child-create expects a dir, yielding EEXIST/ENOTDIR).
        if (dir) {
            if (::mkdir(up.c_str(), host_mode) == 0) (void)::chmod(up.c_str(), host_mode);
            return;
        }
        int in = ::open(lo.c_str(), O_RDONLY | O_CLOEXEC);
        if (in < 0) return;                             // no lower => new file
        int out = ::open(up.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                         host_mode);
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
        // open() masks the mode through umask; set it exactly.
        (void)::chmod(up.c_str(), host_mode);
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
                                          const std::string& lo,
                                          Widened* widened = nullptr) {
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
            // Mirror only a directory the lower layer HAS: the point is to
            // give an existing lower dir an upper twin, never to invent one.
            // Creating every ancestor turned `mkdir a/b` with no a into
            // `mkdir -p` (root got success, a user EACCES on the invented a).
            ::mode_t mode = 0755;
            bool in_lower = false;
            if (!lo_dir.empty()) {
                const std::size_t tail = dir.size() - i;
                if (tail <= lo_dir.size()) {
                    struct ::stat st{};
                    const std::string lsub = lo_dir.substr(0, lo_dir.size() - tail);
                    if (::stat(lsub.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                        mode = st.st_mode & 07777;
                        in_lower = true;
                    }
                }
            }
            if (!in_lower) continue;
            // Owner rwx at least: linuxity must be able to create inside a
            // directory guest root writes into, and a 0555 lower directory
            // (ca-certificates' cadir) mirrored literally refused it.
            const ::mode_t real = mode;
            mode |= 0700;
            if (::mkdir(sub.c_str(), mode) != 0) continue;   // EEXIST: leave it
            if (widened != nullptr && real != mode)
                widened->emplace_back(up.size() - sub.size(), real);
            // Always chmod the one we just created. mkdir's mode is masked by
            // the HOST's umask, which linuxity does not control -- Android's
            // adb shell runs with umask 000, a desktop with 022, so the same
            // mirror produced different modes on different hosts. The
            // sticky/setgid bits never survive mkdir either. Setting it
            // explicitly makes the mirror exact instead of
            // umask-dependent, which is what "directory permissions differ
            // on /etc/" was reporting.
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
            if (!visible(m)) continue;
            const std::string& pre = m.prefix;
            bool match = pre == "/" ? true
                : (abs.starts_with(pre) &&
                   (abs.size() == pre.size() || abs[pre.size()] == '/'));
            if (match && pre.size() >= best_len) { best = &m; best_len = pre.size(); }
        }
        return best;
    }

    std::vector<Mount> mounts_;
    // directory -> symlink answers for classify_impl's parent walk (keyed by
    // guest path + the mount's dirs); cleared on any write
    struct DirProbe { Probe first; std::string second; bool third; };
    mutable std::unordered_map<std::string, DirProbe> dirlink_cache_;
public:
    // -- hooks for the in-guest handler -----------------------------------
    // Called with a guest directory whose whole path the parent walk found
    // free of symlinks, and whether it may exist in the upper layer.
    void set_on_clean_dir(std::function<void(std::string_view, bool)> f) { on_clean_dir_ = std::move(f); }
    // Bumped whenever the mount table, a namespace's view of it, or a
    // directory's symlink-ness may have changed.
    [[nodiscard]] std::uint64_t layout_version() const noexcept { return layout_version_; }
    // Is this host path part of a copy-on-write mount (the rootfs or its
    // upper)? Binds of host folders are not.
    [[nodiscard]] bool in_overlay(std::string_view host) const {
        auto under = [&](const std::string& base) {
            return !base.empty() && host.starts_with(base) &&
                   (host.size() == base.size() || host[base.size()] == '/');
        };
        for (const auto& m : mounts_)
            if (!m.upper.empty() && (under(m.host_base) || under(m.upper))) return true;
        return false;
    }
    void bump_layout() const noexcept { ++layout_version_; }
    // Bumped on every write: a directory may have become a symlink.
    [[nodiscard]] std::uint64_t dirs_version() const noexcept { return dirs_version_; }
    // Paths whited out from now on (the in-guest handler must leave them alone).
    void set_whiteout_log(std::vector<std::string>* log) { whiteout_log_ = log; }
    template <class F> void for_each_whiteout(F&& f) const { for (const auto& w : whiteouts_) f(w); }
    // The mounts every namespace sees: prefix, lower, upper, virtual.
    template <class F> void for_each_shared_mount(F&& f) const {
        if (!pivoted_.empty()) return;
        for (std::size_t i = 0; i < mounts_.size(); ++i) {
            const Mount& m = mounts_[i];
            if (m.mnt_ns != 0) continue;
            f(m.prefix, m.host_base, m.upper, static_cast<bool>(m.producer), m.ro,
              !m.origin.empty(), static_cast<std::uint64_t>(i));
        }
    }
    // Does any mount namespace other than the initial one have mounts?
    [[nodiscard]] bool has_private_mounts() const {
        for (const Mount& m : mounts_) if (m.mnt_ns != 0) return true;
        return !pivoted_.empty();
    }
private:
    std::function<void(std::string_view, bool)> on_clean_dir_;
    mutable std::uint64_t layout_version_{0};
    mutable std::uint64_t dirs_version_{0};
    std::vector<std::string>* whiteout_log_{nullptr};
    // Per-process current directory (see set_current_pid/inherit_cwd). cur_pid_
    // is mutable so a const cwd()/absolutize path can select the active pid.
    mutable std::unordered_map<std::int32_t, std::string> cwds_{};
    mutable std::int32_t cur_pid_{1};   // root/init
    // The pid whose cwds_ record set_current_pid has already confirmed, so
    // the common "same task as last syscall" case costs one compare. Any
    // path that CLEARS or re-seeds cwds_ must reset this to a pid that can
    // never match (0 is not a valid guest pid).
    mutable std::int32_t seeded_pid_{0};
    // The SUPERVISOR's cwd (not any guest's), for absolute_host().
    std::string host_cwd_;
    // The cwd of the most recently seen task, used to seed a task whose parent
    // link is not known yet (see set_current_pid) -- and, in a macOS fork
    // child, the parent's cwd (import_process_state). Mutable for the same reason
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
    mutable MetaStore meta_{};
    mutable fsnotify::Hub fsnotify_{};
    bool fsnotify_emulated_{false};
    LinkTable links_{};
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
    mutable JournalTail whiteout_tail_;   // how much of it whiteouts_ holds
    bool follow_journals_{false};         // see set_shared_with_other_processes

public:
    // Drop a whiteout because the path really exists again (an upper-layer
    // file now shadows the lower one). Safe to call for a path that was
    // never deleted -- the common case, so it checks the set first.
    void clear_whiteout_if_any(const std::string& guest_path) const {
        if (!whiteouts_.empty()) clear_whiteout(guest_path);
    }

    // Record a lower-only removal. Returns nothing; the caller reports success.
    void add_whiteout(const std::string& guest_path) const {
        if (!whiteouts_.insert(guest_path).second) return;
        if (whiteout_log_) whiteout_log_->push_back(guest_path);
        if (!whiteout_journal_.empty()) {
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
        return whiteout_tail_.reload([this] { whiteouts_.clear(); },
                                     [this](std::string_view l) { apply_whiteout_line(l); });
    }
    void catch_up_whiteouts() const {
        (void)whiteout_tail_.follow([this] { whiteouts_.clear(); },
                                    [this](std::string_view l) { apply_whiteout_line(l); });
    }
    void apply_whiteout_line(std::string_view l) const {
        if (l.empty()) return;
        if (l.front() == '!') whiteouts_.erase(std::string{l.substr(1)});   // un-whiteout
        else                  whiteouts_.insert(std::string{l});
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
        whiteout_tail_.adopt();
    }
};

} // namespace lx::kernel
