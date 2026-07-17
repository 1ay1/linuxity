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

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace lx::kernel {

// How a resolved path must be serviced.
enum class Realm2 { host_backed, virtual_file, absent };

// The classification of a guest path.
struct PathClass {
    Realm2      realm{Realm2::absent};
    std::string host_path;   // real on-disk path (host_backed only)
    Errno       error{Errno::enoent};  // meaningful when realm == absent
};

// A synthesized virtual file: a producer of bytes for a virtual path.
struct VirtualFile {
    std::vector<std::byte> bytes;
    bool is_dir{false};
};

// The filesystem namespace. Backends register two kinds of mounts:
//   * a HOST mount   (prefix -> host base dir): host_backed realm.
//   * a VIRTUAL mount(prefix -> producer fn):   virtual_file realm.
// Longest-prefix wins, exactly like the Linux mount table.
class FileNamespace {
public:
    using Producer = std::function<Result<VirtualFile>(std::string_view /*abs path*/)>;

    // Mount a real host directory at an absolute guest prefix ("/" for the
    // rootfs). `host_base` is the on-disk directory it maps to.
    void mount_host(std::string prefix, std::string host_base) {
        if (prefix.size() > 1 && prefix.back() == '/') prefix.pop_back();
        if (!host_base.empty() && host_base.back() == '/') host_base.pop_back();
        mounts_.push_back(Mount{std::move(prefix), std::move(host_base), {}});
    }

    // Mount a virtual producer at an absolute guest prefix ("/proc", "/sys").
    void mount_virtual(std::string prefix, Producer prod) {
        if (prefix.size() > 1 && prefix.back() == '/') prefix.pop_back();
        mounts_.push_back(Mount{std::move(prefix), {}, std::move(prod)});
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

    // Classify an ABSOLUTE, normalized guest path into its realm. For
    // host-backed paths, returns the translated real host path (existence is
    // NOT checked here; the forwarded host syscall reports ENOENT itself).
    [[nodiscard]] PathClass classify(std::string_view abs) const {
        const Mount* m = deepest(abs);
        if (!m) return PathClass{Realm2::absent, {}, Errno::enoent};
        if (m->producer) {
            auto vf = m->producer(abs);
            if (!vf) return PathClass{Realm2::absent, {}, vf.error()};
            return PathClass{Realm2::virtual_file, {}, Errno::enoent};
        }
        // host-backed: base + (abs minus prefix)
        std::string_view rel = abs;
        rel.remove_prefix(m->prefix == "/" ? 0 : m->prefix.size());
        std::string hp = m->host_base;
        if (!rel.empty()) {
            if (rel.front() != '/') hp += '/';
            hp += rel;
        }
        return PathClass{Realm2::host_backed, std::move(hp), Errno::enoent};
    }

    // Produce the bytes of a virtual file (for read/open/getdents on it).
    [[nodiscard]] Result<VirtualFile> produce(std::string_view abs) const {
        const Mount* m = deepest(abs);
        if (!m || !m->producer) return err<VirtualFile>(Errno::enoent);
        return m->producer(abs);
    }

    // -- Guest fd table ----------------------------------------------------
    // Records the guest path bound to a real (forwarded) fd, so readlinkat,
    // getdents, and fd-relative openat can recover the path. The fd number is
    // the REAL host fd the child holds (redirect/inject both yield real fds).
    void bind_fd(int fd, std::string abs) { fd_paths_[fd] = std::move(abs); }
    void unbind_fd(int fd) { fd_paths_.erase(fd); }
    [[nodiscard]] std::string_view path_of_fd(int fd) const {
        auto it = fd_paths_.find(fd);
        return it == fd_paths_.end() ? std::string_view{} : std::string_view{it->second};
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
        std::string host_base;   // real dir (empty for virtual mounts)
        Producer    producer;    // set for virtual mounts
    };

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
};

} // namespace lx::kernel
