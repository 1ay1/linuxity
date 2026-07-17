// linuxity/vfs/vfs.hpp
//
// The VFS proper: a unified namespace over mounted FileSystem backends.
//
//   * A mount table maps a path prefix ("/", "/proc", "/tmp") to a backend.
//   * Path resolution walks components, crossing mount points, to reach an
//     (backend, ino) pair — a resolved dentry.
//   * An open-file table maps guest Fds to (backend, ino, offset) — the
//     "file description" the guest holds.
//
// Backends are heterogeneous (tmpfs vs procfs vs hostfs), so the mount table
// stores them behind a tiny type-erased adapter. The erasure boundary is the
// ONLY dynamic-dispatch in the VFS; every concrete backend is still checked
// against the FileSystem concept at the point it's mounted, so the contract
// is enforced statically even though storage is uniform.
#pragma once

#include "linuxity/vfs/inode.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace lx::vfs {

// -- Type-erased backend ---------------------------------------------------
// The vtable is generated from any type that models FileSystem. Nothing
// outside this file sees it; callers mount concrete types.
class AnyFs {
public:
    template <FileSystem F>
    explicit AnyFs(F fs) : self_{std::make_unique<Model<F>>(std::move(fs))} {}

    [[nodiscard]] Ino root() const { return self_->root(); }
    [[nodiscard]] Result<Stat> stat(Ino i) const { return self_->stat(i); }
    [[nodiscard]] Result<Ino> lookup(Ino d, std::string_view n) const {
        return self_->lookup(d, n);
    }
    [[nodiscard]] Result<Ino> create(Ino d, std::string_view n, FileType t, Mode m) {
        return self_->create(d, n, t, m);
    }
    [[nodiscard]] Result<std::size_t> read_at(Ino i, std::uint64_t o,
                                              std::span<std::byte> b) const {
        return self_->read_at(i, o, b);
    }
    [[nodiscard]] Result<std::size_t> write_at(Ino i, std::uint64_t o,
                                               std::span<const std::byte> b) {
        return self_->write_at(i, o, b);
    }

private:
    struct Concept {
        virtual ~Concept() = default;
        virtual Ino root() const = 0;
        virtual Result<Stat> stat(Ino) const = 0;
        virtual Result<Ino> lookup(Ino, std::string_view) const = 0;
        virtual Result<Ino> create(Ino, std::string_view, FileType, Mode) = 0;
        virtual Result<std::size_t> read_at(Ino, std::uint64_t, std::span<std::byte>) const = 0;
        virtual Result<std::size_t> write_at(Ino, std::uint64_t, std::span<const std::byte>) = 0;
    };
    template <FileSystem F>
    struct Model final : Concept {
        F fs;
        explicit Model(F f) : fs{std::move(f)} {}
        Ino root() const override { return fs.root(); }
        Result<Stat> stat(Ino i) const override { return fs.stat(i); }
        Result<Ino> lookup(Ino d, std::string_view n) const override { return fs.lookup(d, n); }
        Result<Ino> create(Ino d, std::string_view n, FileType t, Mode m) override { return fs.create(d, n, t, m); }
        Result<std::size_t> read_at(Ino i, std::uint64_t o, std::span<std::byte> b) const override { return fs.read_at(i, o, b); }
        Result<std::size_t> write_at(Ino i, std::uint64_t o, std::span<const std::byte> b) override { return fs.write_at(i, o, b); }
    };
    std::unique_ptr<Concept> self_;
};

// -- The VFS ---------------------------------------------------------------
class Vfs {
public:
    // Construct with a root filesystem mounted at "/".
    template <FileSystem F>
    explicit Vfs(F rootfs) {
        mounts_.push_back({"/", AnyFs{std::move(rootfs)}});
    }

    // mount(2): attach a backend at an absolute path prefix. Longest-prefix
    // wins during resolution, so "/proc" shadows "/" beneath it.
    template <FileSystem F>
    void mount(std::string at, F fs) {
        mounts_.push_back({std::move(at), AnyFs{std::move(fs)}});
    }

    // A resolved dentry: which mount, and the inode within it.
    struct Resolved { std::size_t mount; Ino ino; };

    // Resolve an absolute path to (mount index, ino). Walks components and
    // crosses into the deepest matching mount. No symlink following yet.
    [[nodiscard]] Result<Resolved> resolve(std::string_view path) const {
        std::size_t mi = deepest_mount(path);
        const AnyFs& fs = mounts_[mi].fs;
        std::string_view rel = strip_prefix(path, mounts_[mi].at);

        Ino cur = fs.root();
        for (auto comp : components(rel)) {
            Ino next = LX_TRY(fs.lookup(cur, comp));
            cur = next;
        }
        return ok(Resolved{mi, cur});
    }

    // open(2): resolve, honouring O_CREAT, and install an fd.
    [[nodiscard]] Result<Fd> open(std::string_view path, OFlags fl, Mode m) {
        auto r = resolve(path);
        if (!r) {
            if (r.error() == Errno::enoent && has(fl, OFlags::creat))
                r = create_at(path, FileType::regular, m);
            if (!r) return std::unexpected(r.error());
        }
        Fd fd = next_fd_; ++next_fd_;
        open_files_.emplace(fd, OpenFile{r->mount, r->ino, 0, fl});
        return ok(fd);
    }

    [[nodiscard]] Result<std::size_t> read(Fd fd, std::span<std::byte> buf) {
        auto it = open_files_.find(fd);
        if (it == open_files_.end()) return err<std::size_t>(Errno::ebadf);
        OpenFile& of = it->second;
        std::size_t n = LX_TRY(mounts_[of.mount].fs.read_at(of.ino, of.offset, buf));
        of.offset += n;
        return ok(n);
    }

    [[nodiscard]] Result<std::size_t> write(Fd fd, std::span<const std::byte> buf) {
        auto it = open_files_.find(fd);
        if (it == open_files_.end()) return err<std::size_t>(Errno::ebadf);
        OpenFile& of = it->second;
        std::size_t n = LX_TRY(mounts_[of.mount].fs.write_at(of.ino, of.offset, buf));
        of.offset += n;
        return ok(n);
    }

    [[nodiscard]] Status close(Fd fd) {
        return open_files_.erase(fd) ? ok() : err(Errno::ebadf);
    }

    [[nodiscard]] Result<Stat> stat(std::string_view path) const {
        auto r = LX_TRY(resolve(path));
        return mounts_[r.mount].fs.stat(r.ino);
    }

private:
    struct Mount { std::string at; AnyFs fs; };
    struct OpenFile { std::size_t mount; Ino ino; std::uint64_t offset; OFlags flags; };

    // Create a leaf under its parent directory (mkdir/creat helper).
    [[nodiscard]] Result<Resolved> create_at(std::string_view path,
                                             FileType ft, Mode m) {
        auto [dir, leaf] = split_parent(path);
        auto pr = LX_TRY(resolve(dir));
        Ino ino = LX_TRY(mounts_[pr.mount].fs.create(pr.ino, leaf, ft, m));
        return ok(Resolved{pr.mount, ino});
    }

    // Longest-prefix mount match.
    [[nodiscard]] std::size_t deepest_mount(std::string_view path) const {
        std::size_t best = 0, best_len = 0;
        for (std::size_t i = 0; i < mounts_.size(); ++i) {
            const std::string& at = mounts_[i].at;
            if (path.starts_with(at) && at.size() >= best_len) {
                best = i; best_len = at.size();
            }
        }
        return best;
    }

    static std::string_view strip_prefix(std::string_view path, std::string_view at) {
        path.remove_prefix(at == "/" ? 0 : at.size());
        while (path.starts_with('/')) path.remove_prefix(1);
        return path;
    }

    static std::vector<std::string_view> components(std::string_view rel) {
        std::vector<std::string_view> out;
        std::size_t i = 0;
        while (i < rel.size()) {
            std::size_t j = rel.find('/', i);
            if (j == std::string_view::npos) j = rel.size();
            if (j > i) out.push_back(rel.substr(i, j - i));
            i = j + 1;
        }
        return out;
    }

    static std::pair<std::string_view, std::string_view>
    split_parent(std::string_view path) {
        std::size_t slash = path.find_last_of('/');
        if (slash == std::string_view::npos) return {"/", path};
        std::string_view dir = slash == 0 ? std::string_view{"/"} : path.substr(0, slash);
        return {dir, path.substr(slash + 1)};
    }

    std::vector<Mount> mounts_;
    std::unordered_map<Fd, OpenFile> open_files_;
    Fd next_fd_{3}; // 0,1,2 reserved for stdio
};

} // namespace lx::vfs
