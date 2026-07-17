// linuxity/vfs/hostfs.hpp
//
// HostFs — expose a real on-disk directory as a guest filesystem.
//
// This is the payload backend of "install any distro": extract a rootfs
// tarball (alpine-minirootfs, arch bootstrap, debootstrap output) into a
// host directory, mount it at "/", and the guest sees a real Linux tree —
// /bin, /lib, /usr, /etc all backed by actual files on disk.
//
// It reads the host ONLY through the HostFiles capability concept, so the
// dependency on host filesystem access is stated in the type system: a host
// that can't touch the FS simply can't instantiate HostFs. Zero third-party
// dependencies — just the host's open/pread/stat/readdir primitives.
//
// Guest inode numbers are assigned lazily by a monotonic allocator and
// cached bidirectionally with their host-relative paths, so repeated lookups
// are cheap and stat/read address inodes, not paths (matching Linux VFS).
#pragma once

#include "linuxity/host/host.hpp"
#include "linuxity/vfs/inode.hpp"

#include <string>
#include <unordered_map>

namespace lx::vfs {

template <host::HostFiles H>
class HostFs {
public:
    // `base` is the host directory that becomes the guest root ("/").
    HostFs(H& host, std::string base) : host_{host}, base_{std::move(base)} {
        if (!base_.empty() && base_.back() == '/') base_.pop_back();
        // ino 1 == root, mapped to the base directory itself.
        intern(Ino{1}, "");
    }

    [[nodiscard]] Ino root() const noexcept { return Ino{1}; }

    [[nodiscard]] Result<Stat> stat(Ino ino) const {
        const std::string* rel = path_of(ino);
        if (!rel) return err<Stat>(Errno::enoent);
        auto hs = LX_TRY(host_.stat_path(host_path(*rel).c_str()));
        return ok(to_stat(ino, hs));
    }

    [[nodiscard]] Result<Ino> lookup(Ino dir, std::string_view name) const {
        const std::string* drel = path_of(dir);
        if (!drel) return err<Ino>(Errno::enoent);
        std::string childrel = join(*drel, name);
        // Verify it exists on the host before minting an inode.
        auto hs = host_.stat_path(host_path(childrel).c_str());
        if (!hs) return std::unexpected(hs.error());
        return ok(intern_path(std::move(childrel)));
    }

    // HostFs is read-only for now (installing a distro is read-mostly; a
    // writable overlay comes later). Creation is refused with EROFS.
    [[nodiscard]] Result<Ino> create(Ino, std::string_view, FileType, Mode) {
        return err<Ino>(Errno::erofs);
    }

    [[nodiscard]] Result<std::size_t> read_at(Ino ino, std::uint64_t off,
                                              std::span<std::byte> buf) const {
        const std::string* rel = path_of(ino);
        if (!rel) return err<std::size_t>(Errno::enoent);
        int fd = LX_TRY(host_.open_path(host_path(*rel).c_str()));
        auto n = host_.pread(fd, off, buf);
        (void)host_.close(fd);
        return n;
    }

    [[nodiscard]] Result<std::size_t> write_at(Ino, std::uint64_t,
                                               std::span<const std::byte>) {
        return err<std::size_t>(Errno::erofs);
    }

    // Enumerate a directory (getdents). Not part of the FileSystem concept's
    // minimum, but exposed for readdir-style callers.
    [[nodiscard]] Result<std::vector<Dirent>> readdir(Ino dir) {
        const std::string* drel = path_of(dir);
        if (!drel) return err<std::vector<Dirent>>(Errno::enoent);
        auto entries = LX_TRY(host_.list_dir(host_path(*drel).c_str()));
        std::vector<Dirent> out;
        out.reserve(entries.size());
        for (auto& e : entries) {
            Ino ino = intern_path(join(*drel, e.name));
            out.push_back(Dirent{e.name, ino, map_type(e.type)});
        }
        return ok(std::move(out));
    }

private:
    // -- inode <-> host-relative-path interning ----------------------------
    Ino intern_path(std::string rel) const {
        auto it = by_path_.find(rel);
        if (it != by_path_.end()) return it->second;
        Ino ino = next_; ++next_;
        intern(ino, std::move(rel));
        return ino;
    }
    void intern(Ino ino, std::string rel) const {
        by_ino_.emplace(ino, rel);
        by_path_.emplace(std::move(rel), ino);
    }
    [[nodiscard]] const std::string* path_of(Ino ino) const {
        auto it = by_ino_.find(ino);
        return it == by_ino_.end() ? nullptr : &it->second;
    }

    // -- path arithmetic ---------------------------------------------------
    [[nodiscard]] std::string host_path(std::string_view rel) const {
        std::string p = base_;
        if (!rel.empty()) { p += '/'; p += rel; }
        return p;
    }
    static std::string join(std::string_view dir, std::string_view name) {
        if (dir.empty()) return std::string{name};
        std::string r{dir}; r += '/'; r += name; return r;
    }

    static FileType map_type(host::HFileType t) noexcept {
        switch (t) {
            case host::HFileType::directory: return FileType::directory;
            case host::HFileType::symlink:   return FileType::symlink;
            case host::HFileType::regular:   return FileType::regular;
            default:                         return FileType::regular;
        }
    }
    static Stat to_stat(Ino ino, const host::HStat& h) {
        Stat s;
        s.ino  = ino;
        s.mode = mode(h.mode);
        s.size = h.size;
        s.mtime_ns = h.mtime_ns;
        s.type = map_type(h.type);
        return s;
    }

    H& host_;
    std::string base_;
    mutable std::unordered_map<Ino, std::string> by_ino_;
    mutable std::unordered_map<std::string, Ino> by_path_;
    mutable Ino next_{2};
};

} // namespace lx::vfs
