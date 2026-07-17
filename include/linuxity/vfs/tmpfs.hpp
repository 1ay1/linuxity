// linuxity/vfs/tmpfs.hpp
//
// tmpfs — a purely in-memory filesystem. The simplest concrete FileSystem
// backend, and the archetype: it owns every byte, so it lives entirely in
// the Virtual realm (see kernel/authority.hpp) and can be bit-exact with
// Linux tmpfs semantics.
//
// An inode is either a directory (name -> child ino map) or a regular file
// (a byte vector). Inode numbers come from a monotonic allocator — the same
// IdSpace pattern the kernel uses for PIDs.
#pragma once

#include "linuxity/vfs/inode.hpp"

#include <algorithm>
#include <cstring>
#include <map>
#include <unordered_map>
#include <variant>
#include <vector>

namespace lx::vfs {

class Tmpfs {
public:
    Tmpfs() {
        // ino 1 is the root directory, by convention (like a real fs).
        Node root;
        root.st.ino  = Ino{1};
        root.st.type = FileType::directory;
        root.st.mode = mode(0755);
        root.body    = Dir{};
        nodes_.emplace(Ino{1}, std::move(root));
        next_ = Ino{2};
    }

    [[nodiscard]] Ino root() const noexcept { return Ino{1}; }

    [[nodiscard]] Result<Stat> stat(Ino ino) const {
        auto it = nodes_.find(ino);
        if (it == nodes_.end()) return err<Stat>(Errno::enoent);
        return ok(it->second.st);
    }

    [[nodiscard]] Result<Ino> lookup(Ino dir, std::string_view name) const {
        const Node* d = find_dir(dir);
        if (!d) return err<Ino>(Errno::enotdir);
        const auto& entries = std::get<Dir>(d->body).entries;
        auto it = entries.find(std::string{name});
        if (it == entries.end()) return err<Ino>(Errno::enoent);
        return ok(it->second);
    }

    [[nodiscard]] Result<Ino> create(Ino dir, std::string_view name,
                                     FileType ft, Mode m) {
        Node* d = find_dir_mut(dir);
        if (!d) return err<Ino>(Errno::enotdir);
        auto& entries = std::get<Dir>(d->body).entries;
        if (entries.contains(std::string{name})) return err<Ino>(Errno::eexist);

        Ino ino = next_; ++next_;
        Node n;
        n.st.ino  = ino;
        n.st.type = ft;
        n.st.mode = m;
        if (ft == FileType::directory) n.body = Dir{};
        else                           n.body = File{};
        nodes_.emplace(ino, std::move(n));
        entries.emplace(std::string{name}, ino);
        return ok(ino);
    }

    [[nodiscard]] Result<std::size_t> read_at(Ino ino, std::uint64_t off,
                                              std::span<std::byte> buf) const {
        auto it = nodes_.find(ino);
        if (it == nodes_.end()) return err<std::size_t>(Errno::enoent);
        const File* f = std::get_if<File>(&it->second.body);
        if (!f) return err<std::size_t>(Errno::eisdir);
        if (off >= f->data.size()) return ok(std::size_t{0});
        std::size_t n = std::min(buf.size(), f->data.size() - off);
        std::memcpy(buf.data(), f->data.data() + off, n);
        return ok(n);
    }

    [[nodiscard]] Result<std::size_t> write_at(Ino ino, std::uint64_t off,
                                               std::span<const std::byte> buf) {
        auto it = nodes_.find(ino);
        if (it == nodes_.end()) return err<std::size_t>(Errno::enoent);
        File* f = std::get_if<File>(&it->second.body);
        if (!f) return err<std::size_t>(Errno::eisdir);
        if (off + buf.size() > f->data.size()) f->data.resize(off + buf.size());
        std::memcpy(f->data.data() + off, buf.data(), buf.size());
        it->second.st.size = f->data.size();
        return ok(buf.size());
    }

private:
    struct File { std::vector<std::byte> data; };
    struct Dir  { std::map<std::string, Ino> entries; };
    struct Node {
        Stat st;
        std::variant<File, Dir> body;
    };

    [[nodiscard]] const Node* find_dir(Ino ino) const {
        auto it = nodes_.find(ino);
        if (it == nodes_.end() || !std::holds_alternative<Dir>(it->second.body))
            return nullptr;
        return &it->second;
    }
    [[nodiscard]] Node* find_dir_mut(Ino ino) {
        auto it = nodes_.find(ino);
        if (it == nodes_.end() || !std::holds_alternative<Dir>(it->second.body))
            return nullptr;
        return &it->second;
    }

    std::unordered_map<Ino, Node> nodes_;
    Ino next_{2};
};

static_assert(FileSystem<Tmpfs>, "Tmpfs must model the FileSystem concept");

} // namespace lx::vfs
