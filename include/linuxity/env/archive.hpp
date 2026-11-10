// linuxity/env/archive.hpp
//
// Unpacks a distro image (a tar, gzip/xz/zstd compressed) into a directory,
// as an unprivileged user.
//
// What a plain `tar -x` gets wrong here:
//   * ownership. We can't chown, so the owners and the set-ID bits come back
//     as a list for linuxity's metadata journal, which shows them to guests.
//   * hard links. Android refuses link(2) to apps, so a refused link becomes
//     a copy (fine for the read-only lower layer).
//   * devices and FIFOs can't be made; linuxity serves /dev itself.
//   * safety. Every path is resolved with openat and O_NOFOLLOW from the
//     target directory, so a hostile archive (`..`, absolute paths, a symlink
//     followed by a file "through" it) can't write outside it.
//
// gzip is built in (zlib, present on every host including Android); xz and
// zstd go through the host's `xz`/`zstd` when they exist.
#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <zlib.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace lx::env::archive {

enum class Compression { none, gzip, xz, zstd, unknown };

[[nodiscard]] inline Compression sniff(const std::string& path) {
    unsigned char m[262] = {};
    std::FILE* f = std::fopen(path.c_str(), "rbe");
    if (!f) return Compression::unknown;
    const std::size_t n = std::fread(m, 1, sizeof m, f);
    std::fclose(f);
    if (n >= 2 && m[0] == 0x1f && m[1] == 0x8b) return Compression::gzip;
    if (n >= 6 && std::memcmp(m, "\xfd" "7zXZ\0", 6) == 0) return Compression::xz;
    if (n >= 4 && m[0] == 0x28 && m[1] == 0xb5 && m[2] == 0x2f && m[3] == 0xfd) return Compression::zstd;
    if (n >= 262 && std::memcmp(m + 257, "ustar", 5) == 0) return Compression::none;
    return Compression::unknown;
}

[[nodiscard]] inline const char* tool_for(Compression c) {
    return c == Compression::xz ? "xz" : c == Compression::zstd ? "zstd" : nullptr;
}

[[nodiscard]] inline bool have_tool(const char* name) {
    const char* path = std::getenv("PATH");
    std::string_view rest = path ? path : "/usr/bin:/bin";
    while (!rest.empty()) {
        const auto c = rest.find(':');
        const std::string p = std::string{rest.substr(0, c)} + "/" + name;
        if (::access(p.c_str(), X_OK) == 0) return true;
        if (c == std::string_view::npos) break;
        rest.remove_prefix(c + 1);
    }
    return false;
}

// A byte source: gzip via zlib (which also passes plain tar through), or a
// decompressor process's stdout.
class Source {
public:
    ~Source() { close(); }
    bool open(const std::string& path, std::string& why) {
        const Compression c = sniff(path);
        if (c == Compression::unknown) { why = path + " is not a tar archive (or a compressed one)"; return false; }
        if (c == Compression::none || c == Compression::gzip) {
            gz_ = ::gzopen(path.c_str(), "rb");
            if (!gz_) { why = std::string{"cannot open "} + path + ": " + std::strerror(errno); return false; }
            ::gzbuffer(gz_, 1 << 17);
            return true;
        }
        const char* tool = tool_for(c);
        if (!have_tool(tool)) {
            why = path + " is " + tool + "-compressed and this system has no `" + tool +
                  "`; use a .tar.gz image, or decompress it first";
            return false;
        }
        int p[2];
        if (::pipe2(p, O_CLOEXEC) != 0) { why = std::strerror(errno); return false; }
        pid_ = ::fork();
        if (pid_ == 0) {
            ::dup2(p[1], 1);
            const int in = ::open(path.c_str(), O_RDONLY);
            if (in < 0) ::_exit(127);
            ::dup2(in, 0);
            ::execlp(tool, tool, "-dc", static_cast<char*>(nullptr));
            ::_exit(127);
        }
        ::close(p[1]);
        fd_ = p[0];
        return pid_ > 0;
    }
    // Read exactly n bytes; false at end of data or on an error.
    bool read_exact(void* buf, std::size_t n) {
        auto* p = static_cast<char*>(buf);
        while (n > 0) {
            long got;
            if (gz_) got = ::gzread(gz_, p, static_cast<unsigned>(std::min<std::size_t>(n, 1u << 30)));
            else got = ::read(fd_, p, n);
            if (got < 0 && !gz_ && errno == EINTR) continue;
            if (got <= 0) return false;
            p += got;
            n -= static_cast<std::size_t>(got);
        }
        return true;
    }
    // Close; false if the decompressor failed or the gzip stream was bad.
    bool close() {
        bool ok = true;
        if (gz_) { int err = 0; ::gzerror(gz_, &err); ok = err == Z_OK || err == Z_STREAM_END; ::gzclose(gz_); gz_ = nullptr; }
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
        if (pid_ > 0) {
            int st = 0;
            ::waitpid(pid_, &st, 0);
            ok = ok && WIFEXITED(st) && WEXITSTATUS(st) == 0;
            pid_ = -1;
        }
        return ok;
    }

private:
    ::gzFile gz_{nullptr};
    int fd_{-1};
    ::pid_t pid_{-1};
};

// What the host couldn't hold for us: owners other than root, and modes the
// metadata journal should restate.
struct Meta {
    std::string path;   // guest path ("/usr/bin/sudo")
    std::uint32_t uid, gid, mode;
};

struct Result {
    std::uint64_t files{0}, dirs{0}, links{0}, copied_links{0}, skipped{0};
    std::vector<Meta> meta;
    std::string error;
};

namespace detail {

[[nodiscard]] inline std::uint64_t num(const char* f, std::size_t n) {
    if (n && (static_cast<unsigned char>(f[0]) & 0x80)) {   // GNU base-256
        std::uint64_t v = static_cast<unsigned char>(f[0]) & 0x7f;
        for (std::size_t i = 1; i < n; ++i) v = (v << 8) | static_cast<unsigned char>(f[i]);
        return v;
    }
    std::uint64_t v = 0;
    std::size_t i = 0;
    while (i < n && (f[i] == ' ' || f[i] == '\0')) ++i;
    for (; i < n && f[i] >= '0' && f[i] <= '7'; ++i) v = v * 8 + static_cast<unsigned>(f[i] - '0');
    return v;
}

[[nodiscard]] inline std::string field(const char* f, std::size_t n) {
    return std::string{f, ::strnlen(f, n)};
}

// "a/./b/" -> "a/b"; "" for "." or anything with "..".
[[nodiscard]] inline std::string clean(std::string_view p) {
    std::string out;
    while (!p.empty()) {
        const auto s = p.find('/');
        const std::string_view c = p.substr(0, s);
        if (c == "..") return {};
        if (!c.empty() && c != ".") {
            if (!out.empty()) out.push_back('/');
            out.append(c);
        }
        if (s == std::string_view::npos) break;
        p.remove_prefix(s + 1);
    }
    return out;
}

// Open the directory that holds `rel` (creating missing parents), never
// following a symlink. Returns the leaf name in `leaf`, or -1.
inline int open_parent(int root, const std::string& rel, std::string& leaf) {
    int dir = ::dup(root);
    std::string_view rest = rel;
    for (;;) {
        const auto s = rest.find('/');
        if (s == std::string_view::npos) { leaf = std::string{rest}; return dir; }
        const std::string c{rest.substr(0, s)};
        (void)::mkdirat(dir, c.c_str(), 0755);
        const int next = ::openat(dir, c.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        ::close(dir);
        if (next < 0) return -1;
        dir = next;
        rest.remove_prefix(s + 1);
    }
}

inline bool copy_fd(int in, int out) {
    char buf[1 << 16];
    for (;;) {
        const ::ssize_t n = ::read(in, buf, sizeof buf);
        if (n == 0) return true;
        if (n < 0) { if (errno == EINTR) continue; return false; }
        for (::ssize_t d = 0; d < n;) {
            const ::ssize_t w = ::write(out, buf + d, static_cast<std::size_t>(n - d));
            if (w < 0) { if (errno == EINTR) continue; return false; }
            d += w;
        }
    }
}

}  // namespace detail

// Unpack `archive` into `dest` (created if missing). Entries under `strip`
// (e.g. "root.x86_64") have it removed; others are skipped when it's set.
// `progress` gets the entry count now and then.
[[nodiscard]] inline Result extract(const std::string& archive, const std::string& dest,
                                    const std::string& strip = {},
                                    const std::function<void(std::uint64_t)>& progress = {}) {
    Result r;
    Source src;
    if (!src.open(archive, r.error)) return r;
    (void)::mkdir(dest.c_str(), 0755);
    const int root = ::open(dest.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) { r.error = "cannot open " + dest + ": " + std::strerror(errno); return r; }
    struct DirMode { std::string rel; std::uint32_t mode; std::int64_t mtime; };
    std::vector<DirMode> dirs;
    const std::string strip_clean = detail::clean(strip);

    std::string long_name, long_link;
    std::string pax_path, pax_link;
    std::int64_t pax_size = -1, pax_uid = -1, pax_gid = -1;
    char h[512];
    int zero_blocks = 0;
    std::vector<char> data;
    const ::mode_t old_umask = ::umask(0);

    while (src.read_exact(h, 512)) {
        bool zero = true;
        for (const char c : h) if (c) { zero = false; break; }
        if (zero) { if (++zero_blocks == 2) break; continue; }
        zero_blocks = 0;

        const char type = h[156];
        std::uint64_t size = detail::num(h + 124, 12);
        if (pax_size >= 0 && type != 'x' && type != 'g') size = static_cast<std::uint64_t>(pax_size);
        const std::uint64_t padded = (size + 511) & ~std::uint64_t{511};

        // metadata records that describe the NEXT entry
        if (type == 'L' || type == 'K' || type == 'x' || type == 'g') {
            data.resize(padded);
            if (padded && !src.read_exact(data.data(), padded)) break;
            const std::string body{data.data(), ::strnlen(data.data(), size)};
            if (type == 'L') long_name = body;
            else if (type == 'K') long_link = body;
            else if (type == 'x') {
                std::string_view rest{data.data(), size};
                while (!rest.empty()) {
                    const auto sp = rest.find(' ');
                    if (sp == std::string_view::npos) break;
                    const std::size_t len = std::strtoul(std::string{rest.substr(0, sp)}.c_str(), nullptr, 10);
                    if (len == 0 || len > rest.size()) break;
                    const std::string_view rec = rest.substr(sp + 1, len - sp - 2);   // drop "\n"
                    const auto eq = rec.find('=');
                    const std::string_view k = rec.substr(0, eq), v = rec.substr(eq + 1);
                    if (k == "path") pax_path = v;
                    else if (k == "linkpath") pax_link = v;
                    else if (k == "size") pax_size = std::strtoll(std::string{v}.c_str(), nullptr, 10);
                    else if (k == "uid") pax_uid = std::strtoll(std::string{v}.c_str(), nullptr, 10);
                    else if (k == "gid") pax_gid = std::strtoll(std::string{v}.c_str(), nullptr, 10);
                    rest.remove_prefix(len);
                }
            }
            continue;
        }

        std::string name = !pax_path.empty() ? pax_path : !long_name.empty() ? long_name : [&] {
            std::string n = detail::field(h, 100);
            if (std::memcmp(h + 257, "ustar", 5) == 0 && h[345])
                n = detail::field(h + 345, 155) + "/" + n;
            return n;
        }();
        std::string link = !pax_link.empty() ? pax_link : !long_link.empty() ? long_link : detail::field(h + 157, 100);
        const std::uint32_t mode = static_cast<std::uint32_t>(detail::num(h + 100, 8)) & 07777;
        const auto uid = static_cast<std::uint32_t>(pax_uid >= 0 ? pax_uid : static_cast<std::int64_t>(detail::num(h + 108, 8)));
        const auto gid = static_cast<std::uint32_t>(pax_gid >= 0 ? pax_gid : static_cast<std::int64_t>(detail::num(h + 116, 8)));
        const auto mtime = static_cast<std::int64_t>(detail::num(h + 136, 12));
        long_name.clear(); long_link.clear(); pax_path.clear(); pax_link.clear();
        pax_size = pax_uid = pax_gid = -1;

        std::string rel = detail::clean(name);
        bool keep = !rel.empty();
        if (keep && !strip_clean.empty()) {
            if (rel == strip_clean) keep = false;   // the top dir itself
            else if (rel.starts_with(strip_clean + "/")) rel = rel.substr(strip_clean.size() + 1);
            else keep = false;
        }
        const bool is_file = type == '0' || type == '\0' || type == '7';
        auto skip_data = [&] {
            char buf[512];
            for (std::uint64_t left = is_file ? padded : 0; left > 0; left -= 512)
                if (!src.read_exact(buf, 512)) return false;
            return true;
        };
        if (!keep) { if (!skip_data()) break; continue; }

        std::string leaf;
        const int dir = detail::open_parent(root, rel, leaf);
        if (dir < 0) { ++r.skipped; if (!skip_data()) break; continue; }

        bool ok = true;
        if (type == '5') {
            if (::mkdirat(dir, leaf.c_str(), 0755) != 0 && errno != EEXIST) ok = false;
            dirs.push_back({rel, mode, mtime});
            ++r.dirs;
        } else if (is_file) {
            (void)::unlinkat(dir, leaf.c_str(), 0);
            const int fd = ::openat(dir, leaf.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd < 0) ok = false;
            char buf[1 << 16];
            for (std::uint64_t left = size; left > 0;) {
                const std::size_t k = static_cast<std::size_t>(std::min<std::uint64_t>(left, sizeof buf));
                if (!src.read_exact(buf, k)) { ::close(fd); ::close(dir); r.error = "the archive ends early"; goto done; }
                if (fd >= 0 && ::write(fd, buf, k) != static_cast<::ssize_t>(k)) ok = false;
                left -= k;
            }
            if (padded > size) {
                char pad[512];
                if (!src.read_exact(pad, padded - size)) { if (fd >= 0) ::close(fd); ::close(dir); r.error = "the archive ends early"; goto done; }
            }
            if (fd >= 0) {
                (void)::fchmod(fd, static_cast<mode_t>(mode));
                const ::timespec ts[2] = {{mtime, 0}, {mtime, 0}};
                (void)::futimens(fd, ts);
                ::close(fd);
            }
            ++r.files;
        } else if (type == '2') {
            (void)::unlinkat(dir, leaf.c_str(), 0);
            if (::symlinkat(link.c_str(), dir, leaf.c_str()) != 0) ok = false;
            ++r.links;
        } else if (type == '1') {
            std::string target = detail::clean(link);
            if (!strip_clean.empty() && target.starts_with(strip_clean + "/")) target = target.substr(strip_clean.size() + 1);
            std::string tleaf;
            const int tdir = target.empty() ? -1 : detail::open_parent(root, target, tleaf);
            (void)::unlinkat(dir, leaf.c_str(), 0);
            if (tdir < 0) ok = false;
            else if (::linkat(tdir, tleaf.c_str(), dir, leaf.c_str(), 0) == 0) ++r.links;
            else {
                // the host refuses hard links (Android): copy
                const int in = ::openat(tdir, tleaf.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                const int out = in < 0 ? -1 : ::openat(dir, leaf.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
                struct ::stat st{};
                ok = in >= 0 && out >= 0 && ::fstat(in, &st) == 0 && detail::copy_fd(in, out);
                if (out >= 0) { (void)::fchmod(out, st.st_mode & 07777); ::close(out); }
                if (in >= 0) ::close(in);
                ++r.copied_links;
            }
            if (tdir >= 0) ::close(tdir);
        } else {
            ++r.skipped;   // devices, FIFOs: linuxity serves /dev itself
        }
        ::close(dir);
        if (!ok) ++r.skipped;
        if ((type == '5' || is_file) &&
            (uid != 0 || gid != 0 || (mode & 07000) || (type == '5' && (mode & 0700) != 0700)))
            r.meta.push_back({"/" + rel, uid, gid, mode});
        if (progress && ((r.files + r.dirs + r.links) & 1023) == 0) progress(r.files + r.dirs + r.links);
    }
done:
    // directory modes last, deepest first, so a 0555 dir didn't block its
    // own children
    for (auto it = dirs.rbegin(); it != dirs.rend(); ++it) {
        (void)::fchmodat(root, it->rel.c_str(), static_cast<mode_t>(it->mode | 0700), 0);
        const ::timespec ts[2] = {{it->mtime, 0}, {it->mtime, 0}};
        (void)::utimensat(root, it->rel.c_str(), ts, AT_SYMLINK_NOFOLLOW);
    }
    ::umask(old_umask);
    ::close(root);
    if (!src.close() && r.error.empty()) r.error = "the archive is corrupt or truncated";
    if (r.error.empty() && r.files == 0 && r.dirs == 0) r.error = "the archive is empty";
    return r;
}

}  // namespace lx::env::archive
