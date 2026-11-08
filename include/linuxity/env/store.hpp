// linuxity/env/store.hpp
//
// Where environments live and how they are managed. One directory per env:
//
//   $LINUXITY_HOME/envs/<name>/
//       env.vibe        the config (env.vibe is the source of truth)
//       upper/          every write the guest made (the overlay upper)
//       snapshots/<s>/  saved copies of upper/
//       logs/           a detached instance's log and per-service logs
//       run/            control socket, pid file (only while running)
//
// $LINUXITY_HOME defaults to $XDG_DATA_HOME/linuxity, else
// ~/.local/share/linuxity. The Android app sets it to its files dir.
//
// The rootfs itself is NOT copied: env.vibe points at it, and it is never
// written to. That is what makes reset and snapshot cheap -- they only touch
// upper/.
#pragma once

#include "linuxity/env/config.hpp"
#include "linuxity/env/vibe_edit.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace lx::env {

[[nodiscard]] inline std::string home_dir() {
    if (const char* h = std::getenv("LINUXITY_HOME"); h && *h) return h;
    if (const char* x = std::getenv("XDG_DATA_HOME"); x && *x) return std::string{x} + "/linuxity";
    if (const char* h = std::getenv("HOME"); h && *h) return std::string{h} + "/.local/share/linuxity";
    return "/tmp/linuxity-home-" + std::to_string(::getuid());
}

// Env and snapshot names: [A-Za-z0-9._-], not starting with '.' or '-'.
[[nodiscard]] inline bool valid_name(std::string_view n) {
    if (n.empty() || n.size() > 64 || n[0] == '.' || n[0] == '-') return false;
    for (const char c : n)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.'))
            return false;
    return true;
}

[[nodiscard]] inline bool is_dir(const std::string& p) {
    struct ::stat st{};
    return ::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

[[nodiscard]] inline bool exists(const std::string& p) {
    struct ::stat st{};
    return ::lstat(p.c_str(), &st) == 0;
}

inline bool mkdirs(const std::string& p, mode_t mode = 0755) {
    if (p.empty()) return false;
    std::string cur;
    std::size_t i = 0;
    if (p[0] == '/') { cur = "/"; i = 1; }
    while (i <= p.size()) {
        const auto s = p.find('/', i);
        cur += p.substr(i, (s == std::string::npos ? p.size() : s) - i);
        if (!cur.empty() && cur != "/" && ::mkdir(cur.c_str(), mode) != 0 && errno != EEXIST) return false;
        if (s == std::string::npos) break;
        cur += "/";
        i = s + 1;
    }
    return is_dir(p);
}

[[nodiscard]] inline std::vector<std::string> list_dir(const std::string& p) {
    std::vector<std::string> out;
    if (DIR* d = ::opendir(p.c_str())) {
        while (const ::dirent* e = ::readdir(d)) {
            const std::string_view n = e->d_name;
            if (n == "." || n == "..") continue;
            out.emplace_back(n);
        }
        ::closedir(d);
    }
    std::sort(out.begin(), out.end());
    return out;
}

// Remove a tree without following symlinks. Directories inside it may be
// read-only (a package installed 0555 dirs), so make each writable first.
inline bool remove_tree(const std::string& p) {
    struct ::stat st{};
    if (::lstat(p.c_str(), &st) != 0) return errno == ENOENT;
    if (S_ISDIR(st.st_mode)) {
        (void)::chmod(p.c_str(), 0700);
        bool ok = true;
        for (const auto& n : list_dir(p)) ok = remove_tree(p + "/" + n) && ok;
        return ::rmdir(p.c_str()) == 0 && ok;
    }
    return ::unlink(p.c_str()) == 0;
}

// Copy a tree, keeping symlinks as symlinks and modes as modes. Hard links
// become separate files; that is fine for an overlay upper.
inline bool copy_tree(const std::string& from, const std::string& to) {
    struct ::stat st{};
    if (::lstat(from.c_str(), &st) != 0) return false;
    if (S_ISLNK(st.st_mode)) {
        std::string target(static_cast<std::size_t>(st.st_size) + 1, '\0');
        const ::ssize_t n = ::readlink(from.c_str(), target.data(), target.size());
        if (n < 0) return false;
        target.resize(static_cast<std::size_t>(n));
        return ::symlink(target.c_str(), to.c_str()) == 0;
    }
    if (S_ISDIR(st.st_mode)) {
        if (::mkdir(to.c_str(), 0700) != 0 && errno != EEXIST) return false;
        bool ok = true;
        for (const auto& n : list_dir(from)) ok = copy_tree(from + "/" + n, to + "/" + n) && ok;
        (void)::chmod(to.c_str(), st.st_mode & 07777);
        return ok;
    }
    if (S_ISREG(st.st_mode)) {
        const int in = ::open(from.c_str(), O_RDONLY | O_CLOEXEC);
        if (in < 0) return false;
        const int out = ::open(to.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (out < 0) { ::close(in); return false; }
        char buf[1 << 16];
        bool ok = true;
        for (;;) {
            const ::ssize_t n = ::read(in, buf, sizeof buf);
            if (n == 0) break;
            if (n < 0) { if (errno == EINTR) continue; ok = false; break; }
            for (::ssize_t done = 0; done < n;) {
                const ::ssize_t w = ::write(out, buf + done, static_cast<std::size_t>(n - done));
                if (w < 0) { if (errno == EINTR) continue; ok = false; break; }
                done += w;
            }
            if (!ok) break;
        }
        ::close(in);
        (void)::fchmod(out, st.st_mode & 07777);
        ::close(out);
        return ok;
    }
    // FIFOs and sockets in an upper are leftovers of a run; skip them
    return true;
}

[[nodiscard]] inline std::uint64_t tree_bytes(const std::string& p) {
    struct ::stat st{};
    if (::lstat(p.c_str(), &st) != 0) return 0;
    if (!S_ISDIR(st.st_mode)) return static_cast<std::uint64_t>(st.st_blocks) * 512;
    std::uint64_t sum = static_cast<std::uint64_t>(st.st_blocks) * 512;
    for (const auto& n : list_dir(p)) sum += tree_bytes(p + "/" + n);
    return sum;
}

inline bool write_file_atomic(const std::string& path, std::string_view body) {
    const std::string tmp = path + ".tmp." + std::to_string(::getpid());
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return false;
    bool ok = true;
    for (std::size_t done = 0; done < body.size();) {
        const ::ssize_t w = ::write(fd, body.data() + done, body.size() - done);
        if (w < 0) { if (errno == EINTR) continue; ok = false; break; }
        done += static_cast<std::size_t>(w);
    }
    ok = ::fsync(fd) == 0 && ok;
    ::close(fd);
    if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0) { ::unlink(tmp.c_str()); return false; }
    return true;
}

[[nodiscard]] inline std::optional<std::string> slurp(const std::string& path) {
    std::ifstream f{path, std::ios::binary};
    if (!f) return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// A short path for the control socket. sun_path is 108 bytes and an app's
// files dir can be long, so fall back to a hashed name under /tmp (or the
// abstract namespace, chosen by the caller) when the natural one won't fit.
[[nodiscard]] inline std::string socket_path_for(const std::string& run_dir) {
    std::string p = run_dir + "/control.sock";
    if (p.size() < 100) return p;
    std::uint64_t h = 1469598103934665603ULL;
    for (const char c : run_dir) { h ^= static_cast<unsigned char>(c); h *= 1099511628211ULL; }
    char buf[64];
    std::snprintf(buf, sizeof buf, "/tmp/linuxity-%llx.sock", static_cast<unsigned long long>(h));
    return buf;
}

class Store {
public:
    explicit Store(std::string home = home_dir()) : home_{std::move(home)} {}

    [[nodiscard]] const std::string& home() const { return home_; }
    [[nodiscard]] std::string envs_dir() const { return home_ + "/envs"; }
    [[nodiscard]] std::string dir(std::string_view n) const { return envs_dir() + "/" + std::string{n}; }
    [[nodiscard]] std::string config_path(std::string_view n) const { return dir(n) + "/env.vibe"; }
    [[nodiscard]] std::string default_upper(std::string_view n) const { return dir(n) + "/upper"; }
    [[nodiscard]] std::string snapshots_dir(std::string_view n) const { return dir(n) + "/snapshots"; }
    [[nodiscard]] std::string logs_dir(std::string_view n) const { return dir(n) + "/logs"; }
    [[nodiscard]] std::string run_dir(std::string_view n) const { return dir(n) + "/run"; }
    [[nodiscard]] std::string socket_path(std::string_view n) const { return socket_path_for(run_dir(n)); }
    [[nodiscard]] std::string pid_path(std::string_view n) const { return run_dir(n) + "/pid"; }

    [[nodiscard]] bool has(std::string_view n) const { return valid_name(n) && exists(config_path(n)); }
    [[nodiscard]] std::vector<std::string> names() const {
        std::vector<std::string> out;
        for (auto& n : list_dir(envs_dir()))
            if (has(n)) out.push_back(std::move(n));
        return out;
    }

    // Load and validate. The config's name defaults to the env's, and its
    // upper to <env>/upper; a relative rootfs is relative to the env dir.
    [[nodiscard]] ParseResult load(std::string_view n) const {
        ParseResult r;
        const auto text = slurp(config_path(n));
        if (!text) {
            r.diags.push_back({"", "no such environment: " + std::string{n}, true});
            return r;
        }
        r = parse_config(*text);
        fill_defaults(r.config, n);
        return r;
    }

    void fill_defaults(EnvConfig& c, std::string_view n) const {
        if (c.name.empty()) c.name = std::string{n};
        if (c.upper.empty()) c.upper = default_upper(n);
        else if (c.upper.front() != '/') c.upper = dir(n) + "/" + c.upper;
        if (!c.rootfs.empty() && c.rootfs.front() != '/') c.rootfs = dir(n) + "/" + c.rootfs;
        if (c.log.empty()) c.log = logs_dir(n) + "/linuxity.log";
    }

    // Create a new env pointing at `rootfs`. `extra` is appended to the
    // generated env.vibe (from `env create --set`). Errors are returned as
    // text; empty means success.
    [[nodiscard]] std::string create(std::string_view n, const std::string& rootfs,
                                     std::string_view extra = {}) const {
        if (!valid_name(n)) return "bad name '" + std::string{n} + "' (use letters, digits, . _ -)";
        if (exists(dir(n))) return "environment '" + std::string{n} + "' already exists";
        std::string root = rootfs;
        if (char* rp = ::realpath(rootfs.c_str(), nullptr)) { root = rp; std::free(rp); }
        if (!is_dir(root)) return "rootfs '" + rootfs + "' is not a directory";
        if (!mkdirs(dir(n)) || !mkdirs(default_upper(n)) || !mkdirs(logs_dir(n)))
            return "cannot create " + dir(n) + ": " + std::strerror(errno);
        std::string body = template_text(n, root);
        if (!extra.empty()) { body += "\n"; body += extra; }
        if (auto r = parse_config(body); !r.ok()) {
            (void)remove_tree(dir(n));
            std::string why;
            for (const auto& d : r.diags) if (d.error) why += "\n  " + format_diag(d);
            return "the generated config is invalid:" + why;
        }
        if (!write_file_atomic(config_path(n), body)) {
            (void)remove_tree(dir(n));
            return "cannot write " + config_path(n);
        }
        return {};
    }

    // The env.vibe a new environment starts with: every common setting,
    // most commented out at its default so the file documents itself.
    [[nodiscard]] static std::string template_text(std::string_view n, const std::string& rootfs) {
        std::string t;
        t += "# linuxity environment. Edit by hand or with `linuxity env set`.\n";
        t += "# Every key: `linuxity env schema`.\n\n";
        t += "name " + vibe_edit::string_text(n) + "\n";
        t += "rootfs " + vibe_edit::string_text(rootfs) + "\n\n";
        t += "system {\n  hostname " + vibe_edit::string_text(n) + "\n"
             "  # kernel-release 6.6.0-linuxity\n  # timezone Europe/Berlin\n  # locale en_US.UTF-8\n}\n\n";
        t += "login {\n  user root\n  # shell /usr/bin/zsh\n  # cwd /root\n  # umask 022\n}\n\n";
        t += "network {\n  # dns [ 1.1.1.1 8.8.8.8 ]\n}\n\n";
        t += "limits {\n  # cpus 2\n  # memory 2G\n  # pids 4096\n}\n\n";
        t += "storage {\n  persist true\n}\n\n";
        t += "env {\n  # EDITOR vim\n}\n\n";
        t += "# mount phone {\n#   host /sdcard\n#   at /mnt/phone\n# }\n\n";
        t += "# service sshd {\n#   command [ /usr/bin/sshd -D ]\n#   restart on-failure\n# }\n";
        return t;
    }

    // Wipe upper/ so the next run starts from the clean image.
    [[nodiscard]] std::string reset(std::string_view n) const {
        auto r = load(n);
        if (!r.ok()) return "cannot load " + std::string{n};
        if (!remove_tree(r.config.upper)) return "cannot clear " + r.config.upper + ": " + std::strerror(errno);
        if (!mkdirs(r.config.upper)) return "cannot recreate " + r.config.upper;
        return {};
    }

    [[nodiscard]] std::vector<std::string> snapshots(std::string_view n) const {
        std::vector<std::string> out;
        for (auto& s : list_dir(snapshots_dir(n)))
            if (valid_name(s) && is_dir(snapshots_dir(n) + "/" + s)) out.push_back(std::move(s));
        return out;
    }

    [[nodiscard]] std::string snapshot(std::string_view n, std::string_view snap) const {
        if (!valid_name(snap)) return "bad snapshot name '" + std::string{snap} + "'";
        auto r = load(n);
        if (!r.ok()) return "cannot load " + std::string{n};
        const std::string to = snapshots_dir(n) + "/" + std::string{snap};
        if (exists(to)) return "snapshot '" + std::string{snap} + "' already exists";
        if (!mkdirs(snapshots_dir(n))) return "cannot create " + snapshots_dir(n);
        const std::string tmp = to + ".partial";
        (void)remove_tree(tmp);
        if (!copy_tree(r.config.upper, tmp)) { (void)remove_tree(tmp); return "copy failed: " + std::string{std::strerror(errno)}; }
        // the config at the time, so a restore brings both back
        if (const auto cfg = slurp(config_path(n))) (void)write_file_atomic(tmp + ".vibe", *cfg);
        if (::rename(tmp.c_str(), to.c_str()) != 0) { (void)remove_tree(tmp); return "rename failed"; }
        if (exists(tmp + ".vibe")) (void)::rename((tmp + ".vibe").c_str(), (to + ".vibe").c_str());
        return {};
    }

    [[nodiscard]] std::string restore(std::string_view n, std::string_view snap) const {
        auto r = load(n);
        if (!r.ok()) return "cannot load " + std::string{n};
        const std::string from = snapshots_dir(n) + "/" + std::string{snap};
        if (!valid_name(snap) || !is_dir(from)) return "no snapshot '" + std::string{snap} + "'";
        const std::string tmp = r.config.upper + ".restoring";
        (void)remove_tree(tmp);
        if (!copy_tree(from, tmp)) { (void)remove_tree(tmp); return "copy failed"; }
        if (!remove_tree(r.config.upper)) { (void)remove_tree(tmp); return "cannot clear " + r.config.upper; }
        if (::rename(tmp.c_str(), r.config.upper.c_str()) != 0) return "rename failed";
        if (const auto cfg = slurp(from + ".vibe")) (void)write_file_atomic(config_path(n), *cfg);
        return {};
    }

    [[nodiscard]] std::string drop_snapshot(std::string_view n, std::string_view snap) const {
        const std::string p = snapshots_dir(n) + "/" + std::string{snap};
        if (!valid_name(snap) || !is_dir(p)) return "no snapshot '" + std::string{snap} + "'";
        (void)::unlink((p + ".vibe").c_str());
        return remove_tree(p) ? std::string{} : "cannot remove " + p;
    }

    [[nodiscard]] std::string remove(std::string_view n) const {
        if (!has(n)) return "no such environment: " + std::string{n};
        // an upper outside the env dir is the user's; leave it
        return remove_tree(dir(n)) ? std::string{} : "cannot remove " + dir(n) + ": " + std::strerror(errno);
    }

    [[nodiscard]] std::string rename(std::string_view from, std::string_view to) const {
        if (!has(from)) return "no such environment: " + std::string{from};
        if (!valid_name(to)) return "bad name '" + std::string{to} + "'";
        if (exists(dir(to))) return "environment '" + std::string{to} + "' already exists";
        if (::rename(dir(from).c_str(), dir(to).c_str()) != 0) return std::strerror(errno);
        return {};
    }

    // The pid of a running instance, or 0. A stale pid file is ignored.
    [[nodiscard]] ::pid_t running_pid(std::string_view n) const {
        const auto t = slurp(pid_path(n));
        if (!t) return 0;
        const long pid = std::strtol(t->c_str(), nullptr, 10);
        if (pid <= 0) return 0;
        if (::kill(static_cast<::pid_t>(pid), 0) != 0 && errno == ESRCH) return 0;
        return static_cast<::pid_t>(pid);
    }

private:
    std::string home_;
};

}  // namespace lx::env
