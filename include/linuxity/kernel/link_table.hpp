// linuxity/kernel/link_table.hpp
//
// Hardlinks on a host that refuses link(2).
//
// Android denies the SELinux `link` permission on /data to every process, so
// a guest's link() can never be forwarded there. Copying the file is not a
// hardlink: the two names stop sharing data the moment either is written,
// and anything that writes through one name and reads through the other gets
// the wrong answer.
//
// So the FIRST name keeps the real file (the "backing"), and every later name
// is an alias: a placeholder on disk, so readdir and lstat still find the
// name, with every open/stat of it redirected to the backing. All names then
// share one inode -- data, size, st_ino and st_nlink agree, as on Linux.
// When the backing's own name goes away (unlink, or rename over it), the file
// is moved onto one of the aliases instead of being lost.
//
// All paths here are HOST paths, already translated. The table is journaled
// beside the overlay upper so it survives restarts; entries whose files no
// longer exist are dropped on replay.
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unordered_map>
#include <vector>

namespace lx::kernel {

class LinkTable {
public:
    // The journal's file name inside the upper layer. Hidden from listings.
    [[nodiscard]] static constexpr std::string_view journal_leaf() noexcept {
        return ".linuxity-links";
    }

    void attach(const std::string& upper) {
        journal_ = upper + "/" + std::string{journal_leaf()};
        replay();
    }

    [[nodiscard]] bool empty() const noexcept { return alias_.empty(); }

    // Bumped on every change; the in-guest handler re-reads the table when it moves.
    [[nodiscard]] std::uint64_t version() const noexcept { return version_; }
    // Every host path that is an alias or a backing.
    template <class F> void for_each_path(F&& f) const {
        for (const auto& [a, b] : alias_) { f(a); f(b); }
    }

    // The backing for `p` if it is an alias, else nullptr.
    [[nodiscard]] const std::string* backing_of(const std::string& p) const {
        const auto it = alias_.find(p);
        return it == alias_.end() ? nullptr : &it->second;
    }

    // `p` itself if it is not an alias.
    [[nodiscard]] const std::string& resolve(const std::string& p) const {
        const std::string* b = backing_of(p);
        return b != nullptr ? *b : p;
    }

    // st_nlink for the inode whose backing is `backing`.
    [[nodiscard]] std::uint32_t count(const std::string& backing) const {
        const auto it = names_.find(backing);
        return it == names_.end() ? 1u
                                  : 1u + static_cast<std::uint32_t>(it->second.size());
    }

    [[nodiscard]] bool has_aliases(const std::string& backing) const {
        const auto it = names_.find(backing);
        return it != names_.end() && !it->second.empty();
    }

    // `alias` is a new name for the inode at `backing` (already resolved).
    void add(const std::string& alias, const std::string& backing) {
        ++version_;
        alias_[alias] = backing;
        names_[backing].push_back(alias);
        log('+', alias, backing);
    }

    // An alias name was removed.
    void drop(const std::string& alias) {
        ++version_;
        const auto it = alias_.find(alias);
        if (it == alias_.end()) return;
        erase_name(it->second, alias);
        alias_.erase(it);
        log('-', alias, {});
    }

    // The backing's own name is about to disappear. Returns the alias the
    // caller must move the file onto, and re-points the other aliases at it.
    // nullopt when there are no aliases (the file simply goes).
    [[nodiscard]] std::optional<std::string> promote(const std::string& backing) {
        ++version_;
        const auto it = names_.find(backing);
        if (it == names_.end() || it->second.empty()) return std::nullopt;
        std::vector<std::string> rest = std::move(it->second);
        names_.erase(it);
        std::string heir = rest.front();
        rest.erase(rest.begin());
        alias_.erase(heir);
        log('-', heir, {});
        for (const std::string& a : rest) {
            alias_[a] = heir;
            names_[heir].push_back(a);
            log('+', a, heir);
        }
        return heir;
    }

    // A rename moved `from` to `to`. Rewrites every entry naming `from`
    // itself or anything beneath it (a directory rename carries its
    // contents' links along).
    void rename_prefix(const std::string& from, const std::string& to) {
        auto moved = [&](const std::string& p) -> std::optional<std::string> {
            if (p == from) return to;
            if (p.size() > from.size() && p.compare(0, from.size(), from) == 0 &&
                p[from.size()] == '/')
                return to + p.substr(from.size());
            return std::nullopt;
        };
        // Collect first, then apply: rewriting while iterating would rehash
        // under the loop. Only entries that actually move are logged, so a
        // rename touching one link costs one journal line, not the table.
        std::vector<std::pair<std::string, std::string>> before, after;
        for (const auto& [a, b] : alias_) {
            const auto na = moved(a), nb = moved(b);
            if (!na && !nb) continue;
            before.emplace_back(a, b);
            after.emplace_back(na ? *na : a, nb ? *nb : b);
        }
        for (const auto& [a, b] : before) {
            erase_name(b, a);
            alias_.erase(a);
            log('-', a, {});
        }
        for (const auto& [a, b] : after) add(a, b);
    }

    // Does a rename of `p` touch any entry?
    [[nodiscard]] bool touches(const std::string& p) const {
        auto under = [&](const std::string& q) {
            return q == p || (q.size() > p.size() &&
                              q.compare(0, p.size(), p) == 0 && q[p.size()] == '/');
        };
        for (const auto& [a, b] : alias_)
            if (under(a) || under(b)) return true;
        return false;
    }

private:
    std::unordered_map<std::string, std::string> alias_;                 // alias -> backing
    std::unordered_map<std::string, std::vector<std::string>> names_;    // backing -> aliases
    std::string journal_;
    std::uint64_t version_{0};

    void erase_name(const std::string& backing, const std::string& alias) {
        const auto it = names_.find(backing);
        if (it == names_.end()) return;
        auto& v = it->second;
        v.erase(std::remove(v.begin(), v.end(), alias), v.end());
        if (v.empty()) names_.erase(it);
    }

    // One line per change: "+\talias\tbacking" or "-\talias". Append-only, so
    // a crash mid-write loses at most the last line.
    void log(char op, const std::string& alias, const std::string& backing) const {
        if (journal_.empty()) return;
        std::FILE* f = std::fopen(journal_.c_str(), "a");
        if (f == nullptr) return;
        if (op == '+') std::fprintf(f, "+\t%s\t%s\n", alias.c_str(), backing.c_str());
        else           std::fprintf(f, "-\t%s\n", alias.c_str());
        std::fclose(f);
    }

    void replay() {
        std::FILE* f = std::fopen(journal_.c_str(), "r");
        if (f == nullptr) return;
        std::unordered_map<std::string, std::string> state;
        char line[8192];
        while (std::fgets(line, sizeof line, f) != nullptr) {
            std::string s{line};
            if (!s.empty() && s.back() == '\n') s.pop_back();
            if (s.size() < 3 || s[1] != '\t') continue;
            const std::string rest = s.substr(2);
            if (s[0] == '-') { state.erase(rest); continue; }
            const auto tab = rest.find('\t');
            if (s[0] != '+' || tab == std::string::npos) continue;
            state[rest.substr(0, tab)] = rest.substr(tab + 1);
        }
        std::fclose(f);
        // Keep only entries whose files are both still there, then rewrite
        // the journal compactly so it does not grow without bound.
        ++version_;
        struct ::stat st{};
        alias_.clear();
        names_.clear();
        for (const auto& [a, b] : state)
            if (::lstat(a.c_str(), &st) == 0 && ::lstat(b.c_str(), &st) == 0) {
                alias_[a] = b;
                names_[b].push_back(a);
            }
        std::FILE* w = std::fopen(journal_.c_str(), "w");
        if (w == nullptr) return;
        for (const auto& [a, b] : alias_)
            std::fprintf(w, "+\t%s\t%s\n", a.c_str(), b.c_str());
        std::fclose(w);
    }
};

}  // namespace lx::kernel
